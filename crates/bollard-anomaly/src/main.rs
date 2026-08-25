// SPDX-License-Identifier: Apache-2.0
//
// bollard-anomaly — statistical covert-channel detection over bollard-proxy's
// egress log. This is Weekend 2 of the covert-channel detection work: three
// Tukey-fence anomaly tests (timing, byte-size, hostname entropy) over the
// JSONL fields bollard-proxy already emits. See ../../docs/covert_channel_detection.md
// for the design rationale and an upfront prediction of which signal
// generalizes and which doesn't — validated against synthetic adversarial
// traffic in this crate's tests, not just asserted.

use serde::Deserialize;
use std::collections::HashMap;
use std::io::BufRead;

#[derive(Debug, Clone, Deserialize)]
pub struct EgressEvent {
    pub timestamp: f64,
    pub session: String,
    pub host: String,
    pub port: u16,
    pub kind: String,
    pub allow: bool,
    pub reason: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub latency_ms: f64,
    pub hostname_entropy: f64,
    pub baseline: bool,
}

#[derive(Debug, Clone)]
pub struct HostBaseline {
    pub latency_q1: f64,
    pub latency_q3: f64,
    pub size_q1: f64,
    pub size_q3: f64,
    pub n: usize,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Build one (session, host) -> HostBaseline map from events tagged
/// `baseline: true`. Only allowed connections count — a denied request's
/// timing/size reflects the deny path, not real traffic to that host.
pub fn build_baselines(events: &[EgressEvent]) -> HashMap<(String, String), HostBaseline> {
    let mut grouped: HashMap<(String, String), (Vec<f64>, Vec<f64>)> = HashMap::new();
    for ev in events {
        if !ev.baseline || !ev.allow {
            continue;
        }
        let key = (ev.session.clone(), ev.host.clone());
        let entry = grouped.entry(key).or_default();
        entry.0.push(ev.latency_ms);
        entry.1.push((ev.request_bytes + ev.response_bytes) as f64);
    }

    grouped
        .into_iter()
        .map(|(key, (mut lat, mut size))| {
            lat.sort_by(f64::total_cmp);
            size.sort_by(f64::total_cmp);
            let baseline = HostBaseline {
                latency_q1: percentile(&lat, 0.25),
                latency_q3: percentile(&lat, 0.75),
                size_q1: percentile(&size, 0.25),
                size_q3: percentile(&size, 0.75),
                n: lat.len(),
            };
            (key, baseline)
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AnomalyResult {
    pub timing_anomaly: bool,
    pub size_anomaly: bool,
    pub entropy_anomaly: bool,
    pub no_baseline: bool,
}

impl AnomalyResult {
    pub fn any(&self) -> bool {
        self.timing_anomaly || self.size_anomaly || self.entropy_anomaly
    }
}

/// Score one event against its (session, host) baseline, if one exists.
/// `iqr_k` is the Tukey fence multiplier (1.5 = standard "mild outlier").
/// `entropy_threshold` is host-baseline-independent by design — it's the one
/// signal meant to catch exfil to a host with no traffic history at all.
pub fn score_event(
    ev: &EgressEvent,
    baselines: &HashMap<(String, String), HostBaseline>,
    iqr_k: f64,
    entropy_threshold: f64,
) -> AnomalyResult {
    let entropy_anomaly = ev.hostname_entropy > entropy_threshold;

    let key = (ev.session.clone(), ev.host.clone());
    match baselines.get(&key) {
        Some(b) => {
            let lat_iqr = b.latency_q3 - b.latency_q1;
            let lat_hi = b.latency_q3 + iqr_k * lat_iqr;
            let lat_lo = (b.latency_q1 - iqr_k * lat_iqr).max(0.0);
            let timing_anomaly = ev.latency_ms > lat_hi || ev.latency_ms < lat_lo;

            let size = (ev.request_bytes + ev.response_bytes) as f64;
            let size_iqr = b.size_q3 - b.size_q1;
            let size_hi = b.size_q3 + iqr_k * size_iqr;
            let size_lo = (b.size_q1 - iqr_k * size_iqr).max(0.0);
            let size_anomaly = size > size_hi || size < size_lo;

            AnomalyResult { timing_anomaly, size_anomaly, entropy_anomaly, no_baseline: false }
        }
        None => AnomalyResult { timing_anomaly: false, size_anomaly: false, entropy_anomaly, no_baseline: true },
    }
}

fn read_events(path: &str) -> Vec<EgressEvent> {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    std::io::BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: bollard-anomaly <baseline.jsonl> <live.jsonl> [--iqr-k 1.5] [--entropy-threshold 3.5]");
        std::process::exit(1);
    }
    let baseline_events = read_events(&args[1]);
    let live_events = read_events(&args[2]);

    let iqr_k = arg_value(&args, "--iqr-k").unwrap_or(1.5);
    let entropy_threshold = arg_value(&args, "--entropy-threshold").unwrap_or(3.9);

    let baselines = build_baselines(&baseline_events);
    println!("Built baselines for {} (session, host) pairs from {} baseline events", baselines.len(), baseline_events.len());

    let mut flagged = 0;
    let mut no_baseline = 0;
    for ev in &live_events {
        let result = score_event(ev, &baselines, iqr_k, entropy_threshold);
        if result.no_baseline {
            no_baseline += 1;
        }
        if result.any() {
            flagged += 1;
            println!(
                "FLAG {} -> {} (timing={} size={} entropy={} entropy_val={:.2})",
                ev.session, ev.host, result.timing_anomaly, result.size_anomaly, result.entropy_anomaly, ev.hostname_entropy
            );
        }
    }
    println!("\n{flagged}/{} live events flagged ({no_baseline} had no per-host baseline)", live_events.len());
}

fn arg_value(args: &[String], flag: &str) -> Option<f64> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn hostname_entropy(host: &str) -> f64 {
        if host.is_empty() {
            return 0.0;
        }
        let mut counts = HashMap::new();
        for c in host.chars() {
            *counts.entry(c).or_insert(0u32) += 1;
        }
        let len = host.chars().count() as f64;
        counts.values().map(|&c| { let p = c as f64 / len; -p * p.log2() }).sum()
    }

    fn make_event(host: &str, latency_ms: f64, request_bytes: u64, response_bytes: u64, baseline: bool) -> EgressEvent {
        EgressEvent {
            timestamp: 0.0,
            session: "s1".into(),
            host: host.into(),
            port: 443,
            kind: "connect".into(),
            allow: true,
            reason: "policy: allowlisted".into(),
            request_bytes,
            response_bytes,
            latency_ms,
            hostname_entropy: hostname_entropy(host),
            baseline,
        }
    }

    /// 40 events of normal, jittery traffic to two allowed hosts — the
    /// baseline corpus a real deployment would record with
    /// BOLLARD_BASELINE_MODE=1 before turning detection on.
    fn baseline_corpus() -> Vec<EgressEvent> {
        let mut events = Vec::new();
        for i in 0..20 {
            let jitter = (i as f64 * 37.0) % 250.0;
            events.push(make_event("api.example.com", 50.0 + jitter, 400 + (i * 17) % 300, 1800 + (i * 53) % 900, true));
        }
        for i in 0..20 {
            let jitter = (i as f64 * 29.0) % 180.0;
            events.push(make_event("cdn.example.com", 30.0 + jitter, 200 + (i * 11) % 150, 900 + (i * 41) % 500, true));
        }
        events
    }

    const IQR_K: f64 = 1.5;
    // Calibrated empirically, not guessed: a spot-check of real hostnames
    // (mail.google.com 3.06 ... pubads.g.doubleclick.net 3.89) vs. two
    // synthetic encoded-subdomain examples (4.10, 4.39) put the real-world
    // ceiling and the encoded floor only ~0.2 bits/char apart. 3.9 clears
    // every legit sample checked, but see docs/covert_channel_detection.md
    // for why this margin is fragile, not a solved threshold.
    const ENTROPY_THRESHOLD: f64 = 3.9;

    #[test]
    fn clean_traffic_to_a_known_host_does_not_get_flagged() {
        let baselines = build_baselines(&baseline_corpus());
        // a normal, in-distribution request to an already-baselined host
        let clean = make_event("api.example.com", 120.0, 500, 2200, false);
        let result = score_event(&clean, &baselines, IQR_K, ENTROPY_THRESHOLD);
        assert!(!result.any(), "false positive on in-distribution traffic: {result:?}");
    }

    /// Timing channel, "obvious" variant: encode bits as 50ms vs 2000ms
    /// delays, far outside the baseline's ~50-300ms range.
    #[test]
    fn timing_channel_obvious_extreme_delays_are_caught() {
        let baselines = build_baselines(&baseline_corpus());
        let bit_1 = make_event("api.example.com", 2000.0, 500, 2200, false);
        let result = score_event(&bit_1, &baselines, IQR_K, ENTROPY_THRESHOLD);
        assert!(result.timing_anomaly, "expected obvious timing outlier to be flagged: {result:?}");
    }

    /// Timing channel, "naive" variant: encode bits as small in-range delay
    /// buckets (100ms vs 200ms) that stay inside the baseline's IQR fence.
    /// Prediction from docs/covert_channel_detection.md: timing IQR is the
    /// easiest signal to evade because real traffic timing is already noisy,
    /// so an attacker only needs to keep jitter within that noise band.
    #[test]
    fn timing_channel_naive_in_range_jitter_evades_detection() {
        let baselines = build_baselines(&baseline_corpus());
        let bit_0 = make_event("api.example.com", 100.0, 500, 2200, false);
        let bit_1 = make_event("api.example.com", 220.0, 500, 2200, false);
        let r0 = score_event(&bit_0, &baselines, IQR_K, ENTROPY_THRESHOLD);
        let r1 = score_event(&bit_1, &baselines, IQR_K, ENTROPY_THRESHOLD);
        assert!(
            !r0.timing_anomaly && !r1.timing_anomaly,
            "expected the in-range timing channel to evade the IQR fence (confirms the predicted weakness): {r0:?} {r1:?}"
        );
    }

    /// Size channel, "obvious" variant: pad to a fixed 8KB response, well
    /// outside the ~1.8-2.7KB baseline range for this host.
    #[test]
    fn size_channel_obvious_padding_is_caught() {
        let baselines = build_baselines(&baseline_corpus());
        let padded = make_event("api.example.com", 120.0, 500, 8192, false);
        let result = score_event(&padded, &baselines, IQR_K, ENTROPY_THRESHOLD);
        assert!(result.size_anomaly, "expected obvious size outlier to be flagged: {result:?}");
    }

    /// Size channel, "stealthy" variant: encode one bit as a few hundred
    /// bytes of size delta, small enough to stay inside the baseline's
    /// natural size jitter.
    #[test]
    fn size_channel_stealthy_small_delta_evades_detection() {
        let baselines = build_baselines(&baseline_corpus());
        let subtle = make_event("api.example.com", 120.0, 500, 2400, false);
        let result = score_event(&subtle, &baselines, IQR_K, ENTROPY_THRESHOLD);
        assert!(!result.size_anomaly, "expected a small in-distribution size delta to evade detection: {result:?}");
    }

    /// Hostname channel: a base32/hex-style encoded subdomain to a host
    /// that's never been seen before (no baseline entry exists for it at
    /// all — this is the realistic exfil case, a fresh attacker-controlled
    /// domain, not a previously-allowlisted one). Entropy is the one signal
    /// that's baseline-independent, so it's the only one of the three that
    /// can catch this.
    #[test]
    fn hostname_entropy_channel_on_unseen_host_is_caught() {
        let baselines = build_baselines(&baseline_corpus());
        let exfil = make_event("j3f9k2la8xz1q7wm9v.evil-exfil.net", 120.0, 500, 2200, false);
        let result = score_event(&exfil, &baselines, IQR_K, ENTROPY_THRESHOLD);
        assert!(result.no_baseline, "test setup check: this host should have no baseline entry");
        assert!(result.entropy_anomaly, "expected high-entropy unseen hostname to be flagged: {result:?}");
    }

    /// The negative control for the above: a normal, low-entropy but ALSO
    /// unseen hostname should not be flagged just for being new. Otherwise
    /// the entropy test isn't actually testing entropy — it's just
    /// penalizing novelty, which would make it useless (every agent talks
    /// to new hosts constantly).
    #[test]
    fn unseen_but_normal_hostname_is_not_flagged_by_entropy_alone() {
        let baselines = build_baselines(&baseline_corpus());
        let new_but_normal = make_event("status.newvendor.com", 120.0, 500, 2200, false);
        let result = score_event(&new_but_normal, &baselines, IQR_K, ENTROPY_THRESHOLD);
        assert!(!result.entropy_anomaly, "a normal hostname should not be flagged by entropy alone: {result:?}");
    }
}
