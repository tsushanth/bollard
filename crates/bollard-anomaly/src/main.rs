// SPDX-License-Identifier: Apache-2.0
//
// bollard-anomaly CLI — offline analysis over bollard-proxy's egress log,
// plus threshold calibration. The scoring core lives in lib.rs so
// bollard-proxy can use it directly for the live entropy check.

use bollard_anomaly::{build_baselines, corpus, score_event, EgressEvent};
use std::io::BufRead;

fn read_events(path: &str) -> Vec<EgressEvent> {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    std::io::BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

fn arg_value(args: &[String], flag: &str) -> Option<f64> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("calibrate") {
        let percentile_p = arg_value(&args, "--percentile").unwrap_or(0.99);
        let margin = arg_value(&args, "--margin").unwrap_or(0.15);

        let mut hosts: Vec<String> = corpus::LEGIT_HOSTNAMES.iter().map(|s| s.to_string()).collect();
        if let Some(baseline_path) = args.iter().position(|a| a == "--baseline-log").and_then(|i| args.get(i + 1)) {
            let events = read_events(baseline_path);
            let real_hosts: Vec<String> = events.iter().filter(|e| e.baseline && e.allow).map(|e| e.host.clone()).collect();
            println!("Blending {} curated corpus hostnames with {} real hostnames from {baseline_path}", hosts.len(), real_hosts.len());
            hosts.extend(real_hosts);
        } else {
            println!("No --baseline-log given; calibrating from the {} curated corpus hostnames only.", hosts.len());
            println!("This is a safer-than-nothing default, NOT a substitute for calibrating against real traffic.");
        }

        let threshold = corpus::calibrate_entropy_threshold(&hosts, percentile_p, margin);
        println!("\nSuggested BOLLARD_ENTROPY_THRESHOLD: {threshold:.3}");
        println!("(= P{:.1} of {} hostnames' entropy, + {margin} margin)", percentile_p * 100.0, hosts.len());
        return;
    }

    if args.len() < 3 {
        eprintln!("usage:");
        eprintln!("  bollard-anomaly <baseline.jsonl> <live.jsonl> [--iqr-k 1.5] [--entropy-threshold 3.9]");
        eprintln!("  bollard-anomaly calibrate [--baseline-log <file>] [--percentile 0.99] [--margin 0.15]");
        std::process::exit(1);
    }
    let baseline_events = read_events(&args[1]);
    let live_events = read_events(&args[2]);

    let iqr_k = arg_value(&args, "--iqr-k").unwrap_or(1.5);
    let entropy_threshold = arg_value(&args, "--entropy-threshold").unwrap_or_else(corpus::default_threshold);

    let baselines = build_baselines(&baseline_events);
    println!("Built baselines for {} (session, host) pairs from {} baseline events", baselines.len(), baseline_events.len());
    println!("Entropy threshold: {entropy_threshold:.3}");

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

#[cfg(test)]
mod adversarial_tests {
    use bollard_anomaly::{build_baselines, hostname_entropy, score_event, EgressEvent};

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
    // Use the REAL default the proxy ships with, not a hand-picked constant
    // that could silently drift from it. See docs/covert_channel_detection.md
    // for what this number turned out to mean in practice.
    fn entropy_threshold() -> f64 {
        bollard_anomaly::corpus::default_threshold()
    }

    #[test]
    fn clean_traffic_to_a_known_host_does_not_get_flagged() {
        let baselines = build_baselines(&baseline_corpus());
        let clean = make_event("api.example.com", 120.0, 500, 2200, false);
        let result = score_event(&clean, &baselines, IQR_K, entropy_threshold());
        assert!(!result.any(), "false positive on in-distribution traffic: {result:?}");
    }

    #[test]
    fn timing_channel_obvious_extreme_delays_are_caught() {
        let baselines = build_baselines(&baseline_corpus());
        let bit_1 = make_event("api.example.com", 2000.0, 500, 2200, false);
        let result = score_event(&bit_1, &baselines, IQR_K, entropy_threshold());
        assert!(result.timing_anomaly, "expected obvious timing outlier to be flagged: {result:?}");
    }

    #[test]
    fn timing_channel_naive_in_range_jitter_evades_detection() {
        let baselines = build_baselines(&baseline_corpus());
        let bit_0 = make_event("api.example.com", 100.0, 500, 2200, false);
        let bit_1 = make_event("api.example.com", 220.0, 500, 2200, false);
        let r0 = score_event(&bit_0, &baselines, IQR_K, entropy_threshold());
        let r1 = score_event(&bit_1, &baselines, IQR_K, entropy_threshold());
        assert!(!r0.timing_anomaly && !r1.timing_anomaly, "expected in-range timing channel to evade the IQR fence: {r0:?} {r1:?}");
    }

    #[test]
    fn size_channel_obvious_padding_is_caught() {
        let baselines = build_baselines(&baseline_corpus());
        let padded = make_event("api.example.com", 120.0, 500, 8192, false);
        let result = score_event(&padded, &baselines, IQR_K, entropy_threshold());
        assert!(result.size_anomaly, "expected obvious size outlier to be flagged: {result:?}");
    }

    #[test]
    fn size_channel_stealthy_small_delta_evades_detection() {
        let baselines = build_baselines(&baseline_corpus());
        let subtle = make_event("api.example.com", 120.0, 500, 2400, false);
        let result = score_event(&subtle, &baselines, IQR_K, entropy_threshold());
        assert!(!result.size_anomaly, "expected a small in-distribution size delta to evade detection: {result:?}");
    }

    /// A realistic short encoded subdomain (18 chars, the kind you'd
    /// actually see in casual DNS-tunneling code) EVADES the honestly
    /// calibrated threshold. This is the headline finding from expanding the
    /// corpus: a threshold wide enough to clear real hash-heavy CDN/cloud
    /// hostnames (4.726, vs. the originally guessed 3.5-3.9) is also wide
    /// enough to let normal-length encoded payloads straight through. This
    /// used to be the "caught" case at the old, under-calibrated threshold —
    /// keeping the same input and flipping the assertion is the point: the
    /// old test was passing for the wrong reason.
    #[test]
    fn hostname_entropy_channel_short_realistic_payload_evades_calibrated_threshold() {
        let baselines = build_baselines(&baseline_corpus());
        let exfil = make_event("j3f9k2la8xz1q7wm9v.evil-exfil.net", 120.0, 500, 2200, false);
        let result = score_event(&exfil, &baselines, IQR_K, entropy_threshold());
        assert!(result.no_baseline, "test setup check: this host should have no baseline entry");
        assert!(
            !result.entropy_anomaly,
            "this specific finding is the point of this test -- if it now fails, the threshold moved back down and the corpus/docs need re-checking: {result:?}"
        );
    }

    /// The threshold CAN still catch something, at the extreme end: a
    /// single DNS label at its 63-character maximum, high-diversity
    /// alphanumeric. Even here it's marginal (4.796 vs. a 4.726 threshold,
    /// ~1.5% headroom) -- a payload just slightly less diverse at the same
    /// length would evade too. This is the honest ceiling of what entropy
    /// alone catches: near-maximum-length single-label payloads only.
    #[test]
    fn hostname_entropy_channel_dns_label_max_length_payload_is_caught() {
        let baselines = build_baselines(&baseline_corpus());
        let label = "k3j9f2la8xz1q7wm9vb4n6c8d0e2f4g6h8i0j2k4l6m8n0o2p4q6r8s0t2u4v6w"; // 63 chars, the DNS label max
        assert_eq!(label.len(), 63);
        let exfil = make_event(&format!("{label}.evil-exfil.net"), 120.0, 500, 2200, false);
        let result = score_event(&exfil, &baselines, IQR_K, entropy_threshold());
        assert!(result.no_baseline, "test setup check: this host should have no baseline entry");
        assert!(result.entropy_anomaly, "expected a DNS-label-max-length high-diversity payload to be flagged: {result:?}");
    }

    #[test]
    fn unseen_but_normal_hostname_is_not_flagged_by_entropy_alone() {
        let baselines = build_baselines(&baseline_corpus());
        let new_but_normal = make_event("status.newvendor.com", 120.0, 500, 2200, false);
        let result = score_event(&new_but_normal, &baselines, IQR_K, entropy_threshold());
        assert!(!result.entropy_anomaly, "a normal hostname should not be flagged by entropy alone: {result:?}");
    }

    /// The corpus test that matters most: every hostname in the curated
    /// corpus itself -- including the hash-heavy CDN/cloud-storage/ad-tech
    /// entries specifically chosen to be hard -- must clear the calibrated
    /// default threshold. If this fails, the corpus and the threshold
    /// disagree with each other, which would be a real calibration bug.
    #[test]
    fn every_corpus_hostname_clears_the_default_threshold() {
        let threshold = bollard_anomaly::corpus::default_threshold();
        let mut worst: Option<(&str, f64)> = None;
        for host in bollard_anomaly::corpus::LEGIT_HOSTNAMES {
            let e = hostname_entropy(host);
            if e > threshold {
                worst = Some((host, e));
            }
        }
        assert!(worst.is_none(), "corpus hostname exceeds its own calibrated threshold ({threshold:.3}): {worst:?}");
    }
}
