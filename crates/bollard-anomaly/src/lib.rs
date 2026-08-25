// SPDX-License-Identifier: Apache-2.0
//
// Covert-channel anomaly-detection core: hostname entropy, per-(session,host)
// timing/size baselines, and scoring. Shared between the offline
// `bollard-anomaly` analysis binary and `bollard-proxy`'s live path (entropy
// only, opt-in) — see docs/covert_channel_detection.md for what's wired to
// actually block vs. logged-only, and why.

use serde::Deserialize;
use std::collections::HashMap;

pub mod corpus;

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

/// Shannon entropy of a string, in bits per character. A DNS-tunneling /
/// domain-generation-algorithm style covert channel tends to produce higher
/// entropy than typical human-chosen hostnames — see `corpus` for how the
/// default threshold is actually calibrated against real examples, not
/// guessed.
pub fn hostname_entropy(host: &str) -> f64 {
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

pub fn percentile(sorted: &[f64], p: f64) -> f64 {
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

/// Score a (host, latency, request_bytes+response_bytes, hostname_entropy)
/// tuple against a baseline. `iqr_k` is the Tukey fence multiplier (1.5 =
/// standard "mild outlier"). `entropy_threshold` is baseline-independent by
/// design — the one signal meant to catch exfil to a host with no traffic
/// history at all.
pub fn score(
    session: &str,
    host: &str,
    latency_ms: f64,
    total_bytes: f64,
    entropy: f64,
    baselines: &HashMap<(String, String), HostBaseline>,
    iqr_k: f64,
    entropy_threshold: f64,
) -> AnomalyResult {
    let entropy_anomaly = entropy > entropy_threshold;

    let key = (session.to_string(), host.to_string());
    match baselines.get(&key) {
        Some(b) => {
            let lat_iqr = b.latency_q3 - b.latency_q1;
            let lat_hi = b.latency_q3 + iqr_k * lat_iqr;
            let lat_lo = (b.latency_q1 - iqr_k * lat_iqr).max(0.0);
            let timing_anomaly = latency_ms > lat_hi || latency_ms < lat_lo;

            let size_iqr = b.size_q3 - b.size_q1;
            let size_hi = b.size_q3 + iqr_k * size_iqr;
            let size_lo = (b.size_q1 - iqr_k * size_iqr).max(0.0);
            let size_anomaly = total_bytes > size_hi || total_bytes < size_lo;

            AnomalyResult { timing_anomaly, size_anomaly, entropy_anomaly, no_baseline: false }
        }
        None => AnomalyResult { timing_anomaly: false, size_anomaly: false, entropy_anomaly, no_baseline: true },
    }
}

pub fn score_event(
    ev: &EgressEvent,
    baselines: &HashMap<(String, String), HostBaseline>,
    iqr_k: f64,
    entropy_threshold: f64,
) -> AnomalyResult {
    score(&ev.session, &ev.host, ev.latency_ms, (ev.request_bytes + ev.response_bytes) as f64, ev.hostname_entropy, baselines, iqr_k, entropy_threshold)
}

/// A small fixed-capacity ring buffer for live, in-process per-(session,host)
/// baselines — used by bollard-proxy, which can't do an offline batch read of
/// its own log on every connection. Not persisted; resets on proxy restart.
#[derive(Debug, Clone)]
pub struct RollingWindow {
    latencies: Vec<f64>,
    sizes: Vec<f64>,
    capacity: usize,
}

impl RollingWindow {
    pub fn new(capacity: usize) -> Self {
        Self { latencies: Vec::with_capacity(capacity), sizes: Vec::with_capacity(capacity), capacity }
    }

    pub fn push(&mut self, latency_ms: f64, total_bytes: f64) {
        if self.latencies.len() >= self.capacity {
            self.latencies.remove(0);
            self.sizes.remove(0);
        }
        self.latencies.push(latency_ms);
        self.sizes.push(total_bytes);
    }

    pub fn len(&self) -> usize {
        self.latencies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.latencies.is_empty()
    }

    pub fn baseline(&self) -> Option<HostBaseline> {
        if self.latencies.len() < 5 {
            // too few samples for a meaningful IQR fence
            return None;
        }
        let mut lat = self.latencies.clone();
        let mut size = self.sizes.clone();
        lat.sort_by(f64::total_cmp);
        size.sort_by(f64::total_cmp);
        Some(HostBaseline {
            latency_q1: percentile(&lat, 0.25),
            latency_q3: percentile(&lat, 0.75),
            size_q1: percentile(&size, 0.25),
            size_q3: percentile(&size, 0.75),
            n: lat.len(),
        })
    }
}
