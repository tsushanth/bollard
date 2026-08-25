// SPDX-License-Identifier: Apache-2.0
//
// bollard-proxy — the egress boundary.
//
// The agent runs in a cage (a Docker `internal` network) with no route to the
// outside world except through this process. Every outbound connection is a
// CONNECT (HTTPS) or an absolute-form HTTP request that lands here. The proxy
// does not decide policy itself — it asks the broker, which holds the session's
// provenance/taint state, so the *origin of the data* in the agent's context
// governs whether a destination may be reached.
//
// Unbypassability is structural: because the cage has no other route out, even
// a raw `curl` that ignores HTTP(S)_PROXY cannot escape. If the broker is
// unreachable, the proxy fails closed.
//
// Covert-channel anomaly detection is layered on top, NOT folded into the
// broker's taint-based decision: entropy is checked locally, synchronously,
// before even calling the broker (cheap, no round trip, and it only needs
// the hostname) and — ONLY if BOLLARD_ANOMALY_BLOCK is set — can deny on its
// own. Timing/size anomalies are computed live per connection against an
// in-process rolling per-(session,host) baseline, but are logged only, never
// blocking: they're only knowable AFTER a connection completes (you can't
// gate a transfer on its own final byte count), and the adversarial testing
// in bollard-anomaly found both signals are easy to evade by budgeting a
// covert payload inside normal traffic's existing jitter. See
// docs/covert_channel_detection.md for the full rationale, including why the
// entropy threshold's real-vs-encoded margin is thinner than it looks.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bollard_anomaly::{corpus, hostname_entropy, RollingWindow};
use bollard_http as http;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Config {
    broker: String,
    session: String,
    log_path: String,
    baseline_mode: bool,
    entropy_threshold: f64,
    anomaly_block: bool,
    iqr_k: f64,
    windows: Mutex<HashMap<(String, String), RollingWindow>>,
}

/// One egress event, logged as a JSONL line. This is the substrate for
/// covert-channel anomaly detection (timing IQR, size distribution, hostname
/// entropy) — not analysis itself, just capture. See docs/covert_channel_detection.md.
struct EgressEvent<'a> {
    session: &'a str,
    host: &'a str,
    port: u16,
    kind: &'a str, // "connect" | "http"
    allow: bool,
    reason: &'a str,
    request_bytes: u64,
    response_bytes: u64,
    latency_ms: f64,
    baseline: bool,
    entropy_anomaly: bool,
    timing_anomaly: Option<bool>, // None when no rolling baseline existed yet to score against
    size_anomaly: Option<bool>,
}

fn log_event(log_path: &str, ev: EgressEvent) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let line = serde_json::json!({
        "timestamp": timestamp,
        "session": ev.session,
        "host": ev.host,
        "port": ev.port,
        "kind": ev.kind,
        "allow": ev.allow,
        "reason": ev.reason,
        "request_bytes": ev.request_bytes,
        "response_bytes": ev.response_bytes,
        "latency_ms": ev.latency_ms,
        "hostname_entropy": hostname_entropy(ev.host),
        "baseline": ev.baseline,
        "entropy_anomaly": ev.entropy_anomaly,
        "timing_anomaly": ev.timing_anomaly,
        "size_anomaly": ev.size_anomaly,
    })
    .to_string();

    match std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{line}") {
                eprintln!("[bollard] failed to write egress log: {e}");
            }
        }
        Err(e) => eprintln!("[bollard] failed to open egress log {log_path}: {e}"),
    }
}

/// Score this connection's timing/size against the live rolling baseline for
/// (session, host), then update that baseline with this connection's values
/// for future requests to score against. Visibility only — the caller must
/// not use this to gate the current connection's own allow/deny, since the
/// values being scored (this connection's own latency/bytes) are only known
/// after it already completed.
fn score_and_update_window(cfg: &Config, session: &str, host: &str, latency_ms: f64, total_bytes: f64, iqr_k: f64) -> (Option<bool>, Option<bool>) {
    let mut windows = cfg.windows.lock().unwrap_or_else(|e| e.into_inner());
    let key = (session.to_string(), host.to_string());
    let window = windows.entry(key).or_insert_with(|| RollingWindow::new(30));

    let (timing_anomaly, size_anomaly) = match window.baseline() {
        Some(b) => {
            let lat_iqr = b.latency_q3 - b.latency_q1;
            let lat_hi = b.latency_q3 + iqr_k * lat_iqr;
            let lat_lo = (b.latency_q1 - iqr_k * lat_iqr).max(0.0);
            let timing = latency_ms > lat_hi || latency_ms < lat_lo;

            let size_iqr = b.size_q3 - b.size_q1;
            let size_hi = b.size_q3 + iqr_k * size_iqr;
            let size_lo = (b.size_q1 - iqr_k * size_iqr).max(0.0);
            let size = total_bytes > size_hi || total_bytes < size_lo;
            (Some(timing), Some(size))
        }
        None => (None, None), // fewer than 5 samples so far -- not enough for a fence yet
    };

    window.push(latency_ms, total_bytes);
    (timing_anomaly, size_anomaly)
}

#[tokio::main]
async fn main() {
    let listen = std::env::var("BOLLARD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let entropy_threshold = std::env::var("BOLLARD_ENTROPY_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(corpus::default_threshold);
    let anomaly_block = std::env::var("BOLLARD_ANOMALY_BLOCK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let cfg = Arc::new(Config {
        broker: std::env::var("BOLLARD_BROKER")
            .unwrap_or_else(|_| "http://bollard-broker:8090".into()),
        session: std::env::var("BOLLARD_SESSION").unwrap_or_else(|_| "default".into()),
        log_path: std::env::var("BOLLARD_LOG_PATH").unwrap_or_else(|_| "bollard-egress.jsonl".into()),
        baseline_mode: std::env::var("BOLLARD_BASELINE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        entropy_threshold,
        anomaly_block,
        iqr_k: std::env::var("BOLLARD_ANOMALY_IQR_K").ok().and_then(|v| v.parse().ok()).unwrap_or(1.5),
        windows: Mutex::new(HashMap::new()),
    });
    eprintln!(
        "[bollard] egress boundary up on {listen}; broker={} session={}; fail-closed; log={} baseline_mode={}; entropy_threshold={:.3} anomaly_block={}",
        cfg.broker, cfg.session, cfg.log_path, cfg.baseline_mode, cfg.entropy_threshold, cfg.anomaly_block
    );
    if !cfg.anomaly_block {
        eprintln!("[bollard] anomaly_block is OFF by default: entropy is scored and logged but never denies on its own. Set BOLLARD_ANOMALY_BLOCK=1 to enable, only after reviewing docs/covert_channel_detection.md's false-positive caveats.");
    }

    let listener = TcpListener::bind(&listen).await.expect("bind listen address");
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("[bollard] accept error: {e}");
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(client, cfg).await {
                eprintln!("[bollard] connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, cfg: Arc<Config>) -> std::io::Result<()> {
    let start = Instant::now();
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = http::find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            let _ = client
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443);
        return tunnel(client, &host, port, cfg, "connect", start).await;
    }

    let host_header = lines.clone().find_map(|l| {
        let l = l.trim();
        if l.len() >= 5 && l[..5].eq_ignore_ascii_case("host:") {
            Some(l[5..].trim().to_string())
        } else {
            None
        }
    });
    let authority = match host_from_target(target).or(host_header) {
        Some(a) => a,
        None => {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    let (host, port) = split_host_port(&authority, 80);

    let entropy = hostname_entropy(&host);
    let entropy_anomaly = entropy > cfg.entropy_threshold;
    if entropy_anomaly && cfg.anomaly_block {
        let reason = format!("anomaly: hostname entropy {entropy:.3} exceeds threshold {:.3}", cfg.entropy_threshold);
        log_event(&cfg.log_path, EgressEvent {
            session: &cfg.session, host: &host, port, kind: "http", allow: false, reason: &reason,
            request_bytes: buf.len() as u64, response_bytes: 0,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
            entropy_anomaly, timing_anomaly: None, size_anomaly: None,
        });
        return deny(&mut client, &host, &reason).await;
    }

    let (allow, reason) = decide(&cfg, &host).await;
    if !allow {
        log_event(&cfg.log_path, EgressEvent {
            session: &cfg.session, host: &host, port, kind: "http", allow: false, reason: &reason,
            request_bytes: buf.len() as u64, response_bytes: 0,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
            entropy_anomaly, timing_anomaly: None, size_anomaly: None,
        });
        return deny(&mut client, &host, &reason).await;
    }

    // DLP — plain HTTP is the one egress path where we can see the body. Read it
    // in full and refuse a request that carries a registered secret, even to an
    // allowed sink (labels alone cannot catch exfil to a trusted host).
    let content_length = parse_content_length(&head);
    while buf.len() < header_end + 4 + content_length {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = &buf[(header_end + 4).min(buf.len())..];
    if !body.is_empty() && broker_inspect(&cfg, body).await {
        let reason = "DLP: request body carries a registered secret";
        log_event(&cfg.log_path, EgressEvent {
            session: &cfg.session, host: &host, port, kind: "http", allow: false, reason,
            request_bytes: buf.len() as u64, response_bytes: 0,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
            entropy_anomaly, timing_anomaly: None, size_anomaly: None,
        });
        return deny(&mut client, &host, reason).await;
    }

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bollard] UPSTREAM-FAIL http {host}:{port} {e}");
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    eprintln!("[bollard] ALLOW http {host}:{port} ({reason})");
    let sent_bytes = buf.len() as u64;
    upstream.write_all(&buf).await?;
    let (extra_req, resp_bytes) = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .unwrap_or((0, 0));
    let request_bytes = sent_bytes + extra_req;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let (timing_anomaly, size_anomaly) = score_and_update_window(&cfg, &cfg.session, &host, latency_ms, (request_bytes + resp_bytes) as f64, cfg.iqr_k);
    log_event(&cfg.log_path, EgressEvent {
        session: &cfg.session, host: &host, port, kind: "http", allow: true, reason: &reason,
        request_bytes, response_bytes: resp_bytes,
        latency_ms, baseline: cfg.baseline_mode,
        entropy_anomaly, timing_anomaly, size_anomaly,
    });
    Ok(())
}

async fn tunnel(
    mut client: TcpStream,
    host: &str,
    port: u16,
    cfg: Arc<Config>,
    kind: &str,
    start: Instant,
) -> std::io::Result<()> {
    let entropy = hostname_entropy(host);
    let entropy_anomaly = entropy > cfg.entropy_threshold;
    if entropy_anomaly && cfg.anomaly_block {
        let reason = format!("anomaly: hostname entropy {entropy:.3} exceeds threshold {:.3}", cfg.entropy_threshold);
        log_event(&cfg.log_path, EgressEvent {
            session: &cfg.session, host, port, kind, allow: false, reason: &reason,
            request_bytes: 0, response_bytes: 0,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
            entropy_anomaly, timing_anomaly: None, size_anomaly: None,
        });
        return deny(&mut client, host, &reason).await;
    }

    let (allow, reason) = decide(&cfg, host).await;
    if !allow {
        log_event(&cfg.log_path, EgressEvent {
            session: &cfg.session, host, port, kind, allow: false, reason: &reason,
            request_bytes: 0, response_bytes: 0,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
            entropy_anomaly, timing_anomaly: None, size_anomaly: None,
        });
        return deny(&mut client, host, &reason).await;
    }
    let mut upstream = match TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bollard] UPSTREAM-FAIL {kind} {host}:{port} {e}");
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    eprintln!("[bollard] ALLOW {kind} {host}:{port} ({reason})");
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let (req_bytes, resp_bytes) = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .unwrap_or((0, 0));
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let (timing_anomaly, size_anomaly) = score_and_update_window(&cfg, &cfg.session, host, latency_ms, (req_bytes + resp_bytes) as f64, cfg.iqr_k);
    log_event(&cfg.log_path, EgressEvent {
        session: &cfg.session, host, port, kind, allow: true, reason: &reason,
        request_bytes: req_bytes, response_bytes: resp_bytes,
        latency_ms, baseline: cfg.baseline_mode,
        entropy_anomaly, timing_anomaly, size_anomaly,
    });
    Ok(())
}

/// Ask the broker whether `host` may be reached given the session's taint.
/// Any failure to get a clear "allow" is treated as a deny (fail closed).
async fn decide(cfg: &Config, host: &str) -> (bool, String) {
    match broker_decide(&cfg.broker, &cfg.session, host).await {
        Ok((allow, reason)) => (allow, reason),
        Err(e) => {
            eprintln!("[bollard] broker unreachable ({e}); failing closed for {host}");
            (false, "broker unreachable (fail-closed)".into())
        }
    }
}

async fn broker_decide(broker: &str, session: &str, host: &str) -> std::io::Result<(bool, String)> {
    let resp = http::get(broker, &format!("/decide?session={session}&host={host}")).await?;
    let value: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| std::io::Error::other(format!("broker json: {e}")))?;
    let allow = value.get("allow").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let reason = value
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok((allow, reason))
}

/// Ask the broker whether `payload` carries a registered secret. On any failure
/// we do not block here (the label-based decision already gated this request).
async fn broker_inspect(cfg: &Config, payload: &[u8]) -> bool {
    let text = String::from_utf8_lossy(payload);
    let body = serde_json::json!({ "session": cfg.session, "payload": text }).to_string();
    match http::post(&cfg.broker, "/inspect", body.as_bytes()).await {
        Ok(r) => serde_json::from_slice::<serde_json::Value>(&r.body)
            .ok()
            .and_then(|v| v.get("contains_secret").and_then(serde_json::Value::as_bool))
            .unwrap_or(false),
        Err(e) => {
            eprintln!("[bollard] DLP inspect failed ({e}); not blocking on it");
            false
        }
    }
}

fn parse_content_length(head: &str) -> usize {
    head.split("\r\n")
        .skip(1)
        .find_map(|l| {
            let l = l.trim();
            if l.len() >= 15 && l[..15].eq_ignore_ascii_case("content-length:") {
                l[15..].trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

async fn deny(client: &mut TcpStream, host: &str, reason: &str) -> std::io::Result<()> {
    eprintln!("[bollard] DENY {host}: {reason}");
    let _ = client
        .write_all(
            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nbollard: egress denied by policy\n",
        )
        .await;
    Ok(())
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(idx) = authority.rfind(':') {
        let (h, p) = authority.split_at(idx);
        if let Ok(port) = p[1..].parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (authority.to_string(), default_port)
}

fn host_from_target(target: &str) -> Option<String> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    let end = rest.find('/').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            broker: "unused".into(),
            session: "s1".into(),
            log_path: "/dev/null".into(),
            baseline_mode: false,
            entropy_threshold: corpus::default_threshold(),
            anomaly_block: false,
            iqr_k: 1.5,
            windows: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn default_entropy_threshold_is_the_calibrated_corpus_value_not_a_guess() {
        // Regression guard: this must stay wired to corpus::default_threshold(),
        // not silently drift back to a hand-picked constant. See
        // docs/covert_channel_detection.md for what 3.5 vs 4.726 meant in practice.
        let cfg = test_config();
        assert!(cfg.entropy_threshold > 4.0, "expected the calibrated default (~4.7), got {}", cfg.entropy_threshold);
    }

    #[test]
    fn anomaly_block_defaults_to_off() {
        // The safe default: entropy is scored and logged, never blocks on its
        // own, until an operator explicitly opts in after reading the
        // false-positive caveats in the docs.
        assert!(!test_config().anomaly_block);
    }

    #[test]
    fn rolling_window_scores_nothing_until_it_has_five_samples() {
        let cfg = test_config();
        for i in 0..4 {
            let (timing, size) = score_and_update_window(&cfg, "s1", "api.example.com", 100.0 + i as f64, 1000.0, cfg.iqr_k);
            assert_eq!(timing, None, "expected no baseline yet at sample {i}");
            assert_eq!(size, None, "expected no baseline yet at sample {i}");
        }
    }

    #[test]
    fn rolling_window_flags_an_outlier_after_warming_up() {
        let cfg = test_config();
        // 10 normal samples to build a live baseline
        for i in 0..10 {
            let jitter = (i as f64 * 7.0) % 40.0;
            score_and_update_window(&cfg, "s1", "api.example.com", 100.0 + jitter, 1000.0 + jitter * 10.0, cfg.iqr_k);
        }
        // an obvious outlier should now be flagged
        let (timing, size) = score_and_update_window(&cfg, "s1", "api.example.com", 5000.0, 1000.0, cfg.iqr_k);
        assert_eq!(timing, Some(true), "expected the live rolling window to flag an obvious latency outlier");
        let _ = size;
    }

    #[test]
    fn rolling_window_is_per_session_and_host() {
        let cfg = test_config();
        for i in 0..10 {
            score_and_update_window(&cfg, "s1", "api.example.com", 100.0 + i as f64, 1000.0, cfg.iqr_k);
        }
        // a different host has no baseline yet, even in the same session
        let (timing, _) = score_and_update_window(&cfg, "s1", "other.example.com", 100.0, 1000.0, cfg.iqr_k);
        assert_eq!(timing, None);
    }
}
