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

use std::io::Write;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bollard_http as http;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Config {
    broker: String,
    session: String,
    log_path: String,
    baseline_mode: bool,
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
}

/// Shannon entropy of the hostname string, in bits per character. A DNS
/// tunneling / domain-generation-algorithm style covert channel tends to
/// produce much higher entropy than typical human-chosen hostnames.
fn hostname_entropy(host: &str) -> f64 {
    if host.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in host.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let len = host.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
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

#[tokio::main]
async fn main() {
    let listen = std::env::var("BOLLARD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let cfg = Arc::new(Config {
        broker: std::env::var("BOLLARD_BROKER")
            .unwrap_or_else(|_| "http://bollard-broker:8090".into()),
        session: std::env::var("BOLLARD_SESSION").unwrap_or_else(|_| "default".into()),
        log_path: std::env::var("BOLLARD_LOG_PATH").unwrap_or_else(|_| "bollard-egress.jsonl".into()),
        baseline_mode: std::env::var("BOLLARD_BASELINE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    });
    eprintln!(
        "[bollard] egress boundary up on {listen}; broker={} session={}; fail-closed; log={} baseline_mode={}",
        cfg.broker, cfg.session, cfg.log_path, cfg.baseline_mode
    );

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

    let (allow, reason) = decide(&cfg, &host).await;
    if !allow {
        log_event(&cfg.log_path, EgressEvent {
            session: &cfg.session, host: &host, port, kind: "http", allow: false, reason: &reason,
            request_bytes: buf.len() as u64, response_bytes: 0,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
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
    log_event(&cfg.log_path, EgressEvent {
        session: &cfg.session, host: &host, port, kind: "http", allow: true, reason: &reason,
        request_bytes: sent_bytes + extra_req, response_bytes: resp_bytes,
        latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
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
    let (allow, reason) = decide(&cfg, host).await;
    if !allow {
        log_event(&cfg.log_path, EgressEvent {
            session: &cfg.session, host, port, kind, allow: false, reason: &reason,
            request_bytes: 0, response_bytes: 0,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
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
    log_event(&cfg.log_path, EgressEvent {
        session: &cfg.session, host, port, kind, allow: true, reason: &reason,
        request_bytes: req_bytes, response_bytes: resp_bytes,
        latency_ms: start.elapsed().as_secs_f64() * 1000.0, baseline: cfg.baseline_mode,
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
    use super::hostname_entropy;

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert_eq!(hostname_entropy(""), 0.0);
    }

    #[test]
    fn entropy_of_single_repeated_char_is_zero() {
        // no uncertainty: every character is the same
        assert_eq!(hostname_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn typical_hostname_has_low_to_moderate_entropy() {
        let e = hostname_entropy("example.com");
        assert!(e > 0.0 && e < 4.0, "got {e}");
    }

    #[test]
    fn dns_tunneling_style_subdomain_has_higher_entropy() {
        // a plausible base32/hex-encoded exfil subdomain: high character
        // diversity relative to length, vs. a normal hostname of similar length.
        let normal = hostname_entropy("mail.google.com");
        let encoded = hostname_entropy("j3f9k2la8xz1q7wm.evil.com");
        assert!(
            encoded > normal,
            "expected encoded subdomain entropy ({encoded}) > normal hostname entropy ({normal})"
        );
    }
}
