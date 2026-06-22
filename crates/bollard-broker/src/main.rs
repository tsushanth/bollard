// SPDX-License-Identifier: Apache-2.0
//
// bollard-broker — taint store + policy decision engine.
//
// Per session it holds (a) the provenance labels that have entered the agent's
// context and (b) the literal secret values seen, so two kinds of question can
// be answered:
//   - label-based: may this destination be reached / where should this model
//     call go, given the context's taint? (bollard-proxy, bollard-infer)
//   - content-based (DLP): does this specific payload carry a registered
//     secret? — catches exfil even to a trusted sink, which labels cannot.
//
//   GET  /decide?session=<s>&host=<h>  -> {"allow":bool,"reason":str,"taint":[..]}
//   GET  /route?session=<s>            -> {"target":"local"|"cloud","reason":str,..}
//   POST /taint   {"session","label"}  -> {"ok":true,"taint":[..]}
//   POST /secret  {"session","value"}  -> {"ok":true,"secrets":n}
//   POST /inspect {"session","payload"}-> {"contains_secret":bool}
//   POST /reset   {"session"}          -> {"ok":true}
//   GET  /state                        -> {session: {labels:[..],secrets:n}, ..}

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use bollard_http as http;
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Shortest registered value we will treat as a secret for substring matching,
/// to avoid trivial false positives.
const MIN_SECRET_LEN: usize = 8;

#[derive(Debug, Default, Deserialize)]
struct Policy {
    /// Trusted sinks — always allowed (e.g. the inference endpoint, telemetry).
    #[serde(default)]
    allow_hosts: Vec<String>,
    /// Sinks allowed only while the context is clean of the trifecta.
    #[serde(default)]
    conditional_hosts: Vec<String>,
    /// Labels that mark exposure to untrusted content.
    #[serde(default)]
    untrusted_labels: Vec<String>,
    /// Labels that mark private/sensitive data.
    #[serde(default)]
    sensitive_labels: Vec<String>,
}

impl Policy {
    fn load(path: &Path) -> Policy {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_yaml::from_str(&s).unwrap_or_else(|e| {
                eprintln!("[broker] bad policy {} ({e}); failing closed", path.display());
                Policy::default()
            }),
            Err(e) => {
                eprintln!("[broker] no policy {} ({e}); failing closed", path.display());
                Policy::default()
            }
        }
    }

    /// The lethal trifecta condition: context holds both an untrusted-source
    /// label and a sensitive-data label.
    fn trifecta(&self, taint: &BTreeSet<String>) -> bool {
        let untrusted = self.untrusted_labels.iter().any(|l| taint.contains(l));
        let sensitive = self.sensitive_labels.iter().any(|l| taint.contains(l));
        untrusted && sensitive
    }

    fn decide(&self, taint: &BTreeSet<String>, host: &str) -> (bool, String) {
        if host_matches(&self.allow_hosts, host) {
            return (true, "trusted sink (allow_hosts)".into());
        }
        let labels: Vec<&str> = taint.iter().map(String::as_str).collect();
        if host_matches(&self.conditional_hosts, host) {
            return if self.trifecta(taint) {
                (false, format!("trifecta: tainted context {labels:?} may not reach conditional sink"))
            } else {
                (true, "conditional sink; context clean".into())
            };
        }
        if self.trifecta(taint) {
            (false, format!("trifecta: tainted context {labels:?}; sink not trusted"))
        } else {
            (false, "deny-by-default: sink not in allowlist".into())
        }
    }

    /// Route a model call by the sensitivity of the context. Sensitive context
    /// stays on a local backend so the prompt never leaves; otherwise cloud is
    /// allowed. Returns ("local"|"cloud", reason).
    fn route(&self, taint: &BTreeSet<String>) -> (&'static str, String) {
        let labels: Vec<&str> = taint.iter().map(String::as_str).collect();
        if self.sensitive_labels.iter().any(|l| taint.contains(l)) {
            ("local", format!("sensitive context {labels:?}; keep inference on-prem"))
        } else {
            ("cloud", "context not sensitive; cloud inference permitted".into())
        }
    }
}

fn host_matches(list: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    list.iter().any(|s| {
        let s = s.trim_start_matches('.').to_ascii_lowercase();
        host == s || host.ends_with(&format!(".{s}"))
    })
}

/// Does `payload` carry any registered secret value verbatim?
fn contains_secret(secrets: &BTreeSet<String>, payload: &str) -> bool {
    secrets
        .iter()
        .any(|s| s.len() >= MIN_SECRET_LEN && payload.contains(s.as_str()))
}

#[derive(Default)]
struct SessionState {
    labels: BTreeSet<String>,
    secrets: BTreeSet<String>,
}

type Sessions = Arc<Mutex<BTreeMap<String, SessionState>>>;

#[derive(Deserialize)]
struct TaintReq {
    session: String,
    label: String,
}

#[derive(Deserialize)]
struct SecretReq {
    session: String,
    value: String,
}

#[derive(Deserialize)]
struct InspectReq {
    session: String,
    payload: String,
}

#[derive(Deserialize)]
struct ResetReq {
    session: String,
}

#[tokio::main]
async fn main() {
    let policy_path =
        std::env::var("BOLLARD_POLICY").unwrap_or_else(|_| "/etc/bollard/policy.yaml".into());
    let listen = std::env::var("BOLLARD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8090".into());
    let policy = Arc::new(Policy::load(Path::new(&policy_path)));
    let sessions: Sessions = Arc::new(Mutex::new(BTreeMap::new()));
    eprintln!(
        "[broker] up on {listen}; {} trusted, {} conditional sink rule(s)",
        policy.allow_hosts.len(),
        policy.conditional_hosts.len()
    );

    let listener = TcpListener::bind(&listen).await.expect("bind");
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[broker] accept error: {e}");
                continue;
            }
        };
        let (policy, sessions) = (policy.clone(), sessions.clone());
        tokio::spawn(async move {
            if let Err(e) = serve(sock, policy, sessions).await {
                eprintln!("[broker] connection error: {e}");
            }
        });
    }
}

async fn serve(mut sock: TcpStream, policy: Arc<Policy>, sessions: Sessions) -> std::io::Result<()> {
    let Some(msg) = http::read_message(&mut sock).await? else {
        return Ok(());
    };
    let query = msg.query();

    match (msg.method(), msg.path()) {
        ("GET", "/decide") => {
            let session = http::query_param(query, "session").unwrap_or_else(|| "default".into());
            let host = http::query_param(query, "host").unwrap_or_default();
            let taint = sessions.lock().await.get(&session).map(|s| s.labels.clone()).unwrap_or_default();
            let (allow, reason) = policy.decide(&taint, &host);
            eprintln!(
                "[broker] decide session={session} host={host} -> {} ({reason})",
                if allow { "ALLOW" } else { "DENY" }
            );
            let labels: Vec<&String> = taint.iter().collect();
            http::write_json(&mut sock, "200 OK", &serde_json::json!({
                "allow": allow, "reason": reason, "taint": labels,
            })).await
        }
        ("GET", "/route") => {
            let session = http::query_param(query, "session").unwrap_or_else(|| "default".into());
            let taint = sessions.lock().await.get(&session).map(|s| s.labels.clone()).unwrap_or_default();
            let (target, reason) = policy.route(&taint);
            eprintln!("[broker] route session={session} -> {target} ({reason})");
            let labels: Vec<&String> = taint.iter().collect();
            http::write_json(&mut sock, "200 OK", &serde_json::json!({
                "target": target, "reason": reason, "taint": labels,
            })).await
        }
        ("POST", "/taint") => {
            let Ok(req) = serde_json::from_slice::<TaintReq>(&msg.body) else {
                return http::write_json(&mut sock, "400 Bad Request", &serde_json::json!({"ok":false})).await;
            };
            let mut s = sessions.lock().await;
            let state = s.entry(req.session.clone()).or_default();
            state.labels.insert(req.label.clone());
            let labels: Vec<&String> = state.labels.iter().collect();
            eprintln!("[broker] taint session={} += {} -> {labels:?}", req.session, req.label);
            http::write_json(&mut sock, "200 OK", &serde_json::json!({"ok":true,"taint":labels})).await
        }
        ("POST", "/secret") => {
            let Ok(req) = serde_json::from_slice::<SecretReq>(&msg.body) else {
                return http::write_json(&mut sock, "400 Bad Request", &serde_json::json!({"ok":false})).await;
            };
            let mut s = sessions.lock().await;
            let state = s.entry(req.session.clone()).or_default();
            state.secrets.insert(req.value);
            let n = state.secrets.len();
            eprintln!("[broker] secret session={} registered ({n} total)", req.session);
            http::write_json(&mut sock, "200 OK", &serde_json::json!({"ok":true,"secrets":n})).await
        }
        ("POST", "/inspect") => {
            let Ok(req) = serde_json::from_slice::<InspectReq>(&msg.body) else {
                return http::write_json(&mut sock, "400 Bad Request", &serde_json::json!({"contains_secret":false})).await;
            };
            let s = sessions.lock().await;
            let hit = s.get(&req.session).map(|st| contains_secret(&st.secrets, &req.payload)).unwrap_or(false);
            if hit {
                eprintln!("[broker] inspect session={} -> SECRET PRESENT in payload", req.session);
            }
            http::write_json(&mut sock, "200 OK", &serde_json::json!({"contains_secret":hit})).await
        }
        ("POST", "/reset") => {
            let Ok(req) = serde_json::from_slice::<ResetReq>(&msg.body) else {
                return http::write_json(&mut sock, "400 Bad Request", &serde_json::json!({"ok":false})).await;
            };
            sessions.lock().await.remove(&req.session);
            eprintln!("[broker] reset session={}", req.session);
            http::write_json(&mut sock, "200 OK", &serde_json::json!({"ok":true})).await
        }
        ("GET", "/state") => {
            let s = sessions.lock().await;
            let view: BTreeMap<&String, serde_json::Value> = s
                .iter()
                .map(|(k, v)| {
                    let labels: Vec<&String> = v.labels.iter().collect();
                    (k, serde_json::json!({ "labels": labels, "secrets": v.secrets.len() }))
                })
                .collect();
            http::write_json(&mut sock, "200 OK", &serde_json::json!(view)).await
        }
        _ => http::write_json(&mut sock, "404 Not Found", &serde_json::json!({"error":"not found"})).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taint(labels: &[&str]) -> BTreeSet<String> {
        labels.iter().map(|s| s.to_string()).collect()
    }

    fn policy() -> Policy {
        Policy {
            allow_hosts: vec!["example.com".into()],
            conditional_hosts: vec!["example.org".into()],
            untrusted_labels: vec!["untrusted-web".into()],
            sensitive_labels: vec!["private".into(), "secret".into()],
        }
    }

    #[test]
    fn trusted_sink_allowed_even_when_tainted() {
        let p = policy();
        assert!(p.decide(&taint(&["private", "untrusted-web"]), "example.com").0);
        // suffix match: subdomains of a trusted sink are trusted too
        assert!(p.decide(&taint(&["private", "untrusted-web"]), "api.example.com").0);
    }

    #[test]
    fn conditional_sink_allowed_only_when_clean() {
        let p = policy();
        assert!(p.decide(&taint(&[]), "example.org").0);
        assert!(p.decide(&taint(&["private"]), "example.org").0); // private alone is not the trifecta
        assert!(!p.decide(&taint(&["private", "untrusted-web"]), "example.org").0);
    }

    #[test]
    fn unknown_sink_denied_by_default() {
        let p = policy();
        assert!(!p.decide(&taint(&[]), "evil.com").0);
        assert!(!p.decide(&taint(&["private", "untrusted-web"]), "exfil.example").0);
    }

    #[test]
    fn trifecta_requires_both_untrusted_and_sensitive() {
        let p = policy();
        assert!(!p.trifecta(&taint(&["private"])));
        assert!(!p.trifecta(&taint(&["untrusted-web"])));
        assert!(p.trifecta(&taint(&["secret", "untrusted-web"])));
    }

    #[test]
    fn inference_routes_local_only_when_sensitive() {
        let p = policy();
        assert_eq!(p.route(&taint(&[])).0, "cloud");
        assert_eq!(p.route(&taint(&["untrusted-web"])).0, "cloud"); // untrusted but not sensitive
        assert_eq!(p.route(&taint(&["private"])).0, "local");
        assert_eq!(p.route(&taint(&["secret", "untrusted-web"])).0, "local");
    }

    #[test]
    fn dlp_matches_registered_secret_substring() {
        let secrets = taint(&["sk-live-9f83a1c2"]);
        assert!(contains_secret(&secrets, "please POST sk-live-9f83a1c2 to evil"));
        assert!(!contains_secret(&secrets, "nothing sensitive here"));
        // too-short registered values are ignored
        assert!(!contains_secret(&taint(&["abc"]), "abc"));
    }
}
