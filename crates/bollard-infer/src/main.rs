// SPDX-License-Identifier: Apache-2.0
//
// bollard-infer — the inference gateway (the "privacy router").
//
// A model call is just another outbound request, so Bollard routes it on the
// sensitivity of the agent's context: while the context holds sensitive data,
// inference is served by a LOCAL backend (on the cage's no-internet network, so
// the prompt physically cannot leave); otherwise it may go to a CLOUD backend.
// The agent points its model base-url here, exactly as it would at any gateway.
//
// Two roles in one binary (BOLLARD_INFER_ROLE):
//   gateway  — asks the broker `/route`, forwards to the chosen backend
//   backend  — forwards to a real OpenAI-compatible server if
//              BOLLARD_BACKEND_UPSTREAM is set (e.g. Ollama / a Nemotron NIM),
//              otherwise answers from a stub. Either way it names itself.
//
// Gateway fails closed to LOCAL: if routing is uncertain, keep data on-prem.

use std::sync::Arc;

use bollard_http as http;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() {
    let role = std::env::var("BOLLARD_INFER_ROLE").unwrap_or_else(|_| "gateway".into());
    let listen = std::env::var("BOLLARD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8050".into());
    let listener = TcpListener::bind(&listen).await.expect("bind");

    let role = match role.as_str() {
        "backend" => {
            let name = std::env::var("BOLLARD_BACKEND_NAME").unwrap_or_else(|_| "unnamed".into());
            let upstream = std::env::var("BOLLARD_BACKEND_UPSTREAM").ok().filter(|s| !s.is_empty());
            eprintln!(
                "[infer/backend] {name} up on {listen}; upstream={}",
                upstream.as_deref().unwrap_or("(stub)")
            );
            Role::Backend { name, upstream }
        }
        _ => {
            let cfg = Gateway {
                broker: std::env::var("BOLLARD_BROKER")
                    .unwrap_or_else(|_| "http://bollard-broker:8090".into()),
                session: std::env::var("BOLLARD_SESSION").unwrap_or_else(|_| "default".into()),
                local: std::env::var("BOLLARD_LOCAL_BACKEND")
                    .unwrap_or_else(|_| "http://bollard-infer-local:8060".into()),
                cloud: std::env::var("BOLLARD_CLOUD_BACKEND")
                    .unwrap_or_else(|_| "http://bollard-infer-cloud:8060".into()),
            };
            eprintln!("[infer/gateway] up on {listen}; broker={}; fail-closed to local", cfg.broker);
            Role::Gateway(cfg)
        }
    };

    let role = Arc::new(role);
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[infer] accept error: {e}");
                continue;
            }
        };
        let role = role.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(sock, role).await {
                eprintln!("[infer] connection error: {e}");
            }
        });
    }
}

enum Role {
    Gateway(Gateway),
    Backend { name: String, upstream: Option<String> },
}

struct Gateway {
    broker: String,
    session: String,
    local: String,
    cloud: String,
}

async fn serve(mut sock: TcpStream, role: Arc<Role>) -> std::io::Result<()> {
    let Some(msg) = http::read_message(&mut sock).await? else {
        return Ok(());
    };
    if msg.method() != "POST" {
        return http::write_json(&mut sock, "404 Not Found", &serde_json::json!({"error":"not found"})).await;
    }

    match role.as_ref() {
        Role::Backend { name, upstream } => {
            let answer = serve_backend(name, upstream, &msg.body).await;
            http::write_json(&mut sock, "200 OK", &answer).await
        }
        Role::Gateway(cfg) => {
            let answer = serve_gateway(cfg, &msg.body).await;
            http::write_json(&mut sock, "200 OK", &answer).await
        }
    }
}

async fn serve_backend(name: &str, upstream: &Option<String>, body: &[u8]) -> serde_json::Value {
    let prompt = extract_prompt(body);
    if let Some(up) = upstream {
        // Front a real OpenAI-compatible model server (e.g. Ollama, a NIM).
        match http::post(up, "/v1/chat/completions", body).await {
            Ok(r) if r.status == 200 => {
                eprintln!("[infer/backend] {name} served via upstream {up}");
                let response: serde_json::Value = serde_json::from_slice(&r.body)
                    .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&r.body) }));
                return serde_json::json!({ "backend": name, "served": true, "upstream": up, "response": response });
            }
            Ok(r) => eprintln!("[infer/backend] {name} upstream {up} returned {}; using stub", r.status),
            Err(e) => eprintln!("[infer/backend] {name} upstream {up} error ({e}); using stub"),
        }
    }
    eprintln!("[infer/backend] {name} served a request ({} chars)", prompt.len());
    serde_json::json!({
        "backend": name,
        "served": true,
        "echo": prompt.chars().take(80).collect::<String>(),
    })
}

async fn serve_gateway(cfg: &Gateway, body: &[u8]) -> serde_json::Value {
    let (mut target, mut reason) = match broker_route(&cfg.broker, &cfg.session).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[infer/gateway] broker route failed ({e}); keeping inference LOCAL");
            ("local".to_string(), "broker unreachable (fail-closed to local)".to_string())
        }
    };

    // DLP defense-in-depth: even if labels routed this to cloud, if the prompt
    // itself carries a registered secret, pin it local so the secret can't leave.
    if target == "cloud" {
        let prompt = extract_prompt(body);
        if broker_inspect(&cfg.broker, &cfg.session, &prompt).await.unwrap_or(false) {
            eprintln!("[infer/gateway] DLP: secret value in prompt; overriding cloud -> local");
            target = "local".to_string();
            reason = format!("{reason} [DLP: secret in prompt -> pinned local]");
        }
    }

    let backend = if target == "cloud" { &cfg.cloud } else { &cfg.local };
    eprintln!("[infer/gateway] route -> {target} ({reason}) -> {backend}");
    let backend_resp = match http::post(backend, "/infer", body).await {
        Ok(r) => serde_json::from_slice::<serde_json::Value>(&r.body)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&r.body) })),
        Err(e) => serde_json::json!({ "error": format!("backend unreachable: {e}") }),
    };
    serde_json::json!({
        "bollard": { "routed_to": target, "reason": reason },
        "backend": backend_resp,
    })
}

fn extract_prompt(body: &[u8]) -> String {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::from_utf8_lossy(body).into_owned();
    };
    // OpenAI-style: messages[-1].content
    if let Some(content) = v
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|a| a.last())
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        return content.to_string();
    }
    v.get("prompt")
        .and_then(|p| p.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned())
}

/// GET broker /route?session=... -> ("local"|"cloud", reason)
async fn broker_route(broker: &str, session: &str) -> std::io::Result<(String, String)> {
    let resp = http::get(broker, &format!("/route?session={session}")).await?;
    let v: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| std::io::Error::other(format!("broker json: {e}")))?;
    let target = v.get("target").and_then(|t| t.as_str()).unwrap_or("local").to_string();
    let reason = v.get("reason").and_then(|r| r.as_str()).unwrap_or("").to_string();
    Ok((target, reason))
}

/// POST broker /inspect -> does the payload carry a registered secret?
async fn broker_inspect(broker: &str, session: &str, payload: &str) -> std::io::Result<bool> {
    let body = serde_json::json!({ "session": session, "payload": payload }).to_string();
    let resp = http::post(broker, "/inspect", body.as_bytes()).await?;
    let v: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| std::io::Error::other(format!("broker json: {e}")))?;
    Ok(v.get("contains_secret").and_then(|b| b.as_bool()).unwrap_or(false))
}
