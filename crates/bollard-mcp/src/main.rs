// SPDX-License-Identifier: Apache-2.0
//
// bollard-mcp — the tool-mediation layer, as a real MCP server.
//
// Speaks MCP (JSON-RPC 2.0) over the Streamable HTTP transport: `initialize`,
// `tools/list`, `tools/call`. When a tool returns data, bollard-mcp stamps it
// with a provenance label (static config) and reports that label to the broker,
// so the data's origin follows the agent into every later egress decision.

use std::collections::BTreeMap;
use std::sync::Arc;

use bollard_http as http;
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};

const PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug, Deserialize)]
struct ToolDef {
    /// Provenance label stamped on this tool's output (e.g. "private").
    provenance: String,
    #[serde(default)]
    description: String,
    /// If true, register this tool's output as a secret value for content-based
    /// (DLP) inspection downstream, not just a provenance label.
    #[serde(default)]
    secret: bool,
    /// Canned output for the demo stub.
    output: String,
}

#[derive(Debug, Default, Deserialize)]
struct ToolsConfig {
    #[serde(default)]
    tools: BTreeMap<String, ToolDef>,
}

struct Ctx {
    tools: ToolsConfig,
    broker: String,
    session: String,
}

#[tokio::main]
async fn main() {
    let tools_path =
        std::env::var("BOLLARD_TOOLS").unwrap_or_else(|_| "/etc/bollard/tools.yaml".into());
    let listen = std::env::var("BOLLARD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8070".into());
    let broker =
        std::env::var("BOLLARD_BROKER").unwrap_or_else(|_| "http://bollard-broker:8090".into());
    let session = std::env::var("BOLLARD_SESSION").unwrap_or_else(|_| "default".into());

    let tools = match std::fs::read_to_string(&tools_path) {
        Ok(s) => serde_yaml::from_str(&s).unwrap_or_else(|e| {
            eprintln!("[mcp] bad tools config {tools_path} ({e})");
            ToolsConfig::default()
        }),
        Err(e) => {
            eprintln!("[mcp] no tools config {tools_path} ({e})");
            ToolsConfig::default()
        }
    };
    let names: Vec<&String> = tools.tools.keys().collect();
    eprintln!("[mcp] MCP server up on {listen}; tools={names:?}; broker={broker}");

    let ctx = Arc::new(Ctx { tools, broker, session });
    let listener = TcpListener::bind(&listen).await.expect("bind");
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[mcp] accept error: {e}");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(sock, ctx).await {
                eprintln!("[mcp] connection error: {e}");
            }
        });
    }
}

async fn serve(mut sock: TcpStream, ctx: Arc<Ctx>) -> std::io::Result<()> {
    let Some(msg) = http::read_message(&mut sock).await? else {
        return Ok(());
    };
    if (msg.method(), msg.path()) != ("POST", "/mcp") {
        return http::write_status(&mut sock, "404 Not Found").await;
    }

    let rpc: serde_json::Value = match serde_json::from_slice(&msg.body) {
        Ok(v) => v,
        Err(_) => return http::write_status(&mut sock, "400 Bad Request").await,
    };
    let method = rpc.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = rpc.get("id").cloned();

    // Notifications carry no id and get no JSON-RPC response.
    let Some(id) = id else {
        if method == "notifications/initialized" {
            eprintln!("[mcp] client initialized");
        }
        return http::write_status(&mut sock, "202 Accepted").await;
    };

    match method {
        "initialize" => {
            let result = serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "bollard-mcp", "version": env!("CARGO_PKG_VERSION") },
            });
            write_result(&mut sock, &id, result).await
        }
        "tools/list" => {
            let tools: Vec<serde_json::Value> = ctx
                .tools
                .tools
                .iter()
                .map(|(name, def)| {
                    serde_json::json!({
                        "name": name,
                        "description": def.description,
                        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": true },
                    })
                })
                .collect();
            write_result(&mut sock, &id, serde_json::json!({ "tools": tools })).await
        }
        "tools/call" => {
            let name = rpc
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let Some(def) = ctx.tools.tools.get(name) else {
                return write_error(&mut sock, &id, -32602, &format!("unknown tool: {name}")).await;
            };
            eprintln!("[mcp] tools/call {name} -> provenance={}", def.provenance);
            // Stamp provenance and report it before returning the data. Fail
            // closed: if provenance can't be recorded, don't hand over the data.
            if let Err(e) = report_taint(&ctx.broker, &ctx.session, &def.provenance).await {
                eprintln!("[mcp] taint report failed ({e}); refusing tool call");
                return write_error(&mut sock, &id, -32000, "provenance unavailable").await;
            }
            if def.secret {
                if let Err(e) = report_secret(&ctx.broker, &ctx.session, &def.output).await {
                    eprintln!("[mcp] secret report failed ({e}); refusing tool call");
                    return write_error(&mut sock, &id, -32000, "provenance unavailable").await;
                }
            }
            let result = serde_json::json!({
                "content": [ { "type": "text", "text": def.output } ],
                "isError": false,
                "_meta": { "bollard/provenance": def.provenance },
            });
            write_result(&mut sock, &id, result).await
        }
        other => write_error(&mut sock, &id, -32601, &format!("method not found: {other}")).await,
    }
}

/// POST {"session","label"} to the broker's /taint endpoint; fail on rejection.
async fn report_taint(broker: &str, session: &str, label: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "session": session, "label": label }).to_string();
    let resp = http::post(broker, "/taint", body.as_bytes()).await?;
    if resp.status == 200 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("broker returned {}", resp.status)))
    }
}

/// POST {"session","value"} to the broker's /secret endpoint; fail on rejection.
async fn report_secret(broker: &str, session: &str, value: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "session": session, "value": value }).to_string();
    let resp = http::post(broker, "/secret", body.as_bytes()).await?;
    if resp.status == 200 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("broker returned {}", resp.status)))
    }
}

async fn write_result(
    sock: &mut TcpStream,
    id: &serde_json::Value,
    result: serde_json::Value,
) -> std::io::Result<()> {
    http::write_json(sock, "200 OK", &serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })).await
}

async fn write_error(
    sock: &mut TcpStream,
    id: &serde_json::Value,
    code: i32,
    message: &str,
) -> std::io::Result<()> {
    http::write_json(
        sock,
        "200 OK",
        &serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    )
    .await
}
