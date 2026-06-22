// SPDX-License-Identifier: Apache-2.0
//! Minimal HTTP/1.1 helpers shared by the bollard services. Deliberately tiny:
//! one request per connection, `Connection: close`, small JSON bodies. Not a
//! general-purpose HTTP stack — just enough for the internal control plane.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A parsed inbound request: the request line plus the body.
pub struct Message {
    pub request_line: String,
    pub body: Vec<u8>,
}

impl Message {
    pub fn method(&self) -> &str {
        self.request_line.split_whitespace().next().unwrap_or("")
    }
    pub fn target(&self) -> &str {
        self.request_line.split_whitespace().nth(1).unwrap_or("")
    }
    pub fn path(&self) -> &str {
        self.target().split('?').next().unwrap_or("")
    }
    pub fn query(&self) -> &str {
        self.target().split_once('?').map(|(_, q)| q).unwrap_or("")
    }
}

/// An outbound response from a peer service.
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

pub fn body_of(raw: &[u8]) -> Option<&[u8]> {
    find_double_crlf(raw).map(|p| &raw[p + 4..])
}

pub fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

fn content_length(head: &str) -> usize {
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

fn status_of(raw: &[u8]) -> u16 {
    let line_end = raw.iter().position(|&b| b == b'\r').unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..line_end])
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// Read one HTTP message (request line + body). `None` if the peer closed before
/// sending a complete header block.
pub async fn read_message(sock: &mut TcpStream) -> std::io::Result<Option<Message>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if let Some(p) = find_double_crlf(&buf) {
            break p;
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 1024 * 1024 {
            return Ok(None);
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let request_line = head.split("\r\n").next().unwrap_or("").to_string();
    let want = content_length(&head);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < want {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Ok(Some(Message { request_line, body }))
}

pub async fn write_json(
    sock: &mut TcpStream,
    status: &str,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&body).await
}

pub async fn write_status(sock: &mut TcpStream, status: &str) -> std::io::Result<()> {
    let head = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    sock.write_all(head.as_bytes()).await
}

fn authority_of(url: &str) -> &str {
    url.strip_prefix("http://").unwrap_or(url)
}

/// GET `target` (a path, optionally with `?query`) from `base` (`http://host:port`).
pub async fn get(base: &str, target: &str) -> std::io::Result<Response> {
    let authority = authority_of(base);
    let req = format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    request(authority, req.as_bytes(), &[]).await
}

/// POST a JSON `body` to `base` + `path`.
pub async fn post(base: &str, path: &str, body: &[u8]) -> std::io::Result<Response> {
    let authority = authority_of(base);
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    request(authority, head.as_bytes(), body).await
}

async fn request(authority: &str, head: &[u8], body: &[u8]) -> std::io::Result<Response> {
    let mut conn = TcpStream::connect(authority).await?;
    conn.write_all(head).await?;
    if !body.is_empty() {
        conn.write_all(body).await?;
    }
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).await?;
    Ok(Response {
        status: status_of(&raw),
        body: body_of(&raw).map(<[u8]>::to_vec).unwrap_or_default(),
    })
}
