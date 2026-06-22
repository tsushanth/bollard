# Bollard

**A data-flow firewall for AI agents.** Bollard tags where every piece of an
agent's data came from, then gates each outbound call — and routes each model
call — on that provenance, enforced at the network boundary so even a
shelled-out `curl` cannot escape.

It targets the *lethal trifecta*: an agent with private data + untrusted input +
the ability to make outbound calls. The market today *detects* injection
(classifiers) or sets *coarse* network allowlists; neither asks the one question
that matters — **where did the data in this request come from?** Bollard does,
and enforces the answer somewhere the agent can't reach around.

See [DESIGN.md](DESIGN.md) for the full thesis, threat model, and roadmap.

## Status

Milestone **M3 — provenance-gated egress + the privacy router** is built. A real
MCP-client agent connects to the Bollard MCP server; Bollard (1) blocks the
agent's injected exfiltration attempt at the network boundary, and (2) routes
its model calls local-vs-cloud by sensitivity — a call made while a secret is in
context is kept on a local backend that physically can't reach the internet,
while benign calls still use cloud.

## Try the demo

Requires Docker (with the Compose plugin). The cage uses Linux networking, so on
macOS/Windows it runs inside Docker's Linux VM automatically.

```sh
./scripts/demo.sh        # the full agent attack scenario
cargo test               # broker policy decision tests
```

The agent (a real MCP client) does an `initialize` / `tools/list` handshake,
then:

1. egress to `example.org`, **clean** context — **200**, passes.
2. a model call with a clean context — routed to **cloud**.
3. `read_file` puts a secret in context; the next model call is routed to
   **local** — the prompt never leaves the cage.
4. `web_fetch` adds untrusted content; the agent obeys the injected page and
   tries to exfiltrate the secret to `exfil.example` — **403**, refused.
5. it then smuggles the secret to a **trusted** sink (`example.com`) over plain
   HTTP — still **403**, because content inspection (DLP) finds the secret in the
   body even though the host is allowlisted.
6. the **same** `example.org` request as step 1 — now **403**.
7. `example.com` with no secret in the request — **200**, legit flows survive.
8. a raw socket to `1.1.1.1` bypassing the proxy — **no route**: the cage holds.

Edit [`policy/default.yaml`](policy/default.yaml) and
[`config/tools.yaml`](config/tools.yaml) to change the rules and tool provenance.

## Testing

| Layer | How |
| --- | --- |
| Policy / routing / DLP decision logic | `cargo test` — unit tests in `bollard-broker` and `bollard-openshell` |
| Full agent attack scenario | `./scripts/demo.sh` — a real MCP-client agent against the live cage |
| OpenShell policy translation | `cargo test -p bollard-openshell`; `bollard-openshell policy/default.yaml` |
| Translated YAML accepted by OpenShell's **real** parser | build `tools/openshell-validate` (path-deps `openshell-policy`), then `BOLLARD_OPENSHELL_VALIDATOR=tools/openshell-validate/target/debug/openshell-validate cargo test -p bollard-openshell --test conformance`. Needs a local OpenShell checkout; skipped otherwise |
| Live OpenShell integration | requires a Linux host with the OpenShell toolchain (Docker/podman/VM driver); load the translated policy into a real sandbox and replay the scenario — not runnable on macOS without that toolchain |

See [docs/openshell.md](docs/openshell.md) for the OpenShell integration design.

### Real inference

The inference backends are stubs by default so the demo stays hermetic, but the
gateway fronts any OpenAI-compatible server. Set `BOLLARD_BACKEND_UPSTREAM` on a
backend (see [`deploy/docker-compose.yml`](deploy/docker-compose.yml)) to point
the local backend at, e.g., a real Ollama or a Nemotron NIM, and routing then
governs a real model.

## Layout

```
crates/bollard-http/     shared minimal HTTP/1.1 helpers (Rust)
crates/bollard-proxy/    the egress boundary (Rust)
crates/bollard-broker/   taint store + policy/routing decision engine (Rust)
crates/bollard-mcp/      MCP server; tags tool outputs with provenance (Rust)
crates/bollard-infer/    inference gateway; routes model calls by sensitivity (Rust)
crates/bollard-openshell/ translate Bollard policy -> NVIDIA OpenShell policy (Rust)
agent/agent.py           a real MCP-client agent that gets injected
docs/openshell.md        OpenShell integration design + upstream proposal
policy/default.yaml       taint-keyed, deny-by-default policy
config/tools.yaml         per-tool provenance map
deploy/                   the cage: docker-compose + images
scripts/demo.sh           runs the full scenario
site/index.html           landing page (self-contained, no build step)
DESIGN.md                 thesis, threat model, architecture, roadmap
```

## License

Apache-2.0.
