# Bollard — design

*A data-flow firewall for AI agents.* Bollard tags where every piece of an
agent's data came from, then gates each outbound action — network egress and
model calls alike — on that provenance, enforced at the network boundary so even
a shelled-out `curl` cannot escape.

## The problem

Autonomous agents fall to the **lethal trifecta**: they (1) hold private data,
(2) ingest untrusted content (web pages, tool results, documents), and (3) can
make outbound calls. Any single agent with all three can be steered by injected
content into exfiltrating secrets. The failure is not a model bug — it is a
*data-flow* problem.

Today's defenses split into two camps, and both miss:

- **Detection** (Lakera, Invariant, Protect AI): classifiers that *guess*
  whether a prompt is an injection. Probabilistic, bypassable, and they do not
  constrain where data is allowed to flow.
- **Coarse runtime policy** (NemoClaw/OpenShell, E2B, Modal): per-domain or
  per-session network allowlists. They never consider *where the data in a
  request came from*, and they enforce at the SDK/tool layer — which a
  subprocess or raw `curl` walks straight around.

Nobody gates an outbound call on the **provenance** of the data inside it, and
nobody enforces it somewhere the agent cannot reach around.

## Thesis

1. **Tag** every tool output with provenance + sensitivity at the point it
   enters the agent (trusted-config / user / untrusted-web / private-file; and
   public / internal / secret).
2. **Propagate** that taint through the agent loop.
3. **Gate** each outbound action on a taint-keyed policy — including the model
   call, which is just another outbound request: secret-sensitivity context is
   routed to local inference, never the cloud.
4. **Enforce** it at the OS/network boundary, not the tool wrapper.

## Threat model

- **In scope:** an agent that has been prompt-injected by untrusted content and
  attempts exfiltration — via a tool, via a subprocess, via raw sockets, via a
  binary it writes itself. Bollard assumes the agent process is *hostile* the
  moment it touches untrusted input.
- **Trusted:** the host kernel, the Bollard proxy/broker processes, and the
  policy file.
- **Out of scope (v1):** side channels (timing, DNS-tunnelling steganography),
  and a malicious *model provider*. These are tracked, not solved, in v1.

## Architecture

```
            ┌──────────────────────── cage (no route out) ───────────────────────┐
            │                                                                     │
  tools ──► │  bollard-mcp  ──tag tool outputs──►  agent loop  ──outbound calls──►│──► bollard-proxy ──► internet
            │       │  (provenance/sensitivity)                                   │        │  (allow / deny / route)
            └───────┼─────────────────────────────────────────────────────────-──┘        │
                    └──────────────────────────► bollard-broker ◄─────────────────────────┘
                                    (taint store + policy decision engine)
```

- **bollard-proxy** (Rust) — the boundary. The agent runs in a cage with no
  route to the internet except this proxy, so enforcement is unbypassable by
  construction. Today: a deny-by-default forward proxy. *(M0 — built.)*
- **bollard-broker** (Rust) — the taint store and policy decision engine.
  Answers "given the current taint set and this destination, allow / deny /
  route-local?" *(M1+.)*
- **bollard-mcp** (Rust) — an MCP interceptor that tags every tool *output* by
  source and submits every tool/model *call* to the broker. Where taint is
  assigned and propagated. *(M1+.)*
- **policy** (YAML) — deny-by-default, with the trifecta rule and
  sensitivity→inference-routing.
- **bollard-http** (Rust) — the minimal HTTP/1.1 helpers shared by the services
  above (no per-service copies).

## Taint model (v1: coarse, honest)

Taint through an LLM is fundamentally lossy — a model can launder tainted input
into clean-looking output, so token-level taint is a research frontier. v1 does
not pretend otherwise. It tracks taint at **context granularity**: the set of
provenance labels of every tool output that has entered a session, and treats an
outbound action's taint as that whole set (conservative, deny-by-default). This
is weaker than token-level tracking but strictly stronger than every shipping
alternative, and it never produces a false *allow*. Finer-grained propagation
(payload/blob matching) is a later refinement, not a v1 dependency.

## Why the boundary is the foundation

The common mistake is enforcing in the tool/SDK layer. An agent that can run a
shell escapes that instantly (`curl`, a Python socket, a compiled binary).
Bollard inverts it: put the agent where **there is no route out except the
boundary**. On Linux this is a network namespace; portably (and for the
vendor-neutral target) it is a Docker `internal` network with the proxy as the
only dual-homed container. Everything else — taint, policy, routing — is a
decision *at* that boundary, which means it cannot be skipped.

## Non-goals

- Not a sandbox runtime. Bollard rides on top of one (Docker, OpenShell, E2B).
- Not a detection/classifier product. It constrains flow; it does not guess
  intent.
- Not an agent framework.

## Roadmap

- **M0 — the boundary.** Caged agent, deny-by-default proxy, "blocks raw curl"
  demo. *(built)*
- **M1 — provenance tagging + taint-keyed enforcement.** bollard-mcp stamps tool
  outputs; bollard-broker holds the per-session taint set and decides; the proxy
  enforces. The trifecta rule blocks the full read-private → fetch-untrusted →
  exfiltrate scenario, and the *same* request flips from allow to deny once the
  context is tainted. *(built — see `scripts/demo.sh`)*
- **M2 — real MCP + the attack story.** bollard-mcp is a conformant MCP server
  (JSON-RPC: initialize / tools/list / tools/call); a real MCP-client agent is
  injected via untrusted tool output, extracts the exfil URL, and is blocked at
  the boundary. Broker decision logic has unit tests. *(built — `scripts/demo.sh`)*
- **M3 — inference routing (the privacy router).** The model call is just
  another gated egress: bollard-infer asks the broker and routes sensitive-context
  calls to a local backend (on the no-internet network, so the prompt can't
  leave) and benign calls to cloud. *(built — same `scripts/demo.sh`)*
- **M3.1 — hardening.** Shared `bollard-http` crate (no duplicated transport);
  inference backends front any real OpenAI-compatible server via
  `BOLLARD_BACKEND_UPSTREAM`; and per-payload **DLP** — at the points with
  payload visibility (plain-HTTP egress, the inference prompt), Bollard blocks /
  pins a request that carries a registered secret value, catching exfil even to
  a *trusted* sink, which labels alone cannot. *(done.)* Remaining: full
  bidirectional MCP (SSE) transport.
- **M4 — adoption.** Landing page (`site/`); OpenShell adapter — a
  `bollard-openshell` policy translator + a gap report naming what OpenShell
  can't express, and an integration design with a proposed upstream
  `SensitivityClassifier` hook ([docs/openshell.md](docs/openshell.md)).
  *(built.)* Remaining: file the upstream proposal; first design partners.
