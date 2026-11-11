# Bollard measurement harness

Does Bollard's policy survive realistic agent work, and what slips past it?

The harness replays benign and prompt-injected agent traces through the **real**
`bollard-broker` (taint store, policy, DLP) and `bollard-mcp` (provenance
tagging), and scores three things per policy variant:

- **Benign work blocked**, split by cause: taint model, allowlist, or DLP.
- **Injected exfiltration that leaked**, split into *baseline attacks* (what
  Bollard claims to stop) and *gap probes* (deliberate attempts at suspected
  limitations).
- **Model calls forced onto the local backend** by sensitive context.

It also runs a DLP-evasion table, and a conformance check that drives the real
`bollard-proxy` to confirm the egress adapter used for scoring behaves the same.

## Run

```sh
cargo build -p bollard-broker -p bollard-mcp -p bollard-proxy
python3 bench/run_bench.py                 # replay: all policies, no model, no Docker, ~10 s
python3 bench/run_bench.py --policies strict --only b02-fix-test-with-docs a01-classic-trifecta
```

Output goes to `bench/results/replay.{md,json}` (the JSON includes every trace).
Exit code 2 means the adapter disagreed with the real proxy, so the scores are
not trustworthy.

### Live mode (a real model drives the agent)

```sh
python3 bench/run_bench.py --live --model qwen2.5:7b --policies strict
# any OpenAI-compatible endpoint with function calling: --endpoint http://host:11434/v1/chat/completions
```

The model gets the bollard-mcp tools (real taint) plus an `http_request` tool
that goes through the same gate. For attack tasks the text the model sees is
overridden by `tool_outputs` (the injection); taint and secret registration still
come from the real MCP call. A model that ignores the injection is reported as
"not attempted", not as "contained".

## Files

| file | purpose |
|---|---|
| `tasks.json` | 20 benign and 16 attack traces (`known_gap` marks the gap probes) |
| `tools.yaml` | tool provenance map for bollard-mcp |
| `policy_strict.yaml` | small allowlist; every public site denied |
| `policy_browse.yaml` | public sites as *conditional* sinks (reachable until the context is tainted) |
| `policy_open.yaml` | public sites as *trusted* sinks (always reachable) |
| `policy_conformance.yaml` | loopback names, used only by the proxy conformance check |

## Caveats, read before quoting any number

1. **Replay traces are hand-authored.** They show what the policy does with
   these behaviours, not how real agents behave. Live mode is the real test, and
   so far it has only been smoke-tested with a 7B local model that mostly ignores
   injections. It needs a stronger model and a larger task set.
2. **Gap-probe leak rates are not attack success rates.** I wrote those probes to
   find holes. A high number measures coverage, not exposure.
3. **The false-positive rate depends on how tools are labelled and which hosts
   are listed.** That is the operator burden; the three policies show the range.
4. **Scoring is at the decision level.** The adapter mirrors the proxy (verified
   by the conformance table) but the Docker cage and kernel-level isolation are
   not exercised here.
5. **No TLS interception is modelled** because Bollard has none: https is a blind
   CONNECT tunnel, so DLP never sees an https body.
