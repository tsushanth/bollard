# Bollard × NVIDIA OpenShell

[OpenShell](https://github.com/NVIDIA/OpenShell) is a secure agent runtime: it
runs an agent in a sandbox and enforces egress with a per-connection proxy
inside a network namespace. Bollard and OpenShell agree on the hard part — put
the agent where there is no route out except a boundary you control — which
makes them complementary rather than competing. This note maps the seam.

## What OpenShell enforces, and the gap

OpenShell's egress proxy decides every connection, but on two inputs it does
*not* include:

- **It keys decisions on the caller, not the data.** The OPA input is the
  destination `host`/`port` plus the **calling binary's** path, sha256, and
  process ancestors (`crates/openshell-supervisor-network/src/proxy.rs`,
  `evaluate_opa_tcp`; rules in `data/sandbox-policy.rego`). It answers "may
  `/usr/bin/curl` reach `api.github.com`?" — never "did the data in this request
  come from an untrusted or private source?" That is the lethal-trifecta gap.
- **Its inference router has no sensitivity input.** `openshell-router`
  (`src/lib.rs`, `proxy_with_candidates`) selects a backend by *protocol match
  only* — the first route whose `protocols` contains the inbound protocol. The
  crate is the "privacy router," but routing is static; nothing keeps a
  secret-bearing prompt on a local model.

Bollard adds exactly those two axes (provenance-gated egress, sensitivity-based
routing) plus content DLP. Run `bollard-openshell <policy>` to see, for any
Bollard policy, the precise list of controls with no OpenShell equivalent.

## Using them together today (no OpenShell changes)

`bollard-openshell` translates a Bollard policy's host allowlist into a valid
OpenShell `network_policies` block, so the coarse host layer deploys natively on
OpenShell while Bollard's broker enforces the provenance/sensitivity/DLP layer on
top:

```shell
bollard-openshell policy/default.yaml > openshell-policy.yaml   # the host layer
#  ... provenance, routing, and DLP rules print to stderr as the Bollard-only layer
```

The OpenShell schema is `crates/openshell-policy/src/lib.rs` (`PolicyFile` →
`network_policies: map<string, NetworkPolicyRule>`); the translator targets it
field-for-field (it parses with `deny_unknown_fields`).

## The clean upstream integration (proposed)

The highest-leverage hook is a single injection point in OpenShell's inference
path. `InferenceContext` (`proxy.rs`) already holds the resolved routes and is
the one place every model call passes through; route selection is
`router.proxy_with_candidates(...)`. Adding an optional classifier there lets an
external policy source (Bollard) influence routing without touching the egress
fast path:

```rust
// in openshell-supervisor-network, consulted before proxy_with_candidates
pub trait SensitivityClassifier: Send + Sync {
    fn classify(&self, req: &L7Request) -> Sensitivity;   // Public | Internal | Secret
}
// routes are then filtered/ordered by the returned tier before selection
```

A symmetric, smaller step for egress is to add the request's provenance tier to
the OPA `NetworkInput` so policies can gate on it; today the input is
caller+destination only.

### How to land it

OpenShell auto-closes PRs from unvouched external contributors (`vouch-check`),
and requires a design proposal before implementation. So the path is **issue /
RFC first** (per `AGENTS.md` and the feature-request template), not a cold PR —
the same play as proposing a stable telemetry surface upstream. This doc is the
seed of that proposal: a named hook, a file to put it in, and a working
reference implementation (Bollard) that already does the thing end to end.

## Status

- `bollard-openshell` translator + gap report: built and tested
  (`cargo test -p bollard-openshell`).
- **Conformance:** the translated YAML is accepted by OpenShell's real
  `openshell_policy::parse_sandbox_policy` — proven by `tools/openshell-validate`
  and an env-gated test (`--test conformance`); see
  [the testing notes](../README.md#testing).
- Live OpenShell integration test (load the translated policy into a real
  OpenShell sandbox and replay the exfil scenario): requires a Linux host with
  the OpenShell toolchain.
- Upstream `SensitivityClassifier` proposal: drafted here, not yet filed.
