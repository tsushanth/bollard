# Covert-channel detection

Status: instrumentation (Weekend 1) + three anomaly tests, adversarially
validated against synthetic traffic (Weekend 2). Not yet wired into the
live proxy's block decision — see "Policy shape" at the bottom.

Bollard's provenance-gated egress (M3) blocks requests the policy engine can
label as bad. It says nothing about a channel that never trips a label rule —
an agent that's been told (via prompt injection, or scheming on its own) to
exfiltrate data by encoding it in, say, DNS query subdomains, request timing,
or padding byte counts to a *host that's already allowed*. This doc scopes
the anomaly-detection layer meant to catch that class of channel.

## What's shipped now (Weekend 1 of this work)

`bollard-proxy` now emits one JSONL line per connection to
`BOLLARD_LOG_PATH` (default `bollard-egress.jsonl`):

```json
{
  "timestamp": 1787606601.234,
  "session": "default",
  "host": "example.com",
  "port": 443,
  "kind": "connect",       // "connect" | "http"
  "allow": true,
  "reason": "policy: allowlisted",
  "request_bytes": 1042,
  "response_bytes": 8391,
  "latency_ms": 214.7,
  "hostname_entropy": 3.32,  // Shannon entropy of the hostname, bits/char
  "baseline": true           // set when BOLLARD_BASELINE_MODE=1
}
```

`request_bytes`/`response_bytes` come from `copy_bidirectional`'s actual
transfer counts, not just the initial buffered request — so a CONNECT tunnel
that holds a connection open and streams data for minutes gets a real total,
not zero.

Run with `BOLLARD_BASELINE_MODE=1` while exercising known-legitimate agent
traffic to build a labeled baseline corpus before turning on detection —
this flag doesn't change proxy behavior at all, it just tags the log so
baseline and live traffic can be told apart later.

## What's shipped now (Weekend 2)

`bollard-anomaly` (new crate) implements three Tukey-fence tests over the
JSONL log and validates them against synthetic adversarial traffic in
`cargo test -p bollard-anomaly` — 7 tests, not just unit tests of the math,
but explicit "does this specific evasion get caught" cases per signal.

**Caveat upfront: this is synthetic-traffic validation, not a live Docker
demo with a real mock MCP agent.** Building the three statistical tests
against hand-constructed event streams was enough to test the *detection
logic itself* (does the IQR fence catch what it should, where does entropy
actually separate real from encoded) within a weekend; wiring a real agent
through the live cage to generate this traffic organically is follow-up
work, not done here.

1. **Request timing IQR** per (session, host) — confirmed the prediction:
   `timing_channel_obvious_extreme_delays_are_caught` passes (2000ms delay
   vs. a ~50-300ms baseline), but `timing_channel_naive_in_range_jitter_evades_detection`
   also passes — meaning a channel using 100ms vs. 220ms delay buckets,
   comfortably inside the baseline's natural jitter, is invisible to this
   test entirely. **This is the weakest signal, exactly as predicted, and
   confirmed rather than assumed.**

2. **Byte-size distribution** per (session, host) — same shape of result.
   An obvious 8KB pad against a ~1.8-2.7KB baseline gets caught; a ~200-byte
   delta that stays inside the baseline's natural size jitter does not.
   Moderately useful against a lazy/obvious channel, useless against one
   that budgets its payload to fit inside existing noise.

3. **Hostname entropy** — the only baseline-independent signal (it doesn't
   need history for a host to judge it), so it's the only one that can catch
   exfil to a *brand-new* attacker-controlled domain, which is the realistic
   case. But calibration turned out to be genuinely hard, not just a matter
   of picking a number: a spot-check of real hostnames (`mail.google.com`
   3.06, `pubads.g.doubleclick.net` 3.89 bits/char) sits within ~0.2
   bits/char of two synthetic encoded-subdomain examples (4.10, 4.39). The
   threshold shipped (3.9) clears every legit sample checked, but that
   margin is thin and the "legit sample checked" list has ~9 hostnames on
   it — a real ad-tech/CDN/cloud-storage domain corpus (hash-like
   auto-generated subdomains are common there) would very plausibly push
   the false-positive rate up. This is the opposite of the confident "decent
   signal" framing this doc had before testing it — it's real, but fragile,
   and needs a much bigger legitimate-traffic sample to calibrate honestly.

None of these three catches a channel that piggybacks on legitimate-looking
request bodies to an allowed host with normal timing and normal size — that
requires content-level analysis this log format doesn't capture yet
(DLP inspection exists for *known* secrets, not for arbitrary encoded
payloads). Worth being explicit about that gap rather than implying these
three tests are a complete covert-channel defense.

## Policy shape (not yet wired to the proxy)

`bollard-anomaly` is a standalone analysis binary today — it reads log
files, it does not yet feed a block decision back into `bollard-proxy`'s
live `decide()` path. Wiring `anomaly_score > threshold` into the broker as
an actual gate (matching the existing fail-closed posture, not just an
offline report) is the next step, and per the project's own framing, the
hard part isn't the wiring — it's that the entropy threshold's fragile
margin (above) means a naive "block on flag" policy risks exactly the
false-positive-driven "researchers turn it off" failure mode this project
set out to avoid. A bigger real-traffic calibration corpus should come
before that wiring, not after.
