# Covert-channel detection

Status: instrumentation (Weekend 1) + three anomaly tests, adversarially
validated against synthetic traffic (Weekend 2) + a bigger real-hostname
corpus and live wiring into the proxy (Weekend 3, entropy-only, opt-in).

Bollard's provenance-gated egress (M3) blocks requests the policy engine can
label as bad. It says nothing about a channel that never trips a label rule —
an agent that's been told (via prompt injection, or scheming on its own) to
exfiltrate data by encoding it in, say, DNS query subdomains, request timing,
or padding byte counts to a *host that's already allowed*. This doc scopes
the anomaly-detection layer meant to catch that class of channel.

## What's shipped now (Weekend 1)

`bollard-proxy` emits one JSONL line per connection to `BOLLARD_LOG_PATH`
(default `bollard-egress.jsonl`):

```json
{
  "timestamp": 1787606601.234,
  "session": "default",
  "host": "example.com",
  "port": 443,
  "kind": "connect",
  "allow": true,
  "reason": "policy: allowlisted",
  "request_bytes": 1042,
  "response_bytes": 8391,
  "latency_ms": 214.7,
  "hostname_entropy": 3.32,
  "baseline": true,
  "entropy_anomaly": false,
  "timing_anomaly": null,
  "size_anomaly": null
}
```

`request_bytes`/`response_bytes` come from `copy_bidirectional`'s actual
transfer counts, not just the initial buffered request. `timing_anomaly`/
`size_anomaly` are `null` until the live per-(session,host) rolling window
(Weekend 3) has at least 5 samples to fence against.

Run with `BOLLARD_BASELINE_MODE=1` while exercising known-legitimate agent
traffic to build a labeled baseline corpus for the offline `bollard-anomaly`
tool — this flag doesn't change proxy behavior, it just tags the log.

## What's shipped now (Weekend 2): three tests, adversarially validated

`bollard-anomaly` implements three Tukey-fence tests and validates them
against synthetic adversarial traffic — 9 tests (as of Weekend 3), not just
unit tests of the math, but explicit "does this specific evasion get caught"
cases per signal.

**Caveat: this is synthetic-traffic validation, not a live Docker demo with
a real mock MCP agent.** Testing against hand-constructed event streams was
enough to validate the *detection logic itself* within a weekend; wiring a
real agent through the live cage to generate this traffic organically is
still follow-up work.

1. **Request timing IQR** — confirmed the prediction: an obvious 2000ms
   delay against a ~50-300ms baseline is caught; a channel using 100ms vs.
   220ms delay buckets, comfortably inside normal jitter, is invisible to
   this test entirely. **The weakest signal, exactly as predicted.**

2. **Byte-size distribution** — same shape. An obvious 8KB pad against a
   ~1.8-2.7KB baseline is caught; a ~200-byte delta that stays inside normal
   size jitter is not.

3. **Hostname entropy** — the only baseline-independent signal, so the only
   one that can catch exfil to a brand-new attacker-controlled domain (the
   realistic case). See Weekend 3 below — the honest answer here turned out
   to be more sobering than this section originally said.

None of the three catches a channel that piggybacks on legitimate-looking
request bodies to an allowed host with normal timing and normal size — that
needs content-level analysis this log format doesn't capture (DLP exists for
*known* secrets, not arbitrary encoded payloads).

## What's shipped now (Weekend 3): a real corpus, and a harder truth

The Weekend 2 threshold (3.9) was calibrated against ~9 hand-picked
hostnames. `crates/bollard-anomaly/src/corpus.rs` replaces that with ~140
realistic hostnames spanning the categories most likely to break an entropy
heuristic: hash-like CDN edge nodes (`d2j6dbq0eux0bg.cloudfront.net`),
cloud-storage buckets, ad-tech domains, and SaaS multi-tenant subdomains.
`bollard_anomaly::corpus::default_threshold()` computes the max entropy over
that corpus plus a 0.15 margin — **4.726**, not 3.9. `bollard-anomaly
calibrate [--baseline-log <file>]` recomputes this from real captured
traffic (blended with the corpus) once a deployment has its own baseline.

**This changed the finding, not just the number.** At 4.726, the same
18-character encoded-subdomain example that "passed" the Weekend-2 test at
3.9 now evades detection entirely
(`hostname_entropy_channel_short_realistic_payload_evades_calibrated_threshold`).
A follow-up test characterized how much payload it actually takes to
reliably clear the honest threshold: a random alphanumeric string needs to
be roughly **48-64 characters** before it reliably exceeds 4.726 — and 63
characters is the maximum length of a single DNS label. A deterministic
63-character test case clears the threshold, but only by ~1.5% headroom
(4.796 vs. 4.726) — `hostname_entropy_channel_dns_label_max_length_payload_is_caught`.

**Honest conclusion: hostname-entropy detection, calibrated to actually
avoid false positives on real infrastructure, only catches encoded payloads
near the physical maximum size of a single DNS label.** A short-to-moderate
encoded subdomain — which is what most casual DNS-tunneling code would
actually produce, since exfiltrating in bulk means many small labels, not
one maximal one — evades it. This is a materially weaker result than
Weekend 2's "the one signal that generalizes" framing suggested. It's still
worth having (it catches the laziest, most obvious channels, and it's the
only baseline-independent signal), but it should not be sold as more than
that.

## What's wired into the live proxy now (Weekend 3)

`bollard-proxy` now computes hostname entropy synchronously, before even
calling the broker (cheap — needs only the hostname, no round trip):

- **`BOLLARD_ENTROPY_THRESHOLD`** — defaults to `corpus::default_threshold()`
  (4.726), overridable.
- **`BOLLARD_ANOMALY_BLOCK`** — **defaults to off.** When off (the default),
  entropy is scored and logged (`entropy_anomaly` in the JSONL) but never
  denies on its own — matching the honest assessment above, where a naive
  "block on flag" policy risks the false-positive-driven "turn the policy
  off" failure mode this project set out to avoid, and where the signal's
  actual catch rate against realistic payloads is now known to be low.
  When explicitly set to `1`, an entropy-anomalous host is denied
  immediately, before the broker is even consulted, with reason
  `anomaly: hostname entropy ... exceeds threshold ...`.
- **Timing and size are wired live but never block**, by design, not as a
  placeholder for future blocking. Each (session, host) gets an in-process
  rolling window (last 30 samples); once it has 5+, subsequent connections
  are scored against it and the flags are logged. They can't gate the
  connection they're computed for (its own latency/bytes are only known
  after it completes), and Weekend 2 already showed both are easy to evade
  by budgeting inside normal jitter — wiring them to auto-block would add
  false-positive risk for close to zero real detection power. `BOLLARD_ANOMALY_IQR_K`
  (default 1.5) controls the fence width if a deployment wants to retune it.

## What's still not done

- The live rolling windows reset on proxy restart and aren't shared across
  proxy replicas — fine for the current single-process demo, not for a
  multi-replica deployment.
- `bollard-anomaly calibrate --baseline-log` blends real hostnames with the
  curated corpus but doesn't yet weight or filter them — a baseline log
  containing a genuinely weird one-off real hostname would push the
  threshold up further, with no outlier rejection.
- Content-level covert channels (payload encoded in an otherwise-normal
  body, to an otherwise-normal host, with otherwise-normal timing) remain
  fully undetected. This is not close to being addressed by anything here.
