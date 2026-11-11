# OpenShell run: runbook for a fresh Ubuntu 24.04 VM

Goal: drive the same 36-trace corpus through a real NVIDIA OpenShell sandbox and compare it with
`bollard-proxy` and Pipelock (`python3 -I bench/run_bench.py --driver openshell`).

**Status: executed end to end on 2026-11-11 on a fresh Ubuntu 24.04 VM; the record of what failed and what was fixed is in
[Run record](#run-record-2026-11-11) at the end.** The steps and predictions below were written beforehand on macOS and are kept
as written, so you can see which held. [Test status](#test-status) describes the pre-run state. Every OpenShell command is traceable to a source in
[Sources](#sources); where I inferred rather than read, the step says so.

Pinned target: OpenShell **v0.1.8** (released 2026-11-10, commit `f3d976590d3eb1379690a2abaf0f0e26c21d487d`),
Debian package `openshell_0.1.8-1_amd64.deb`, sha256 `b3339527085d9b44afc0d5e4f835c2d34e44e33d0b67d6a4cac9d96f25a656b1`.
Policy language: YAML/Rego. **Cedar is not in v0.1.8**: the Cedar work (PR #4565 RFC 0020 engine, PR #5006 dev-build gating,
PR #4991 examples) is unmerged as of 2026-11-11, and per #5006 only the rolling `dev` build would include it. So this run
cannot exercise Cedar.

VM: Ubuntu 24.04, 4 vCPU, 8 GB, x86_64 or arm64, kernel >= 6.2 (24.04 ships 6.8) with Landlock enabled, outbound internet
(GitHub releases, Docker apt repo, static.rust-lang.org, crates.io, ghcr.io, nvcr.io). A normal user with sudo.

## Ordered steps

| # | step | expected time |
|---|---|---|
| 1 | get the repo onto the VM | 1 min |
| 2 | `bash bench/openshell/setup.sh` | 8-15 min |
| 3 | reboot | 1-2 min |
| 4 | start and register the gateway | 1-2 min |
| 5 | build the sandbox image | 1-3 min |
| 6 | host networking (`host-net.sh up`) | < 1 min |
| 7 | dry run (review only) | < 1 min |
| 8 | smoke test | 2-5 min (first sandbox pulls images) |
| 9 | full run | 10-30 min (unknown: depends on `sandbox exec` latency) |
| 10 | capture | 2 min |
| 11 | teardown | 2 min |

### 1. Repo

Put the Bollard checkout on the VM at the commit under test and record `git rev-parse HEAD`. Everything below runs from the
repo root. (The harness is Python stdlib only; `python3 -I` as in the existing drivers.)

### 2. setup.sh (does not start anything)

```sh
bash bench/openshell/setup.sh 2>&1 | tee /tmp/setup.log
```

What it does (read it first; it is ~150 lines): apt prerequisites; Docker Engine 5:28.5.2 from Docker's apt repo if no
Docker >= 28 (key fingerprint checked); `usermod -aG docker`, `loginctl enable-linger`; downloads the pinned `.deb`, checks the
sha256 against both the pin and the published `openshell-checksums-sha256.txt`, then `apt-get install ./deb` (the same steps as
the project's `install.sh`, minus `curl | sh`); a private Rust 1.99.1 toolchain under `bench/openshell/toolchain` (checksum-pinned tarball, no rustup);
`cargo build --locked -p bollard-openshell` into `bench/openshell/target`. It writes `bench/openshell/versions.txt` and `bench/openshell/env.sh`.

Expected: ends with `[setup] done.` and a versions block. It prints `ACTION REQUIRED` if it added you to the `docker` group.
Failure modes it checks itself: not Ubuntu 24.04 (override `ALLOW_OTHER_OS=1`), kernel < 6.2, Landlock absent from
`/sys/kernel/security/lsm` (override `SKIP_LANDLOCK_CHECK=1`, but the sandbox will then refuse to start), checksum mismatch, wrong Docker key.

### 3. Reboot

```sh
sudo reboot
```

Why (my reasoning, not from the docs): with linger on, the systemd *user* manager that runs the gateway keeps the group list it had when it
started, so it would not see the new `docker` group. After login: `id -nG | tr ' ' '\n' | grep -x docker` must print `docker`.

### 4. Start and register the gateway

Source: `docs/about/installation.mdx` (Linux section) and `install.sh` (`start_user_gateway`, `register_local_gateway`).

```sh
systemctl --user daemon-reload
systemctl --user enable --now openshell-gateway
systemctl --user is-active openshell-gateway              # expect: active
openshell gateway add https://127.0.0.1:17670 --local --name openshell
openshell status                                          # expect: a connected/healthy line (exact text unknown)
journalctl --user -u openshell-gateway --no-pager | tail  # inspect if status fails
```

Optional but recommended, to remove runtime auto-detection (Kubernetes, then Podman, then Docker; `docs/how-it-works/sandboxes/runtimes.mdx`):

```sh
mkdir -p ~/.config/openshell
printf '[openshell]\nversion = 2\n\n[openshell.gateway]\ncompute_driver = "docker"\n' > ~/.config/openshell/gateway.toml
openshell-gateway config preflight --path ~/.config/openshell/gateway.toml   # docs/about/installation.mdx, "Validate Gateway Configuration"
systemctl --user restart openshell-gateway
```

Expected time: the installer waits up to 30 s for the listener. If `status` fails, the usual causes are a stale docker group (step 3) or
the Docker daemon not running.

### 5. Sandbox image (curl)

The default workload image has no agent CLIs (`docs/about/support-matrix.mdx`) and the driver runs `curl` in the sandbox. `--from` takes a
locally built image for a Docker gateway (`docs/how-it-works/sandboxes/overview.mdx`, "Sandbox Images").

```sh
docker build -t bench-curl:local bench/openshell/image
docker image inspect --format '{{index .RepoDigests 0}}' nvcr.io/nvidia/base/ubuntu:24.04   # record the base digest
```

### 6. Host networking: the one root-level change

```sh
. bench/openshell/env.sh
mkdir -p bench/openshell/out
python3 -I bench/run_bench.py --driver openshell --os-print-hosts > bench/openshell/out/hosts.txt
bash bench/openshell/host-net.sh up bench/openshell/out/hosts.txt
getent hosts pypi-org.bench.test                          # expect: 10.99.99.1  pypi-org.bench.test
docker run --rm --network host --entrypoint getent bench-curl:local hosts pypi-org.bench.test   # expect the same
```

Why: OpenShell never allows a loopback destination, so `*.localhost` is unusable (`schema.mdx`: "Network policy never authorizes an
outbound endpoint whose destination is loopback, link-local, or unspecified"). `host-net.sh` creates a dummy interface `bench0` holding
10.99.99.1/32 and a marker-delimited `/etc/hosts` block. The second `getent` checks the assumption that a host-network container sees the
host's `/etc/hosts` (the supervisor container resolves destinations; Docker supervisor networking defaults to `host`, `runtimes.mdx`).
**If the second `getent` fails, stop: the supervisor will not resolve the corpus names; see risk 1.**

### 7. Dry run (also works on the Mac)

```sh
python3 -I bench/run_bench.py --driver openshell --dry-run --policies strict --only b01-research-to-slack a01-classic-trifecta
```

Prints every `openshell sandbox create/exec/delete` command and the curl each step would run; executes nothing except the local translator;
writes the generated policies to `bench/openshell/out/os_policy_<p>.yaml`. Review them. Sample outputs are committed under `bench/openshell/examples/`.

### 8. Smoke test (decide whether the full run is worth starting)

```sh
python3 -I bench/run_bench.py --driver openshell --os-smoke 2>&1 | tee bench/openshell/out/smoke.txt
```

Creates one sandbox on the strict policy, makes 4 requests (allowed/denied x http/https), prints each verdict and the raw record. Expected
(formats of the log/JSON text are inferred from the OpenShell docs and source, not observed):

1. `GET http://pypi.org/...` -> `allow: True`, `reason: reached the mock upstream`, `status: 200`
2. `GET https://pypi.org/...` -> `allow: True`, `reason: reached the mock upstream (TLS ClientHello seen)`, `status: None` (the mock is not a TLS server)
3. `GET http://randomblog.example.net/` -> `allow: False`, `cls: allowlist`, reason like `endpoint randomblog-example-net.bench.test:18080 is not allowed by any policy` with `(sandbox log)` or `(response)`
4. `GET https://randomblog.example.net/` -> same class

If 1 or 2 is denied, fix that before anything else (risks 1, 2, 4). If 3 or 4 prints `INFERRED` or `UNATTRIBUTED`, the verdicts are still valid but the denial
classes need the raw log format: rerun the smoke test with `--os-keep`, then `openshell logs bench-os-strict --source sandbox -n 100`, and delete the sandbox afterwards (see risk 8).

### 9. Full run

```sh
python3 -I bench/run_bench.py --driver openshell --os-raw 2>&1 | tee bench/openshell/out/run.txt
```

`--os-raw` adds one extra pass with the translator's **unedited** output; the expected result is that OpenShell refuses it (see findings below), which is itself a result.
Per policy it creates a sandbox, replays the 36 traces (41 egress steps, one `sandbox exec` each, plus one `openshell logs` per denial), runs the DLP-evasion
payloads and the benign-traffic probes on the first policy, then deletes the sandbox. Writes `bench/results/openshell.{md,json}` and, because `bollard-proxy.json` exists,
`bench/results/comparison-openshell.md`. Exit code 0 even when attacks leak (that is a finding, not an error).

### 10. Capture (copy these off the VM before destroying it)

- `bench/results/openshell.md`, `openshell.json`, `comparison-openshell.md`
- `bench/openshell/out/` (generated policies incl. `*.raw.yaml`, `hosts.txt`, `smoke.txt`, `run.txt`)
- `bench/openshell/versions.txt`
- `journalctl --user -u openshell-gateway --no-pager > bench/openshell/out/gateway.log`
- `docker images --digests > bench/openshell/out/images.txt` (the supervisor and sandbox-runtime images are pulled by tag at first use; the digests are the real pin)
- `git rev-parse HEAD` of the repo and `openshell --version`

### 11. Teardown

```sh
bash bench/openshell/host-net.sh down                      # removes the /etc/hosts block and bench0
openshell sandbox list                                     # driver deletes its own; delete strays with: openshell sandbox delete <name>
systemctl --user disable --now openshell-gateway           # docs/about/installation.mdx, "Uninstall OpenShell"
sudo apt remove -y openshell
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/openshell" ~/.config/openshell
docker rmi bench-curl:local
```

Then destroy the VM. `bench/openshell/{downloads,toolchain,cargo-home,target}` are untracked and disposable.

## What the run should show (predictions, NOT measurements)

OpenShell keys on host:port and calling binary only. So I expect: no `taint` or `dlp` denials; the same `allowlist` blocks as Bollard's allowlist;
attacks that go to a host in the policy leak (Bollard's conditional hosts become unconditional); every DLP-evasion payload passes; `browse` and `open`
identical (the translator emits the same 14 hosts for both). A result that contradicts these is worth a second look before it is believed.

## Findings already established without running OpenShell

1. **The translator's output is rejected by OpenShell v0.1.8's own parser.** Tested: `tools/openshell-validate` built against `openshell-policy` at tag v0.1.8
   rejects all three translated policies: `network policy 'bollard-egress': endpoint 0: unknown tls value 'terminate'; omit the field to keep automatic TLS termination`.
   (The repo's conformance test passes against an older OpenShell pin.)
2. The translator emits **no `binaries`**; OpenShell: "A rule with an empty `binaries` list matches no binary and allows nothing" (`network-rules.mdx`). Read from source, not yet observed at runtime.
3. The translator hard-codes **port 443**; the corpus's http:// steps would not match. Edited here to the mock's port.
4. **`browse` and `open` translate to the identical host set** (14 hosts): the trusted-versus-conditional distinction is lost, as the translator's own gap report says.
5. Not expressible (the translator's gap report, per policy, is copied into `openshell.md`): conditional sinks, the lethal-trifecta taint rule, sensitivity routing, content DLP.

Harness edits applied to the translator output (listed in `openshell.md` too): drop `tls: terminate`; port 443 -> 18080; add `binaries: [/usr/bin/curl]`;
add `allowed_ips: ["10.99.99.1/32"]` per endpoint (`--os-no-allowed-ips` removes it; exact declared hosts may reach private addresses without it, `schema.mdx`, but `allowed_ips` is the documented route and I wanted
the run not to depend on the more recent behaviour); `--os-fs-header` optionally adds the quickstart filesystem/Landlock header.

## Highest risks (check in this order)

1. **Name resolution inside the supervisor.** Everything depends on the supervisor container resolving `*.bench.test` to 10.99.99.1. Check: step 6's second `getent`, then smoke case 1.
   Unconfirmed assumptions: Docker host-network containers inherit the host's `/etc/hosts` at creation (sandboxes are created after `host-net.sh up`, so order matters); OpenShell's policy-DNS layer
   (`crates/openshell-supervisor-network/src/policy_dns`) answers the workload's lookups for policy hosts. Fallback if it fails: switch the driver to IP-literal hosts (not implemented; an IP-literal endpoint is
   authorized implicitly, `destination.rs` `ImplicitIpLiteral`), or add an `extra_hosts`-style mapping if the Docker driver config offers one (not found in the docs I read).
2. **Gateway cannot start sandboxes**: stale docker group (step 3), Docker < 28, image pull from `ghcr.io`/`nvcr.io` blocked or rate-limited, or the Landlock/seccomp qualification fails on this kernel
   ("launch fails closed", `support-matrix.mdx`). Hypothesis, unverified: Ubuntu 24.04's `kernel.apparmor_restrict_unprivileged_userns=1` could interfere with sandbox setup; read the gateway journal and
   `docker logs` of the supervisor container.
3. **The default workload image `nvcr.io/nvidia/base/ubuntu:24.04` may need authentication** for `docker build`. Override: `docker build --build-arg BASE=ubuntu:24.04 ...`.
4. **Mediation mode differs from the docs' tutorial.** The tutorial describes an HTTP proxy ("Received HTTP code 403 from proxy after CONNECT"), but v0.1.8's `process.rs` strips proxy variables ("must not redirect a transparently
   mediated process") and `architecture.mdx` describes seccomp-mediated TCP/DNS. The driver passes no `-x`, so it works either way; what changes is where a denial shows up (a refused connect or DNS failure versus a 403 body).
   Denial classes then depend on `openshell logs`, whose line format I only know from doc examples.
5. **https verdict relies on the TCP connection reaching the mock.** Allowed https steps end in a failed TLS handshake against a plain-HTTP mock; the verdict counts the arrival of the connection (first byte 0x16 recorded).
   If OpenShell dials the upstream only after a successful inner TLS + HTTP parse, a TLS trust problem inside the sandbox would show as a false deny. The driver uses `curl -k`; check `curl` exit codes in `openshell.json` `raw`.
6. **Second validation layer.** The parser accepting the edited policy (tested) is not the same as the supervisor's L7 validator accepting it at `sandbox create` (untested): look for `rejected`/`quarantine` text if create fails.
7. **Log lag**: the gateway log stream lags decisions; the driver retries 4 times with backoff. Denials may come back `INFERRED`. Gateway log buffer: 2,000 lines per sandbox (`accessing-logs.mdx`).
8. The driver deletes each sandbox when its policy finishes, so the gateway's log buffer for it is lost (`accessing-logs.mdx`). If you need the complete log, add `--os-keep` (sandboxes stay; delete them by hand afterwards) or run `openshell logs <name> --tail` in a second terminal while a single policy runs (`--policies strict`).
9. Per-step latency of `sandbox exec` is unknown. If it is > 3 s the full run exceeds 30 minutes; use `--policies strict` first.

## Test status

Tested on the authoring Mac:
- `python3 -I -m py_compile bench/run_bench.py`
- `--dry-run` for all policies, with and without `--os-raw`, and `--os-smoke --dry-run`, `--os-print-hosts`
- the Bollard translator on all three policies (output summarised in the hand-off; samples in `bench/openshell/examples/`)
- the harness's text edits to the translator output, fed to OpenShell v0.1.8's real parser (`openshell-policy`): edited accepted, raw rejected (all three policies, with and without `--os-fs-header` / `--os-no-allowed-ips`)
- the driver's verdict, parsing and classification code against a local mock upstream with a real local `curl` standing in for the in-sandbox one, incl. the whole corpus through `replay_task`/`score`
- `shellcheck` on `setup.sh` and `host-net.sh`

Not tested (everything that needs Linux, Docker or OpenShell): `setup.sh`, `host-net.sh`, the Dockerfile, gateway start, `sandbox create/exec/delete/logs` flags and output formats,
whether the supervisor resolves the mapped names, the L7 validator, the 4 sandbox-side curl invocations, timing.

## Sources

All paths are in `https://github.com/NVIDIA/OpenShell` at tag `v0.1.8` (commit `f3d976590d3eb1379690a2abaf0f0e26c21d487d`) unless noted. Rendered docs: `https://docs.nvidia.com/openshell/latest/`.

| used for | source |
|---|---|
| install via the `.deb`, checksum file name, apt flags, user-service start, `gateway add ... --local --name openshell`, port 17670 | `install.sh` (`install_linux_deb`, `verify_checksum`, `install_deb_package`, `start_user_gateway`, `register_local_gateway`); `docs/about/installation.mdx` |
| release assets, sha256 of the `.deb` | GitHub release `v0.1.8` assets API digest and `openshell-checksums-sha256.txt` (the two agreed) |
| Docker >= 28, kernel (Landlock ABI 3, seccomp), glibc >= 2.28, default image | `docs/about/support-matrix.mdx` |
| gateway TOML, `compute_driver = "docker"`, host network default, `config preflight` | `docs/how-it-works/sandboxes/runtimes.mdx`, `docs/about/installation.mdx` |
| `sandbox create --name/--from/--policy/--no-auto-providers/--no-tty/--detach -- cmd`, `sandbox exec -n --no-login-shell --no-tty --timeout --`, `sandbox delete` | `docs/how-it-works/sandboxes/overview.mdx`; `crates/openshell-cli/src/main.rs` (clap definitions) |
| `openshell logs <name> --source sandbox -n --since`, OCSF log line format, 2,000-line buffer | `docs/observability/accessing-logs.mdx`; `crates/openshell-cli/src/main.rs` |
| default-deny demo, deny log line `[reason:...]`, `policy_denied` 403 body | `docs/tutorials/first-network-policy.mdx`, `examples/sandbox-policy-quickstart/{demo.sh,policy.yaml}` |
| policy schema: `network_policies`, `binaries` (empty = none), endpoint fields, `allowed_ips`, loopback never allowed, `tls` values | `docs/how-it-works/policies/schema.mdx`, `network-rules.mdx` |
| deny reason strings (`endpoint %s:%d is not allowed by any policy`, `binary '...' not allowed in policy`, `network connections not allowed by policy`) | `crates/openshell-supervisor-network/data/sandbox-policy.rego` |
| `tls: terminate` rejected | `crates/openshell-supervisor-network/src/l7/mod.rs` (test `validate_rejects_unknown_endpoint_modes_without_warning`); confirmed by running `openshell-policy` v0.1.8 |
| destination resolution and private/loopback rules | `crates/openshell-supervisor-network/src/proxy.rs` (`resolve_socket_addrs`, `validate_declared_endpoint_resolved_addrs`), `proxy/destination.rs` |
| proxy variables stripped, transparent mediation | `crates/openshell-sandbox/src/process.rs` (`PROXY_ENV_VARS`), `docs/about/architecture.mdx` |
| curl `-w` variables (`http_connect`, `exitcode`, `errormsg`) | curl documentation (not OpenShell); curl 8.5 is Ubuntu 24.04's |
| Docker apt repo, key fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`, `docker-ce 5:28.5.2` | `https://download.docker.com/linux/ubuntu/gpg` and `dists/noble/stable/binary-amd64/Packages.gz` (fetched 2026-11-11) |
| Rust 1.99.1 tarball sha256 | `https://static.rust-lang.org/dist/rust-1.99.1-<triple>.tar.xz.sha256` |
| Cedar status | PRs #4565, #5006, #4991, issue #4411 on the OpenShell repo; CNCF post `https://www.cncf.io/blog/2026/11/10/welcoming-openshell-to-the-cncf-open-governance-to-secure-agentic-ai/` |

## Run record (2026-11-11)

Box: Ubuntu 24.04.5, kernel 6.8.0-139, 4 vCPU, 8 GB, Docker 28.5.2, OpenShell 0.1.8 (deb sha256 matched the pin and the published list), Rust 1.99.1.
The repo was copied without its history (rsync), so `versions.txt` could not record a commit; the tree was `8f57ed6` plus the driver edits listed below.
Wall clock from a bare VM to the first full result: about 25 minutes, most of it the Rust download; the full three-policy run takes about one minute
(a `sandbox exec` round trip is about 0.3 s, sandbox creation 1-3 s with the image already local). Versions, image digests, per-sandbox logs and the exact
output of every step are in `bench/results/openshell-evidence/`.

### What worked first time

`setup.sh` (all checksums matched, translator built), reboot, gateway start and registration (`openshell status` -> Connected, mTLS), the optional
`compute_driver = "docker"` config, the sandbox image, `host-net.sh up`, the `getent` check from a host-network container. Risks 1-3 and 6 of the list above did not occur:
the supervisor resolves the mapped names (it runs its own "policy DNS": it answers lookups for policy hosts with the real address and for every other name with a synthetic
`198.18.0.x` address, and refuses the connection later), the docker group and Landlock were fine, `nvcr.io/nvidia/base/ubuntu:24.04` pulled without authentication, and the supervisor's
L7 validator accepted the edited policy. Whether the reboot was really required was not tested (it was done as written).

### Failures and fixes

| # | what happened | cause | fix |
|---|---|---|---|
| 1 | smoke: denied requests came back as class `error`, reason `transparent_tcp_policy_denied [policy:-]` | v0.1.8 mediates TCP transparently: no proxy variables, no 403 body, curl just gets exit 7 (refused). The words OpenShell gives are spread over three log lines and use `reason:` tags the driver did not know | `deny_from_logs` now keeps every distinct reason for the host (the verbose `reason=endpoint <host>:<port> is not allowed by any policy` from the supervisor WARN line, plus the `[reason:...]` tags); `os_classify` knows `policy_dns_ineligible`, `transparent_tcp_policy_denied`, `transparent_tcp_mapping_denied` |
| 2 | first full run: probe `a13-dns-style-hostname` was "INFERRED" denied (curl exit 6, could not resolve) | the host mapping turned a 58-character label into a 70+ character one, which is not a legal DNS label: the sandbox's own resolver refused it before OpenShell saw anything | `os_map_host` truncates the label to 63 characters; `hosts.txt` and `/etc/hosts` regenerated. After the fix every denial is attributed to OpenShell's own log text (0 INFERRED, 0 UNATTRIBUTED in the final run). The verdict (denied) did not change |
| 3 | `os_policy_*.raw.yaml` (translator output, unedited) cannot start a sandbox | as predicted: `unknown tls value 'terminate'` | none needed; recorded as a result. All three raw policies are refused with the same error |

The full set was run three times (before fix 2, after fix 2, after the final driver tidy-up); the scores were identical every time.
Gateway journal: no errors; occasional `WARN concurrent modification detected during sandbox reconciliation` while sandboxes were created and deleted, harmless here.
`write_os_comparison` was also extended to add the Pipelock rows, the DLP-evasion table and a comparability section to `results/comparison-openshell.md`.

### Edit ladder (`bench/openshell/ladder.sh`, output in `results/openshell-evidence/ladder.txt`)

What each harness edit is actually needed for, observed with a one-line curl to a listed and an unlisted host:

| policy | curl to listed host | OpenShell's words |
|---|---|---|
| raw minus `tls: terminate` only (port 443, no binaries) | refused (curl 7) | `transparent TCP mapping does not authorize the requested port` [reason:transparent_tcp_mapping_denied] |
| + port rewritten to the mock's | refused (curl 7) | `binary '/usr/bin/curl' not allowed in policy 'bollard-egress' (ancestors: [], cmdline: []). SYMLINK HINT ...` [reason:transparent_tcp_policy_denied] |
| + `binaries: [/usr/bin/curl]` (no `allowed_ips`) | 200 | `NET:OPEN ALLOWED ... [policy:bollard-egress engine:opa]`, `HTTP:GET ALLOWED ... engine:l7` |

So the translator needs all three of: drop `tls: terminate`, the right port, a `binaries` list. **`allowed_ips` was not needed**: a full run with `--os-no-allowed-ips` gave scores identical to
the default (exact declared hosts may reach a private address, as `schema.mdx` says). The default still adds it; it is harmless.

### Deny reasons OpenShell gave (all denials in the run, 17 over the three policies)

- host not in the policy: `NET:REFUSE ... DENIED <host> [reason:policy_dns_ineligible]`, then a supervisor WARN `Denied staged transparent connection destination=198.18.0.N:18080 reason=endpoint <host>:18080 is not allowed by any policy`, then `NET:OPEN ... DENIED /usr/bin/curl(0) -> <host>:18080 [reason:transparent_tcp_policy_denied]`. The client sees only a refused connection (curl exit 7), for http and https alike.
- listed host, wrong port: `transparent TCP mapping does not authorize the requested port` [reason:transparent_tcp_mapping_denied] (ladder only).
- listed host, wrong binary: `binary '/usr/bin/curl' not allowed in policy 'bollard-egress' ...` (ladder only).
- No taint, DLP, content or provenance reason exists. There is no `[policy:...]` name on a denial, because no policy matched.

Allowed plain-http requests are logged with method and URL (`HTTP:POST ALLOWED POST http://<host>:18080/path [policy:bollard-egress engine:l7]`), never the body. Allowed https connections log only `NET:OPEN ALLOWED`
followed by `NET:FAIL` (the mock is not a TLS server); no L7 line is produced for them.

### Predictions versus measurement

All of "What the run should show" held: no `taint` or `dlp` denials; the allowlist blocks equal Pipelock's allowlist blocks (8 / 1 / 1; Bollard reports 7 / 1 / 1 because it attributes some allowlist-host denials to taint first, e.g. `a01` and `a13` to the unlisted attacker host); every attack to a host in the policy leaked;
every DLP-evasion payload passed, including the verbatim secret that Bollard and Pipelock block; `browse` and `open` identical. Step-by-step comparison with `bollard-proxy`: in all 3 x 41 egress steps, the only disagreements are steps Bollard denies by taint or DLP and OpenShell allows (8 / 10 / 8 per policy); there is no step OpenShell denies and Bollard allows.

### Known limits of this run

- One mock port (18080) and one binary (`curl`): port, binary and L7 method/path rules were not exercised beyond the ladder. The translator emits `protocol: rest, access: read-write` for every host (all methods) and the run did not probe the REST rules.
- An https:// step is judged by the TCP connection reaching the mock. Whether OpenShell terminated and re-originated TLS or tunnelled blind cannot be told from that test (the mock sees a ClientHello either way), so nothing here shows whether OpenShell could inspect those bodies; per its own gap report it does not do content DLP.
- A denial of a listed host (wrong port or binary) is logged against the synthetic address without the host name, so the driver would report it as `UNATTRIBUTED`. It did not occur in the corpus.
- Only the first policy is run in the `--os-raw` pass; the other two raw policies were refused with the same message when tried by hand.
