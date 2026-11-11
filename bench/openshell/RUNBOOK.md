# OpenShell run: runbook for a fresh Ubuntu 24.04 VM

Goal: drive the same 36-trace corpus through a real NVIDIA OpenShell sandbox and compare it with
`bollard-proxy` and Pipelock (`python3 -I bench/run_bench.py --driver openshell`).

**Status of everything below: written on macOS, never executed against OpenShell.** What was and was not
tested is in [Test status](#test-status). Every OpenShell command is traceable to a source in
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
