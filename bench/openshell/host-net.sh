#!/usr/bin/env bash
# bench/openshell/host-net.sh - the two root-level network changes the OpenShell driver needs, kept out of setup.sh
# on purpose so each is a named, reversible step.   STATUS: UNTESTED (written on macOS; reviewed with shellcheck).
#
#   bash bench/openshell/host-net.sh up bench/openshell/out/hosts.txt     # needs sudo
#   bash bench/openshell/host-net.sh status
#   bash bench/openshell/host-net.sh down
#
# Why: OpenShell never authorizes a loopback destination ("Network policy never authorizes an outbound endpoint whose
# destination is loopback, link-local, or unspecified", docs/how-it-works/policies/schema.mdx @ v0.1.8), so the other
# drivers' `<host>.localhost` names cannot be used. The mock upstream instead listens on a private address on a DUMMY
# interface (default 10.99.99.1/32 on bench0; the VM's real NIC and routes are not touched), and every corpus host
# name `<host-with-dashes>.bench.test` is pointed at it through a marker-delimited block in /etc/hosts.
# The supervisor resolves destinations with the host resolver (proxy.rs resolve_nonliteral_socket_addrs ->
# tokio::net::lookup_host -> getaddrinfo), so /etc/hosts is honoured. Whether the Docker driver's supervisor container
# sees this /etc/hosts (host network mode) is an UNCONFIRMED assumption: RUNBOOK step 7 tests it.
set -euo pipefail

IP="${BENCH_IP:-10.99.99.1}"
IFACE="${BENCH_IFACE:-bench0}"
BEGIN="# BEGIN bollard-bench-openshell"
END="# END bollard-bench-openshell"

log() { printf '[host-net] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

strip_block() {  # print /etc/hosts without our block
  awk -v b="$BEGIN" -v e="$END" '$0 == b {skip=1; next} $0 == e {skip=0; next} !skip {print}' /etc/hosts
}

drop_block() {
  if grep -qxF "$BEGIN" /etc/hosts; then
    strip_block | sudo tee /etc/hosts.bench.new >/dev/null
    sudo install -m 0644 /etc/hosts.bench.new /etc/hosts
    sudo rm -f /etc/hosts.bench.new
    log "removed our block from /etc/hosts"
  fi
}

cmd="${1:-}"
case "$cmd" in
  up)
    hosts_file="${2:-}"
    [ -n "$hosts_file" ] && [ -r "$hosts_file" ] || die "usage: $0 up <hosts-file>   (python3 -I bench/run_bench.py --driver openshell --os-print-hosts > FILE)"
    grep -qE '^[0-9.]+ [a-z0-9.-]+\.bench\.test$' "$hosts_file" || die "$hosts_file does not look like --os-print-hosts output"
    if ! ip -br addr show dev "$IFACE" >/dev/null 2>&1; then
      sudo ip link add "$IFACE" type dummy
      log "created dummy interface $IFACE"
    fi
    if ! ip -br addr show dev "$IFACE" | grep -q "$IP/"; then
      sudo ip addr add "$IP/32" dev "$IFACE"
    fi
    sudo ip link set "$IFACE" up
    drop_block
    { echo "$BEGIN"; cat "$hosts_file"; echo "$END"; } | sudo tee -a /etc/hosts >/dev/null
    log "added $(wc -l < "$hosts_file") names -> $IP in /etc/hosts"
    ;;
  down)
    drop_block
    if ip -br addr show dev "$IFACE" >/dev/null 2>&1; then
      sudo ip link del "$IFACE"
      log "deleted $IFACE"
    fi
    ;;
  status)
    ip -br addr show dev "$IFACE" 2>&1 || true
    grep -cF "bench.test" /etc/hosts || true
    getent hosts pypi-org.bench.test || log "pypi-org.bench.test does not resolve"
    ;;
  *)
    die "usage: $0 up <hosts-file> | down | status"
    ;;
esac
