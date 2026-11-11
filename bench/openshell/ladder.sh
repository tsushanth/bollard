#!/usr/bin/env bash
# bench/openshell/ladder.sh - which of the harness's edits to the translator's output does OpenShell v0.1.8 actually need?
#
# Run on the VM after RUNBOOK steps 4-6 (gateway up, bench-curl image built, host-net.sh up), as the user that owns the gateway:
#   bash bench/openshell/ladder.sh
# It needs `bench/openshell/out/os_policy_strict.raw.yaml`, which `run_bench.py --driver openshell --os-raw` writes.
# It starts its own tiny mock upstream on 10.99.99.1:18080 and creates/deletes three sandboxes (lad-r1..r3).
#   r1 = raw translation with only `tls: terminate` removed (still port 443, no binaries)
#   r2 = r1 with the port rewritten to the mock's port
#   r3 = r2 with `binaries: [/usr/bin/curl]` added (no allowed_ips: the private address is not allow-listed here)
# For each it curls one listed host and one unlisted host and prints OpenShell's own deny lines.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/out"
RAW="$OUT/os_policy_strict.raw.yaml"
[ -r "$RAW" ] || { echo "missing $RAW: run the driver with --os-raw first" >&2; exit 1; }
mkdir -p "$OUT/ladder" && cd "$OUT/ladder" || exit 1
python3 -I - <<'EOF' &
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
ThreadingHTTPServer(("10.99.99.1", 18080), H).serve_forever()
EOF
MOCK=$!
sleep 1
grep -v 'tls: terminate' "$RAW" > r1.yaml
sed 's/port: 443/port: 18080/' r1.yaml > r2.yaml
{ cat r2.yaml; echo "    binaries:"; echo "      - path: /usr/bin/curl"; } > r3.yaml
for v in r1 r2 r3; do
  echo "=== $v"
  openshell sandbox delete "lad-$v" >/dev/null 2>&1
  openshell sandbox create --name "lad-$v" --from bench-curl:local --policy "$v.yaml" --no-auto-providers --no-tty --detach -- sleep 3600 2>&1 | tail -5
  for u in http://pypi-org.bench.test:18080/ http://randomblog-example-net.bench.test:18080/; do
    echo "--- curl $u"
    openshell sandbox exec -n "lad-$v" --no-login-shell --no-tty --timeout 20 -- curl -sS -m 10 -i "$u" 2>&1 | head -8
  done
  sleep 3
  echo "--- sandbox NET/HTTP/WARN lines"
  openshell logs "lad-$v" --source sandbox -n 300 2>&1 | grep -E "NET:|HTTP:|Denied|WARN|reject|policy" | grep -v "SSH:" | cut -c1-420
  openshell sandbox delete "lad-$v" >/dev/null 2>&1
done
kill "$MOCK"
