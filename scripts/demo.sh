#!/usr/bin/env bash
# Provenance-gated egress, end to end. A real MCP-client agent reads a private
# file, ingests an injected page, obeys it, and tries to exfiltrate a secret —
# and is blocked at the boundary, along with a request that was fine moments
# earlier, while a trusted sink keeps working.
set -euo pipefail
cd "$(dirname "$0")/../deploy"

echo "==> Building and starting the cage (broker + mcp + proxy + agent)..."
docker compose up -d --build >/dev/null
sleep 1

echo
echo "======================= agent (MCP client) ======================="
docker compose exec -T agent python3 /agent/agent.py || true
echo "=================================================================="

echo
echo "==> broker (taint + decisions):"
docker compose logs bollard-broker 2>/dev/null | grep -E '\[broker\] (decide|taint|route|secret|inspect)' || true

echo
echo "==> boundary (enforcement):"
docker compose logs bollard-proxy 2>/dev/null | grep -E '\[bollard\] (ALLOW|DENY)' || true

echo
echo "==> tearing down"
docker compose down >/dev/null 2>&1 || true
