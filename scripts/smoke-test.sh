#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${CORTASENTRY_BIN:-$ROOT/bin/cortasentry}"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup(){ if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi; rm -rf "$WORK"; }
trap cleanup EXIT
cp -R "$ROOT/rules" "$WORK/rules"
cd "$WORK"
"$BIN" init > init.out
test -s data/admin.token
test "$(stat -c '%a' data/admin.token 2>/dev/null || stat -f '%Lp' data/admin.token)" = 600
"$BIN" demo > demo.out
grep -q 'state 2 changing' demo.out
grep -q 'changes=1' demo.out
"$BIN" assets list > assets.json
grep -q 'Samsung' assets.json
grep -q 'Hikvision' assets.json
"$BIN" observations list > observations.json
grep -q 'http_connect\|tcp_connect\|"Source":"http"' observations.json
if "$BIN" scan --cidr 8.8.8.8/32 --ports 80 > outside.out 2>&1; then echo "out-of-scope scan unexpectedly succeeded" >&2; exit 1; fi
CORTASENTRY_BIND=127.0.0.1:18088 "$BIN" serve > server.log 2>&1 & SERVER_PID=$!
for _ in $(seq 1 50); do curl -fsS http://127.0.0.1:18088/readyz >/dev/null && break; sleep .1; done
test "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18088/api/v1/assets)" = 401
TOKEN="$(tr -d '\n' < data/admin.token)"
curl -fsS -c cookies.txt -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}" http://127.0.0.1:18088/api/v1/auth/login > login.json
curl -fsS -b cookies.txt http://127.0.0.1:18088/api/v1/assets > api-assets.json
grep -q 'Samsung' api-assets.json
curl -fsS -b cookies.txt http://127.0.0.1:18088/api/v1/changes > changes.json
grep -q 'http_title_changed' changes.json
curl -fsS -b cookies.txt http://127.0.0.1:18088/api/v1/audit > audit.json
grep -q 'scope.decision' audit.json
grep -q 'denied' audit.json
kill "$SERVER_PID"; wait "$SERVER_PID" || true; SERVER_PID=""
"$BIN" assets list > reopened-assets.json
grep -q 'Samsung' reopened-assets.json
echo "CortaSentry smoke test passed: init, fixture scans, stable assets, changes, auth API, scope denial, and reopen persistence."
