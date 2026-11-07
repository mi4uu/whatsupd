#!/usr/bin/env bash
# Smoke test of the container image: starts it without a WhatsApp account and
# checks what works before pairing. Usage: scripts/docker-test.sh IMAGE
set -euo pipefail
IMG=$1
N=whatsupd-smoke
PORT=18765
OUT=$(mktemp -d)
cleanup() {
  docker rm -f "$N" >/dev/null 2>&1 || true
  docker volume rm "$N-data" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; docker logs "$N" 2>&1 | tail -20 >&2; exit 1; }

mkdir -p "$OUT/files"
echo hello > "$OUT/files/note.txt"
chmod -R a+rX "$OUT"
docker run -d --name "$N" -p "127.0.0.1:$PORT:8765" -v "$N-data:/data" -v "$OUT/files:/files:ro" \
  -e WHATSUPD_MCP_ALLOW_SEND=true -e WHATSUPD_MCP_SEND_TO=+48600000101 -e WHATSUPD_MCP_SEND_FILES_FROM=/files \
  "$IMG" >/dev/null

for _ in $(seq 30); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break
  sleep 1
done
docker logs "$N" 2>&1 | grep -q 'whatsupd started' || fail "daemon did not start"
[ "$(docker inspect -f '{{.Config.User}}' "$N")" = "65532:65532" ] || fail "image must not run as root"

TOK=$(docker exec "$N" whatsupd token --mcp)
U=http://127.0.0.1:$PORT/mcp
H=(-H "Authorization: Bearer $TOK" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Content-Type: application/json" "$U" -d '{}')
[ "$code" = 401 ] || fail "/mcp without a token: want 401, got $code"

curl -s -D "$OUT/h" -o /dev/null "${H[@]}" "$U" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ci","version":"1"}}}'
head -1 "$OUT/h" | grep -q ' 200' || fail "initialize: $(head -1 "$OUT/h")"
SID=$(grep -i '^mcp-session-id' "$OUT/h" | cut -d' ' -f2 | tr -d '\r')
S=(-H "Mcp-Session-Id: $SID")
curl -s -o /dev/null "${H[@]}" "${S[@]}" "$U" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

tools=$(curl -s "${H[@]}" "${S[@]}" "$U" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
grep -q '"name":"send_file"' <<<"$tools" || fail "send_file missing: WHATSUPD_MCP_ALLOW_SEND was ignored"

call() {
  curl -s "${H[@]}" "${S[@]}" "$U" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_file","arguments":{"chat":"+48600000101","path":"'"$1"'"}}}'
}
grep -q 'not connected' <<<"$(call /files/note.txt)" || fail "a file in /files should pass the path check"
grep -q 'outside /files' <<<"$(call /etc/ssl/certs/ca-certificates.crt)" || fail "a path outside /files must be refused"

docker restart "$N" >/dev/null
sleep 3
[ "$(docker exec "$N" whatsupd token --mcp)" = "$TOK" ] || fail "the token changed after a restart: /data is not kept"
echo "docker image OK: $(docker exec "$N" whatsupd version)"
