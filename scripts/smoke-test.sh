#!/usr/bin/env bash
set -euo pipefail

# Usage: ADMIN_SECRET=... scripts/smoke-test.sh <base-url> <push-token>
# Requires curl, jq, sha256sum, zstd, nix-store, and nix-hash.
# Creates a disposable cache on the target; fixture generation never writes to the Nix store.
BASE="${1:?usage: smoke-test.sh <base-url> <auth-token>}"
TOKEN="${2:?usage: smoke-test.sh <base-url> <auth-token>}"
: "${ADMIN_SECRET:?set ADMIN_SECRET to create the test cache}"
BASE="${BASE%/}"
for tool in curl jq sha256sum zstd nix-store nix-hash; do command -v "$tool" >/dev/null; done
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  ok: $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc (expected=$expected got=$actual)"
    FAIL=$((FAIL + 1))
  fi
}
post() {
  curl -fsS -X POST "$BASE/_api/v1$1" -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' --data-binary "$2"
}

echo "=== Smoke test against $BASE ==="
STATUS=$(curl -sS -o "$TMP/health" -w '%{http_code}' "$BASE/healthz")
check 'health returns 200' 200 "$STATUS"
check 'health has ok=true' true "$(jq -r .ok "$TMP/health")"

CACHE_NAME="smoke-$(date +%s)"
STATUS=$(curl -sS -o "$TMP/cache" -w '%{http_code}' -X POST "$BASE/_api/v1/admin/caches" \
  -H "authorization: Bearer $ADMIN_SECRET" -H 'content-type: application/json' \
  -d "{\"name\":\"$CACHE_NAME\",\"protocols\":[\"nix\"]}")
check "creates cache $CACHE_NAME" 201 "$STATUS"
STATUS=$(curl -sS -o "$TMP/info" -w '%{http_code}' "$BASE/$CACHE_NAME/nix-cache-info")
check 'cache info returns 200' 200 "$STATUS"
check 'contains StoreDir' 'StoreDir: /nix/store' "$(head -1 "$TMP/info")"

STORE_PATH_HASH=00000000000000000000000000000000
printf %s nix-archive-smoke-test-payload1234 > "$TMP/payload"
nix-store --dump "$TMP/payload" > "$TMP/payload.nar"
NAR_HASH="sha256:$(nix-hash --type sha256 --base32 --flat "$TMP/payload.nar")"
NAR_SIZE=$(wc -c < "$TMP/payload.nar")
zstd -q -c "$TMP/payload.nar" > "$TMP/payload.zst"
FILE_SIZE=$(wc -c < "$TMP/payload.zst")
FILE_HASH=$(sha256sum "$TMP/payload.zst" | cut -d' ' -f1)
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/$CACHE_NAME/$STORE_PATH_HASH.narinfo")
check 'missing narinfo returns 404' 404 "$STATUS"

echo 'Creating, reserving, uploading, and finalizing a stream'
PAYLOAD=$(jq -nc --arg hash "$STORE_PATH_HASH" --arg nar "$NAR_HASH" --argjson size "$NAR_SIZE" \
  '{paths:[{storePath:("/nix/store/"+$hash+"-smoke-test"),storePathHash:$hash,narHash:$nar,narSize:$size,compression:"zstd"}]}')
STATUS=$(curl -sS -o "$TMP/session" -w '%{http_code}' -X POST "$BASE/_api/v1/caches/$CACHE_NAME/upload-streams/batch" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' --data-binary "$PAYLOAD")
check 'stream created' 201 "$STATUS"
SESSION_ID=$(jq -er '.sessions[0].sessionId' "$TMP/session")
check 'stream uses s2 ID' s2 "${SESSION_ID%%.*}"
GRANTS=$(post "/uploads/$SESSION_ID/parts" "{\"parts\":[{\"partNumber\":1,\"size\":$FILE_SIZE}]}")
PART_URL=$(jq -er '.parts[0].url' <<<"$GRANTS")
HEADERS=()
while IFS= read -r header; do HEADERS+=(-H "$header"); done < <(jq -r '.parts[0].headers | to_entries[] | .key+": "+.value' <<<"$GRANTS")
STATUS=$(curl -sS -o "$TMP/part" -D "$TMP/headers" -w '%{http_code}' -X PUT "$PART_URL" \
  "${HEADERS[@]}" --data-binary "@$TMP/payload.zst")
check 'part PUT returns 200' 200 "$STATUS"
ETAG=$(awk 'tolower($1)=="etag:" {gsub(/["\r]/,"",$2); print $2}' "$TMP/headers")
check 'part PUT returns an ETag' yes "$(if [ -n "$ETAG" ]; then echo yes; else echo no; fi)"
FINALIZE=$(jq -nc --arg id "$SESSION_ID" --arg nar "$NAR_HASH" --arg hash "$FILE_HASH" --arg etag "$ETAG" --argjson size "$FILE_SIZE" --argjson narSize "$NAR_SIZE" \
  '{uploads:[{sessionId:$id,narHash:$nar,narSize:$narSize,fileHash:$hash,fileSize:$size,parts:[{partNumber:1,etag:$etag}]}]}')
RESULT=$(post /uploads/finalize "$FINALIZE")
check 'finalize publishes the path' true "$(jq -r '.results[0].published' <<<"$RESULT")"

STATUS=$(curl -sS -o "$TMP/narinfo" -w '%{http_code}' "$BASE/$CACHE_NAME/$STORE_PATH_HASH.narinfo")
check 'narinfo returns 200 after a cached miss' 200 "$STATUS"
check 'narinfo contains StorePath' "/nix/store/$STORE_PATH_HASH-smoke-test" "$(sed -n 's/^StorePath: //p' "$TMP/narinfo")"
check 'narinfo contains NarHash' "$NAR_HASH" "$(sed -n 's/^NarHash: //p' "$TMP/narinfo")"
STATUS=$(curl -sS -o "$TMP/nar" -w '%{http_code}' "$BASE/$CACHE_NAME/nar/$FILE_HASH/zstd.nar")
check 'NAR download returns 200' 200 "$STATUS"
check 'NAR bytes match upload' "$FILE_HASH" "$(sha256sum "$TMP/nar" | cut -d' ' -f1)"
zstd -q -d -c "$TMP/nar" > "$TMP/download.nar"
check 'downloaded NAR hash matches metadata' "$NAR_HASH" "sha256:$(nix-hash --type sha256 --base32 --flat "$TMP/download.nar")"
RESULT=$(post /uploads/finalize "$FINALIZE")
check 'finalize replay is idempotent' true "$(jq -r '.results[0].alreadyExisted' <<<"$RESULT")"

echo 'Auth enforcement'
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/_api/v1/caches/$CACHE_NAME/upload-streams/batch" \
  -H 'content-type: application/json' -d '{}')
check 'write without auth returns 401' 401 "$STATUS"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/_api/v1/caches/$CACHE_NAME/upload-streams/batch" \
  -H 'authorization: Bearer wrong-token' -H 'content-type: application/json' -d '{}')
check 'bad token is refused' refused "$(case "$STATUS" in 401|403) echo refused ;; *) echo "$STATUS" ;; esac)"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/$CACHE_NAME/nix-cache-info")
check 'public read needs no auth' 200 "$STATUS"
MISSING=$(post /get-missing-paths "{\"cache\":\"$CACHE_NAME\",\"storePathHashes\":[\"$STORE_PATH_HASH\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}")
check 'only unknown path is missing' '["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]' "$(jq -c .missing <<<"$MISSING")"
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
