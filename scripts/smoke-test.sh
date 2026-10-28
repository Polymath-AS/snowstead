#!/usr/bin/env bash
set -euo pipefail

# Smoke test for the Snowstead Nix binary cache worker.
#
# Usage:
#   ADMIN_SECRET=... ./scripts/smoke-test.sh <base-url> <auth-token>
#
# ADMIN_SECRET creates the test cache through the admin API.
#
# Example:
#   ADMIN_SECRET=... ./scripts/smoke-test.sh https://snowstead.your-subdomain.workers.dev "your-token"

BASE="${1:?usage: smoke-test.sh <base-url> <auth-token>}"
TOKEN="${2:?usage: smoke-test.sh <base-url> <auth-token>}"
: "${ADMIN_SECRET:?set ADMIN_SECRET to create the test cache}"

# Strip trailing slash
BASE="${BASE%/}"

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

echo "=== Smoke test against $BASE ==="
echo

echo "1. Health check"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/healthz")
check "/healthz returns 200" "200" "$STATUS"

BODY=$(curl -s "$BASE/healthz")
check "/healthz has ok=true" "true" "$(echo "$BODY" | grep -o '"ok" *: *true' | head -1 | grep -o 'true')"
echo

echo "2. Creating a test cache"
CACHE_NAME="smoke-$(date +%s)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "authorization: Bearer $ADMIN_SECRET" -H "content-type: application/json" \
  -d "{\"name\":\"$CACHE_NAME\",\"protocols\":[\"nix\"]}" "$BASE/_api/v1/admin/caches")
check "admin creates cache $CACHE_NAME" "201" "$STATUS"
echo

echo "3. nix-cache-info"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$CACHE_NAME/nix-cache-info")
check "returns 200" "200" "$STATUS"

BODY=$(curl -s "$BASE/$CACHE_NAME/nix-cache-info")
check "contains StoreDir" "StoreDir: /nix/store" "$(echo "$BODY" | head -1)"
echo

echo "4. Missing narinfo returns 404"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$CACHE_NAME/00000000000000000000000000000000.narinfo")
check "returns 404" "404" "$STATUS"
echo

echo "5. Upload, complete, publish, read"

FILE_HASH="$(head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n')"
STORE_PATH_HASH="00000000000000000000000000000000"
NAR_HASH="sha256:1111111111111111111111111111111111111111111111111111"
NAR_CONTENT="nix-archive-smoke-test-payload1234"
FILE_SIZE=${#NAR_CONTENT}

# 5a. Create upload session
echo "  5a. Creating upload session"
SESSION_STATUS=$(curl -s -o /tmp/smoke-session.json -w "%{http_code}" -X POST "$BASE/_api/v1/caches/$CACHE_NAME/upload-sessions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"storePath\": \"/nix/store/${STORE_PATH_HASH}-smoke-test\",
    \"storePathHash\": \"$STORE_PATH_HASH\",
    \"narHash\": \"$NAR_HASH\",
    \"narSize\": 2048,
    \"fileHash\": \"$FILE_HASH\",
    \"fileSize\": $FILE_SIZE,
    \"compression\": \"none\"
  }")

SESSION_RESP=$(cat /tmp/smoke-session.json)
rm -f /tmp/smoke-session.json
SESSION_ID=$(echo "$SESSION_RESP" | grep -o '"sessionId":"[^"]*"' | cut -d'"' -f4)
R2_KEY=$(echo "$SESSION_RESP" | grep -o '"r2Key":"[^"]*"' | cut -d'"' -f4)

if [ -z "$SESSION_ID" ]; then
  echo "  FAIL: could not create session (status=$SESSION_STATUS): $SESSION_RESP"
  FAIL=$((FAIL + 1))
else
  check "session created (201)" "201" "$SESSION_STATUS"
  echo "  session=$SESSION_ID r2Key=$R2_KEY"

  # 5b. Upload blob via API
  echo "  5b. Uploading blob via API"
  UPLOAD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "$BASE/_api/v1/uploads/$SESSION_ID/blob" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "$NAR_CONTENT")
  check "blob upload returns 200" "200" "$UPLOAD_STATUS"

  # 5c. Complete
  echo "  5c. Completing upload"
  COMPLETE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "$BASE/_api/v1/uploads/$SESSION_ID/complete" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}')
  check "complete returns 200" "200" "$COMPLETE_STATUS"

  # 5d. Publish
  echo "  5d. Publishing path"
  PUBLISH_RESP=$(curl -s -X POST "$BASE/_api/v1/uploads/$SESSION_ID/publish" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}')
  PUBLISH_STATUS=$(echo "$PUBLISH_RESP" | grep -o '"published":true' | head -1)
  check "publish returns published=true" '"published":true' "$PUBLISH_STATUS"

  # 5e. Read narinfo
  echo "  5e. Reading narinfo"
  NARINFO_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$CACHE_NAME/$STORE_PATH_HASH.narinfo")
  check "narinfo returns 200" "200" "$NARINFO_STATUS"

  NARINFO=$(curl -s "$BASE/$CACHE_NAME/$STORE_PATH_HASH.narinfo")
  check "narinfo contains StorePath" "/nix/store/${STORE_PATH_HASH}-smoke-test" \
    "$(echo "$NARINFO" | grep '^StorePath:' | cut -d' ' -f2)"
  check "narinfo contains NarHash" "$NAR_HASH" \
    "$(echo "$NARINFO" | grep '^NarHash:' | cut -d' ' -f2)"

  # 5f. Read NAR blob
  echo "  5f. Reading NAR blob"
  NAR_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$CACHE_NAME/nar/$FILE_HASH/none.nar")
  check "NAR download returns 200" "200" "$NAR_STATUS"

  NAR_BODY=$(curl -s "$BASE/$CACHE_NAME/nar/$FILE_HASH/none.nar")
  check "NAR body matches uploaded content" "$NAR_CONTENT" "$NAR_BODY"

  # 5g. Idempotent publish
  echo "  5g. Duplicate publish is idempotent"
  REPUB=$(curl -s -X POST "$BASE/_api/v1/uploads/$SESSION_ID/publish" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}')
  check "re-publish has alreadyExisted" '"alreadyExisted":true' \
    "$(echo "$REPUB" | grep -o '"alreadyExisted":true' | head -1)"
fi
echo

echo "6. Auth enforcement"
UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$BASE/_api/v1/caches/$CACHE_NAME/upload-sessions" \
  -H "Content-Type: application/json" \
  -d '{}')
check "write without auth returns 401" "401" "$UNAUTH"

BAD_AUTH=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$BASE/_api/v1/caches/$CACHE_NAME/upload-sessions" \
  -H "Authorization: Bearer wrong-token" \
  -H "Content-Type: application/json" \
  -d '{}')
# 401 with JWT auth (the token is invalid), 403 with only the legacy token.
check "write with bad token is refused" "refused" "$(case "$BAD_AUTH" in 401|403) echo refused ;; *) echo "$BAD_AUTH" ;; esac)"

PUBLIC_READ=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$CACHE_NAME/nix-cache-info")
check "read without auth returns 200" "200" "$PUBLIC_READ"
echo

echo "7. get-missing-paths"
MISSING_RESP=$(curl -s -X POST "$BASE/_api/v1/get-missing-paths" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"cache\": \"$CACHE_NAME\", \"storePathHashes\": [\"$STORE_PATH_HASH\", \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}")
check "published hash not in missing" "" \
  "$(echo "$MISSING_RESP" | grep -o "\"$STORE_PATH_HASH\"" | head -1)"
check "unknown hash is in missing" '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  "$(echo "$MISSING_RESP" | grep -o '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' | head -1)"
echo

echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
