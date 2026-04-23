#!/usr/bin/env bash
set -euo pipefail

# Push Nix store paths to an Odin binary cache.
#
# Usage:
#   ./scripts/push-paths.sh <base-url> <auth-token> <cache-name> <store-path>...
#
# Examples:
#   # Push a single path
#   ./scripts/push-paths.sh https://odin-cache.polymath-as.workers.dev "$TOKEN" main /nix/store/abc...-hello
#
#   # Push a NixOS system closure
#   ./scripts/push-paths.sh https://odin-cache.polymath-as.workers.dev "$TOKEN" main \
#     $(nix path-info -r /run/current-system)
#
#   # Push a flake output closure
#   ./scripts/push-paths.sh https://odin-cache.polymath-as.workers.dev "$TOKEN" main \
#     $(nix path-info -r .#nixosConfigurations.myhost.config.system.build.toplevel)
#
# Requirements: curl, nix, zstd, sha256sum

BASE="${1:?usage: push-paths.sh <base-url> <auth-token> <cache-name> <paths...>}"
TOKEN="${2:?usage: push-paths.sh <base-url> <auth-token> <cache-name> <paths...>}"
CACHE="${3:?usage: push-paths.sh <base-url> <auth-token> <cache-name> <paths...>}"
shift 3

BASE="${BASE%/}"
PATHS=("$@")

if [ ${#PATHS[@]} -eq 0 ]; then
  echo "error: no store paths given" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PUSHED=0
SKIPPED=0
FAILED=0
TOTAL=${#PATHS[@]}

# Step 1: Ask the server which paths are already published
echo "Checking $TOTAL paths against cache '$CACHE'..."

# Extract store path hashes (the 32-char component after /nix/store/)
declare -A HASH_TO_PATH
HASHES=()
for p in "${PATHS[@]}"; do
  basename="$(basename "$p")"
  hash="${basename%%-*}"
  HASHES+=("\"$hash\"")
  HASH_TO_PATH["$hash"]="$p"
done

# Batch check in chunks of 100
MISSING_HASHES=()
for ((i=0; i<${#HASHES[@]}; i+=100)); do
  chunk=("${HASHES[@]:i:100}")
  joined=$(IFS=,; echo "${chunk[*]}")
  resp=$(curl -s -X POST "$BASE/_api/v1/get-missing-paths" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"cache\": \"$CACHE\", \"storePathHashes\": [$joined]}")

  # Parse missing array from JSON response
  while IFS= read -r h; do
    MISSING_HASHES+=("$h")
  done < <(echo "$resp" | grep -o '"[^"]*"' | grep -v '"missing"' | tr -d '"')
done

SKIPPED=$((TOTAL - ${#MISSING_HASHES[@]}))
echo "  $SKIPPED already cached, ${#MISSING_HASHES[@]} to push"

if [ ${#MISSING_HASHES[@]} -eq 0 ]; then
  echo "Nothing to push."
  exit 0
fi

# Step 2: Push each missing path
for hash in "${MISSING_HASHES[@]}"; do
  store_path="${HASH_TO_PATH[$hash]}"
  name="$(basename "$store_path")"
  echo ""
  echo "[$((PUSHED + FAILED + 1))/${#MISSING_HASHES[@]}] $name"

  # Get path metadata from nix
  info=$(nix path-info --json "$store_path" 2>/dev/null)
  nar_hash=$(echo "$info" | grep -o '"narHash":"[^"]*"' | cut -d'"' -f4)
  nar_size=$(echo "$info" | grep -o '"narSize":[0-9]*' | cut -d: -f2)

  # Extract references (just the hash part, strip "references": key)
  refs_raw=$(echo "$info" | grep -o '"references":\[[^]]*\]' | head -1 | sed 's/"references"://')
  if [ -z "$refs_raw" ] || [ "$refs_raw" = "[]" ]; then
    refs_arr="[]"
  else
    # Convert full paths to just the 32-char hash prefix
    refs_arr=$(echo "$refs_raw" | sed 's|/nix/store/||g' | sed 's|-[^"]*||g')
  fi

  # Dump NAR and compress with zstd
  nar_file="$TMPDIR/nar.zst"
  nix store dump-path "$store_path" 2>/dev/null | zstd -q -o "$nar_file"

  # Compute file hash and size
  file_hash=$(sha256sum "$nar_file" | cut -d' ' -f1)
  file_size=$(stat -c%s "$nar_file")

  # Create upload session
  session_resp=$(curl -s -o "$TMPDIR/session.json" -w "%{http_code}" \
    -X POST "$BASE/_api/v1/caches/$CACHE/upload-sessions" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"storePath\": \"$store_path\",
      \"storePathHash\": \"$hash\",
      \"narHash\": \"$nar_hash\",
      \"narSize\": $nar_size,
      \"fileHash\": \"$file_hash\",
      \"fileSize\": $file_size,
      \"compression\": \"zstd\",
      \"references\": $refs_arr
    }")

  if [ "$session_resp" != "201" ]; then
    echo "  FAIL: create session returned $session_resp: $(cat "$TMPDIR/session.json")"
    FAILED=$((FAILED + 1))
    rm -f "$nar_file"
    continue
  fi

  session_id=$(grep -o '"sessionId":"[^"]*"' "$TMPDIR/session.json" | cut -d'"' -f4)
  r2_key=$(grep -o '"r2Key":"[^"]*"' "$TMPDIR/session.json" | cut -d'"' -f4)

  # Upload blob through the API
  upload_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "$BASE/_api/v1/uploads/$session_id/blob" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$nar_file")

  rm -f "$nar_file"

  if [ "$upload_status" != "200" ]; then
    echo "  FAIL: blob upload returned $upload_status"
    FAILED=$((FAILED + 1))
    continue
  fi

  # Complete
  complete_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE/_api/v1/uploads/$session_id/complete" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}')

  if [ "$complete_status" != "200" ]; then
    echo "  FAIL: complete returned $complete_status"
    FAILED=$((FAILED + 1))
    continue
  fi

  # Publish
  publish_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE/_api/v1/uploads/$session_id/publish" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}')

  if [ "$publish_status" != "200" ]; then
    echo "  FAIL: publish returned $publish_status"
    FAILED=$((FAILED + 1))
    continue
  fi

  size_kb=$((file_size / 1024))
  echo "  ok (${size_kb}KB compressed)"
  PUSHED=$((PUSHED + 1))
done

echo ""
echo "=== Done: $PUSHED pushed, $SKIPPED skipped, $FAILED failed ==="
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
