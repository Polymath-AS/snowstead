#!/usr/bin/env bash
# Load test for a deployed (or `wrangler dev`) cache worker.
#
# Usage:
#   TOKEN=... PUBLIC_KEY=helios-cache-1:... ./scripts/load-test.sh <base-url> <cache> <store-path>
#
# <store-path> must already be pushed to <cache> with its closure. TOKEN is
# a push token (for get-missing-paths); PUBLIC_KEY is the cache's signing
# key, for substituting with signatures required. DURATION (default 10s)
# and CONCURRENCY (default 32) tune the runs.
set -euo pipefail

BASE="${1:?usage: load-test.sh <base-url> <cache> <store-path>}"
CACHE="${2:?usage: load-test.sh <base-url> <cache> <store-path>}"
TARGET="${3:?usage: load-test.sh <base-url> <cache> <store-path>}"
: "${TOKEN:?set TOKEN to a push token for the cache}"
: "${PUBLIC_KEY:?set PUBLIC_KEY to the cache signing key}"
BASE="${BASE%/}"
DURATION="${DURATION:-10s}"
CONCURRENCY="${CONCURRENCY:-32}"

for tool in oha jq nix; do
  command -v "$tool" >/dev/null || { echo "$tool not found: run inside 'nix develop'" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

HASH="$(basename "$TARGET" | cut -c1-32)"
NAR="$(curl -sf "$BASE/$CACHE/$HASH.narinfo" | sed -n 's/^URL: //p')"
[ -n "$NAR" ] || { echo "$TARGET is not in $CACHE" >&2; exit 1; }
# Resolve the URL against the cache's, as Nix does: public caches point at ../nar/.
case "$NAR" in
  ../*) NAR_URL="$BASE/${NAR#../}" ;;
  *) NAR_URL="$BASE/$CACHE/$NAR" ;;
esac

# A full get-missing-paths batch: the closure plus random hashes.
{
  nix path-info -r "$TARGET" | xargs -n1 basename | cut -c1-32
  head -c 20000 /dev/urandom | od -An -vtx1 | tr -d ' \n' | fold -w32 | head -n $((1000 - $(nix path-info -r "$TARGET" | wc -l)))
} | jq -R . | jq -sc --arg cache "$CACHE" '{cache: $cache, storePathHashes: .}' > "$WORK/missing.json"

# oha's random URLs mangle escaped dots; [.] stays a literal dot.
HOST_RE="$(printf '%s' "$BASE" | sed 's/\./[.]/g')"

run() {
  local name=$1 conc=$2; shift 2
  oha -z "$DURATION" -c "$conc" --no-tui --output-format json "$@" > "$WORK/$name.json"
  jq -r --arg n "$name" '"\($n)\t\(.summary.requestsPerSec|floor)\t\(.latencyPercentiles.p50*1e4|floor/10)\t\(.latencyPercentiles.p99*1e4|floor/10)\t\(.statusCodeDistribution|tostring)"' "$WORK/$name.json"
}

echo "Load test against $BASE ($CACHE), $DURATION per scenario"
printf 'scenario\treq/s\tp50 ms\tp99 ms\tstatus\n'
run info "$CONCURRENCY" "$BASE/$CACHE/nix-cache-info"
run narinfo-hit "$CONCURRENCY" "$BASE/$CACHE/$HASH.narinfo"
run narinfo-miss "$CONCURRENCY" --rand-regex-url "$HOST_RE/$CACHE/[0-9a-df-np-sv-z]{32}[.]narinfo"
run missing-paths "$CONCURRENCY" -m POST -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -D "$WORK/missing.json" "$BASE/_api/v1/get-missing-paths"
run nar 4 "$NAR_URL"

echo
PATHS="$(nix path-info -r "$TARGET" | wc -l)"
start=$(date +%s%N)
NIX_CONFIG="trusted-public-keys = $PUBLIC_KEY
require-sigs = true
narinfo-cache-negative-ttl = 0
narinfo-cache-positive-ttl = 0" XDG_CACHE_HOME="$WORK/xdg" nix copy --from "$BASE/$CACHE" --to "$WORK/store" "$TARGET" 2>&1 | tail -3
end=$(date +%s%N)
echo "nix copy --from ($PATHS paths, signatures required): $(( (end - start) / 1000000 )) ms"
