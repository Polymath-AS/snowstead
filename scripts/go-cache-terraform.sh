#!/usr/bin/env bash
# Local integration gate: actual Terraform builds against workerd and private R2.
# Run inside `nix develop` with Go >=1.24, git, curl, and a C compiler on PATH.
set -euo pipefail

ROOT="$(realpath "$(dirname "$0")/..")"
DIR="$(mktemp -d)"
ARTIFACTS="${GO_CACHE_PROOF_DIR:-$(mktemp -d)}"
mkdir -p "$ARTIFACTS"
ARTIFACTS="$(realpath "$ARTIFACTS")"
: >"$ARTIFACTS/results.log"
SERVER_PID=""
TIME=""
if [ "${GO_CACHE_BENCHMARK:-false}" = true ]; then
  TIME="$(type -P time)"
fi
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$DIR"
  echo "Proof logs retained at $ARTIFACTS"
}
trap cleanup EXIT

SOURCE="${TERRAFORM_SOURCE:-$DIR/terraform}"
COMMIT=328813676aec7a4e2a491484f91b5e0b67847b6c
if [ -z "${TERRAFORM_SOURCE:-}" ]; then
  git clone --quiet --depth 1 --branch v1.13.5 https://github.com/hashicorp/terraform.git "$SOURCE"
fi
SOURCE="$(realpath "$SOURCE")"
[ "$(git -C "$SOURCE" rev-parse HEAD)" = "$COMMIT" ] || { echo 'Expected Terraform v1.13.5' >&2; exit 1; }
[ -z "$(git -C "$SOURCE" status --porcelain)" ] || { echo 'Terraform checkout is not clean' >&2; exit 1; }

# Build this helper before enabling GOCACHEPROG; never bootstrap through itself.
HELPER="${GO_CACHE_HELPER:-$DIR/snowstead-go-cache}"
if [ -z "${GO_CACHE_HELPER:-}" ]; then
  env -u GOCACHEPROG go -C "$ROOT/apps/go-cache" build -o "$HELPER" .
fi
HELPER="$(realpath "$HELPER")"
PORT="$(node -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')"
URL="http://127.0.0.1:$PORT"
# Public local-only fixtures, not deployment credentials. A disposable R2 store
# and a fresh namespace ensure earlier runs cannot populate this gate.
node "$ROOT/node_modules/wrangler/bin/wrangler.js" dev \
  --config "$ROOT/workers/go-cache/wrangler.jsonc" --local --ip 127.0.0.1 --port "$PORT" \
  --persist-to "$DIR/worker-state" \
  --var READ_TOKEN:terraform-gate-reader --var WRITE_TOKEN:terraform-gate-writer \
  --var CACHE_NAMESPACE:terraform-gate >"$ARTIFACTS/worker.log" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 100); do
  if curl --silent --output /dev/null "$URL"; then break; fi
  kill -0 "$SERVER_PID" || { cat "$ARTIFACTS/worker.log"; exit 1; }
  sleep 0.2
done
curl --silent --output /dev/null "$URL"

export SNOWSTEAD_GO_CACHE_URL="$URL"
export CHECKPOINT_DISABLE=1
export GOMODCACHE="${GOMODCACHE:-$DIR/modules}"
# Download once so the measured builds compare compilation, not module fetching.
env -u GOCACHEPROG go -C "$SOURCE" mod download >"$ARTIFACTS/dependencies.log" 2>&1
{
  go version
  echo "terraform_commit=$COMMIT"
  echo 'flags=-trimpath -buildvcs=false'
} >"$ARTIFACTS/environment.log"

build() {
  local name="$1"
  local token="$2"
  local helper="$3"
  local scope="${6:-$name}"
  # Each run has BOTH an empty native Go cache and an empty helper cache.
  # Only the explicitly named local-repeat cases reuse a previous client.
  export GOCACHE="$DIR/$scope-go-cache"
  export SNOWSTEAD_GO_CACHE_DIR="$DIR/$scope-helper-cache"
  if [ "$scope" = "$name" ]; then
    [ ! -e "$GOCACHE" ] && [ ! -e "$SNOWSTEAD_GO_CACHE_DIR" ]
  fi
  export SNOWSTEAD_GO_CACHE_TOKEN="$token"
  export SNOWSTEAD_GO_CACHE_READ_ONLY="${4:-false}"
  export GOCACHEPROG="$helper"
  local -a measure=()
  if [ -n "$TIME" ]; then
    measure=("$TIME" -o "$ARTIFACTS/$name.build-metrics" -f 'seconds=%e maxrss_kib=%M')
    if [ -n "$helper" ]; then
      export GOCACHEPROG="$TIME -o $ARTIFACTS/$name.helper-rss-kib -f %M $helper"
    fi
  fi
  local -a flags=()
  if [ -n "${5:-}" ]; then flags=("$5"); fi
  local start=$SECONDS
  "${measure[@]}" go -C "$SOURCE" build -x -trimpath -buildvcs=false "${flags[@]}" -o "$DIR/$name-terraform" . >"$ARTIFACTS/$name.log" 2>&1
  echo "$name seconds=$((SECONDS-start))" | tee -a "$ARTIFACTS/results.log"
  "$DIR/$name-terraform" version >>"$ARTIFACTS/results.log"
  sha256sum "$DIR/$name-terraform" >>"$ARTIFACTS/results.log"
}

build baseline '' ''
build populate terraform-gate-writer "$HELPER"
# The reader credential independently enforces no writes on the server. Also
# configure the helper read-only so expected misses do not attempt uploads.
build remote terraform-gate-reader "$HELPER" true

cmp "$DIR/baseline-terraform" "$DIR/populate-terraform"
cmp "$DIR/baseline-terraform" "$DIR/remote-terraform"
grep 'snowstead-go-cache:' "$ARTIFACTS/populate.log" "$ARTIFACTS/remote.log" | tee -a "$ARTIFACTS/results.log"
grep -Eq 'remote_hits=[1-9][0-9]*' "$ARTIFACTS/remote.log"
grep -Eq 'uploads=[1-9][0-9]* upload_errors=0 conflicts=0' "$ARTIFACTS/populate.log"
BASE_COMPILES="$(grep -c '/pkg/tool/.*/compile ' "$ARTIFACTS/baseline.log" || true)"
REMOTE_COMPILES="$(grep -c '/pkg/tool/.*/compile ' "$ARTIFACTS/remote.log" || true)"
echo "compiler_invocations baseline=$BASE_COMPILES remote=$REMOTE_COMPILES" | tee -a "$ARTIFACTS/results.log"
[ "$BASE_COMPILES" -gt 0 ] && [ "$REMOTE_COMPILES" -eq 0 ]
echo 'PASS: byte-identical Terraform binaries; clean client reused remote artifacts' | tee -a "$ARTIFACTS/results.log"

# A tempting but incorrect cache keyed only by package names would reuse the
# optimized outputs here. Changing compiler inputs must force compilation.
build changed-flags terraform-gate-reader "$HELPER" true '-gcflags=all=-N'
CHANGED_COMPILES="$(grep -c '/pkg/tool/.*/compile ' "$ARTIFACTS/changed-flags.log" || true)"
[ "$CHANGED_COMPILES" -gt 0 ]
if cmp -s "$DIR/baseline-terraform" "$DIR/changed-flags-terraform"; then
  echo 'Compiler flag change reused the original binary' >&2
  exit 1
fi
grep 'snowstead-go-cache:' "$ARTIFACTS/changed-flags.log" | tee -a "$ARTIFACTS/results.log"
echo "PASS: changed compiler flags forced $CHANGED_COMPILES compiler invocations and produced a different runnable binary" | tee -a "$ARTIFACTS/results.log"

if [ -n "$TIME" ]; then
  # Three repeated samples per state. Native caches are empty for baseline and
  # remote samples; local samples reuse the first verified remote client cache.
  for i in 1 2 3; do
    build "baseline-repeat-$i" '' ''
    build "remote-repeat-$i" terraform-gate-reader "$HELPER" true
    build "local-repeat-$i" terraform-gate-reader "$HELPER" true '' remote
    for state in baseline remote local; do
      cmp "$DIR/baseline-terraform" "$DIR/$state-repeat-$i-terraform"
    done
  done
fi
