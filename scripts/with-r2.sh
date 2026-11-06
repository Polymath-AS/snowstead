#!/usr/bin/env bash
# Run real-client tests against disposable, private S3-compatible buckets.
# Never uses an inherited R2 endpoint or production credentials.
set -euo pipefail

for tool in minio mc node; do
  command -v "$tool" >/dev/null || { echo "$tool not found: run inside 'nix develop'" >&2; exit 1; }
done

DIR="$(mktemp -d)"
PID=""
cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$DIR"
}
trap cleanup EXIT

PORT="$(node -e 'const s = require("net").createServer().listen(0, "127.0.0.1", () => { console.log(s.address().port); s.close(); })')"
export R2_ENDPOINT="http://127.0.0.1:$PORT"
export R2_ACCESS_KEY_ID="snowstead-test"
export R2_SECRET_ACCESS_KEY
R2_SECRET_ACCESS_KEY="$(node -e 'console.log(require("node:crypto").randomBytes(32).toString("hex"))')"
export R2_BUCKET_NAME="snowstead-private"
export R2_PUBLIC_BUCKET_NAME="snowstead-public"
export SNOWSTEAD_TEST_R2_ENDPOINT="$R2_ENDPOINT"
MINIO_ROOT_USER="$R2_ACCESS_KEY_ID" MINIO_ROOT_PASSWORD="$R2_SECRET_ACCESS_KEY" \
  minio server --address "127.0.0.1:$PORT" --console-address '127.0.0.1:0' "$DIR/objects" >"$DIR/server.log" 2>&1 &
PID=$!
mc --config-dir "$DIR/client" alias set --api S3v4 --path on test "$R2_ENDPOINT" "$R2_ACCESS_KEY_ID" "$R2_SECRET_ACCESS_KEY" >/dev/null
for attempt in $(seq 1 100); do
  if mc --config-dir "$DIR/client" ready test >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null || [ "$attempt" = 100 ]; then
    echo 'Disposable S3 server did not become ready' >&2
    exit 1
  fi
  sleep 0.1
done
mc --config-dir "$DIR/client" mb "test/$R2_BUCKET_NAME" "test/$R2_PUBLIC_BUCKET_NAME" >/dev/null
"$@"
