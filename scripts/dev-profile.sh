#!/usr/bin/env bash
# Runs the cache worker locally, as `pnpm dev` does, with the inspector on a
# fixed port so Chrome DevTools can record CPU profiles of it.
#
# Usage: pnpm dev:profile (inside `nix develop`). Set SNOWSTEAD_INSPECTOR_PORT
# to move the inspector off 9230.
set -euo pipefail

PORT="${SNOWSTEAD_INSPECTOR_PORT:-9230}"

cat <<EOF2
To profile:
  1. In Chrome, open chrome://inspect, click Configure and add localhost:$PORT.
  2. Under Remote Target, click "inspect" on "Cloudflare Worker", then open
     the Profiler tab (Performance, in newer versions).
  3. Start recording, send requests to the worker (scripts/load-test.sh, or
     curl), and stop: the flame graph shows where the CPU time went.
  The profiler samples, so functions under about 100 µs may not show up.

EOF2

exec "$(dirname "$0")/dev.sh" --inspector-port "$PORT" "$@"
