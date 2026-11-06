#!/usr/bin/env bash
# Deploy only the forwarding gateway. Rust service deployment belongs to infra.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV="${1:-production}"
case "$ENV" in production|staging) ;; *) echo "Expected production or staging" >&2; exit 1 ;; esac
if [ "$ENV" = staging ]; then
  : "${API_ORIGIN:?set API_ORIGIN to the staging Rust origin}"
  exec pnpm --dir "$ROOT" exec wrangler deploy --config "$ROOT/wrangler.jsonc" --env "$ENV" --var "API_ORIGIN:$API_ORIGIN"
fi
exec pnpm --dir "$ROOT" exec wrangler deploy --config "$ROOT/wrangler.jsonc" --env "$ENV"
