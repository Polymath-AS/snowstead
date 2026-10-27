#!/usr/bin/env bash
# Deploy the services before switching the stable public gateway.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV="${1:-production}"
case "$ENV" in production|staging) ;; *) echo "Expected production or staging" >&2; exit 1 ;; esac
pnpm --dir "$ROOT" --filter @snowstead/cache-core db:migrate
pnpm --dir "$ROOT" exec wrangler deploy --config "$ROOT/workers/nix/wrangler.jsonc" --env "$ENV"
pnpm --dir "$ROOT" exec wrangler deploy --config "$ROOT/workers/go/wrangler.jsonc" --env "$ENV"
pnpm --dir "$ROOT" exec wrangler deploy --config "$ROOT/workers/control/wrangler.jsonc" --env "$ENV"
pnpm --dir "$ROOT" exec wrangler deploy --config "$ROOT/wrangler.jsonc" --env "$ENV"
