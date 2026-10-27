#!/usr/bin/env bash
# Runs the cache worker locally with everything it needs: a Postgres cluster
# in .dev/postgres that keeps its data between runs, migrated to the latest
# schema, and a .dev.vars with local secrets, written on the first run.
#
# Usage: pnpm dev (inside `nix develop`). Set SNOWSTEAD_DEV_PG_PORT to move
# Postgres off 54320.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/.dev/postgres"
PORT="${SNOWSTEAD_DEV_PG_PORT:-54320}"
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:$PORT/snowstead"

for tool in initdb pg_ctl psql nix; do
  command -v "$tool" >/dev/null || { echo "$tool not found: run inside 'nix develop'" >&2; exit 1; }
done

if [ ! -d "$DATA" ]; then
  mkdir -p "$ROOT/.dev"
  printf postgres >"$ROOT/.dev/pw"
  # A password, as Hyperdrive (and miniflare) require; SCRAM like a real server.
  initdb -D "$DATA" -U postgres --pwfile="$ROOT/.dev/pw" --auth=scram-sha-256 --no-sync >/dev/null
  rm "$ROOT/.dev/pw"
fi

# Stop Postgres on exit only if this run started it, so a second run
# sharing the cluster doesn't lose it when the first one ends.
if ! pg_ctl -D "$DATA" status >/dev/null 2>&1; then
  pg_ctl -D "$DATA" -l "$ROOT/.dev/postgres.log" -w -o "-c listen_addresses=127.0.0.1 -p $PORT -k $ROOT/.dev" start >/dev/null
  trap 'pg_ctl -D "$DATA" -m fast stop >/dev/null 2>&1 || true' EXIT
fi

if ! PGPASSWORD=postgres psql -h 127.0.0.1 -p "$PORT" -U postgres -tAc "select 1 from pg_database where datname = 'snowstead'" | grep -q 1; then
  PGPASSWORD=postgres psql -h 127.0.0.1 -p "$PORT" -U postgres -qc "create database snowstead"
fi

DATABASE_URL="$DATABASE_URL" pnpm --filter @snowstead/cache-core db:migrate >/dev/null

if [ ! -f "$ROOT/.dev.vars" ]; then
  cat >"$ROOT/.dev.vars" <<EOF
ADMIN_SECRET=local-admin-secret
AUTH_TOKEN=local-auth-token
JWT_SECRET=$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')
SIGNING_KEY_NAME=local-1
SIGNING_PRIVATE_KEY=$(nix key generate-secret --key-name local-1 | cut -d: -f2)
EOF
  echo "Wrote .dev.vars with local secrets (ADMIN_SECRET=local-admin-secret)."
fi
# Seals each cache's own signing key; added to .dev.vars written before it.
if ! grep -q '^SIGNING_MASTER_KEY=' "$ROOT/.dev.vars"; then
  echo "SIGNING_MASTER_KEY=$(node -e 'console.log(require("crypto").randomBytes(32).toString("base64"))')" >>"$ROOT/.dev.vars"
fi

# Wrangler loads .dev.vars beside each service's config in multi-Worker mode.
# Share the generated local source, preserving any service-local overrides.
for worker in nix control; do
  if [ ! -e "$ROOT/workers/$worker/.dev.vars" ]; then
    ln -s ../../.dev.vars "$ROOT/workers/$worker/.dev.vars"
  fi
done

echo "Postgres: $DATABASE_URL"
# One local secret source for both services; never load deployment credentials.
CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV=true \
CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="$DATABASE_URL" \
pnpm exec wrangler dev --local --config "$ROOT/wrangler.jsonc" \
  --config "$ROOT/workers/nix/wrangler.jsonc" --config "$ROOT/workers/control/wrangler.jsonc" \
  --env-file "$ROOT/.dev.vars" "$@"
