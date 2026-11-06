#!/usr/bin/env bash
# Describe query macros against a fresh disposable schema, never a live database.
set -euo pipefail

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --check ) ]]; then
  echo "Usage: $0 [--check]" >&2
  exit 2
fi

ROOT="$(realpath "$(dirname "$0")/..")"
OUTPUT="$(mktemp -d)"
trap 'rm -rf "$OUTPUT"' EXIT

env -u SNOWSTEAD_TEST_DATABASE_URL \
  "$ROOT/scripts/with-postgres.sh" bash -euo pipefail -s -- "$ROOT" "$OUTPUT" <<'BASH'
    root=$1
    output=$2
    for migration in "$root"/workers/server/migrations/*.sql; do
      psql "$SNOWSTEAD_TEST_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 \
        --file "$migration" > /dev/null
    done
    # Describe the SQLx-owned ledger queries too. This fixture belongs only to
    # the throwaway database, not the application schema baseline.
    psql "$SNOWSTEAD_TEST_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 > /dev/null <<SQL
CREATE TABLE _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);
SQL
    export DATABASE_URL="$SNOWSTEAD_TEST_DATABASE_URL"
    export SQLX_OFFLINE=false SQLX_OFFLINE_DIR="$output"
    cargo clean --manifest-path "$root/Cargo.toml" --package snowstead-server
    cargo check --manifest-path "$root/Cargo.toml" --locked \
      --package snowstead-server --all-targets --features profiling
BASH

if [[ ${1:-} == --check ]]; then
  diff --recursive "$ROOT/workers/server/.sqlx" "$OUTPUT"
else
  mkdir -p "$ROOT/workers/server/.sqlx"
  rm -f "$ROOT"/workers/server/.sqlx/query-*.json
  cp "$OUTPUT"/query-*.json "$ROOT/workers/server/.sqlx/"
fi
