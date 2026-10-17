#!/usr/bin/env bash
# Runs a command with HELIOS_TEST_DATABASE_URL pointing at a Postgres server.
# When it is already set, that server is used; otherwise a throwaway
# cluster is started on a free local port and removed afterwards.
#
# Usage: scripts/with-postgres.sh <command> [args...]
set -euo pipefail

if [ -n "${HELIOS_TEST_DATABASE_URL:-}" ]; then
  exec "$@"
fi

for tool in initdb pg_ctl; do
  command -v "$tool" >/dev/null || { echo "$tool not found: run inside 'nix develop' or set HELIOS_TEST_DATABASE_URL" >&2; exit 1; }
done

DIR="$(mktemp -d)"
cleanup() {
  pg_ctl -D "$DIR/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$DIR"
}
trap cleanup EXIT

PORT="$(node -e 'const s = require("net").createServer().listen(0, "127.0.0.1", () => { console.log(s.address().port); s.close(); })')"
# A password, as Hyperdrive (and miniflare) require; SCRAM like a real server.
printf postgres >"$DIR/pw"
initdb -D "$DIR/data" -U postgres --pwfile="$DIR/pw" --auth=scram-sha-256 --no-sync >/dev/null
pg_ctl -D "$DIR/data" -l "$DIR/log" -w -o "-c listen_addresses=127.0.0.1 -p $PORT -k $DIR -c fsync=off" start >/dev/null

export HELIOS_TEST_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:$PORT/postgres"
"$@"
