#!/usr/bin/env bash
# Local Rust backend with disposable Postgres and S3. No deployment secrets.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cargo build --locked --manifest-path "$ROOT/Cargo.toml" -p snowstead-server
exec env -u SNOWSTEAD_TEST_DATABASE_URL -u DATABASE_READ_URL -u DATABASE_READ_MAX_CONNECTIONS \
  "$ROOT/scripts/with-postgres.sh" "$ROOT/scripts/with-r2.sh" bash -c '
    set -euo pipefail
    export DATABASE_URL="$SNOWSTEAD_TEST_DATABASE_URL"
    export JWT_SECRET="$(node -e '\''console.log(require("node:crypto").randomBytes(32).toString("hex"))'\'')"
    export SIGNING_MASTER_KEY="$(node -e '\''console.log(require("node:crypto").randomBytes(32).toString("base64"))'\'')"
    export ADMIN_SECRET=local-admin-secret SIGNING_PRIVATE_KEY=""
    # Pairs with the dashboard's local-only CACHE_ASSERTION_PRIVATE_KEY in its
    # .env.example. SNOWSTEAD_DEV_WEB_KEYS overrides it, as `pnpm fuzz` does.
    export WEB_ASSERTION_PUBLIC_KEYS="${SNOWSTEAD_DEV_WEB_KEYS:-2aLdazRgIkJp0m0Ik8oS5B0sUJQvwU6jvSaO4wWP/o0=}"
    export REQUIRE_CACHE_SIGNING_KEYS=true UPSTREAM_CACHES="" PUBLIC_URL=""
    export PUBLIC_CACHE_ORIGIN="" CDN_ZONE_ID="" CDN_PURGE_TOKEN="" ANALYTICS_TOKEN=""
    export POSTHOG_HOST="" POSTHOG_PROJECT_TOKEN="" TRUSTED_PROXY_IPS=""
    export CACHE_HOST_SUFFIX="" CACHE_CANONICAL_HOSTS=""
    export LISTEN_ADDR="${SNOWSTEAD_DEV_LISTEN_ADDR:-127.0.0.1:8787}"
    "$1/target/debug/snowstead-server" migrate
    echo "Local API: http://$LISTEN_ADDR (ADMIN_SECRET=local-admin-secret)"
    echo "Database and objects are removed when this process stops."
    exec "$1/target/debug/snowstead-server"
  ' dev "$ROOT"
