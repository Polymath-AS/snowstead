# Snowstead

A Cloudflare-native Nix binary cache.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Polymath-AS/snowstead)
## Workspace

```
workers/cache/        Cloudflare Worker (main service)
packages/cache-domain/  Shared types and input parsers
apps/cli/             CLI for pushing store paths
scripts/              smoke-test.sh
```

## Setup

```bash
nix develop # drops you into a shell with node, pnpm, wrangler, postgres
pnpm install
```

## Develop

```bash
pnpm check # type-check + tests across the workspace
```

The worker's tests run against a throwaway Postgres that
`scripts/with-postgres.sh` starts (or the server `SNOWSTEAD_TEST_DATABASE_URL`
names). To run the worker locally on http://localhost:8787:

```bash
pnpm dev
```

It starts a Postgres cluster in `.dev/postgres` that keeps its data
between runs, migrates it, and on the first run writes `.dev.vars` with
local secrets (`ADMIN_SECRET=local-admin-secret`, a fresh signing key).
Delete `.dev/` to start over.

After changing `workers/cache/src/db/schema.ts`, run
`pnpm --filter @snowstead/cache-worker db:generate` and commit the migration.


## Deploy

See [docs.md](docs.md) for the full reference. Short version:

```bash
wrangler r2 bucket create snowstead-private
# Postgres on PlanetScale, with a role holding pg_read_all_data and
# pg_write_all_data. Query caching off: uploads must read their own writes.
wrangler hyperdrive create snowstead --caching-disabled \
  --connection-string "postgres://USER:PASSWORD@HOST:5432/postgres?sslmode=require"
# set the Hyperdrive id in wrangler.jsonc
wrangler secret put JWT_SECRET
wrangler secret put ADMIN_SECRET
# Required: 32 random bytes, base64 (openssl rand -base64 32). Each new
# cache gets its own signing key, encrypted under this master key.
# Back it up separately from the database; losing it prevents signing.
wrangler secret put SIGNING_MASTER_KEY
# S3 keys of an R2 token limited to the two buckets (key id: the token id,
# secret: the SHA-256 of its value). With them uploads go straight to R2
# through presigned URLs; without them uploads go through the Worker.
# Private downloads always go through the Worker for authorization.
wrangler secret put R2_ACCESS_KEY_ID
wrangler secret put R2_SECRET_ACCESS_KEY
wrangler secret put R2_ENDPOINT        # https://<account id>.r2.cloudflarestorage.com
# migrates the database directly (not through Hyperdrive), then deploys
DATABASE_URL="postgres://USER:PASSWORD@HOST:5432/postgres?sslmode=require" pnpm deploy
```

The default configuration requires per-cache keys and fails closed without
the master key. Existing caches without their own key need a staged key
and explicit trust-overlap activation before they can publish. Self-hosters
who deliberately want the legacy shared key can set
`REQUIRE_CACHE_SIGNING_KEYS` to `"false"` and configure
`SIGNING_PRIVATE_KEY` and `SIGNING_KEY_NAME`. See the signing-key lifecycle
and recovery guidance in [docs.md](docs.md).

## Push store paths

Build the CLI (or `nix run .` for one-off use):

```bash
nix build       # produces ./result/bin/snowstead
```

Save credentials once:

```bash
snowstead login prod https://your-worker.workers.dev "$PUSH_TOKEN"
```

Push a single path:

```bash
snowstead push main /nix/store/abc...-hello
```

Push a full closure:

```bash
snowstead push main --closure /run/current-system
```

Push a flake output closure:

```bash
snowstead push main --closure .#nixosConfigurations.myhost.config.system.build.toplevel
```

See [docs.md](docs.md) for token management and parallelism options.

## Use as a substituter

```nix
# configuration.nix or flake
nix.settings.substituters = [ "https://your-worker.workers.dev/main" ];
```

## License

Source-available. See [LICENSE](LICENSE).
