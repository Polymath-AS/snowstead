# Snowstead

A Cloudflare-native Nix binary cache.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Polymath-AS/helios)
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
names). To run the worker locally against a database of your own:

```bash
export DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/snowstead
pnpm --filter @snowstead/cache-worker db:migrate
CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="$DATABASE_URL" pnpm dev
```

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
# set the Hyperdrive id in wrangler.jsonc and workers/cache/wrangler.jsonc
wrangler secret put JWT_SECRET
wrangler secret put ADMIN_SECRET
wrangler secret put SIGNING_PRIVATE_KEY
wrangler secret put SIGNING_KEY_NAME
# S3 keys of an R2 token limited to the two buckets (key id: the token id,
# secret: the SHA-256 of its value). With them uploads go straight to R2
# through presigned URLs and private NARs redirect to R2; without them both
# go through the Worker.
wrangler secret put R2_ACCESS_KEY_ID
wrangler secret put R2_SECRET_ACCESS_KEY
wrangler secret put R2_ENDPOINT        # https://<account id>.r2.cloudflarestorage.com
# migrates the database directly (not through Hyperdrive), then deploys
DATABASE_URL="postgres://USER:PASSWORD@HOST:5432/postgres?sslmode=require" pnpm deploy
```

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
