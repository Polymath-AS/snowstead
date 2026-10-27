# Snowstead

A Cloudflare-native Nix binary cache.

## Workspace

```
workers/gateway/      Public URL routing through service bindings
workers/nix/          Nix reads and upload protocol
workers/control/      Organizations, caches, tokens, signing management, and maintenance
packages/cache-core/  Shared auth, storage policy, database, migrations, and integration tests
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
names). To run all three Workers locally through the gateway on http://localhost:8787:

```bash
pnpm dev
```

It starts a Postgres cluster in `.dev/postgres` that keeps its data
between runs, migrates it, and on the first run writes `.dev.vars` with
local secrets (`ADMIN_SECRET=local-admin-secret`, a fresh signing key).
Delete `.dev/` to start over.

After changing `packages/cache-core/src/db/schema.ts`, run
`pnpm --filter @snowstead/cache-core db:generate` and commit the migration.


## Deploy

See [docs.md](docs.md) for resource setup, secret provisioning, and the
existing-installation cutover. The gateway has no storage or secrets;
Nix and control share the existing database, buckets, and authorization state.
Hosted reads enter through the web gateway, which uses the existing R2/CDN
origin for public objects. Production cache Worker routes remain API-only.

```bash
# With resources and service secrets provisioned: migrate, deploy Nix and
# control, then switch the existing public Worker to the gateway.
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
