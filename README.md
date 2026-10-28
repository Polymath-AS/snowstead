# Snowstead

A Cloudflare-native cache for Nix paths and Go compiler outputs.

The [native Go helper](apps/go-cache/README.md) uses
`https://cache.snowstead.com/_api/v1/go/<org-slug>/<cache-name>` as its base URL.
Public caches allow anonymous reads; private reads require `go:read`, and every
upload requires `go:write`. Nix permissions do not grant Go access. Give write
access only to protected CI jobs building reviewed code: hashes detect
corruption, not malicious outputs from authorized writers.

Go objects use the private bucket and internal Cache API, expire seven days
after upload, and count toward organization storage limits. Resetting Go leaves
Nix paths intact. Apply the included database migrations before deploying the
updated services. Management and garbage collection belong to control; artifact
reads and writes belong to the private Go Worker.

The isolated [Go prototype](workers/go-cache/README.md) and its Terraform build
gate remain disposable local benchmarks, not the hosted named-cache API.

## Workspace

```
workers/gateway/      Public URL routing through service bindings
workers/nix/          Nix reads and upload protocol
workers/go/           Hosted Go action-cache protocol
workers/go-cache/     Isolated prototype for disposable benchmark harnesses
workers/control/      Organizations, caches, tokens, signing management, and maintenance
workers/download/     Gated SQL-free publication admission (no public routes yet)
workers/bytes/        Binding-only immutable bytes (native caching disabled)
workers/storage/      Isolated read-only authority and publication RPC capabilities
packages/cache-core/  Shared auth, storage policy, database, migrations, and integration tests
packages/cache-domain/  Shared types and input parsers
apps/cli/             CLI for pushing store paths
apps/go-cache/        Native GOCACHEPROG helper
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
names). To run all four hosted Workers locally through the gateway on http://localhost:8787:

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
Nix, Go, and control share the existing database, buckets, and authorization state.
Hosted reads enter through the web gateway, which uses the existing R2/CDN
origin for public objects. Production cache Worker routes remain API-only.
That is the legacy deployment. The strong publication implementation is gated
off by default; the existing deploy script does not deploy its new Workers.
Do not deploy the companion web gateway removal independently. See the
[publication cutover and release gates](docs.md#strong-publication-cutover).

```bash
# With resources and service secrets provisioned: migrate, deploy Nix, Go, and
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
