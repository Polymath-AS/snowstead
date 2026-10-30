# Snowstead

A Cloudflare-native cache for Nix paths and Go compiler outputs.

The [native Go helper](apps/go-cache/README.md) uses
`https://cache.snowstead.com/_api/v1/go/<org-slug>/<cache-name>` as its base URL.
Public caches allow anonymous reads; private reads require `go:read`, and every
upload requires `go:write`. Nix permissions do not grant Go access. Give write
access only to protected CI jobs building reviewed code: hashes detect
corruption, not malicious outputs from authorized writers.

New caches require explicit protocols: `snowstead cache create main --protocols nix`
for Nix, `--protocols go` for Go, or `--protocols nix,go` for both; there is no
default. API creation requests require the corresponding `protocols` array.
Existing-cache updates may omit it to preserve the selection, or add protocols
but not remove them (for example, `snowstead cache set main --protocols nix,go`).
Existing database caches migrate with both protocols enabled.

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

Control owns the SQLite-backed `UploadCoordinator` Durable Object namespace;
Nix and Go bind to it for shared per-organization upload coordination. Deploy
control first to create the namespace and apply its Durable Object migration,
then Nix and Go, and the gateway last. Staging uses its own control namespace.
The coordinator has no public route and does not require a separate Worker.

Only reservation SQL enters the queue, after authorization and input validation.
Each org admits one reservation at a time, with at most 64 active/queued calls
and a two-second queue deadline. Overload returns 429 with `Retry-After: 1`
without opening a reservation connection. Postgres quota checks and transaction
locks remain authoritative, including during rolling deployments. Nix batches
reserve their sessions in one call; payloads, signing, and publication stay
outside the coordinator. Go's separate transfer transaction still fences cache
reset and garbage collection. Reservation traces include protocol and queue wait.

```bash
# With resources and service secrets provisioned: migrate, deploy control,
# then Nix and Go, then switch the existing public Worker to the gateway.
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

The CLI is a native Rust binary using the Zig NAR core. On Linux, NAR
serialization, SHA-256, and zstd compression run in-process; Nix is still used
for path metadata and closure resolution. On macOS, Nix also serializes the
NAR. The flake includes Nix as a runtime dependency, not Node or the workspace's
Worker dependencies. Existing credentials in `~/.config/snowstead/config.json`
continue to work. The full development environment is separate (`nix develop`).

Sign in once (use `--no-browser` over SSH and open the printed URL elsewhere):

```bash
snowstead login
```

Approve the organization and token lifetime in your browser: 30 days, 90 days
(the default), 365 days, or never. The ten-minute device approval window is
separate from the saved token's lifetime.

For CI, set both `SNOWSTEAD_TOKEN` and `SNOWSTEAD_URL` (the cache base URL).
For self-hosted manual tokens, use
`snowstead login --token-stdin --url https://cache.example.com --name prod < token-file`.
Manual tokens are configured without remote validation; positional login tokens
are no longer accepted. `snowstead auth status [--server <profile>]` shows local
configuration, and `snowstead logout [--server <profile>]` removes local
credentials without revoking the remote token. See the
[CLI authentication guide](apps/cli/README.md) for profile details.

Like `cachix push`, `snowstead push` uploads each given path together with its
runtime closure (everything it references), and reads paths from stdin when
none are given as arguments:

```bash
snowstead push main ./result
snowstead push main /run/current-system
nix build --no-link --print-out-paths .#nixosConfigurations.myhost.config.system.build.toplevel \
  | snowstead push main
```

Paths must be built first; the CLI never evaluates or builds an installable.
Each path is published only after the references pushed with it, so an
interrupted push never leaves a published path whose references are missing.
Use `--no-deps` to push only the exact paths given; then a path already in the
cache is skipped without needing a local copy. `.drv` paths are build recipes,
not outputs, and are rejected unless you pass `--allow-drv`.

Normal output contains a summary and any errors. Add `--verbose` (or `-v`) for
`tracing` diagnostics on stderr, including compression sizes/times and upload
request status/retries. Credentials and signed upload URLs are not logged.
`RUST_LOG` alone does not enable logging.

```bash
snowstead push main /run/current-system --verbose
```

Compression defaults to zstd level 3; use `--compression-level <1-19>` to change
it. Independent paths use a bounded native worker pool. NARs of at least
64 MiB use up to four additional zstd workers; the producer and codec workers
share one CPU budget, rather than multiplying workers by `--jobs`.
The Rust CLI streams compressed NARs directly into multipart uploads: no NAR
temporary files, whole-NAR buffering, or compression pass just to learn the
size. Upload buffers share a global budget of 64 MiB, or one negotiated part
if a very large NAR needs larger parts. Codec memory is additional. Slow
uploads pause compression; queued and retrying parts keep their buffer
reservation, so retries reuse the same bytes without recompression.

The server reserves quota before granting each exact-size part upload, then
checks the final size, compressed hash, and receipts before publishing. Each
session uploads private staging bytes, even when the hash is already stored.
Existing v1 clients remain supported. Deploy the database migration and new
Workers before the streaming CLI; it does not fall back to disk spooling on
older servers. Config and credential writes still use atomic temporary files.

Large canonical installations keep a durable source/destination pin. An
ambiguous storage completion stays blocked rather than reopening on a timeout;
an operator must reconcile its R2 upload before clearing that pin. Drain
pre-upgrade canonical multipart sessions before rollout. Staged session bytes
are retained for retries and removed by garbage collection after expiry.

For local CLI development, run `cargo build -p snowstead-cli` and
`cargo test -p snowstead-cli` inside `nix develop`. `pnpm check` includes the
Rust checks and a real CLI upload against disposable Workers and Postgres.

For development-only function and thread profiling, use
`nix run .#hotpath -- push main /nix/store/…`. This runs the same CLI with
Hotpath annotations; Hotpath is a Cargo dev-dependency, not linked into the
normal CLI. Set `HOTPATH_OUTPUT_FORMAT=json` and `HOTPATH_OUTPUT_PATH=report.json`
to save a report instead of printing it. Reports include metadata queries,
NAR encoding, buffer backpressure, batch waits, transfers, and finalization.
Async durations include waiting, and concurrent/nested durations overlap;
do not add them together or treat them as CPU time. `poop` is available in the
Linux development shell for separate CPU-counter comparisons. Profiling adds
overhead, so use the normal binary for throughput benchmarks.

To isolate local work from HTTP, profile existing store paths with
`nix run .#hotpath -- local --closure /nix/store/… --rounds 1`.
This development-only command resolves the closure, queries metadata, and
prepares NARs sequentially, without loading credentials or uploading anything.
It validates each NAR against the Nix database and discards encoded output
directly into a sink. Hotpath separates Nix queries and encoding; the Zig
call includes filesystem reads, hashing, and compression.
It is elapsed-time instrumentation, not a CPU sample inside Zig or libzstd.

For throughput without profiler overhead, build the same development target:

```bash
RUSTFLAGS="--cfg snowstead_local" cargo build --release -p snowstead-cli --example snowstead
target/release/examples/snowstead local /nix/store/… --rounds 5
target/release/examples/snowstead local /nix/store/… --rounds 5 --upstream
```

Run inside `nix develop`. `--upstream` replaces the native walker with
`nix-store --dump`, keeping the same Zig hashing, zstd settings, and sink
output. Use `--compression-level 0` for raw NAR encoding plus hashing,
or the default level 3 for upload preparation; `--threads 4` enables four
additional zstd workers. Use the same Nix on `PATH` for both runs. JSON lines
report metadata timings and input MB/s (decimal), not compressed-output MB/s.
One warm-up pass is omitted from throughput rows but included in Hotpath.
Results describe warm-cache, sequential local preparation, not parallel upload
speed, durable disk throughput, or a pure in-process libnix comparison.

See [docs.md](docs.md) for token management and parallelism options.

## Use as a substituter

```nix
# configuration.nix or flake
nix.settings.substituters = [ "https://your-worker.workers.dev/main" ];
```

## License

Source-available. See [LICENSE](LICENSE).
