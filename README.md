# Snowstead

A cache for Nix paths and Go, Rust, and C/C++ compiler outputs.

The Rust server works with unmodified sccache
clients over WebDAV. Enable `--protocols sccache` and use scoped
`sccache:read,sccache:write` tokens for Rust and C/C++ CI builds.

The [native Go helper](apps/go-cache/README.md) uses
`https://cache.snowstead.com/_api/v1/go/<org-slug>/<cache-name>` as its base URL.
Public caches allow anonymous reads; private reads require `go:read`, and every
upload requires `go:write`. Nix permissions do not grant Go access. Give write
access only to protected CI jobs building reviewed code: hashes detect
corruption, not malicious outputs from authorized writers.

New caches require explicit protocols: `snowstead cache create main --protocols nix`
for Nix, `--protocols go` for Go, `--protocols sccache` for Rust/C/C++, or a
comma-separated combination such as `--protocols nix,go,sccache`; there is no
default. API creation requests require the corresponding `protocols` array.
Existing-cache updates may omit it to preserve the selection, or add protocols
but not remove them (for example, `snowstead cache set main --protocols nix,go`).
Existing database caches keep Nix and Go enabled; sccache requires explicit opt-in.

Go objects use the private bucket, expire seven days
after upload, and count toward organization storage limits. Resetting Go leaves
Nix paths intact. The Rust server owns all protocols, management, and maintenance.

The [control-plane API](docs.md#cache-policy-api) exposes token last-use times,
cross-product eviction candidates and 30-day history, named Nix closure pins,
and a whole-cache eviction that keeps settings and credentials.
These features are API-only; they do not add dashboard or CLI commands.

## Workspace

```
workers/gateway/      Forwarding-only gateway to API_ORIGIN
workers/server/       Rust API, protocols, maintenance, migrations, and tests
apps/cli/             CLI for pushing store paths
apps/go-cache/        Native GOCACHEPROG helper
infra/                Rust service deployment
scripts/              Development and verification harnesses
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

Run the Rust server locally on http://127.0.0.1:8787:

```bash
pnpm dev
```

It starts disposable Postgres and S3 services, applies the Rust migrations,
and generates fresh local secrets. It does not read or write `.dev.vars`;
local state is discarded when the stack stops. Database migrations live in
`workers/server/migrations`.

## Deploy

Deploy the Rust service and its migrations through [infra/deploy.sh](infra/deploy.sh).
See [docs.md](docs.md#deployment) for gateway configuration and cutover cautions.
The gateway only forwards to `API_ORIGIN`; it has no storage or backend secrets.
Hosted public reads retain the existing R2/CDN origin.

```bash
# Deploy only the production gateway; no database migrations run here.
pnpm deploy
```

The hosted configuration requires per-cache keys and fails closed without
the master key. Existing caches without their own key need a staged key
and explicit trust-overlap activation before they can publish. Self-hosters
who deliberately want the legacy shared key can set
`REQUIRE_CACHE_SIGNING_KEYS` to `"false"` and configure
`SIGNING_PRIVATE_KEY` and `SIGNING_KEY_NAME`. See the signing-key lifecycle
and recovery guidance in [docs.md](docs.md).

### Optional read replica

Set `DATABASE_READ_URL` to a replica PostgreSQL URI to serve only
`GET /_api/v1/admin/overview` totals from that replica. These reporting values
may lag. All other queries, including authorization and organization overviews,
continue to use the primary `DATABASE_URL`.

For PlanetScale direct replicas, use port `5432` and append `%7Creplica` to
the URI username. Use verified TLS and a read-only role.
`DATABASE_READ_MAX_CONNECTIONS` defaults to 8 and must be positive. This is a
separate per-process pool limit; budget for application instances, deployment
overlap, and other clients. Do not assume replica connections divide evenly.
The primary pool keeps at least 2 connections warm and the replica pool keeps
at least 1, capped by each pool's configured maximum. Excess idle connections
are eligible to close after 60 seconds.

When `DATABASE_READ_URL` is unset, reads share the existing primary pool with
no additional connections. An invalid or unreachable configured replica fails
startup. Runtime replica errors do not fall back to primary. Migrations ignore
replica settings, and `pnpm dev` clears them to keep the local stack disposable.

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

`snowstead push` uploads each given path together with its
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

The server grants exact-size parts from a separate, bounded staging budget,
then checks the final size, compressed hash, and receipts before publishing.
Publication owns a unique immutable NAR key before copying bytes, without a
retained-byte reservation or a borrowed SQL connection. One short transaction
then admits current capacity, evicts eligible least-recently-used entries
across the org's products, adopts the pointer, and records completion. Failure
rolls back eviction together with publication. Completed retries return their
recorded result and cannot restore a deleted path. SQL decisions fail fast on
contention; they are not literally lock-free. Cleanup of retired exact keys is
asynchronous. Direct CDN downloads do not update access times; pushes and
service reads update use.
Each session uploads private staging bytes, even when the hash is already
stored. Session creation overlaps transfers instead of delaying the first
upload until every path has a session.

Only the streaming upload protocol is supported; the old upload-session,
blob, complete, publish, and commit routes have been removed. Deploy database
migrations and the Rust server before using the streaming CLI. It does not fall
back to disk spooling on older servers. Config and credential writes still
use atomic temporary files.

Legacy canonical installations keep a durable source/destination pin that
never expires automatically. An operator must reconcile an ambiguous R2
operation before clearing that pin. Outstanding pre-upgrade canonical multipart
grants keep their legacy objects protected; removing their API routes does not
revoke those grants. New immutable publications do not wait for them. Staged
session bytes are retained for retries and removed by garbage collection
after expiry.

Old raw CDN metadata and client caches can outlive SQL changes. Slug changes,
deletion, and signing rotation do not erase those copies; see the
[deployment caveats](docs.md#public-caches-on-a-custom-domain).

For local CLI development, run `cargo build -p snowstead-cli` and
`cargo test -p snowstead-cli` inside `nix develop`. `pnpm check` includes the
Rust checks and a real CLI upload against the disposable local stack.

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
nix.settings.substituters = [ "https://cache.example.com/main" ];
```

## License

Source-available. See [LICENSE](LICENSE).
