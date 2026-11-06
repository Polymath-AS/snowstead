# Rust and C/C++ compiler cache

Snowstead implements the WebDAV subset used by unmodified **sccache**. Enable
the `sccache` protocol on a named cache, and issue a cache-scoped token with
`sccache:read,sccache:write`. Nix and Go permissions do not grant compiler access.

```sh
snowstead cache create compiler --protocols sccache --private
snowstead token create ci --caches compiler --perms sccache:read,sccache:write

export SCCACHE_WEBDAV_ENDPOINT=https://cache.snowstead.com/_api/v1/sccache/ORG_SLUG/compiler/
export SCCACHE_WEBDAV_TOKEN="$SNOWSTEAD_TOKEN"
export RUSTC_WRAPPER=sccache
export CARGO_INCREMENTAL=0
cargo build --release
sccache --show-stats
```

Use a client built with WebDAV support. For CMake, configure
`-DCMAKE_C_COMPILER_LAUNCHER=sccache -DCMAKE_CXX_COMPILER_LAUNCHER=sccache`, or invoke
`sccache cc` / `sccache c++` directly. Stop an existing sccache server before
changing its endpoint or credentials. Do not set `SCCACHE_WEBDAV_KEY_PREFIX`:
the endpoint already identifies the namespace. Recent clients can set
`SCCACHE_WEBDAV_DISABLE_CREATE_DIR=true` to avoid directory probes; older
clients work with the virtual directories exposed here.

For untrusted pull requests, use `SCCACHE_WEBDAV_RW_MODE=READ_ONLY` and a token
with only `sccache:read`. Public caches permit anonymous artifact reads.
Only protected jobs building reviewed code should get write credentials:
compiler keys identify inputs, not trustworthy output. A writer can poison
the cache. Use separate caches for separate trust domains.

## Storage and contention

- GET/HEAD authorize before consulting the internal edge cache. Reads use one
  indexed metadata query plus a last-access update coalesced to five minutes,
  and release the database connection before streaming.
  Artifacts up to 8 MiB can populate the edge cache; larger artifacts stream
  directly from the private R2 bucket to avoid an unbounded clone backlog.
- PUT requires Content-Length and streams into R2 with exact-length validation.
  The maximum archive is 64 MiB; larger archives are rejected with 413.
  The Worker neither decompresses nor buffers the whole archive.
- Artifacts expire seven days after publication. Duplicate writes do not
  replace a completed archive or extend retention, even if bytes differ.
  Failed reservations remain tracked for cleanup; pending uploads expire after
  one hour. Published storage counts toward shared Nix/Go/compiler retained
  capacity. Publication takes the shared org capacity gate and evicts eligible
  least-recently-used artifacts before succeeding. An individual archive larger
  than capacity returns 413; busy victims or an insufficient eviction budget
  return retryable 503. Retrying publication preserves the first stored bytes.
  Compiler staging is separately bounded to 256 pending archives per org and
  bytes no greater than its capacity (1 GiB for unlimited orgs), with 503 on
  overload. A partial index keeps staging queries off completed archives.
- Compiler quota uses transactionally maintained totals per cache, generation
  and expiry minute. One SQL snapshot combines future-minute totals with an
  indexed scan of entries expiring during the current minute, preserving exact
  expiry without waiting for GC. A large synchronized expiry can still make that
  boundary scan expensive. PostgreSQL statement triggers aggregate changed rows
  per bucket; bucket locks are held during SQL, not while streaming to R2.
  Archive sizes and totals are `bigint` bytes, mapped to JavaScript numbers
  (exact through 2^53 - 1 bytes, approximately 8 PiB).
- Before any SQL, a Durable Object named `sccache:<org slug>` admits up to eight
  reads and eight writes concurrently, with separate queues so stalled uploads
  cannot occupy read capacity. Each queue holds up to 64 waiters for two seconds;
  overflow/expiry returns 429 with `Retry-After: 1`, without touching Postgres.
  The DO invokes a Worker RPC callback; neither payloads nor responses pass
  through the DO. Admission ends after the callback closes its DB connections.
  Traces include `sccache_admission` with lane and queue-wait attributes.
- The existing per-org coordinator serializes **reservation SQL only**, with
  its bounded queue and 429 overload response. Transfers hold a shared cache
  lock and an exclusive per-artifact lock, never an org-wide transfer lock.
  Distinct keys transfer concurrently; duplicate keys contend only with each
  other. A database transaction remains open during each upload to fence reset,
  deletion and garbage collection. This is not a lock-free backend.
  Admission bounds this exposure per org, not globally across all tenants.
  Size the shared Hyperdrive pool for the database's total connection budget;
  Hyperdrive's configured maximum is a soft limit, not a hard admission bound.
- Control owns statistics, reset and cleanup. Use
  `GET /_api/v1/orgs/:org/caches/:name/sccache` for completed-entry statistics and
  `POST /_api/v1/orgs/:org/caches/:name/sccache/reset` for a compiler-only reset.
  These require org-management authorization, not compiler tokens. Reset does
  not touch Nix or Go data. Cache deletion/recreation invalidates old token scope.

The endpoint supports sccache's `a/b/c/<64-lowercase-hex-key>` paths,
`.sccache_check`, and virtual directory PROPFIND/MKCOL. It is not a general
WebDAV server: arbitrary prefixes, listing, DELETE, MOVE, and COPY are not
supported. Capability probes do not create R2 objects or reserve storage.

## Deployment and verification

Apply migration `0009` before deploying. It creates compiler metadata, quota
totals, indexes and accounting triggers together, after the deployed
`0008_retained_capacity` migration, which remains unchanged. Development
databases with earlier unshipped compiler migrations must be rebuilt.
Provision the new private
`snowstead-sccache` Worker with the same JWT_SECRET as control, and the existing
environment-specific buckets, Hyperdrive, AUTH_KV and coordinator binding.
Deploy control before sccache, and the gateway last. `scripts/deploy.sh` includes
this order; `pnpm dev` includes the fifth Worker. Public Nix/CDN URLs are unchanged.

Inside `nix develop`, run `pnpm check`. The Worker tests cover tenant and
permission isolation, duplicate races, malformed uploads, quota, expiry,
reset/deletion and an independent upload completing while another body stalls.
The real-service integration test runs Rust and C++ through sccache with fresh
local caches and daemons, requires remote hits on the second pass, and compares
the restored outputs byte-for-byte. Its fixture timings are local smoke-test
measurements, not production CI speedup or WAN latency claims.

### Real build benchmark

From the repository root, with `/.amp/in/` in `.git/info/exclude`, run:

```sh
nix develop --command scripts/with-postgres.sh node scripts/sccache-build-bench.mjs
```

This downloads pinned ripgrep 14.1.1 and RocksDB 9.10.0 sources and builds
release outputs with 12 jobs against disposable local Workers, R2 and Postgres.
It runs three uncached clean builds, one cold-cache population, and three warm
clean builds per project. Each cached build gets a fresh sccache daemon and
local cache; Cargo incremental compilation is disabled. Dependencies are
prefetched outside timing. Wall time includes compilation, linking/archiving,
and upload drain, but excludes cleaning, daemon startup and output checks.
Every run must pass a functional smoke check. Rust outputs must match
byte-for-byte across all modes. C++ archives must match the uncached control
after removing debug sections, and warm restores must also match the complete
cold-cache archive. sccache deduplicates empty translation units, including
their debug metadata, which can differ from an uncached compilation.

Set `BENCH_JOBS`, `BENCH_REPEATS`, or `BENCH_SCCACHE` to select job count,
repetitions, or the sccache executable. Logs, client statistics, Worker request
logs, timings and storage counts go to `.amp/in/artifacts/compiler-bench/`;
rerunning replaces those results. RocksDB disables optional compression and
allocator dependencies and adds `-include cstdint` for GCC 15 compatibility.
All modes use identical flags. These are same-path, single-runner local-stack
measurements, not evidence of WAN performance or multi-runner contention.

### API and database profile

```sh
nix develop --command node scripts/sccache-api-profile.mjs current
```

This starts its own disposable PostgreSQL cluster with `pg_stat_statements`
and exercises the real gateway/Workers/DOs with 64 KiB artifacts. It measures
misses, new/duplicate uploads, cold/warm reads, 64-way bursts, stalled bodies,
96-way overload and recovery. SQL counts include transaction commands;
execution time excludes planning, connection setup and network time. A 10 ms
`pg_stat_activity` sampler records peak connections, idle transactions and lock
waiters. Raw query aggregates, samples and HTTP results are written under
`.amp/in/artifacts/sccache-api/<label>/`. Local Hyperdrive does not reproduce
production pooling/caching; these measurements prove admission behavior, not
production latency or a global database connection cap.

For a large-cache profile, set `PROFILE_ENTRIES=1000000`. This seeds one million
compiler metadata rows (64 KiB each) without creating their R2 payloads, then
runs three repetitions of real uploads and reads with finite quota enabled.
It checks exact usage totals and sweeps 500 expired metadata rows per repetition
through control's scheduled handler, verifying that live rows survive. Use
distinct labels for before/after runs. By default all seeded entries expire
together in seven days. Set `PROFILE_EXPIRY_MINUTES=10020` to spread expiries over
10,020 minutes starting one hour ahead, exercising many accounting buckets.
Quota totals use one SQL statement with independent aggregates; compiler
accounting scans summary buckets and only the current expiry minute's entries.
Bulk cleanup deletes only the IDs selected and locked by the sweep. Selection
uses separate expired, detached and obsolete-generation index ranges, sharing
one 500-entry budget and skipping locked entries. Obsolete generations use two
range probes per cache rather than walking the live generation; this work scales
with cache count, not just the number of garbage entries.
The profile also measures empty sweeps and detached/obsolete zero-byte entries.
Finally it fills retained capacity and measures 48 more uploads, each requiring
an eviction, verifying that published usage remains exactly at the limit.
Set `PROFILE_EXPLAIN=1` to save post-cleanup selection plans outside the timed
measurements; those plans show the no-garbage path after each sweep.
