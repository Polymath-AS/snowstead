# Snowstead Documentation

## Deployment

The Rust backend is `workers/server`; SQL migrations live in
`workers/server/migrations`. It owns Nix, Go, sccache, management, and scheduled
maintenance. Deploy it and run migrations through [infra/deploy.sh](infra/deploy.sh).
It connects directly to Postgres and S3-compatible storage, without Worker
service bindings, KV, Hyperdrive, or Durable Objects.

The root `wrangler.jsonc` deploys the forwarding-only gateway (`snowstead`).
`API_ORIGIN` selects the Rust origin; the gateway has no database, storage,
signing, authorization, or maintenance logic. `pnpm deploy` deploys only this
production gateway and does not run database migrations. Backend secrets belong
to the Rust runtime, not the gateway. Hosted reads retain the existing R2/CDN
origin for public objects; production gateway routes remain API-only.

Staging must set its own `API_ORIGIN` before deploying the gateway:

```bash
API_ORIGIN=https://staging-api.example.com scripts/deploy.sh staging
```

Use an independently provisioned staging backend, database, buckets, and secrets;
never point it at production data. The populated benchmark database is not staging.

For local development, `pnpm dev` runs Rust on http://127.0.0.1:8787 with
disposable Postgres and S3 services and fresh local secrets, without `.dev.vars`.

# Provision the SAME JWT_SECRET on both services: control issues tokens, Nix verifies them.
### Existing-installation cutover

Back up and restore-test the existing database before migration. Preserve the
original `JWT_SECRET`, `ADMIN_SECRET`, signing master key, database, buckets,
object keys, cache URLs, and CDN rules. Supply the existing master-key value as
Rust's `SIGNING_MASTER_KEY`; a new key makes sealed signing keys unreadable.
Legacy self-hosters must also preserve `AUTH_TOKEN` and shared signing settings
until their clients migrate. Keep secret values out of source control and logs.

Validate the Rust backend against existing objects and clients before changing
traffic. Retain a tested rollback path and legacy state, including KV, until
all readers and writers have moved. Drain or reconcile outstanding uploads;
removing old routes does not revoke existing multipart grants. Do not run old
and new maintenance concurrently or re-enable the legacy bandwidth importer:
it can overwrite Rust's origin counters. See infra's cutover record before any
further traffic change. Removing the TypeScript source is not authorization to
delete deployed resources or data, and does not prove exhaustive API parity.

Fresh databases use `snowstead-server migrate`. Existing installations must
follow the checked migration ledger: a Drizzle-only database must first use
the pre-baseline Rust release; the complete legacy SQLx history requires the
explicit `migrate --rebaseline` operator action. The current binary refuses to
infer or overwrite an unknown schema. Historical releases remain in Git;
source removal does not change this upgrade requirement.

The hosted `REQUIRE_CACHE_SIGNING_KEYS=true` policy refuses cache creation
without a master key and refuses publication without a per-cache key.
Self-hosters may explicitly set it to `"false"` to use
`SIGNING_PRIVATE_KEY` for caches without their own key. Existing shared-key
caches need trust-overlap activation before publishing under hosted policy;
do not silently replace a key clients already trust.

### Public caches on a custom domain

For self-hosted direct cache URLs, public caches can be served straight from
the `snowstead-public` bucket. The bucket needs a custom domain on a zone in
the same account, Worker routes for `/_api/*` and `/private/*` on that hostname,
and a Cache Rule. Hosted production instead keeps this as the web gateway's
internal CDN origin. Cloudflare caches only some file
extensions by default, and `.narinfo` and `.nar` are not among them:

```bash
wrangler r2 bucket create snowstead-public
wrangler r2 bucket local-uploads enable snowstead-public
wrangler r2 bucket domain add snowstead-public --domain cache.example.com --zone-id <zone id>
```

Cache Rule, on the zone:

- Expression: `(http.host eq "cache.example.com" and not starts_with(http.request.uri.path, "/_api/") and not starts_with(http.request.uri.path, "/private/"))`
- Cache eligibility: eligible; Edge TTL: use cache-control if present,
  bypass if not, and 60 seconds for status 404; Browser TTL: respect origin.

NARs are content-addressed and cached for a year. Narinfo can be deleted or
re-signed, so it is cached for five minutes, without `immutable`. Misses are
cached for a minute. Publishing, re-publishing, backfilling, and deleting
paths (including retention) request CDN purges to accelerate visibility.
Purging needs the vars `CDN_ZONE_ID` and `PUBLIC_CACHE_ORIGIN` and the
secret `CDN_PURGE_TOKEN`, an API token with Cache Purge on the zone;
without them nothing is purged. Automatic purges are saved under
`cdn-purges/` in the **private** bucket before dispatch. Requests are batched
and paced, with bounded retries for network errors, 429s, and 5xx responses.
Rust's maintenance loop retries unfinished jobs and respects `Retry-After`.
Inspect the service logs for persistent failures, fix the configuration or
credentials, and the backlog resumes. No new bucket or database table is needed.

To purge by hand (an empty object purges the cache prefix, while
`storePathHashes` targets up to 500 narinfo URLs):

```bash
curl -X POST https://cache.example.com/_api/v1/admin/caches/main/purge \
  -H "authorization: Bearer $ADMIN_SECRET" -d '{}'   # or {"storePathHashes": [...]}

# An org API key can purge only its own public caches.
curl -X POST https://cache.example.com/_api/v1/orgs/ORG_ID/caches/main/purge \
  -H "authorization: Bearer $ORG_API_KEY" -d '{}'
```

The response `{ "accepted": true, "paths": "all" }` means Cloudflare
acknowledged the request, not that eviction was verified everywhere.
Purges don't remove clients' local copies, Nix's negative cache, or shared
content-addressed NARs. This is cache invalidation, not erasure of public data.

**Upgrading:** existing objects and CDN entries may still have the former
one-year TTL. Run `POST /_api/v1/admin/narinfo/backfill` through all pages
to rewrite their metadata and queue purges. The five-minute fallback
applies after those old copies have been replaced; changing the server
alone cannot shorten an already-cached response's TTL.

## Rust and C/C++ compiler cache

Snowstead implements the WebDAV subset used by unmodified sccache. Enable the
`sccache` protocol and issue a cache-scoped token. Nix and Go permissions do
not grant compiler access.

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

Use a client built with WebDAV support. For CMake, set
`-DCMAKE_C_COMPILER_LAUNCHER=sccache -DCMAKE_CXX_COMPILER_LAUNCHER=sccache`, or
invoke `sccache cc` / `sccache c++` directly. Stop an existing sccache daemon
before changing its endpoint or credentials. Do not set
`SCCACHE_WEBDAV_KEY_PREFIX`: the endpoint already identifies the namespace.
Clients can set `SCCACHE_WEBDAV_DISABLE_CREATE_DIR=true` to avoid directory
probes; older clients can use the virtual directories.

For untrusted pull requests, use `SCCACHE_WEBDAV_RW_MODE=READ_ONLY` and a token
with only `sccache:read`. Public caches allow anonymous reads. Give write
credentials only to protected jobs building reviewed code: a writer can poison
compiler outputs. Use separate caches for separate trust domains.

PUT requires Content-Length and exact-length validation, with a 64 MiB archive
limit. Archives expire seven days after publication. Duplicate writes preserve
the published bytes and do not extend retention. Storage counts toward shared
organization capacity; compiler staging also has a separate byte budget.
The endpoint supports `a/b/c/<64-lowercase-hex-key>`, `.sccache_check`, and
virtual directory PROPFIND/MKCOL, not general WebDAV listing, DELETE, MOVE, or COPY.

Org-management credentials can read statistics with
`GET /_api/v1/orgs/:org/caches/:name/sccache` and reset only compiler data with
`POST /_api/v1/orgs/:org/caches/:name/sccache/reset`. Reset leaves Nix and Go intact.

`pnpm check` exercises real Rust and C++ clients against Rust with disposable
Postgres/S3 and fresh local client caches. For longer local build benchmarks:

```sh
nix develop --command scripts/with-postgres.sh scripts/with-r2.sh node scripts/sccache-build-bench.mjs
```

The benchmark builds pinned ripgrep and RocksDB releases, checks outputs, and
records client statistics under `.amp/in/artifacts/compiler-backend-bench/`.
It measures a local stack, not production or WAN performance.

## Rust API compatibility

The Rust server implements the hosted Nix, Go, sccache, and management APIs.
The migration target is API compatibility with documented improvements, not
identical behavior for every Worker input or storage state. Do not claim
1:1 parity from passing the two implementations' separate test suites.

The following differences are intentional:

- **Integrity and authorization:** Rust verifies compressed NAR content,
  declared hashes, and sizes before publication. It checks token revocation
  in SQL on each authentication and requires current publication/membership
  for NAR reads. It does not reproduce the Worker's corrupt-upload acceptance,
  revocation propagation gaps, or stale cached authorization.
- **Upload recovery:** failed compiler transfers do not commit their declared
  output. Pending attempts share a byte reservation; the first verified
  transfer adopted under the organization lock commits its actual output and
  size. A corrected retry may change either before adoption without cancelling
  another writer. Once adopted, Go outputs are immutable, and different-size
  sccache retries cannot publish an unfinished adopted object. Replays of
  published sccache entries still leave the original bytes unchanged.
- **HTTP behavior:** unsupported methods use Axum's 405 responses and GET
  routes support HEAD. Unmatched API routes return 404 without authenticating
  a nonexistent operation. Validation messages are not byte-for-byte copies
  of Worker errors. Compiler ETags identify the immutable entry, rather than
  exposing the storage provider's ETag. Clients must treat them as opaque.
- **Management inputs:** path deletion accepts RFC3339 timestamps with an
  offset or complete `YYYY-MM-DD` dates at midnight UTC. JavaScript's other
  date formats, including `YYYY-MM`, are not supported. Audited management
  request bodies are limited to 1 MiB; oversized bodies currently return 400.
- **Storage and caching:** Rust compiler reads access storage rather than the
  Worker's Cache API and return `x-snowstead-cache: MISS`. Expiration is checked
  after storage access and again before returning a response; transfers are
  not interrupted if their entry expires after response streaming starts.
  Direct public narinfo misses use `no-store`, not negative edge caching.
  Public CDN handoff remains a separate configured path.
- **Backfill:** missing canonical NARs are repaired from the recorded blob
  source before narinfo is written. Rust also writes private narinfo and
  includes it in `written`; private metadata remains in the private bucket
  and may be preserved during slug moves.
- **Accounting and maintenance:** origin downloads attempt immediate SQL
  bandwidth increments independently of optional telemetry; these count
  selected object bytes, not confirmed client receipt. The public importer
  updates public bytes separately, rather than replacing origin totals from
  sampled Worker analytics. Maintenance uses bounded cleanup batches, a token
  expiry grace period, and retention selection that skips caches with no work.
- **Admission and tracing:** removal of request/upload-count admission caps
  and optional tracing are deliberate changes. Protocol validation, retained
  storage limits, staging safeguards, and bounded buffers still apply.

Cloudflare Cache API/CDN behavior, all storage failure interleavings, and all
maintenance recovery states have not been exhaustively compared. These
differences are not a claim that every unlisted behavior has been proven equal.

## Rust server observability (opt-in)

PostHog export is behind the Rust server's `observability` Cargo feature,
which is off by default. Opt in with either build:

```bash
nix build .#server-observability
# Or, inside nix develop:
cargo build --release -p snowstead-server --features observability
```

The default `server` package and deployment bundles still use the build
without this feature. To enable export in a deployment, explicitly select
the observability-enabled server package. Existing Hotpath profiling is
separate and is not enabled by `observability`.

For an observability-enabled binary, configure export through its runtime
environment, not Nix build arguments:

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTHOG_PROJECT_TOKEN` | unset | PostHog project token; required together with `POSTHOG_HOST` to export |
| `POSTHOG_HOST` | unset | Regional PostHog ingestion origin |
| `OBSERVABILITY_SAMPLE_RATE` | `0.4` | Trace sampling rate (40%) |
| `OTEL_SERVICE_NAME` | `snowstead-api` | Telemetry service name |
| `SNOWSTEAD_RELEASE` | unset | Optional release ID |

With both PostHog variables missing, logging stays in the local journal only.
Partial or invalid configuration disables export with a safe warning that
does not reveal credentials. Set `POSTHOG_HOST` to the regional ingestion
origin, not a dashboard URL or signal-specific endpoint. SDK error reporting
uses PostHog; OTLP export appends `/i/v1/traces`, `/i/v1/logs`, and
`/i/v1/metrics` to that origin. PostHog metrics support is alpha.

Export is asynchronous and bounded; request handling does not wait for
PostHog ingestion, and telemetry can be dropped under pressure. It is not a
durable audit log. Exported telemetry excludes secrets, raw SQL, request
bodies, cookies, query strings, and storage keys. Keep project tokens out of
source control, command arguments, and diagnostic output.

Spans cover HTTP requests through response streaming, database queries and
transaction waits, storage reads and mutations, multipart uploads, outbound
HTTP requests and response reads, and maintenance stages. Operation names
are static; arguments and provider errors are not exported. This uses the
existing Axum middleware and `tracing-opentelemetry` bridge rather than a
second HTTP tracing layer. All additional spans compile out without the
`observability` feature (existing profiling remains independently opt-in).

## Setup

Configure the CLI with your gateway URL and admin secret:

```bash
snowstead login --token-stdin --url https://cache.example.com --name prod < admin-token-file
```

## Using as a substituter

```nix
nix.settings.substituters = [ "https://cache.example.com/main" ];
```

## Private caches

Caches are public unless created private. Reading a private cache
(`nix-cache-info`, narinfo, NARs) needs a token with `pull` on it, as a
bearer token or as the password of HTTP Basic auth, which is what Nix sends
from a netrc file.

```bash
snowstead cache create team --protocols nix --private
# For an existing cache: snowstead cache set team --private
snowstead token create builders --caches team --perms pull
```

New caches require an explicit protocol selection: `--protocols nix`,
`--protocols go`, `--protocols sccache`, or a comma-separated combination (no default).
API creation payloads likewise require a nonempty `protocols` array of these names on
`POST /_api/v1/admin/caches` and `POST /_api/v1/orgs/:org/caches`.
Existing caches keep their protocols when omitted on updates. To add Go to a
Nix cache, use `snowstead cache set team --protocols nix,go`; updates must keep
all enabled protocols and cannot remove them. Cache lists, details, and creation
responses include the `protocols` array. Existing database caches keep Nix and
Go enabled; sccache requires explicit opt-in.

On the machines that substitute from it:

```
# /etc/nix/netrc
machine cache.example.com
password <the pull token>
```

```nix
nix.settings = {
  substituters = [ "https://cache.example.com/team" ];
  netrc-file = "/etc/nix/netrc";
};
```

Only empty caches can change visibility. Private reads check current SQL
authorization and publication state. Private NAR downloads are authorized
and streamed by the Rust server, never redirected to a reusable presigned URL.

## Managing tokens

JWT tokens scope write access to specific caches. The signed JWT is
returned once on creation and never stored. Save it immediately.

```bash
# Create a token scoped to the "main" cache with push access
snowstead token create ci-runner --caches main --perms push --expires 90

# Create a token with access to all caches
snowstead token create admin-bot --caches "*" --perms push,pull

# List all tokens
snowstead token list

# Revoke a token
snowstead token revoke $JTI "employee offboarded"
```

| Option | Default | Description |
|--------|---------|-------------|
| `--caches` | `*` | Comma-separated cache names or `*` for all |
| `--perms` | `push` | Comma-separated: `push` and/or `pull` |
| `--expires` | `90` | Token lifetime in days (1-365) |

## Pushing store paths

Log in with a push token (not the admin secret):

```bash
snowstead login --token-stdin --url https://cache.example.com --name prod < push-token-file
```

Then push:

```bash
# A path and its runtime closure
snowstead push main /run/current-system

# Built flake outputs, read from stdin
nix build --no-link --print-out-paths .#nixosConfigurations.myhost.config.system.build.toplevel \
  | snowstead push main

# Only the exact path, without its references
snowstead push main /nix/store/abc...-hello --no-deps
```

References are published before the paths that need them. `.drv` paths are
rejected unless you pass `--allow-drv`.

Use `--jobs <n>` to control how many paths are in flight (default 32).

Paths that an upstream cache already serves are not pushed: whoever
substitutes from a cache has its upstreams too. The upstreams are the
`UPSTREAM_CACHES` runtime variable, space-separated; set it empty to push everything.
The server remembers paths found upstream, so each is looked up there once.

## Migrating from AUTH_TOKEN

1. Set `JWT_SECRET` and `ADMIN_SECRET` in the Rust runtime's secret environment.
2. Log in with the admin secret: `snowstead login --token-stdin --url "$URL" --name prod < admin-token-file`
3. Create scoped tokens: `snowstead token create ci-runner --caches main`
4. Update publishers to log in with their JWT
5. Remove `AUTH_TOKEN` to disable legacy auth

## Audit logging

All write operations and admin actions are logged to Postgres with actor,
action, cache name, IP, and status code. Logs are retained for 30 days.
Each entry also records its org; an org reads its own with
`GET /_api/v1/orgs/:org/audit`.

## Orgs

A hosted service runs Snowstead for many tenants. Each tenant is an org,
which has caches, tokens, API keys, an audit log, and operator-set limits
in Postgres. Membership and commercial policy stay with the service that
runs Snowstead, outside the cache service.

A self-hosted install doesn't need to know about any of this: everything
belongs to the `default` org, which has no storage limit, and tokens made
without an org are its tokens.

- **Cache names are an org's own.** Each org has a slug, and its caches
  are served at `<host>/<slug>/<name>`, so every org can have a `main`.
  The default org's caches stay at `<host>/<name>`. Public caches are
  stored at their URL for the CDN to serve, so changing an org's slug
  moves objects: `PUT /orgs/:org` readies the new paths, then
  `POST /orgs/:org/move` moves the narinfo a page at a time. Until it's
  done the org keeps its old slug, and the old URLs answer for paths not
  moved yet; after, they're gone.
- **Each org has its own API** under `/_api/v1/orgs/:org`: its storage,
  caches, tokens, API keys, and audit log. `ADMIN_SECRET` reaches every
  org; an org's API key (`snowstead_key_…`) reaches only its own. Only the
  operator sets org limits and permissions, and makes API keys.
  An org without private-cache permission keeps its
  private caches private and readable, but they take no pushes, and it
  can't make new ones.
- **Tokens reach only their org's caches,** for pushing and for pulling
  from a private cache. A token is made naming caches, which it keeps by
  id, so it outlives a rename, or patterns over names where `*` matches
  anything: `ci-*` reaches every cache starting with `ci-`, including
  ones made later, and `*` reaches them all. A push names its cache within
  the token's org, so `snowstead push main` pushes to that org's `main`.
- **Storage limits.** A push that would take an org's caches past its
  limit is refused with 507 before anything uploads.
- **Admission.** Rust does not retain the Worker's per-minute request caps.
  Storage limits, staging safeguards, and bounded runtime resources still apply.
- **Bandwidth.** `GET /orgs/:org` reports `servedThisMonth` for the current UTC
  month's origin bytes. Rust records selected object bytes in SQL, not confirmed
  client receipts. Configured CDN imports report public bytes separately as
  `publicServedThisMonth`.
- **Signing keys.** Each new cache gets its own cryptographically generated
  Ed25519 key, shown as its `publicKey`. Managed key names use the immutable
  cache ID and a random UUID; managed public bytes are unique in Postgres.
  Creation and initial key registration are atomic. `customSigningKeys`
  is an operator-set org permission for BYOK; org API keys cannot
  change it. Removing permission does not disable an active imported key.

### Org limits API

All responses are `Cache-Control: no-store`. `storageLimit` is a nonnegative
safe integer number of bytes, or `null` for unlimited; `0` refuses new storage.

- `GET /_api/v1/admin/orgs` returns
  `{orgs: [{id, slug, storageLimit, privateCaches, customSigningKeys}]}`.
- `PUT /_api/v1/orgs/:org` takes
  `{slug?, storageLimit?, privateCaches?, customSigningKeys?}`. Creation
  requires a slug and defaults to unlimited storage, private caches allowed,
  and custom signing keys disallowed. Omitted limits preserve existing
  values, including concurrent updates. Unknown fields are rejected with 400.
- Org GET and PUT responses contain `id`, `slug`, `movingFrom`,
  `storageLimit`, `privateCaches`, `customSigningKeys`, `used`, `pending`, and
  `servedThisMonth`.
- `GET /_api/v1/admin/overview` retains the global operator overview.

All admin endpoints and org PUTs require operator `ADMIN_SECRET`
authentication; org API keys cannot change their own limits or list all orgs.
`org.put` records old/new slug and limits in the affected org's audit log,
with the operator or forwarded dashboard actor identity.

Limits are read from Postgres on every enforcement lookup.
Updates apply immediately on subsequent requests. Lowering a limit never
deletes published data or makes a private cache public: it refuses disallowed
new pushes and new private caches, and blocks BYOK import/activation while
leaving already-active keys working.

Rust reads authorization from SQL; no KV synchronization is required.
The compatibility `POST /_api/v1/admin/auth/sync` route does not populate KV.

### Cache policy API

Apply the Rust migrations through infra before deploying. All endpoints below
use `/_api/v1/orgs/:org` (the org ID, not its mutable slug),
return JSON with `Cache-Control: no-store`, and require `ADMIN_SECRET` or that
org's management API key unless stated otherwise. Dates are ISO strings; sizes
are integer bytes. Errors use `{ "error": "message" }`.

#### Token last use

| Method and suffix | Body | Response |
| --- | --- | --- |
| `GET /tokens` | none | `{ tokens: Token[] }` |
| `GET /tokens/:jti` | none | `{ token: Token }`; 404 for missing or another org's token |

`Token` is `{ jti, subject, caches: string[], perms: string[], org, createdAt,
lastUsedAt, expiresAt, createdBy, revokedAt, revokedBy, revocationReason }`.
`lastUsedAt` is an ISO string or null; it is the only addition to the existing
org token-list shape. The operator-wide admin token list is unchanged.
`expiresAt`, `revokedAt`, `revokedBy`, and `revocationReason` can be null.

Successful JWT authentication for Nix, Go, and sccache attempts a conditional
SQL update through the bounded connection pool. A token's timestamp changes at most once
per five minutes, including concurrent calls. It records authentication, not
successful artifact delivery. Anonymous public/CDN reads cannot identify a
token. This is best-effort activity telemetry, not a security audit or exact
request counter; failed writes can leave it stale.

#### Eviction visibility

`GET /eviction?limit=50&nextCursor=...&recentCursor=...` has no body. `limit`
defaults to 50, must be 1–200, and applies separately to each list. Cursors are
opaque strings; URL-encode them and pass each list's cursor independently.
Null means the end of that list. The JSON response is:

```ts
{
  next: { items: Candidate[], cursor: string | null, bytesToFree: number },
  recent: { items: Eviction[], cursor: string | null }
}
// Candidate:
{ product: "nix" | "go" | "sccache", cache: string, cacheId: number,
  key: string, size: number, lastAccessedAt: string | null }
// Eviction: Candidate plus
{ id: number, evictedAt: string,
  reason: "capacity" | "retention" | "clear" | "evict" }
```

For Nix, `key` is the full store path; for Go/sccache it is the action key.
`next` uses capacity's shared selection query, ordered by the later of last
publication and access, then product and entry ID. It excludes pinned closures,
active Nix uploads/installations, and expired/obsolete action entries. It is
an advisory preview, not a reservation: row locks, accesses, and uploads can
change what admission actually removes. Each response uses a consistent DB
snapshot; subsequent pages are live views, not a frozen multi-request snapshot.
`bytesToFree` is `max(used - storageLimit, 0)`, or zero for unlimited storage;
it excludes pending transfers and hypothetical future uploads. Candidates are
still available when this number is zero.

`recent` is newest-first by log ID. Set-based SQL triggers record logical
removal transactionally: capacity (`capacity`), expired-data GC (`retention`),
product resets, explicit path deletion and cache deletion (`clear`), or the
whole-cache endpoint below (`evict`). Later physical cleanup does not duplicate
events. Logs retain the cache's ID and name even after deletion/name reuse.
Only the last 30 days are returned; Rust's scheduled GC sweeps older rows.

#### Named Nix pins

| Method and suffix | Body | Response |
| --- | --- | --- |
| `GET /caches/:name/pins` | none | `{ pins: Pin[] }`, ordered by name |
| `POST /caches/:name/pins` | `{ name, storePath, keep }` | `{ pin: Pin }`; 201 created, 200 updated |
| `DELETE /caches/:name/pins/:pin` | none | `{ deleted: true, name: string }`, including an already absent pin |

```ts
type Keep = "forever" | { days: number } | { revisions: number };
type Pin = {
  name: string; keep: Keep; currentRevision: number;
  history: { revision: number; storePath: string; createdAt: string;
    supersededAt: string | null; pinned: boolean }[];
};
```

Pin names match `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; `storePath` is a full
`/nix/store/<hash>-<name>` path; days/revisions are integers 1–10000. Unknown
request fields and invalid policies return 400. POST and DELETE also accept a
JWT with Nix `push` permission for this exact cache and org. GET remains
management-only. Writes audit `pin.create`, `pin.update`, or `pin.delete`.

Re-pinning a name to a different path adds a monotonically numbered revision;
retrying the current path does not add another. History is newest-first.
The current revision always remains pinned. `forever` keeps every revision;
`revisions: N` keeps the newest N including current; `days: N` keeps an old
revision for N days after it was superseded. Old history remains visible after
protection expires, until the pin is deleted. Extending keep returns 409 if it
would reactivate a revision with missing paths.

Closure handling is **cache-local and transitive**: a recursive SQL query
deduplicates cycles/shared dependencies, then inserts indexed membership rows
in one batch per revision. The root and every referenced dependency must
already be published in this cache (409 otherwise); upstream-only dependencies
are not fetched or silently assumed protected. More than 10000 distinct paths
returns 413. Creation cost and stored membership scale with closure size;
history storage scales with revisions and their closures. Candidate scans use
indexed membership checks, not recursive traversal. Pin mutations serialize
with publication and deletion under the existing org-then-cache transaction
locks. Pinned roots and dependencies cannot be removed by capacity, retention,
or the existing individual-path deletion endpoint. Whole-cache eviction and
cache deletion explicitly override pins.

#### Empty a cache without deleting it

`POST /caches/:name/evict` takes **no body** and returns:

```ts
{ evicted: true, name: string,
  removed: { nix: number, go: number, sccache: number }, pinsDeleted: number }
```

This management-only operation audits `cache.evict`, removes all Nix paths and
Go/sccache rows (including staged/obsolete rows still attached to the cache),
and deletes all its pins. It preserves the cache ID, slug, protocols/settings,
tokens, and signing keys. It invalidates old action generations and aborts Nix
sessions, so pre-eviction uploads cannot publish later. A fresh upload after
the operation can repopulate the cache.

The operation follows org → upload-session fence → cache → entry lock order;
SQL changes and eviction logs commit together after idempotent external deletes.
Partial external failure leaves durable SQL retry records; retry the request.
An already empty cache returns zero counts. External deletes cannot roll back,
so some objects may already be unavailable after a failed attempt. NAR blobs
remain for reference-aware GC so other caches sharing them are not damaged.
Detached Go/sccache objects from earlier capacity eviction remain owned by GC.
Large evictions use batches internally but hold transaction locks until the
request finishes; they can delay uploads and should run outside peak CI load.

### Cache signing key lifecycle

Run database migrations before deploying. Signing management uses the org
API's bearer authentication (`ADMIN_SECRET` or that org's API key), not a
push token. BYOK staging and activation require `customSigningKeys`; managed
key rotation does not. In the dashboard, mutations require the org owner.
All responses are
`Cache-Control: no-store`; private or sealed key material is never returned.

Under `/_api/v1/orgs/:org/caches/:cache/signing-keys`:

- `GET` returns `activePublicKey`, `shared` (true while the cache signs with
  the service's key rather than one of its own), and `keys`, each with `id`, `publicKey`,
  and `state` (`staged`, `active`, or `retired`). New initial managed keys
  have history IDs. A legacy shared key has `id: null` until its first
  rotation records its history.
- `POST {}` generates a Snowstead-managed key, **staged**, not yet signing.
- `POST {"secretKey":"name:base64"}` stages a BYOK Nix secret key. Import
  requires canonical base64 of exactly 64 bytes (32-byte Ed25519 seed then
  its matching public half). Names are 1–200 ASCII characters: alphanumeric
  first, followed by alphanumeric or `._/+-`. Do not send a PEM, bare seed,
  or trailing newline. The secret is sealed with AES-GCM under
  `SIGNING_MASTER_KEY`, authenticated to the version, cache ID, key UUID,
  name, and public key. Both staging forms
  return `201 {id, publicKey, state: "staged"}`. A key name cannot be reused
  in the cache, including its historical keys or the service key name.
- `POST /:id/activate {"trustedPublicKeys":["name:base64", ...]}` activates
  a staged key and retires the previous active key atomically. First deploy
  **all** keys returned by GET to clients' `trusted-public-keys`, retaining
  old keys; then pass that full set as explicit confirmation. Missing trust
  confirmation or a non-staged key returns 409; a missing cache/key is 404.
  Activation does not prove clients were updated: the caller must ensure it.

Staging and activation require `SIGNING_MASTER_KEY` (409 without it).
Legacy shared signing is available only with explicit self-hosted opt-out
from the required-per-cache-key policy. The
cache's existing `publicKey` field continues to show its current active key;
use this lifecycle GET to discover the complete trust set after rotations.
Retired public keys are retained permanently, and cannot be reactivated or
deleted through this API. Their sealed secrets are removed from history.

Rotation is **trust overlap**, not indefinite dual signing: new publications
use only the new key. Existing R2/CDN narinfo is untouched and keeps its old
signature and URL. Keep historical public keys trusted for as long as those
objects or client caches exist. An explicit narinfo backfill may replace old
signatures; don't use one as an automatic rotation step. This API is not an
emergency compromise-revocation mechanism: removing old trust safely would
require a separate re-sign/backfill and R2/CDN/client invalidation plan.
No CDN purge is needed for this additive rotation. Any future rewrite must
purge the rewritten narinfo URLs after R2 writes; purge implementation is
outside signing management.

Publication uses the current signing key from Postgres. There is no signing
on public reads.
A publish already in flight at activation may finish with the prior key,
which is another reason to retain overlapping trust. Rotation does not
rotate `SIGNING_MASTER_KEY`; retain that deployment secret to open active
and staged keys.

### Signing-key backup and recovery

Back up Postgres (including caches and key history) and keep a separate,
access-controlled backup of `SIGNING_MASTER_KEY` in a password manager or
secrets vault. Restrict production secret access to operators; never put
keys in logs, source control, public R2, or support tickets. A database
backup alone cannot restore signing. The master key can decrypt every
tenant key, so it remains a shared security boundary, not HSM isolation.

Before inviting testers, restore a database backup into an isolated
environment using the matching master key, publish a test narinfo, and
verify its signature against the unchanged advertised public key. A wrong
or missing master key must fail rather than fall back to a shared key.
Existing v1 sealed keys remain readable; newly sealed keys use v2 identity
authentication. Do not replace the master secret to rotate cache keys:
that makes existing ciphertext unreadable. Master-key rotation and
emergency compromise recovery need a separate, tested migration plan.
