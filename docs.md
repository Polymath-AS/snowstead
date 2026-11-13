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

### Existing-installation cutover

Back up and restore-test the existing database before migration. Preserve the
original `JWT_SECRET`, `ADMIN_SECRET`, signing master key, database, buckets,
object keys, cache URLs, and CDN rules. Supply the existing master-key value as
Rust's `SIGNING_MASTER_KEY`; a new key makes sealed signing keys unreadable.
Legacy self-hosters must also preserve shared signing settings, and keep
`AUTH_TOKEN` with `ALLOW_SHARED_AUTH_TOKEN=true` until their clients migrate. Keep secret values out of source control and logs.

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

Apply the additive `0001_optimistic_publication.sql` migration before deploying
the new server. It adds bucket pointers, durable object ownership, completion
receipts, and the exact-key cleanup queue without removing legacy objects.
Drain old writers and maintenance before cutover. Legacy canonical ownership
records never expire automatically; reconcile ambiguous provider operations
before an operator releases their source/destination pins.

The additive `0014_lifecycle_constraints.sql` migration names the persisted
state machines documented in `workers/server/src/lifecycle.rs`. Its CHECK
constraints are `NOT VALID`, so rows written by retired releases are not
scanned and cannot fail the deployment; new and updated rows are checked. It
also indexes upload sessions by cache and path, and enforces one active
signing key per cache unless the database already holds a cache with several,
which it reports with a warning instead.

After publishing immutable pointers, do not roll back to a server that cannot
read them. Use a compatible reader release or a forward fix.

The hosted `REQUIRE_CACHE_SIGNING_KEYS=true` policy refuses cache creation
without a master key and refuses publication without a per-cache key.
Self-hosters may explicitly set it to `"false"` to use
`SIGNING_PRIVATE_KEY` for caches without their own key. Existing shared-key
caches need trust-overlap activation before publishing under hosted policy;
do not silently replace a key clients already trust.

### Presigned-upload cutover

This release replaces relayed multipart bodies with direct S3 UploadPart grants.
It needs no additional schema migration, bucket, public route, or CLI credential.
Keep the existing private-bucket S3 endpoint and credentials. Clients must be
able to reach that endpoint over HTTPS. The storage credential must permit
multipart creation, part upload, completion, abort, read, and delete. Do not
replace the S3 API endpoint with a public bucket or CDN hostname.

Before activation:

1. Build both release packages and run the real CLI proof below against disposable
   Postgres and S3. This checks the packaged binaries, not only debug builds.
2. Verify direct part signing and completion against an isolated R2 test bucket.
   Local MinIO tests do not prove provider compatibility or production capacity.
   Never run the normal server with a disposable database and live buckets: its
   maintenance process can classify live objects as orphans.
3. Stop new pushes and let current pushes finish, or cancel them through the
   existing authenticated API. Cancellation is an operator action, not part of
   deployment. Restart cancelled pushes after the upgrade.
4. Deploy through `infra/deploy.sh`. It runs the candidate's read-only
   `snowstead-server check-upload-cutover` with the runtime environment before
   activation. The command reports the count of active relay sessions containing
   uploaded parts and exits unsuccessfully until those sessions drain or are
   cancelled. Server startup repeats the guard in case an old writer races the
   preflight. Do not bypass it by editing upload receipts or provider IDs.

To verify the release packages locally, from the repository root:

```bash
server=$(nix build --no-link --print-out-paths .#server)
cli=$(nix build --no-link --print-out-paths .#default)
SNOWSTEAD_TEST_SERVER="$server/bin/snowstead-server" \
SNOWSTEAD_TEST_CLI="$cli/bin/snowstead" \
nix develop --command env -u SNOWSTEAD_TEST_DATABASE_URL \
  scripts/with-postgres.sh scripts/with-r2.sh \
  node --test workers/server/test/cli.mjs
```

The proof uses default CLI concurrency, checks that multipart bytes bypass the
API, verifies downloaded NARs against the local Nix store, and exercises restart
and cutover refusal. It creates only disposable databases and buckets.

After activation, run a bounded CLI push before resuming bulk uploads. Verify
completion and a signed download, not only a successful part PUT. Do not log
presigned URLs: they grant temporary write access to a reserved part.

Before rolling back to a relay-only server, drain or abort direct-storage
sessions with the new server. Old code cannot resume their provider uploads.
Keep the database, published objects, and signing keys intact; prefer a forward
fix if an upload or publication has an ambiguous result.

### Public caches on a custom domain

Use the Rust origin as the substituter URL, including for public caches.
Rust renders narinfo from current SQL publication and signing state, and
serves `nix-cache-info` after resolving the cache in SQL. Neither metadata
endpoint redirects to the CDN or reads mutable metadata from R2.
Public narinfo has a five-minute TTL and an ETag derived from the rendered
bytes; misses use `no-store`. Public cache-info has a one-hour TTL.
Private metadata requires authorization and uses `private, no-cache`.

Only public NAR bytes use the bucket hostname. With `PUBLIC_CACHE_ORIGIN`
configured, Rust validates publication and redirects to the committed bucket
pointer (or a validated legacy key). Without it, Rust streams public NARs.
Private NARs always stream through Rust after authorization, without reusable
presigned redirects. Hosted production keeps `cache.snowstead.com` as the
public NAR origin, not the substituter metadata origin.

For a self-hosted public bucket, use a dedicated custom domain on a zone in
the same account and a Cache Rule. Keep API and private reads on Rust.
Cloudflare does not cache `.nar` by default:

```bash
wrangler r2 bucket create snowstead-public
wrangler r2 bucket local-uploads enable snowstead-public
wrangler r2 bucket domain add snowstead-public --domain cache.example.com --zone-id <zone id>
```

Cache Rule, on the zone:

- Expression: `(http.host eq "cache.example.com" and not starts_with(http.request.uri.path, "/_api/") and not starts_with(http.request.uri.path, "/private/"))`
- Cache eligibility: eligible; Edge TTL: use cache-control if present,
  bypass if not, and 60 seconds for status 404; Browser TTL: respect origin.

New NAR objects have unique immutable keys; SQL stores separate public/private
bucket pointers while retaining logical content deduplication. Public NARs
use a one-year immutable TTL. The bucket rule's one-minute negative TTL
does not apply to Rust metadata misses.

Legacy CDN invalidation remains available. Purging needs the vars
`CDN_ZONE_ID` and `PUBLIC_CACHE_ORIGIN` and the
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

**Upgrading:** old raw CDN narinfo/cache-info and client copies can remain
stale, including former one-year TTLs. Switch substituters to the Rust origin.
SQL withdrawal, slug changes, and signing activation do not erase those copies.
Backfill repairs missing NAR bucket pointers and queues known legacy metadata
keys for asynchronous deletion; it does not rewrite mutable metadata or
shorten existing edge/client TTLs. Plan explicit legacy CDN invalidation where
needed. Purges do not clear client caches or revoke public bytes already shared.

### Optimistic publication and cleanup

Nix publication first records ownership of a unique destination key and
protects its source. Storage copying runs outside SQL transactions and does
not reserve retained capacity. A short SQL transaction then checks ownership,
expiry, current policy, and signing configuration, admits retained capacity,
and atomically adopts the bucket pointer, publishes the path, and saves the
completion receipt. Replaying that receipt does not republish withdrawn paths.
A stale attempt cannot adopt its object or overwrite published bytes.

These are SQL-only, fail-fast decisions, not literal lock freedom.
They use bounded connection acquisition, `pg_try_advisory_xact_lock`, explicit
`NOWAIT` locks, and a 100 ms `lock_timeout` after acquiring the org fence.
Same-process writers wait on a per-org gate before borrowing a connection,
with the pool's acquisition deadline and a bounded queue of at most one waiter
per configured pool connection. Queue slots do not borrow connections.
Transaction startup finishes even if its caller disconnects: cancelling SQLx
0.9 during `BEGIN` can otherwise return an untracked transaction to the pool.
The gate ends with each transaction and never spans storage I/O. PostgreSQL
still serializes writers across server instances; rejected writers must retry.
The CLI retries explicit session-creation 503 responses up to four attempts,
but does not replay a lost creation response. The Go helper retries uploads
marked `503` with `Retry-After: 1` before opening its circuit breaker.

Capacity remains logical and shared across Nix, Go, and sccache. Admission
counts committed retained entries, separately from staging budgets.
LRU ordering still uses the later of publication and access, with existing
pin and active-upload protections. Direct CDN downloads do not update access.
Quota eviction and publication commit together after storage preparation.
Failed preparation or a rolled-back publication does not evict existing content.

Deletion, retention, and eviction withdraw SQL visibility atomically and queue
known exact keys for asynchronous cleanup. Storage failure does not roll back
the committed withdrawal. Maintenance retries idempotent deletion outside SQL
transactions. Expiry revokes adoption of new attempts, not provider work;
orphan sweeps find late writes. Legacy canonical ownership never autoexpires.

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
Postgres/S3 and fresh local client caches.

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
  Only public NAR delivery uses the configured CDN handoff.
- **Backfill:** `POST /_api/v1/admin/narinfo/backfill` repairs missing NARs
  from the recorded source using an immutable destination and conditional SQL
  adoption. It queues known legacy public/private metadata keys for cleanup,
  rather than writing narinfo. `written` counts adopted NAR repairs, not
  metadata writes. Follow `next` through all pages and review `skipped`.
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

API tokens (`snowstead_tok_…`) scope access to specific caches. The token is
returned once on creation; the server keeps only a hash of it. Save it immediately.

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

1. Set `ADMIN_SECRET` in the Rust runtime's secret environment, and keep
   `AUTH_TOKEN` with `ALLOW_SHARED_AUTH_TOKEN=true` meanwhile.
2. Log in with the admin secret: `snowstead login --token-stdin --url "$URL" --name prod < admin-token-file`
3. Create scoped tokens: `snowstead token create ci-runner --caches main`
4. Update publishers to log in with their token
5. Remove `ALLOW_SHARED_AUTH_TOKEN` and `AUTH_TOKEN` to disable legacy auth

## Authentication and authorization

Authentication turns a request's bearer credential into one principal;
`workers/server/src/authz.rs` then decides, in one function, whether that
principal may take the route's action on its org, cache, or the service.
Anything it does not allow is denied.

| Credential | Principal | May |
| --- | --- | --- |
| `ADMIN_SECRET` | operator | `/_api/v1/admin/...` only, including org creation and limits |
| `snowstead_web.<claims>.<signature>` | dashboard user (owner, admin, or member) | its org's management API; only the owner changes the slug, API keys, or signing keys, or moves caches |
| `snowstead_key_<id>_<secret>` | org API key | its org's management API, except creating keys and changing the slug |
| `snowstead_tok_<id>_<secret>` | API token | Nix, Go, and sccache in its org, per its permissions and caches; pins with `push` |
| JWT-era token | API token | the same, only while its `jti` is listed and unrevoked in `api_tokens` |
| `AUTH_TOKEN` | shared token | Nix pushes to the `default` org, only with `ALLOW_SHARED_AUTH_TOKEN=true` |

API tokens store only a SHA-256 hash of their secret. Their permissions and
caches live in `token_permissions` and `token_caches` and are read on every
request; a JWT's own claims grant nothing. Migration `0015_central_auth.sql`
backfills those tables from existing rows.

The dashboard signs each org request with an Ed25519 key. The claims are
`{aud: "snowstead-cache", org, sub, email, role, iat, exp, method, path, body}`,
base64url-encoded JSON signed over `snowstead_web.<claims>`. They live at most
60 seconds and bind the request's method, path (with its query), and body
(`body` is the hex SHA-256 of the request body, of the empty string when
there is none). The
route's org must match, and audit logs name `user:<email>` from the claims.
`WEB_ASSERTION_PUBLIC_KEYS` holds the base64 raw public keys, separated by
whitespace for rotation.

The server refuses to start without an `ADMIN_SECRET` of at least 16
characters, with a malformed or empty `WEB_ASSERTION_PUBLIC_KEYS`, with
`ALLOW_SHARED_AUTH_TOKEN=true` but no `AUTH_TOKEN`, or without `JWT_SECRET`
while unrevoked JWT-era tokens exist. Self-hosters without a dashboard set
`WEB_ASSERTIONS_DISABLED=true` instead of keys. The local development key,
whose private half the dashboard's `.env.example` publishes, is refused
unless `SNOWSTEAD_LOCAL_DEV_WEB_KEY=true`, which only `pnpm dev` sets.

### Rolling out central authorization

The previous dashboard calls org routes with `ADMIN_SECRET` and an
unverified `x-snowstead-actor`. `ALLOW_LEGACY_WEB_ADMIN=true` accepts those
calls again, as a transitional principal allowed exactly what the operator
was on org routes. The server warns at startup while it is on, and audit
entries it produces carry `"legacyWeb": true`. Deploy in this order:

1. Apply migration `0015_central_auth.sql`. The previous server keeps
   working against it.
2. Deploy the server with `ALLOW_LEGACY_WEB_ADMIN=true` and
   `WEB_ASSERTION_PUBLIC_KEYS`.
3. Deploy the dashboard with its `CACHE_ASSERTION_PRIVATE_KEY`.
4. Remove `ALLOW_LEGACY_WEB_ADMIN` and restart the server.

Validly signed JWTs whose `jti` is not in `api_tokens` stop working at step
2. That is intended: only listed tokens can be revoked. A JWT-era row whose
`perms_json` or `caches_json` was invalid, or empty, gets no permissions or
caches, so it is refused rather than widened. After migrating, list live
JWT-era tokens left without either:

```sql
SELECT t.jti, t.org_id, t.subject
FROM api_tokens t
WHERE t.secret_hash IS NULL
    AND t.revoked_at IS NULL
    AND (t.expires_at IS NULL OR t.expires_at > now())
    AND (NOT EXISTS (SELECT 1 FROM token_permissions p WHERE p.token_jti = t.jti)
        OR NOT EXISTS (SELECT 1 FROM token_caches c WHERE c.token_jti = t.jti));
```

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
  The default org's caches stay at `<host>/<name>`. `PUT /orgs/:org`
  changes SQL routing immediately; Rust serves metadata at the new slug
  and refuses the old slug. `POST /orgs/:org/move` queues known old
  metadata keys for cleanup and clears `movingFrom`. It does not move
  NARs or rewrite narinfo. Old raw CDN/client copies can remain stale.
- **Each org has its own API** under `/_api/v1/orgs/:org`: its storage,
  caches, tokens, API keys, and audit log. The dashboard reaches it for its
  signed-in users, and an org's API key (`snowstead_key_…`) reaches only
  its own; `ADMIN_SECRET` does not. Only the operator sets org limits and
  permissions, through `/_api/v1/admin/orgs/:org`.
  An org without private-cache permission keeps its
  private caches private and readable, but they take no pushes, and it
  can't make new ones.
- **Tokens reach only their org's caches,** for pushing and for pulling
  from a private cache. A token is made naming caches, which it keeps by
  id, so it outlives a rename, or patterns over names where `*` matches
  anything: `ci-*` reaches every cache starting with `ci-`, including
  ones made later, and `*` reaches them all. A push names its cache within
  the token's org, so `snowstead push main` pushes to that org's `main`.
- **Storage limits.** Verified Nix candidates do not reserve retained capacity.
  A short SQL transaction admits current usage, evicts eligible LRU entries
  across products, publishes pointers, and records completion together. Failed
  preparation or publication does not evict existing content. Staging has its
  own budget; retained admission can fail after uploads finish. A publication
  needing more than 256 evictions must first delete retained paths explicitly.
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
- `GET /_api/v1/admin/orgs/:org` returns one org as the org GET does.
- `PUT /_api/v1/admin/orgs/:org` takes
  `{slug?, storageLimit?, privateCaches?, customSigningKeys?}`. Creation
  requires a slug and defaults to unlimited storage, private caches allowed,
  and custom signing keys disallowed. Omitted limits preserve existing
  values, including concurrent updates. Unknown fields are rejected with 400.
- Org GET and PUT responses contain `id`, `slug`, `movingFrom`,
  `storageLimit`, `privateCaches`, `customSigningKeys`, `used`, `pending`, and
  `servedThisMonth`.
- `GET /_api/v1/admin/overview` retains the global operator overview.

Admin endpoints require operator `ADMIN_SECRET` authentication. An org's
owner can change only its slug, with `PUT /_api/v1/orgs/:org` and
`{slug}`; org API keys cannot change limits or list all orgs. `org.put`
records old/new slug and limits in the affected org's audit log, with the
operator (`admin`) or the signed-in user as actor.

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
return JSON with `Cache-Control: no-store`, and require a dashboard user's
assertion for that org or that org's API key unless stated otherwise. Dates are ISO strings; sizes
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

Successful API token authentication for Nix, Go, and sccache attempts a conditional
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
request fields and invalid policies return 400. POST and DELETE also accept an
API token with Nix `push` permission for this exact cache and org. GET remains
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
with publication and deletion through short, fail-fast SQL decisions,
not locks held across storage I/O. Pinned roots and dependencies cannot be
removed by capacity, retention, or the existing individual-path deletion
endpoint. Whole-cache eviction and cache deletion explicitly override pins.

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

SQL withdrawal, upload invalidation, eviction logs, and exact-key cleanup
records commit together. No storage deletion runs under those locks.
An already empty cache returns zero counts. Maintenance deletes retired
objects asynchronously and retries failures; it does not roll back withdrawal.
Shared NAR blobs remain for reference-aware GC. Detached Go/sccache objects
from earlier capacity eviction remain owned by GC. Large SQL withdrawals
can still contend with writers; fail-fast callers must retry.

### Cache signing key lifecycle

Run database migrations before deploying. Signing management uses the org
API's bearer authentication (a dashboard assertion or that org's API key), not a
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

Rotation is **trust overlap**, not indefinite dual signing. Rust renders
narinfo for existing and new publications with the current SQL signing key,
including on public reads. Activation changes freshly rendered bytes and
their ETags without an R2 rewrite or backfill. Publication validates current
signing policy at commit; rotation does not cancel prepared candidates.

Keep historical public keys trusted while old CDN or client copies exist.
Cached API narinfo can also retain the prior signature until revalidation.
Rotation does not purge those copies. This API is not an emergency
compromise-revocation mechanism; removing old trust needs a separate CDN/client
invalidation and recovery plan. Backfill repairs NAR pointers, not signatures.
Rotation does not rotate `SIGNING_MASTER_KEY`; retain that deployment secret
to open active and staged keys.

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
