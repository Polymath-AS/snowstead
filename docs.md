# Snowstead Documentation

## Deployment

The root `wrangler.jsonc` is the public **gateway** (`snowstead`). It routes
management APIs to `snowstead-control`, Nix reads/uploads to `snowstead-nix`,
`/_api/v1/go/` artifact requests to `snowstead-go`, and `/_api/v1/sccache/`
compiler artifacts to `snowstead-sccache`
over HTTP service bindings, forwarding the original URL, headers, and body.
It has no database, storage, signing, or authorization logic. The service
configs are under `workers/control`, `workers/nix`, `workers/go`, and `workers/sccache`.
Only control runs garbage collection and CDN-purge retries. Hosted reads enter
through snowstead-web's owner/cache gateway, which uses the existing R2/CDN
origin for public objects. The production cache Worker exposes only `/_api/*`;
its workers.dev and preview aliases stay disabled. Staging keeps its existing
read hostname and wildcard route.

The Nix and control services retain Smart Placement; the routing-only gateway
stays at the edge without placement.

The services share the environment's existing R2 buckets, AUTH_KV, Hyperdrive,
database, and signing-master-key source. Shared code and migrations live in
`packages/cache-core`. The Worker split itself leaves existing data unchanged;
Go support additionally requires migrations `0004` and `0005` before rollout.
Give Go the same `JWT_SECRET` as control so it can verify scoped Go tokens;
Go permissions are independent of Nix push/pull permissions. Go management and
cleanup remain in control, not the protocol Worker.

The [sccache backend](workers/sccache/README.md) requires migration `0009` and
the same `JWT_SECRET` as control. Deploy control first, then the protocol
Workers, then the gateway. sccache access requires explicit protocol selection
and `sccache:read` / `sccache:write` permissions.

```bash
wrangler r2 bucket create snowstead-private
# Uploads land near the pusher and replicate to the bucket; reads stay
# consistent. Free, and only faster for pushers far from the bucket.
wrangler r2 bucket local-uploads enable snowstead-private
# Postgres on PlanetScale, with a role holding pg_read_all_data and
# pg_write_all_data. Query caching off: uploads must read their own writes.
wrangler hyperdrive create snowstead --caching-disabled \
  --connection-string "postgres://USER:PASSWORD@HOST:5432/postgres?sslmode=require"
# Set the production Hyperdrive id in both service configs.
# Provision the SAME JWT_SECRET on both services: control issues tokens, Nix verifies them.
wrangler secret put JWT_SECRET --config workers/nix/wrangler.jsonc --env production
wrangler secret put JWT_SECRET --config workers/go/wrangler.jsonc --env production
wrangler secret put JWT_SECRET --config workers/sccache/wrangler.jsonc --env production
wrangler secret put JWT_SECRET --config workers/control/wrangler.jsonc --env production
wrangler secret put ADMIN_SECRET --config workers/control/wrangler.jsonc --env production
# Generate 32 cryptographically random bytes, base64; keep a private backup
# separately from Postgres. Paste through the hidden prompt, not shell arguments.
# The account store container is owned by the infrastructure Terraform stack.
wrangler secrets-store secret create <STORE_ID> \
  --name snowstead-production-signing-master-key --scopes workers --remote
# S3 keys of an R2 token limited to the two buckets (key id: the token id,
# secret: the SHA-256 of its value). With them uploads go straight to R2
# through presigned URLs; without them they go through the Worker. Private
# NARs are always served by the Worker, which checks the reader.
wrangler secret put R2_ACCESS_KEY_ID --config workers/nix/wrangler.jsonc --env production
wrangler secret put R2_SECRET_ACCESS_KEY --config workers/nix/wrangler.jsonc --env production
wrangler secret put R2_ENDPOINT --config workers/nix/wrangler.jsonc --env production # https://<account id>.r2.cloudflarestorage.com
# migrates the database directly (not through Hyperdrive), then deploys
DATABASE_URL="postgres://USER:PASSWORD@HOST:5432/postgres?sslmode=require" pnpm deploy
```

| Secret | Purpose |
|--------|---------|
| `JWT_SECRET` | HMAC-SHA256 key for JWT token signing |
| `ADMIN_SECRET` | Bearer token for the admin API |
| `SIGNING_MASTER_KEY_STORE` | Secrets Store binding to the 32-byte base64 AES-GCM key sealing per-cache signing keys |
| `SIGNING_PRIVATE_KEY` | Legacy shared Ed25519 key; only for explicit self-hosted shared-key mode |

`SIGNING_KEY_NAME` is a non-secret key-name prefix in both service configs.
Hosted deployment explicitly selects `--env production`, whose bindings are
not inherited from the local configuration. Staging must use its own R2, KV,
database, Hyperdrive and environment-prefixed secret source. Cloudflare permits
one Secrets Store per account: source names isolate deployment configuration,
not account-level IAM. Terraform owns the store, never secret values.

### Existing-installation cutover

Deploy control, Nix, Go, and sccache **before** replacing the existing `snowstead` Worker
with the gateway. Keep the original JWT secret, signing-master-key source,
bucket names, KV namespace, and database; generating replacement secrets would
invalidate tokens or make existing sealed keys unreadable. Give both services
the same `CDN_PURGE_TOKEN` when CDN purging is enabled. Legacy self-hosted
installations also move `AUTH_TOKEN` to Nix and shared signing settings to both.
No secret belongs on the gateway; remove its obsolete secrets after acceptance.

For first deployment, private per-service JSON secret files can be supplied
with Wrangler's `--secrets-file` option. Do not commit them. Test the private
services through a local gateway before switching public traffic. Keep the
old deployment available for rollback. `pnpm deploy` migrates the existing
schema, deploys control, then Nix, Go, and sccache, and updates the gateway last. The old
Worker and control may briefly both run maintenance during this sequence;
schedule the cutover between cron invocations rather than running concurrent GC.
The gateway explicitly clears its former schedules. No bucket, database,
KV namespace, public object key, cache URL, or CDN rule is replaced.

The master key is loaded lazily through `SIGNING_MASTER_KEY_STORE.get()` only
when signing or creating keys. Successful reads are reused by the isolate;
failed reads can be retried and never fall back to a different key. A plain
`SIGNING_MASTER_KEY` secret is supported for local/self-hosted installations
only when the store binding is absent. Never replace an existing master key
without a re-encryption migration; a database backup alone cannot recover
sealed signing keys.

Staging uses `cache-staging.snowstead.com`, serving reads through its Worker
instead of production's public CDN. Its database starts empty with the same
migrations; the populated benchmark `dev` branch is not staging. After setting
the non-secret bindings from Terraform's staging handoff:

```bash
# A private JSON file containing distinct staging ADMIN_SECRET and JWT_SECRET.
# Do not copy production values or commit this file.
pnpm exec wrangler deploy --config workers/nix/wrangler.jsonc --env staging --secrets-file /private/staging-nix.json
pnpm exec wrangler deploy --config workers/go/wrangler.jsonc --env staging --secrets-file /private/staging-go.json
pnpm exec wrangler deploy --config workers/control/wrangler.jsonc --env staging --secrets-file /private/staging-control.json
pnpm exec wrangler deploy --env staging
```

Staging uses authenticated proxied uploads until its own bucket-scoped R2
credentials are configured. Its S3 bucket names are explicit, so adding them
cannot silently target production's default bucket names. Staging disables
workers.dev and preview aliases.

The default `REQUIRE_CACHE_SIGNING_KEYS: "true"` refuses cache creation
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
The five-minute cron retries unfinished jobs and respects `Retry-After`;
GC still runs every six hours. Persistent failures appear in Worker error
logs as `CDN purge backlog remains`. Fix the configuration or credentials
and the backlog resumes. No new bucket or database table is needed.

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
applies after those old copies have been replaced; changing the Worker
alone cannot shorten an already-cached response's TTL.

## Setup

Configure the CLI with your gateway URL and admin secret:

```bash
snowstead login prod https://your-worker.workers.dev $ADMIN_SECRET
```

## Using as a substituter

```nix
nix.settings.substituters = [ "https://your-worker.workers.dev/main" ];
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
machine your-worker.workers.dev
password <the pull token>
```

```nix
nix.settings = {
  substituters = [ "https://your-worker.workers.dev/team" ];
  netrc-file = "/etc/nix/netrc";
};
```

Only empty caches can change visibility. Private-cache deletion changes a
generation in KV, so old cached narinfo and NARs stop being served as the
new value propagates. The KV and isolate cache TTLs are 30 seconds, but KV
is eventually consistent and propagation can take 60 seconds or more;
there is no strict global deadline. Private NAR downloads are authorized
and streamed by the Worker, never redirected to a reusable presigned URL.

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
snowstead login prod https://your-worker.workers.dev $PUSH_TOKEN
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
`UPSTREAM_CACHES` var in `wrangler.jsonc`, space-separated
(`https://cache.nixos.org` by default); set it empty to push everything.
The server remembers paths found upstream, so each is looked up there once.

## Migrating from AUTH_TOKEN

1. Set `JWT_SECRET` and `ADMIN_SECRET` via `wrangler secret put`
2. Log in with the admin secret: `snowstead login prod $URL $ADMIN_SECRET`
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
- **Rate limits.** Pushes (per token), org API calls (per key or dashboard
  user), and private reads (per cache and address) each have a limit per
  minute, set under `ratelimits` in `wrangler.jsonc`. Past it, requests get
  429 with `retry-after`. The operator's own `ADMIN_SECRET` calls go
  unlimited.
- **Bandwidth.** `GET /orgs/:org` reports `servedThisMonth`: the NAR bytes
  the Worker served from the org's private caches this UTC month, counted
  by day in `bandwidth_daily`. Public caches are served by the bucket and
  CDN without the Worker, so they aren't counted here.
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

Limits are read from Postgres on every enforcement lookup, not held in KV.
Updates apply immediately on subsequent requests. Lowering a limit never
deletes published data or makes a private cache public: it refuses disallowed
new pushes and new private caches, and blocks BYOK import/activation while
leaving already-active keys working.

After upgrading to orgs, run `POST /_api/v1/admin/auth/sync` once: it
writes each private cache's org into KV, where pulls check it. This existing
visibility index is unrelated to org limits; changing limits requires
no KV synchronization.

### Cache policy API

Apply migration `0010_needy_risque.sql` after `0009` before deploying. All
endpoints below use `/_api/v1/orgs/:org` (the org ID, not its mutable slug),
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

Successful JWT authentication for Nix, Go, and sccache schedules a conditional
SQL update after foreground transactions and upload admission finish, using a
separate connection under `waitUntil`. A token's timestamp changes at most once
per five minutes, including concurrent calls. It records authentication, not
successful artifact delivery. Anonymous public/CDN reads cannot identify a
token. This is best-effort activity telemetry, not a security audit or exact
request counter; failed background writes can leave it stale.

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
Only the last 30 days are returned; control's scheduled GC sweeps older rows.

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

Each publish re-reads the current sealed key version before selecting a
bounded (256-entry), promise-coalescing memo of non-extractable, signing-only
CryptoKeys. Decrypted tenant secret bytes are not memoized; transient byte
buffers are cleared after use where practical. This is not a guarantee of
complete memory erasure in a JavaScript runtime.
There is no signing on public reads. Keep Hyperdrive query caching disabled
as required by setup above: stale database reads would delay key changes.
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
