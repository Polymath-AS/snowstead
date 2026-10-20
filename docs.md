# Snowstead Documentation

## Deployment

```bash
wrangler r2 bucket create snowstead-private
# Uploads land near the pusher and replicate to the bucket; reads stay
# consistent. Free, and only faster for pushers far from the bucket.
wrangler r2 bucket local-uploads enable snowstead-private
# Postgres on PlanetScale, with a role holding pg_read_all_data and
# pg_write_all_data. Query caching off: uploads must read their own writes.
wrangler hyperdrive create snowstead --caching-disabled \
  --connection-string "postgres://USER:PASSWORD@HOST:5432/postgres?sslmode=require"
# set the Hyperdrive id in wrangler.jsonc
wrangler secret put JWT_SECRET
wrangler secret put ADMIN_SECRET
wrangler secret put SIGNING_PRIVATE_KEY
wrangler secret put SIGNING_KEY_NAME
# S3 keys of an R2 token limited to the two buckets (key id: the token id,
# secret: the SHA-256 of its value). With them uploads go straight to R2
# through presigned URLs; without them they go through the Worker. Private
# NARs are always served by the Worker, which checks the reader.
wrangler secret put R2_ACCESS_KEY_ID
wrangler secret put R2_SECRET_ACCESS_KEY
wrangler secret put R2_ENDPOINT        # https://<account id>.r2.cloudflarestorage.com
# migrates the database directly (not through Hyperdrive), then deploys
DATABASE_URL="postgres://USER:PASSWORD@HOST:5432/postgres?sslmode=require" pnpm deploy
```

| Secret | Purpose |
|--------|---------|
| `JWT_SECRET` | HMAC-SHA256 key for JWT token signing |
| `ADMIN_SECRET` | Bearer token for the admin API |
| `SIGNING_PRIVATE_KEY` | Ed25519 key for narinfo signing |
| `SIGNING_KEY_NAME` | Key name prefix for signatures |

### Public caches on a custom domain

Public caches are served straight from the `snowstead-public` bucket, not
the Worker. The bucket needs a custom domain on a zone in the same
account, the Worker routes for `/_api/*` and `/private/*` on it (in
`wrangler.jsonc`), and a Cache Rule. Cloudflare caches only some file
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

Stored objects carry their own `Cache-Control` and are cached for a year.
Misses are cached for a minute, so the many lookups Nix makes for paths a
cache lacks are answered by the CDN. Publishing and deleting a path purge
its narinfo from the CDN, so neither waits for a cached answer to expire.
Purging needs the vars `CDN_ZONE_ID` and `PUBLIC_CACHE_ORIGIN` and the
secret `CDN_PURGE_TOKEN`, an API token with Cache Purge on the zone;
without them nothing is purged. To purge by hand:

```bash
curl -X POST https://cache.example.com/_api/v1/admin/caches/main/purge \
  -H "authorization: Bearer $ADMIN_SECRET" -d '{}'   # or {"storePathHashes": [...]}
```

## Setup

Configure the CLI with your server URL and admin secret:

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
snowstead cache create team --private        # or: snowstead cache set team --private
snowstead token create builders --caches team --perms pull
```

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

Making a cache private or public takes effect within 30 seconds everywhere.

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
# Single path
snowstead push main /nix/store/abc...-hello

# Full closure
snowstead push main --closure /run/current-system

# Flake output closure
snowstead push main --closure .#nixosConfigurations.myhost.config.system.build.toplevel
```

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
which has caches, tokens, API keys, an audit log, and a storage limit.
Who belongs to an org, and what it pays for, stay with the service that
runs Snowstead.

A self-hosted install doesn't need to know about any of this: everything
belongs to the `default` org, which has no storage limit, and tokens made
without an org are its tokens.

- **Cache names are an org's own.** Each org has a slug, and its caches
  are served at `<host>/<slug>/<name>`, so every org can have a `main`.
  The default org's caches stay at `<host>/<name>`. An org's slug can
  change only while its caches have no paths, since public caches are
  stored at their URL for the CDN to serve.
- **Each org has its own API** under `/_api/v1/orgs/:org`: its storage,
  caches, tokens, API keys, and audit log. `ADMIN_SECRET` reaches every
  org; an org's API key (`snowstead_key_…`) reaches only its own. Only the
  operator sets the storage limit and makes API keys.
- **Tokens reach only their org's caches,** for pushing and for pulling
  from a private cache. A token is made naming caches, which it keeps by
  id, so it outlives a rename, or patterns over names where `*` matches
  anything: `ci-*` reaches every cache starting with `ci-`, including
  ones made later, and `*` reaches them all. A push names its cache within
  the token's org, so `snowstead push main` pushes to that org's `main`.
- **Storage limits.** A push that would take an org's caches past its
  limit is refused with 507 before anything uploads.
- **Signing keys.** With `SIGNING_MASTER_KEY` set, each new cache signs
  with a key of its own, shown as the cache's `publicKey`. Caches from
  before, and every cache without a master key, sign with
  `SIGNING_PRIVATE_KEY`.

After upgrading to orgs, run `POST /_api/v1/admin/auth/sync` once: it
writes each private cache's org into KV, where pulls check it.
