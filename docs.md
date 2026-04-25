# Helios Documentation

## Deployment

```bash
wrangler r2 bucket create helios-cache
wrangler d1 create helios-cache
# set database_id in workers/cache/wrangler.jsonc
wrangler d1 migrations apply helios-cache --remote
wrangler secret put JWT_SECRET
wrangler secret put ADMIN_SECRET
wrangler secret put SIGNING_PRIVATE_KEY
wrangler secret put SIGNING_KEY_NAME
pnpm deploy
```

| Secret | Purpose |
|--------|---------|
| `JWT_SECRET` | HMAC-SHA256 key for JWT token signing |
| `ADMIN_SECRET` | Bearer token for the admin API |
| `SIGNING_PRIVATE_KEY` | Ed25519 key for narinfo signing |
| `SIGNING_KEY_NAME` | Key name prefix for signatures |

## Using as a substituter

```nix
nix.settings.substituters = [ "https://your-worker.workers.dev/main" ];
```

## Pushing store paths

```bash
# Single path
nix run . -- push --cache main /nix/store/...

# Full closure
./scripts/push-paths.sh https://your-worker.workers.dev "$TOKEN" main \
  $(nix path-info -r /run/current-system)
```

## Authentication

JWT tokens scope write access to specific caches. At least one of
`JWT_SECRET` or `AUTH_TOKEN` must be configured, otherwise all writes
are rejected.

### Managing tokens

```bash
# Create a token scoped to the "main" cache with push access
curl -X POST $URL/_api/v1/admin/tokens \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"subject":"ci-main","caches":["main"],"perms":["push"],"expiresInDays":90}'

# List all tokens
curl $URL/_api/v1/admin/tokens \
  -H "Authorization: Bearer $ADMIN_SECRET"

# Revoke a token
curl -X POST $URL/_api/v1/admin/tokens/$JTI/revoke \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"reason":"offboarded"}'
```

The signed JWT is returned once on creation and never stored. Save it
immediately.

### Create token parameters

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `subject` | yes | | Human label, max 256 chars |
| `caches` | yes | | Cache names to grant access to, or `["*"]` for all |
| `perms` | yes | | `"push"` and/or `"pull"` |
| `expiresInDays` | no | 90 | Token lifetime, 1 to 365 |

### Using a token

Pass the JWT as a bearer token on any write request:

```bash
curl -X POST $URL/_api/v1/caches/main/upload-sessions \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ ... }'
```

The CLI and `push-paths.sh` accept it the same way as the legacy
`AUTH_TOKEN`.

### Migrating from AUTH_TOKEN

1. Set `JWT_SECRET` and `ADMIN_SECRET` via `wrangler secret put`
2. Create scoped JWT tokens for each publisher
3. Update each publisher to use its JWT
4. Remove `AUTH_TOKEN` to disable legacy auth

### Audit logging

All write operations and admin actions are logged to D1 with actor,
action, cache name, IP, and status code. Logs are retained for 30 days.
