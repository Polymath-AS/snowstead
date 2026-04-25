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

## Setup

Configure the CLI with your server URL and admin secret:

```bash
helios login prod https://your-worker.workers.dev $ADMIN_SECRET
```

## Using as a substituter

```nix
nix.settings.substituters = [ "https://your-worker.workers.dev/main" ];
```

## Managing tokens

JWT tokens scope write access to specific caches. The signed JWT is
returned once on creation and never stored. Save it immediately.

```bash
# Create a token scoped to the "main" cache with push access
helios token create ci-runner --caches main --perms push --expires 90

# Create a token with access to all caches
helios token create admin-bot --caches "*" --perms push,pull

# List all tokens
helios token list

# Revoke a token
helios token revoke $JTI "employee offboarded"
```

| Option | Default | Description |
|--------|---------|-------------|
| `--caches` | `*` | Comma-separated cache names or `*` for all |
| `--perms` | `push` | Comma-separated: `push` and/or `pull` |
| `--expires` | `90` | Token lifetime in days (1-365) |

## Pushing store paths

Log in with a push token (not the admin secret):

```bash
helios login prod https://your-worker.workers.dev $PUSH_TOKEN
```

Then push:

```bash
# Single path
helios push main /nix/store/abc...-hello

# Full closure
helios push main --closure /run/current-system

# Flake output closure
helios push main --closure .#nixosConfigurations.myhost.config.system.build.toplevel
```

Use `--jobs <n>` to control parallelism (default 8).

## Migrating from AUTH_TOKEN

1. Set `JWT_SECRET` and `ADMIN_SECRET` via `wrangler secret put`
2. Log in with the admin secret: `helios login prod $URL $ADMIN_SECRET`
3. Create scoped tokens: `helios token create ci-runner --caches main`
4. Update publishers to log in with their JWT
5. Remove `AUTH_TOKEN` to disable legacy auth

## Audit logging

All write operations and admin actions are logged to D1 with actor,
action, cache name, IP, and status code. Logs are retained for 30 days.
