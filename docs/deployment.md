# Deployment Checklist

## Cloudflare Resources

Create these resources before deploying:

1. **R2 Bucket**: `helios-cache`
   ```bash
   wrangler r2 bucket create helios-cache
   ```

2. **D1 Database**: `helios-cache`
   ```bash
   wrangler d1 create helios-cache
   ```
   Update the `database_id` in `workers/cache/wrangler.jsonc` with the
   returned ID.

3. **Apply D1 migrations**:
   ```bash
   wrangler d1 migrations apply helios-cache --remote
   ```

## Secrets

Set these secrets before the first deploy:

```bash
wrangler secret put JWT_SECRET
wrangler secret put ADMIN_SECRET
wrangler secret put SIGNING_PRIVATE_KEY
wrangler secret put SIGNING_KEY_NAME
```

- `JWT_SECRET`: HMAC-SHA256 signing key for JWT auth tokens
- `ADMIN_SECRET`: bearer token for the token management admin API
- `SIGNING_PRIVATE_KEY`: base64-encoded Ed25519 private key for narinfo signing
- `SIGNING_KEY_NAME`: the key name prefix for signatures (e.g., `helios-cache-1`)

Optionally set `AUTH_TOKEN` for legacy static-token auth (not
recommended for new deployments). See [auth.md](auth.md) for the full
auth documentation.

## Deploy

```bash
pnpm deploy
```

## Post-Deploy Verification

```bash
# Health check
curl https://your-worker.workers.dev/healthz

# Cache info (requires a cache to exist)
curl https://your-worker.workers.dev/your-cache/nix-cache-info
```
