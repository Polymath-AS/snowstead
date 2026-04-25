# Authentication and Authorization

Helios uses JWT tokens to control who can push to which caches. Tokens
are scoped to specific caches and permissions, issued through an admin
API, and tracked in D1 as the authoritative source of truth.

## Secrets

Three secrets control the auth system. Set them with `wrangler secret put`:

| Secret | Purpose |
|--------|---------|
| `JWT_SECRET` | HMAC-SHA256 signing key for JWT tokens. Required for JWT auth. |
| `ADMIN_SECRET` | Bearer token for the admin API (token management). |
| `AUTH_TOKEN` | Legacy static bearer token. Grants full push access to all caches. |

At least one of `JWT_SECRET` or `AUTH_TOKEN` must be set. If neither is
configured, all write requests are rejected (fail-closed).

When both are set, JWT verification is attempted first. If the token is
not a valid JWT, it falls back to matching `AUTH_TOKEN`.

## Token lifecycle

### Create a token

```bash
curl -X POST https://your-worker.workers.dev/_api/v1/admin/tokens \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "ci-runner-main",
    "caches": ["main"],
    "perms": ["push"],
    "expiresInDays": 90
  }'
```

Response:

```json
{
  "token": "eyJhbGci...",
  "jti": "a1b2c3d4-...",
  "subject": "ci-runner-main",
  "caches": ["main"],
  "perms": ["push"],
  "expiresAt": "2026-07-24T..."
}
```

The signed JWT is returned once and never stored. Save it immediately.

Parameters:

| Field | Required | Description |
|-------|----------|-------------|
| `subject` | yes | Human-readable label for the token (max 256 chars). |
| `caches` | yes | Cache names this token can access. Use `["*"]` for all caches. Max 50 entries. |
| `perms` | yes | Permissions: `"push"` and/or `"pull"`. Max 10 entries. |
| `expiresInDays` | no | Token lifetime in days (1-365, default 90). Must be an integer. |

### List tokens

```bash
curl https://your-worker.workers.dev/_api/v1/admin/tokens \
  -H "Authorization: Bearer $ADMIN_SECRET"
```

Returns metadata for all tokens, including revocation status.
The signed JWT itself is never stored or returned here.

### Revoke a token

```bash
curl -X POST https://your-worker.workers.dev/_api/v1/admin/tokens/$JTI/revoke \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"reason": "employee offboarded"}'
```

Revocation is immediate. The token row is preserved for audit history
with `revokedAt`, `revokedBy`, and `revocationReason` fields. Revoked
tokens are rejected on the next request. Expired token rows are cleaned
up by the scheduled GC.

## Using a token

Pass the JWT as a bearer token on write API requests:

```bash
curl -X POST https://your-worker.workers.dev/_api/v1/caches/main/upload-sessions \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ ... }'
```

The CLI and `push-paths.sh` accept the token the same way they accepted
the legacy `AUTH_TOKEN`.

## How verification works

On each write request, the worker verifies the token in this order:

1. Extract the bearer token from the `Authorization` header.
2. If `JWT_SECRET` is configured, attempt JWT verification:
   - Reject tokens larger than 4 KB.
   - Compare the header against the expected `HS256` header (base64url comparison, no decode).
   - Decode the payload and check expiry before signature verification (cheap rejection of expired tokens).
   - Verify the HMAC-SHA256 signature using a cached `CryptoKey` (cached per isolate across requests).
   - Validate claims: `iss` and `aud` must be `"helios-cache"`, timestamps must be safe integers, `iat` must not be in the future (60s skew), `exp` must be after `iat`.
   - Check the token is active in D1 (row exists and is not revoked).
3. If JWT verification fails and `AUTH_TOKEN` is configured, try a timing-safe comparison against the static token.
4. If all checks fail, return 401 or 403.

## Authorization enforcement

After authentication, the worker enforces scoped access:

- **Push permission**: JWT tokens must include `"push"` in their `perms` claim. Legacy tokens have implicit push access.
- **Cache access**: When creating an upload session, the target cache name is checked against the token's `caches` claim. `"*"` grants access to all caches.
- **Session-level enforcement**: All upload routes (multipart, part, blob, complete, publish) resolve the session's cache and verify the caller has access. This prevents cross-tenant session hijacking.
- **Session expiry**: Sessions are rejected inline when expired, not only by scheduled GC.

## Audit logging

All write operations and admin actions produce audit log entries stored
in D1. Each entry records:

- `actor`: the token's `jti` for JWT tokens, `"legacy"` for static tokens, `"admin"` for admin operations
- `action`: `push`, `token.create`, `token.list`, `token.revoke`
- `cacheName`: the target cache, when applicable
- `ip`: the client IP from `cf-connecting-ip`
- `status`: the HTTP response status code

Audit logs are written non-blocking via `waitUntil`. Read operations
(narinfo, NAR downloads) are not audited. Logs are retained for 30 days
and cleaned up by the scheduled GC.

## Security properties

- **Fail-closed**: no auth configured means all writes are rejected.
- **Timing-safe comparison**: legacy token and admin secret use SHA-256 digest comparison to prevent timing side-channels.
- **Generic error messages**: auth failures return `"Unauthorized"` or `"Forbidden"` without leaking token state, claim details, or configuration.
- **No-store caching**: all API responses include `Cache-Control: no-store`. Auth failures include `WWW-Authenticate: Bearer`.
- **D1 authoritative**: token existence and revocation are checked against D1 on every request, not just the JWT signature.
- **CryptoKey caching**: the HMAC key is imported once per isolate and reused across requests.
- **Pre-signature rejection**: expired tokens and malformed headers are rejected before the HMAC verification, saving CPU on expired/invalid tokens.

## Migration from AUTH_TOKEN

Existing deployments using `AUTH_TOKEN` continue to work. To migrate:

1. Set `JWT_SECRET` and `ADMIN_SECRET` via `wrangler secret put`.
2. Create JWT tokens for each CI runner or system that pushes.
3. Update each system to use its JWT token.
4. Once all systems are migrated, remove `AUTH_TOKEN` to disable legacy auth.
