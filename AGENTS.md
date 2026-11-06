# Snowstead

This repository contains the Rust cache service, native clients, and a thin
Cloudflare gateway. `pnpm` manages workspace commands.

## Workspace Layout

- `workers/server`: Rust APIs, protocols, maintenance, SQL migrations, and tests
- `workers/gateway`: forwarding-only Cloudflare Worker using `API_ORIGIN`
- `apps/cli`: Rust CLI with Zig NAR core
- `apps/go-cache`: native Go build-cache helper
- `infra`: Rust service deployment and infrastructure

Keep backend runtime code and migrations in `workers/server`.

## Tooling

- Use `pnpm`, not `npm`, for dependency management and scripts.
- Do not commit `package-lock.json` files.
- If `pnpm` or `wrangler` are missing locally, use `nix shell nixpkgs#nodejs nixpkgs#pnpm nixpkgs#wrangler`.
- Run workspace commands from the repository root unless a package-specific command is clearer.

## Cloudflare Rules

- Before changing Workers, R2, Hyperdrive, Durable Objects, Queues, or platform limits, fetch current Cloudflare docs.
- Prefer platform-native APIs such as `fetch`, Web Streams, and Web Crypto.
- Do not enable `nodejs_compat` unless a concrete dependency requires it.
- The root `wrangler.jsonc` deploys only the forwarding gateway. Both production and staging require `API_ORIGIN`. Keep public URLs and the public R2/CDN bypass unchanged. After changing bindings, run `pnpm cf-typegen`.
- Rust owns authentication, storage policy, signing, all protocols, and scheduled maintenance. It uses direct Postgres and S3 access, not KV, Hyperdrive, or Durable Objects. Deploy Rust and migrations through `infra`; `pnpm deploy` is gateway-only and never migrates the database.
- Preserve existing secrets, signing keys, database, and objects during cutover. Source removal does not authorize deleting legacy resources or re-enabling legacy maintenance. See `docs.md` for cutover cautions and compatibility limits.

## Verification

- Install dependencies with `pnpm install` from the repo root.
- Run `pnpm check` before finishing substantial changes.
- `pnpm dev` runs Rust on `127.0.0.1:8787` with disposable Postgres/S3 and fresh local secrets; it does not use `.dev.vars`.
