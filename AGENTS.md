# Snowstead

This repository is a `pnpm` workspace for Cloudflare-native services.

## Workspace Layout

- `workers/*`: deployable Cloudflare Workers
- `apps/*`: operator or end-user applications that sit beside Workers
- `packages/*`: shared code used by workers or apps

Keep deployable runtime code inside `workers/`. Move shared protocol, parsing, and storage helpers into `packages/` only after they are reused.

## Tooling

- Use `pnpm`, not `npm`, for dependency management and scripts.
- Do not commit `package-lock.json` files.
- If `pnpm` or `wrangler` are missing locally, use `nix shell nixpkgs#nodejs nixpkgs#pnpm nixpkgs#wrangler`.
- Run workspace commands from the repository root unless a package-specific command is clearer.

## Cloudflare Rules

- Before changing Workers, R2, Hyperdrive, Durable Objects, Queues, or platform limits, fetch current Cloudflare docs.
- Prefer platform-native APIs such as `fetch`, Web Streams, and Web Crypto.
- Do not enable `nodejs_compat` unless a concrete dependency requires it.
- The root `wrangler.jsonc` deploys the routing-only gateway. `workers/nix/wrangler.jsonc`, `workers/go/wrangler.jsonc`, and `workers/control/wrangler.jsonc` deploy its private services. Only control owns scheduled maintenance. Keep public URLs and the public R2/CDN bypass unchanged. After changing bindings, run `pnpm cf-typegen`.
- `packages/cache-core` owns shared authentication, storage policy, database schema, migrations, and integration tests. Protocol handlers belong in `workers/nix` and `workers/go`; management APIs belong in `workers/control`. Do not import one Worker's runtime into another. `workers/go-cache` is the isolated benchmark prototype, not the hosted service.

## Verification

- Install dependencies with `pnpm install` from the repo root.
- Run `pnpm check` before finishing substantial changes.
- `pnpm dev` runs all four hosted Workers locally with service bindings.
