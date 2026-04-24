# Helios

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

- Before changing Workers, R2, D1, Durable Objects, Queues, or platform limits, fetch current Cloudflare docs.
- Prefer platform-native APIs such as `fetch`, Web Streams, and Web Crypto.
- Do not enable `nodejs_compat` unless a concrete dependency requires it.
- After changing a worker's bindings in `wrangler.jsonc`, run that package's `cf-typegen` script.

## Verification

- Install dependencies with `pnpm install` from the repo root.
- Run `pnpm check` before finishing substantial changes.
- For worker-only iteration, use `pnpm --filter <package> dev`.
