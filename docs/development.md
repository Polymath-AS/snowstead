# Development Guide

## Prerequisites

- Node.js 20+
- pnpm 10+
- On NixOS: `nix shell nixpkgs#nodejs nixpkgs#pnpm`

## Setup

```bash
pnpm install
```

## Development

Start the worker locally:

```bash
pnpm dev
```

## Type Checking

```bash
pnpm check
```

## Testing

Run all tests:

```bash
pnpm check
```

Run worker tests only:

```bash
pnpm --filter @helios/cache-worker test
```

Run domain package tests only:

```bash
pnpm --filter @helios/cache-domain test
```

## Type Generation

After changing `wrangler.jsonc` bindings:

```bash
pnpm --filter @helios/cache-worker cf-typegen
```

## Database Migrations

After changing `workers/cache/src/db/schema.ts`:

```bash
pnpm --filter @helios/cache-worker exec drizzle-kit generate
```

## Project Structure

```
helios/
├── packages/
│   └── cache-domain/     # Shared types and input parsers
├── workers/
│   └── cache/            # Cloudflare Worker (main service)
│       ├── src/
│       │   ├── index.ts      # Entry point (fetch + scheduled)
│       │   ├── router.ts     # URL routing
│       │   ├── uploads.ts    # Write API handlers
│       │   ├── narinfo.ts    # Narinfo text rendering
│       │   ├── config.ts     # Binding validation
│       │   ├── db/           # Drizzle schema + repository
│       │   └── ...
│       ├── test/             # Integration tests
│       └── migrations/       # D1 migrations (drizzle-kit)
└── docs/
    └── architecture/
```
