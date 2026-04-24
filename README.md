# Helios

A Cloudflare-native Nix binary cache.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Polymath-AS/helios)
## Workspace

```
workers/cache/        Cloudflare Worker (main service)
packages/cache-domain/  Shared types and input parsers
apps/cli/             CLI for pushing store paths
scripts/              push-paths.sh, smoke-test.sh
docs/                 Architecture decisions, deployment, development
```

## Setup

```bash
nix develop # drops you into a shell with node, pnpm, wrangler
pnpm install
```

## Develop

```bash
pnpm dev   # runs the worker locally via wrangler
pnpm check # type-check + tests across the workspace
```

## Deploy

See [docs/deployment.md](docs/deployment.md) for the full checklist. Short version:

```bash
wrangler r2 bucket create helios-cache
wrangler d1 create helios-cache
# update database_id in workers/cache/wrangler.jsonc
wrangler d1 migrations apply helios-cache --remote
wrangler secret put AUTH_TOKEN
wrangler secret put SIGNING_PRIVATE_KEY
wrangler secret put SIGNING_KEY_NAME
pnpm deploy
```

## Push store paths

```bash
./scripts/push-paths.sh <base-url> <auth-token> <cache-name> <store-path>...
```

Push a full closure:

```bash
./scripts/push-paths.sh https://your-worker.workers.dev "$TOKEN" main \
  $(nix path-info -r /run/current-system)
```

Or use the CLI (builds with `nix build`):

```bash
nix run . -- push --cache main /nix/store/...
```

## Use as a substituter

```nix
# configuration.nix or flake
nix.settings.substituters = [ "https://your-worker.workers.dev/main" ];
```

## License

Source-available. See [LICENSE](LICENSE).
