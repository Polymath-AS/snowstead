# Helios

A Cloudflare-native Nix binary cache.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Polymath-AS/helios)
## Workspace

```
workers/cache/        Cloudflare Worker (main service)
packages/cache-domain/  Shared types and input parsers
apps/cli/             CLI for pushing store paths
scripts/              smoke-test.sh
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

See [docs.md](docs.md) for the full reference. Short version:

```bash
wrangler r2 bucket create helios-cache
wrangler d1 create helios-cache
# update database_id in workers/cache/wrangler.jsonc
wrangler d1 migrations apply helios-cache --remote
wrangler secret put JWT_SECRET
wrangler secret put ADMIN_SECRET
wrangler secret put SIGNING_PRIVATE_KEY
wrangler secret put SIGNING_KEY_NAME
pnpm deploy
```

## Push store paths

Build the CLI (or `nix run .` for one-off use):

```bash
nix build       # produces ./result/bin/helios
```

Save credentials once:

```bash
helios login prod https://your-worker.workers.dev "$PUSH_TOKEN"
```

Push a single path:

```bash
helios push main /nix/store/abc...-hello
```

Push a full closure:

```bash
helios push main --closure /run/current-system
```

Push a flake output closure:

```bash
helios push main --closure .#nixosConfigurations.myhost.config.system.build.toplevel
```

See [docs.md](docs.md) for token management and parallelism options.

## Use as a substituter

```nix
# configuration.nix or flake
nix.settings.substituters = [ "https://your-worker.workers.dev/main" ];
```

## License

Source-available. See [LICENSE](LICENSE).
