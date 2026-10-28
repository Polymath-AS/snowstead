#!/usr/bin/env node

import { parseArgs } from "node:util";
import { login, getServer } from "./config.js";
import { createClient, createToken, listTokens, revokeToken, createCache, listCaches } from "./api.js";
import type { CacheProtocol } from "./api.js";
import { pushPaths } from "./push.js";
import { getClosurePaths } from "./nix.js";

const USAGE = `snowstead - Nix binary cache CLI

Commands:
  snowstead login <name> <server-url> <token>   Save server credentials
  snowstead push <cache> <paths...>             Push store paths to a cache
  snowstead push <cache> --closure <path>       Push a store path and its closure
  snowstead cache create <name> --protocols nix|go|nix,go [--private]
                                               Create a cache (admin; no protocol default)
  snowstead cache set <name> [--private|--public] [--protocols nix|go|nix,go]
                                               Update visibility or add protocols (admin)
  snowstead cache list                          List caches (admin)
  snowstead token create <subject>              Create a new API token
  snowstead token list                          List all API tokens
  snowstead token revoke <jti> <reason>         Revoke an API token

Options:
  --server <name>    Use a specific server (default: last logged-in)
  --jobs <n>         Paths in flight at once (default: 32)
  --help             Show this help

Token create options:
  --caches <names>   Comma-separated cache names or "*" (default: *)
  --perms <perms>    Comma-separated permissions (default: push)
  --expires <days>   Token lifetime in days (default: 90)

Examples:
  snowstead login prod https://cache.example.com my-admin-secret
  snowstead cache create main --protocols nix
  snowstead push main /nix/store/abc...-hello
  snowstead push main --closure /run/current-system
  snowstead token create ci-runner --caches main --perms push --expires 90
  snowstead token list
  snowstead token revoke a1b2c3d4-... "employee offboarded"
`;

async function main(): Promise<void> {
  const rawArgs = process.argv.slice(2);

  if (rawArgs.length === 0) {
    console.log(USAGE);
    process.exit(0);
  }

  const { values, positionals: args } = parseArgs({
    args: rawArgs,
    allowPositionals: true,
    options: {
      help: { type: "boolean", short: "h" },
      server: { type: "string" },
      jobs: { type: "string" },
      closure: { type: "string" },
      caches: { type: "string" },
      protocols: { type: "string" },
      perms: { type: "string" },
      expires: { type: "string" },
      private: { type: "boolean" },
      public: { type: "boolean" },
    },
  });
  if (values.help) {
    console.log(USAGE);
    return;
  }

  const command = args[0];

  if (command === "login") {
    if (args.length < 4) {
      console.error("Usage: snowstead login <name> <server-url> <token>");
      process.exit(1);
    }
    await login(args[1], args[2], args[3]);
    console.log(`Logged in to '${args[1]}' at ${args[2]}`);
    return;
  }

  if (command === "push") {
    if (args.length < 2 || (args.length < 3 && values.closure === undefined)) {
      console.error("Usage: snowstead push <cache> <paths...> | snowstead push <cache> --closure <path>");
      process.exit(1);
    }

    const concurrency = values.jobs === undefined ? undefined : Number(values.jobs);
    if (concurrency !== undefined && (!Number.isInteger(concurrency) || concurrency < 1)) {
      console.error("--jobs must be a positive integer");
      process.exit(1);
    }

    const serverConfig = await getServer(values.server);
    const client = createClient(serverConfig.server, serverConfig.token);
    const cache = args[1];

    const progress = (current: number, total: number, name: string, status: string) => {
      console.log(`[${String(current)}/${String(total)}] ${name}  ${status}`);
    };

    const pushOpts = { concurrency, onProgress: progress };

    let result;
    if (values.closure !== undefined) {
      const rootPath = values.closure;
      console.log(`Resolving closure for ${rootPath}...`);
      const paths = await getClosurePaths(rootPath);
      console.log(`Found ${String(paths.length)} paths in closure`);
      result = await pushPaths(client, cache, paths, pushOpts);
    } else {
      const paths = args.slice(2);
      if (paths.length === 0) {
        console.error("No paths specified");
        process.exit(1);
      }
      result = await pushPaths(client, cache, paths, pushOpts);
    }

    console.log("");
    console.log(`Done: ${String(result.pushed)} pushed, ${String(result.skipped)} skipped (${String(result.upstream)} served upstream), ${String(result.failed)} failed`);

    if (result.failed > 0) {
      process.exit(1);
    }
    return;
  }

  if (command === "token") {
    const subcommand = args[1];

    const serverConfig = await getServer(values.server);
    const client = createClient(serverConfig.server, serverConfig.token);

    if (subcommand === "create") {
      const subject = args[2];
      if (!subject) {
        console.error("Usage: snowstead token create <subject> [--caches ...] [--perms ...] [--expires <days>]");
        process.exit(1);
      }

      const expiresInDays = values.expires === undefined ? undefined : Number(values.expires);
      if (expiresInDays !== undefined && (!Number.isInteger(expiresInDays) || expiresInDays < 1)) {
        console.error("--expires must be a positive integer");
        process.exit(1);
      }

      const caches = (values.caches ?? "*").split(",").map(s => s.trim()).filter(Boolean);
      const perms = (values.perms ?? "push").split(",").map(s => s.trim()).filter(Boolean);

      const result = await createToken(client, { subject, caches, perms, expiresInDays });
      console.log(`Token created for '${result.subject}'`);
      console.log(`  JTI:     ${result.jti}`);
      console.log(`  Caches:  ${result.caches.join(", ")}`);
      console.log(`  Perms:   ${result.perms.join(", ")}`);
      console.log(`  Expires: ${result.expiresAt ?? "never"}`);
      console.log("");
      console.log(result.token);
      return;
    }

    if (subcommand === "list") {
      const tokens = await listTokens(client);
      if (tokens.length === 0) {
        console.log("No tokens found");
        return;
      }
      for (const t of tokens) {
        const status = t.revokedAt ? `revoked (${t.revokedAt})` : "active";
        console.log(`${t.jti}  ${t.subject}  [${t.perms.join(",")}]  caches=[${t.caches.join(",")}]  ${status}  expires=${t.expiresAt ?? "never"}`);
      }
      return;
    }

    if (subcommand === "revoke") {
      const jti = args[2];
      const reason = args.slice(3).join(" ");
      if (!jti || !reason) {
        console.error("Usage: snowstead token revoke <jti> <reason>");
        process.exit(1);
      }
      await revokeToken(client, jti, reason);
      console.log(`Token ${jti} revoked`);
      return;
    }

    console.error("Usage: snowstead token <create|list|revoke>");
    process.exit(1);
  }

  if (command === "cache") {
    const subcommand = args[1];
    const serverConfig = await getServer(values.server);
    const client = createClient(serverConfig.server, serverConfig.token);

    if (subcommand === "create" || subcommand === "set") {
      const name = args[2];
      const wantPrivate = values.private ? true : values.public ? false : undefined;
      if (values.private && values.public) {
        throw new Error("--private and --public cannot be combined");
      }
      let protocols: CacheProtocol[] | undefined;
      if (values.protocols !== undefined) {
        const parsed = values.protocols.split(",").map(s => s.trim());
        if (!parsed.every((p): p is CacheProtocol => p === "nix" || p === "go") || new Set(parsed).size !== parsed.length) {
          throw new Error("--protocols must be a nonempty, unique comma-separated list of nix and/or go");
        }
        protocols = parsed;
      }
      if (!name || (subcommand === "create" && protocols === undefined) || (subcommand === "set" && wantPrivate === undefined && protocols === undefined)) {
        console.error(subcommand === "set" ? "Usage: snowstead cache set <name> [--private|--public] [--protocols nix|go|nix,go]" : "Usage: snowstead cache create <name> --protocols nix|go|nix,go [--private]");
        process.exit(1);
      }
      const result = await createCache(client, name, wantPrivate, protocols);
      const visibility = result.private ? "private" : "public";
      if (result.created) {
        console.log(`Cache '${result.name}' created (${visibility}; protocols=${result.protocols.join(",")})`);
      } else if (result.changed) {
        console.log(`Cache '${result.name}' is now ${visibility} (protocols=${result.protocols.join(",")})`);
      } else {
        console.log(`Cache '${result.name}' already exists (${visibility}; protocols=${result.protocols.join(",")})`);
      }
      return;
    }

    if (subcommand === "list") {
      for (const c of await listCaches(client)) {
        console.log(`${c.name}  ${c.private ? "private" : "public"}  protocols=${c.protocols.join(",")}  created=${c.createdAt}`);
      }
      return;
    }

    console.error("Usage: snowstead cache <create|set|list>");
    process.exit(1);
  }

  console.error(`Unknown command: ${command}`);
  console.error("Run 'snowstead --help' for usage");
  process.exit(1);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
