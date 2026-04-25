#!/usr/bin/env node

import { login, getServer } from "./config.js";
import { createClient, createToken, listTokens, revokeToken } from "./api.js";
import { pushPaths } from "./push.js";
import { getClosurePaths } from "./nix.js";

const USAGE = `helios - Nix binary cache CLI

Commands:
  helios login <name> <server-url> <token>   Save server credentials
  helios push <cache> <paths...>             Push store paths to a cache
  helios push <cache> --closure <path>       Push a store path and its closure
  helios token create <subject>              Create a new API token
  helios token list                          List all API tokens
  helios token revoke <jti> <reason>         Revoke an API token

Options:
  --server <name>    Use a specific server (default: last logged-in)
  --jobs <n>         Number of parallel uploads (default: 8)
  --help             Show this help

Token create options:
  --caches <names>   Comma-separated cache names or "*" (default: *)
  --perms <perms>    Comma-separated permissions (default: push)
  --expires <days>   Token lifetime in days (default: 90)

Examples:
  helios login prod https://cache.example.com my-admin-secret
  helios push main /nix/store/abc...-hello
  helios push main --closure /run/current-system
  helios token create ci-runner --caches main --perms push --expires 90
  helios token list
  helios token revoke a1b2c3d4-... "employee offboarded"
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(USAGE);
    process.exit(0);
  }

  const command = args[0];

  if (command === "login") {
    if (args.length < 4) {
      console.error("Usage: helios login <name> <server-url> <token>");
      process.exit(1);
    }
    await login(args[1], args[2], args[3]);
    console.log(`Logged in to '${args[1]}' at ${args[2]}`);
    return;
  }

  if (command === "push") {
    if (args.length < 3) {
      console.error("Usage: helios push <cache> <paths...> | helios push <cache> --closure <path>");
      process.exit(1);
    }

    const filteredArgs = [...args];

    // Extract --server flag
    let serverName: string | undefined;
    const serverIdx = filteredArgs.indexOf("--server");
    if (serverIdx !== -1 && serverIdx + 1 < filteredArgs.length) {
      serverName = filteredArgs[serverIdx + 1];
      filteredArgs.splice(serverIdx, 2);
    }

    // Extract --jobs flag
    let concurrency: number | undefined;
    const jobsIdx = filteredArgs.indexOf("--jobs");
    if (jobsIdx !== -1 && jobsIdx + 1 < filteredArgs.length) {
      concurrency = parseInt(filteredArgs[jobsIdx + 1], 10);
      filteredArgs.splice(jobsIdx, 2);
    }

    if (concurrency !== undefined && (!Number.isInteger(concurrency) || concurrency < 1)) {
      console.error("--jobs must be a positive integer");
      process.exit(1);
    }

    const serverConfig = await getServer(serverName);
    const client = createClient(serverConfig.server, serverConfig.token);
    const cache = filteredArgs[1];

    const progress = (current: number, total: number, name: string, status: string) => {
      console.log(`[${String(current)}/${String(total)}] ${name}  ${status}`);
    };

    const pushOpts = { concurrency, onProgress: progress };

    const closureIdx = filteredArgs.indexOf("--closure");
    let result;
    if (closureIdx !== -1) {
      const rootPath = filteredArgs[closureIdx + 1];
      if (!rootPath) {
        console.error("--closure requires a store path or installable");
        process.exit(1);
      }
      console.log(`Resolving closure for ${rootPath}...`);
      const paths = await getClosurePaths(rootPath);
      console.log(`Found ${String(paths.length)} paths in closure`);
      result = await pushPaths(client, cache, paths, pushOpts);
    } else {
      const paths = filteredArgs.slice(2);
      if (paths.length === 0) {
        console.error("No paths specified");
        process.exit(1);
      }
      result = await pushPaths(client, cache, paths, pushOpts);
    }

    console.log("");
    console.log(`Done: ${String(result.pushed)} pushed, ${String(result.skipped)} skipped, ${String(result.failed)} failed`);

    if (result.failed > 0) {
      process.exit(1);
    }
    return;
  }

  if (command === "token") {
    const subcommand = args[1];

    // Extract --server flag
    let serverName: string | undefined;
    const serverIdx = args.indexOf("--server");
    if (serverIdx !== -1 && serverIdx + 1 < args.length) {
      serverName = args[serverIdx + 1];
    }

    const serverConfig = await getServer(serverName);
    const client = createClient(serverConfig.server, serverConfig.token);

    if (subcommand === "create") {
      const subject = args[2];
      if (!subject) {
        console.error("Usage: helios token create <subject> [--caches ...] [--perms ...] [--expires <days>]");
        process.exit(1);
      }

      let cachesStr = "*";
      const cachesIdx = args.indexOf("--caches");
      if (cachesIdx !== -1 && cachesIdx + 1 < args.length) {
        cachesStr = args[cachesIdx + 1];
      }

      let permsStr = "push";
      const permsIdx = args.indexOf("--perms");
      if (permsIdx !== -1 && permsIdx + 1 < args.length) {
        permsStr = args[permsIdx + 1];
      }

      let expiresInDays: number | undefined;
      const expiresIdx = args.indexOf("--expires");
      if (expiresIdx !== -1 && expiresIdx + 1 < args.length) {
        expiresInDays = parseInt(args[expiresIdx + 1], 10);
        if (!Number.isInteger(expiresInDays) || expiresInDays < 1) {
          console.error("--expires must be a positive integer");
          process.exit(1);
        }
      }

      const caches = cachesStr.split(",").map(s => s.trim()).filter(Boolean);
      const perms = permsStr.split(",").map(s => s.trim()).filter(Boolean);

      const result = await createToken(client, { subject, caches, perms, expiresInDays });
      console.log(`Token created for '${result.subject}'`);
      console.log(`  JTI:     ${result.jti}`);
      console.log(`  Caches:  ${result.caches.join(", ")}`);
      console.log(`  Perms:   ${result.perms.join(", ")}`);
      console.log(`  Expires: ${result.expiresAt}`);
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
        console.log(`${t.jti}  ${t.subject}  [${t.perms.join(",")}]  caches=[${t.caches.join(",")}]  ${status}  expires=${t.expiresAt}`);
      }
      return;
    }

    if (subcommand === "revoke") {
      const jti = args[2];
      const reason = args.slice(3).join(" ");
      if (!jti || !reason) {
        console.error("Usage: helios token revoke <jti> <reason>");
        process.exit(1);
      }
      await revokeToken(client, jti, reason);
      console.log(`Token ${jti} revoked`);
      return;
    }

    console.error("Usage: helios token <create|list|revoke>");
    process.exit(1);
  }

  console.error(`Unknown command: ${command}`);
  console.error("Run 'helios --help' for usage");
  process.exit(1);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
