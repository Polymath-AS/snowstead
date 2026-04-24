#!/usr/bin/env node

import { login, getServer } from "./config.js";
import { createClient } from "./api.js";
import { pushPaths } from "./push.js";
import { getClosurePaths } from "./nix.js";

const USAGE = `odin - Nix binary cache CLI

Commands:
  odin login <name> <server-url> <token>   Save server credentials
  odin push <cache> <paths...>             Push store paths to a cache
  odin push <cache> --closure <path>       Push a store path and its closure

Options:
  --server <name>    Use a specific server (default: last logged-in)
  --jobs <n>         Number of parallel uploads (default: 8)
  --help             Show this help

Examples:
  odin login prod https://cache.example.com my-token
  odin push main /nix/store/abc...-hello
  odin push main --closure /run/current-system
  odin push main --closure .#nixosConfigurations.myhost.config.system.build.toplevel
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
      console.error("Usage: odin login <name> <server-url> <token>");
      process.exit(1);
    }
    await login(args[1], args[2], args[3]);
    console.log(`Logged in to '${args[1]}' at ${args[2]}`);
    return;
  }

  if (command === "push") {
    if (args.length < 3) {
      console.error("Usage: odin push <cache> <paths...> | odin push <cache> --closure <path>");
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

  console.error(`Unknown command: ${command}`);
  console.error("Run 'odin --help' for usage");
  process.exit(1);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
