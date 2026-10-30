import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";
import { createTestHarness } from "wrangler";

const require = createRequire(new URL("../../../packages/cache-core/package.json", import.meta.url));
const { Client } = require("pg");
const { drizzle } = require("drizzle-orm/node-postgres");
const { migrate } = require("drizzle-orm/node-postgres/migrator");
const exec = promisify(execFile);
const binary = new URL("../../../target/debug/snowstead", import.meta.url).pathname;

test("Rust CLI uploads, publishes, and skips a real NAR through the hosted Workers", { timeout: 120_000 }, async () => {
  const database = new URL(process.env.SNOWSTEAD_TEST_DATABASE_URL);
  const name = `snowstead_cli_${process.pid}`;
  const admin = new Client({ connectionString: database.toString() });
  await admin.connect();
  await admin.query(`CREATE DATABASE "${name}"`);
  database.pathname = `/${name}`;
  const home = await mkdtemp(join(tmpdir(), "snowstead-native-cli-"));
  let server;
  try {
    const db = new Client({ connectionString: database.toString() });
    await db.connect();
    try {
      await migrate(drizzle(db), { migrationsFolder: new URL("../../../packages/cache-core/migrations", import.meta.url).pathname });
    } finally {
      await db.end();
    }
    process.env.CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE = database.toString();
    process.env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = "false";
    const secrets = {
      ADMIN_SECRET: "cli-admin-secret",
      JWT_SECRET: "cli-jwt-secret-0123456789abcdef",
      SIGNING_MASTER_KEY: "dGVzdC1zaWduaW5nLW1hc3Rlci1rZXktMzItYnl0ZXM=",
    };
    const vars = { UPSTREAM_CACHES: "", CDN_ZONE_ID: "", PUBLIC_CACHE_ORIGIN: "" };
    server = createTestHarness({
      root: new URL("../../../", import.meta.url).pathname,
      workers: [
        { configPath: "wrangler.jsonc" },
        ...["nix", "control", "go"].map((worker) => ({ configPath: `workers/${worker}/wrangler.jsonc`, vars, secrets })),
      ],
    });
    const { url } = await server.listen();
    // A nonexistent spool directory makes any return to disk-backed NAR
    // preparation fail, while auth's atomic config writes stay in HOME.
    const run = (...args) => exec(binary, args, {
      env: { ...process.env, HOME: home, TMPDIR: join(home, "no-upload-spool") }, maxBuffer: 1024 * 1024,
    });
    const login = (name, token) => {
      const result = run("login", "--token-stdin", "--name", name, "--url", url.toString());
      result.child.stdin.end(token);
      return result;
    };
    await login("test", secrets.ADMIN_SECRET);
    await run("cache", "create", "native", "--protocols", "nix");
    const issued = await run("token", "create", "cli-uploader", "--caches", "native", "--perms", "push,pull");
    const token = issued.stdout.trim().split("\n").at(-1);
    await login("upload", token);

    // An immutable toolchain already on this machine; no writes to the Nix store.
    const storePath = /^(\/nix\/store\/[^/]+)/.exec(process.execPath)?.[1];
    assert.ok(storePath, "run inside nix develop so Node is a registered store path");
    const pushed = await run("push", "native", storePath, "--no-deps", "--jobs", "2");
    assert.match(pushed.stdout, /1 pushed, 0 skipped/);
    assert.equal(pushed.stderr, "");
    const repeated = await run("push", "native", storePath, "--no-deps", "--verbose");
    assert.match(repeated.stdout, /0 pushed, 1 skipped/);
    assert.match(repeated.stderr, /checked remote availability/);
    assert.ok(!repeated.stderr.includes(token));

    const hash = storePath.split("/").at(-1).slice(0, 32);
    const infoUrl = new URL(`/native/${hash}.narinfo`, url);
    const response = await fetch(infoUrl);
    assert.equal(response.status, 200);
    const info = await response.text();
    assert.match(info, /^Compression: zstd$/m);
    assert.match(info, /^Sig: /m);
    const narUrl = new URL(/^URL: (.+)$/m.exec(info)[1], infoUrl);
    const nar = await fetch(narUrl);
    assert.equal(nar.status, 200);
    const compressed = Buffer.from(await nar.arrayBuffer());
    assert.equal(compressed.length, Number(/^FileSize: (\d+)$/m.exec(info)[1]));
    async function digest(command, args, input) {
      const child = spawn(command, args, { stdio: [input ? "pipe" : "ignore", "pipe", "inherit"] });
      const sum = createHash("sha256");
      child.stdout.on("data", (chunk) => sum.update(chunk));
      if (input) child.stdin.end(input);
      const [code] = await once(child, "close");
      assert.equal(code, 0);
      return sum.digest("hex");
    }
    assert.equal(await digest("zstd", ["-d", "-q", "-c"], compressed), await digest("nix-store", ["--dump", storePath]));

    // By default, a path read from stdin brings its closure, and every path is
    // published after the references pushed with it. Node's own closure is too
    // large, so use its first dependency that has references of its own.
    const closureOf = async (path) =>
      (await exec("nix", ["--extra-experimental-features", "nix-command", "path-info", "-r", path])).stdout.trim().split("\n");
    let root;
    let closure;
    for (const candidate of await closureOf(storePath)) {
      closure = await closureOf(candidate);
      if (closure.length > 1) {
        root = candidate;
        break;
      }
    }
    assert.ok(root, "Node's closure contains a path with references");
    const piped = run("push", "native");
    piped.child.stdin.end(`${root}\n`);
    const withDeps = await piped;
    assert.match(withDeps.stdout, new RegExp(`Found ${closure.length} paths in closure`));
    assert.match(withDeps.stdout, new RegExp(`${closure.length} pushed, 0 skipped`));
    const check = new Client({ connectionString: database.toString() });
    await check.connect();
    let rows;
    try {
      ({ rows } = await check.query("SELECT store_path, references_json FROM published_paths ORDER BY id"));
    } finally {
      await check.end();
    }
    const position = new Map(rows.map((row, i) => [row.store_path.split("/").at(-1), i]));
    for (const path of closure) {
      const own = path.split("/").at(-1);
      const row = rows[position.get(own)];
      for (const reference of JSON.parse(row.references_json)) {
        if (reference !== own) assert.ok(position.get(reference) < position.get(own), `${reference} before ${own}`);
      }
    }
  } finally {
    if (server) await server.close();
    await rm(home, { recursive: true, force: true });
    await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
    await admin.end();
  }
});
