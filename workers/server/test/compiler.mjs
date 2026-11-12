// Build snowstead-server first, then run inside nix develop:
// scripts/with-postgres.sh scripts/with-r2.sh node --test workers/server/test/compiler.mjs
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { test } from "node:test";
import { Client } from "pg";

const exec = promisify(execFile);
const serverBinary = new URL("../../../target/debug/snowstead-server", import.meta.url).pathname;
const goSource = new URL("../../../apps/go-cache/", import.meta.url).pathname;

test("unchanged compiler clients reuse Rust TCP artifacts with fresh local caches", { timeout: 240_000 }, async t => {
  const base = process.env.SNOWSTEAD_TEST_DATABASE_URL;
  assert.ok(base, "run via scripts/with-postgres.sh inside nix develop");
  assert.equal(process.env.R2_ENDPOINT, process.env.SNOWSTEAD_TEST_R2_ENDPOINT, "run via scripts/with-r2.sh");
  assert.ok(process.env.SNOWSTEAD_TEST_R2_ENDPOINT, "requires disposable S3 buckets");
  const home = await mkdtemp(join(tmpdir(), "snowstead-compiler-"));
  const admin = new Client({ connectionString: base });
  const name = `snowstead_compiler_${process.pid}_${randomBytes(4).toString("hex")}`;
  let created = false;
  let server;
  let closed;
  t.after(async () => {
    try {
      if (server) {
        if (server.exitCode === null && server.signalCode === null) server.kill("SIGTERM");
        const [code] = await closed;
        assert.equal(code, 0, "Rust server exits cleanly");
      }
    } finally {
      try {
        if (created) await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
      } finally {
        try { await admin.end(); }
        finally { await rm(home, { recursive: true, force: true }); }
      }
    }
  });
  await admin.connect();
  await admin.query(`CREATE DATABASE "${name}"`);
  created = true;
  const database = new URL(base);
  database.pathname = `/${name}`;
  const env = {
    ...process.env, DATABASE_URL: database.toString(),
    JWT_SECRET: "", ADMIN_SECRET: randomBytes(32).toString("hex"), WEB_ASSERTIONS_DISABLED: "true", SIGNING_MASTER_KEY: "",
    SIGNING_PRIVATE_KEY: "", REQUIRE_CACHE_SIGNING_KEYS: "false", PUBLIC_URL: "", UPSTREAM_CACHES: "",
    PUBLIC_CACHE_ORIGIN: "", CDN_ZONE_ID: "", CDN_PURGE_TOKEN: "",
    ANALYTICS_TOKEN: "", TRUSTED_PROXY_IPS: "",
    DATABASE_MAX_CONNECTIONS: "2", LISTEN_ADDR: "127.0.0.1:0", RUST_LOG: "info",
  };
  await exec(serverBinary, ["migrate"], { env, timeout: 30_000 });
  const tokens = {};
  const db = new Client({ connectionString: database.toString() });
  await db.connect();
  try {
    for (const protocol of ["go", "sccache"]) {
      const { rows: [{ id }] } = await db.query(
        "INSERT INTO caches(name,is_public) VALUES ($1,false) RETURNING id", [protocol]);
      await db.query("INSERT INTO cache_protocols(cache_id,protocol) VALUES ($1,$2)", [id, protocol]);
      // An opaque API token, stored as the service issues them: a hashed
      // secret, with its scope in token_permissions and token_caches.
      const jti = randomUUID();
      const tokenSecret = randomBytes(32).toString("base64url");
      await db.query(
        "INSERT INTO api_tokens(jti,subject,secret_hash,created_by,org_id,expires_at) VALUES ($1,'compiler-fixture',$2,'test','default',now()+interval '1 hour')",
        [jti, createHash("sha256").update(tokenSecret).digest("hex")]);
      await db.query(
        "INSERT INTO token_permissions(token_jti,permission,position) VALUES ($1,$2,1),($1,$3,2)",
        [jti, `${protocol}:read`, `${protocol}:write`]);
      await db.query("INSERT INTO token_caches(token_jti,cache_id) VALUES ($1,$2)", [jti, id]);
      tokens[protocol] = `snowstead_tok_${jti}_${tokenSecret}`;
    }
  } finally { await db.end(); }
  const token = protocol => tokens[protocol];
  server = spawn(serverBinary, [], { env, stdio: ["ignore", "pipe", "inherit"] });
  closed = once(server, "exit");
  const lines = createInterface({ input: server.stdout });
  const ready = once(lines, "line");
  const [line] = await Promise.race([
    ready,
    closed.then(([code, signal]) => { throw new Error(`server exited before listening: ${code}/${signal}`); }),
  ]);
  const address = /127\.0\.0\.1:\d+/.exec(line)?.[0];
  assert.ok(address, line);
  const url = `http://${address}`;

  // Exercise unmodified Rust and C++ compiler clients with fresh local caches.
  const dir = join(home, "sccache");
  await mkdir(dir);
  const clientEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("SCCACHE_")));
  Object.assign(clientEnv, {
    SCCACHE_SERVER_UDS: join(dir, "server.sock"), SCCACHE_CONF: join(dir, "config"),
    SCCACHE_WEBDAV_ENDPOINT: `${url}/_api/v1/sccache/default/sccache/`,
    SCCACHE_WEBDAV_TOKEN: token("sccache"),
  });
  const run = args => exec("sccache", args, { env: clientEnv, cwd: dir, timeout: 30_000 });
  try {
    await writeFile(join(dir, "config"), "");
    await writeFile(join(dir, "input.cpp"), "int cached(int n) { return n * 7 + 3; }\n");
    await writeFile(join(dir, "input.rs"), "pub fn cached(n: u64) -> u64 { n * 11 + 5 }\n");
    let expected;
    for (let pass = 0; pass < 2; pass++) {
      clientEnv.SCCACHE_DIR = join(dir, `local-${pass}`);
      await run(["--start-server"]);
      await run(["c++", "-c", "input.cpp", "-o", "cpp.o", "-O2"]);
      await run(["rustc", "--crate-name", "fixture", "--crate-type", "rlib", "--emit=link", "input.rs", "--out-dir", ".", "-O"]);
      const stats = JSON.parse((await run(["--show-stats", "--stats-format", "json"])).stdout).stats;
      const sum = counts => Object.values(counts).reduce((a, b) => a + b, 0);
      assert.equal(sum(stats.cache_hits.counts), pass ? 2 : 0, JSON.stringify(stats));
      assert.equal(sum(stats.cache_misses.counts), pass ? 0 : 2, JSON.stringify(stats));
      assert.equal(stats.cache_write_errors, 0, JSON.stringify(stats));
      const outputs = await Promise.all(["cpp.o", "libfixture.rlib"].map(name => readFile(join(dir, name))));
      if (expected) assert.deepEqual(outputs, expected);
      expected = outputs;
      console.log(`sccache ${pass ? "warm" : "cold"}: hits=${sum(stats.cache_hits.counts)} misses=${sum(stats.cache_misses.counts)} write_errors=${stats.cache_write_errors} output_bytes=${outputs.map(b => b.length).join(",")}`);
      await run(["--stop-server"]);
      await Promise.all(["cpp.o", "libfixture.rlib"].map(name => rm(join(dir, name))));
    }
  } finally { await run(["--stop-server"]).catch(() => {}); }

  // Build the unchanged helper with an isolated Go cache, not the user's cache.
  const goEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GO") && !key.startsWith("SNOWSTEAD_GO_")));
  Object.assign(goEnv, {
    HOME: home, GOENV: "off", GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off",
    GOMODCACHE: join(home, "gomod"), GOCACHE: join(home, "helper-build-cache"), CGO_ENABLED: "0",
  });
  const helper = join(home, "snowstead-go-cache");
  await exec("go", ["build", "-o", helper, "."], { cwd: goSource, env: goEnv, timeout: 120_000 });
  const project = join(home, "go-project");
  await mkdir(project);
  await writeFile(join(project, "go.mod"), "module compiler.fixture\n\ngo 1.24\n");
  await writeFile(join(project, "main.go"), 'package main\nfunc main() { println("snowstead compiler fixture") }\n');
  // Go refuses to cache a module index for files less than two seconds old.
  // Make both passes eligible instead of creating a warm-only index record.
  const timestamp = new Date(Date.now() - 60_000);
  for (const name of ["go.mod", "main.go"]) await utimes(join(project, name), timestamp, timestamp);
  const goToken = token("go");
  let expectedGo;
  for (let pass = 0; pass < 2; pass++) {
    const output = join(project, "fixture");
    // This throwaway module has no VCS metadata (nor any need for stamping).
    const result = await exec("go", ["build", "-trimpath", "-buildvcs=false", "-o", output, "."], {
      cwd: project, timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
      env: { ...goEnv, GOCACHE: join(home, `go-local-${pass}`), GOCACHEPROG: helper,
        SNOWSTEAD_GO_CACHE_DIR: join(home, `go-helper-${pass}`),
        SNOWSTEAD_GO_CACHE_URL: `${url}/_api/v1/go/default/go`, SNOWSTEAD_GO_CACHE_TOKEN: goToken,
        SNOWSTEAD_GO_CACHE_READ_ONLY: "false" },
    });
    const summary = result.stderr.split("\n").filter(line => line.startsWith("snowstead-go-cache: local_hits="));
    assert.equal(summary.length, 1, result.stderr);
    const stats = Object.fromEntries([...summary[0].matchAll(/(\w+)=(\w+)/g)].map(([, key, value]) => [key, value === "true" ? true : value === "false" ? false : Number(value)]));
    for (const key of ["upload_errors", "read_errors", "read_timeouts", "conflicts"]) assert.equal(stats[key], 0, summary[0]);
    assert.equal(stats.remote_disabled, false, summary[0]);
    if (pass === 0) {
      assert.equal(stats.remote_hits, 0, summary[0]);
      assert.ok(stats.misses > 0 && stats.uploads > 0 && stats.uploaded_bytes > 0, summary[0]);
    } else {
      // Go does not request every cold metadata put on a warm build, and
      // linking can still put an empty stdout record. Require real artifact
      // downloads and no newly uploaded payload, not identical request counts.
      assert.ok(stats.remote_hits > 0 && stats.downloaded_bytes >= expectedGo.length, summary[0]);
      assert.equal(stats.uploaded_bytes, 0, summary[0]);
    }
    const bytes = await readFile(output);
    if (expectedGo) assert.deepEqual(bytes, expectedGo);
    expectedGo = bytes;
    const executed = await exec(output, [], { timeout: 10_000 });
    assert.equal(executed.stderr, "snowstead compiler fixture\n");
    console.log(`Go ${pass ? "warm" : "cold"}: ${summary[0]} executable_bytes=${bytes.length} sha256=${createHash("sha256").update(bytes).digest("hex")}`);
    await rm(output);
  }
});
