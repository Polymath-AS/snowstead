#!/usr/bin/env node
// Run inside nix develop through scripts/with-postgres.sh. Every trial gets
// a new database and nonpersistent Workers/R2/KV/DO/Cache API state.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { parseArgs } from "node:util";
import { createTestHarness } from "wrangler";

const { values } = parseArgs({ options: {
  variant: { type: "string" }, fixtures: { type: "string" }, output: { type: "string" },
  "source-root": { type: "string" },
  "comparison-root": { type: "string" }, "comparison-variant": { type: "string" },
  binary: { type: "string", default: "target/release/snowstead" },
  "comparison-binary": { type: "string" },
  "request-delay-ms": { type: "string", default: "0" },
  rounds: { type: "string", default: "20" }, warmups: { type: "string", default: "1" },
  workloads: { type: "string", default: "tiny24,mixed25" },
  visibility: { type: "string", default: "private,public" }, jobs: { type: "string", default: "8" },
} });
assert.ok(values.variant && values.fixtures && values.output, "--variant, --fixtures and --output are required");
assert.match(values.variant, /^[a-z0-9-]+$/);
const rounds = Number(values.rounds), warmups = Number(values.warmups);
assert.ok(Number.isInteger(rounds) && rounds > 0 && Number.isInteger(warmups) && warmups >= 0);
const requestDelayMs = Number(values["request-delay-ms"]);
assert.ok(Number.isInteger(requestDelayMs) && requestDelayMs >= 0 && requestDelayMs <= 2_147_483_647, "--request-delay-ms must be a nonnegative timer-safe integer");
const repository = new URL("../", import.meta.url).pathname;
const root = values["source-root"] ? resolve(values["source-root"]) : repository;
const binary = resolve(values.binary);
const variants = [{ name: values.variant, root, binary }];
if (values["comparison-root"] || values["comparison-variant"] || values["comparison-binary"]) {
  assert.ok(values["comparison-root"] && values["comparison-variant"], "comparison needs a root and variant");
  assert.match(values["comparison-variant"], /^[a-z0-9-]+$/);
  assert.notEqual(values.variant, values["comparison-variant"]);
  variants.push({ name: values["comparison-variant"], root: resolve(values["comparison-root"]), binary: values["comparison-binary"] ? resolve(values["comparison-binary"]) : binary });
}
const output = resolve(values.output);
await mkdir(output, { recursive: true });
const require = createRequire(new URL("../packages/cache-core/package.json", import.meta.url));
const { Client } = require("pg");
const { drizzle } = require("drizzle-orm/node-postgres");
const { migrate } = require("drizzle-orm/node-postgres/migrator");
const exec = promisify(execFile);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fixtures = JSON.parse(await readFile(values.fixtures, "utf8"));
const workloads = values.workloads.split(",").map(name => {
  const workload = fixtures.workloads.find(w => w.name === name);
  assert.ok(workload?.paths?.length, `missing workload: ${name}`);
  return workload;
});
const visibility = values.visibility.split(",");
assert.ok(visibility.every(v => ["private", "public"].includes(v)));
const originalNars = new Map();
for (const path of new Set(workloads.flatMap(w => w.paths))) {
  const { stdout } = await exec("nix-store", ["--dump", path], { encoding: "buffer", maxBuffer: 64 * 1024 * 1024 });
  originalNars.set(path, { sha256: digest(stdout), size: stdout.length });
}
const sourceFiles = ["workers/nix/src/uploads.ts", "workers/nix/src/router.ts", "workers/control/src/admin.ts", "workers/control/src/slug-move.ts", "packages/cache-core/src/narinfo.ts", "packages/cache-core/src/nar-install.ts", "packages/cache-core/src/upload-timing.ts", "packages/cache-core/src/db/repository.ts"];
for (const { name, root, binary } of variants) {
const provenance = {
  variant: name, created: new Date().toISOString(), rounds, warmups, jobs: Number(values.jobs),
  sourceRoot: root,
  head: (await exec("git", ["rev-parse", "HEAD"], { cwd: repository })).stdout.trim(),
  binary, binarySha256: digest(await readFile(binary)),
  sources: Object.fromEntries(await Promise.all(sourceFiles.map(async file => [file, digest(await readFile(join(root, file)))]))),
  workloads, visibility, originalNars: Object.fromEntries(originalNars),
  reset: "New isolated PostgreSQL database and nonpersistent Worker harness for EVERY trial, including warmups. No shared or production state is modified.",
  timing: "Push: CLI wall clock, including discovery/compression/network. Requests: local forwarding proxy through consumed response body. Reads: through consumed response body. Setup, reset, validation and teardown excluded. SQL execution durations exclude Parse/Bind and network time; SQL counts cover the push window and may include background writes.",
  requestDelayMs,
  requestDelay: "Injected benchmark delay, NOT measured production latency. Applied after reading the request body and before forwarding each recorded inline-batch/finalize request; included in request ms and push wall clock. Other requests are not delayed.",
  requestMetrics: "startOffsetMs/endOffsetMs are relative to push start. Publication means inline-batch or finalize. publicationConcurrencyAtArrival includes this request; publicationConcurrencyMax is the peak overlapping publication requests during this request. maxPublicationConcurrency is the trial peak. Intervals include body receipt, injected delay, forwarding, and response consumption, not client receipt. inlineItemCount is uploads.length from the four-byte big-endian length-prefixed JSON manifest, including retry attempts.",
  fixtureDependencies: "Push uses --no-deps --allow-drv. Fixtures must explicitly list every dependency to upload, including dependencies of derivations.",
  order: "Each workload/visibility pair runs both variants, reversing variant order on alternating rounds. Warmup trials also have fresh state; they warm tooling, not cache contents.",
};
await writeFile(join(output, `${name}-provenance.json`), JSON.stringify(provenance, null, 2));
}
await writeFile(join(output, "working-checkout.patch"), (await exec("git", ["diff", "--", "workers", "packages", "apps/cli"], { cwd: repository, maxBuffer: 16 * 1024 * 1024 })).stdout);
const database = new URL(process.env.SNOWSTEAD_TEST_DATABASE_URL);
assert.ok(["127.0.0.1", "localhost"].includes(database.hostname), "local disposable Postgres only");
const admin = new Client({ connectionString: database.toString() });
await admin.connect();
const { rows: [{ data_directory: dataDirectory }] } = await admin.query("SHOW data_directory");
// with-postgres.sh starts pg_ctl with -l <cluster parent>/log.
const logPath = join(dirname(dataDirectory), "log");
const sqlLog = async () => readFile(logPath, "utf8").catch(() => "");
const secrets = { ADMIN_SECRET: "benchmark-admin-only", JWT_SECRET: "benchmark-jwt-secret-0123456789abcdef", SIGNING_MASTER_KEY: "dGVzdC1zaWduaW5nLW1hc3Rlci1rZXktMzItYnl0ZXM=" };
let trial = 0, failed = 0;
try {
  for (let round = -warmups; round < rounds; round++) for (const workload of workloads) for (const mode of visibility)
  for (const { name: variant, root, binary } of (round % 2 === 0 ? variants : [...variants].reverse())) {
    const name = `pub_bench_${process.pid}_${trial++}`;
    const home = await mkdtemp(join(tmpdir(), "snowstead-pub-bench-"));
    let harness, proxy;
    const result = { variant, workload: `${workload.name}-${mode}`, round, warmup: round < 0, seconds: null, requests: [], reads: [], errors: [], reset: { database: name, persistentState: false } };
    await admin.query(`CREATE DATABASE "${name}"`);
    const local = new URL(database);
    local.pathname = `/${name}`;
    try {
      const db = new Client({ connectionString: local.toString() });
      await db.connect();
      try {
        await migrate(drizzle(db), { migrationsFolder: join(root, "packages/cache-core/migrations") });
        for (const table of ["published_paths", "upload_sessions", "upload_parts", "nar_installations", "blob_objects"]) {
          const { rows: [{ count }] } = await db.query(`SELECT count(*) FROM ${table}`);
          assert.equal(Number(count), 0, `fresh ${table}`);
        }
        await db.query(`ALTER DATABASE "${name}" SET log_min_duration_statement = 0`);
        await db.query(`ALTER DATABASE "${name}" SET log_parameter_max_length = 0`);
      } finally { await db.end(); }
      process.env.CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE = local.toString();
      process.env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = "false";
      harness = createTestHarness({ root, workers: [
        { configPath: "wrangler.jsonc" },
        ...["nix", "control", "go", "sccache"].map(worker => ({ configPath: `workers/${worker}/wrangler.jsonc`, secrets, vars: { UPSTREAM_CACHES: "", CDN_ZONE_ID: "", PUBLIC_CACHE_ORIGIN: "" } })),
      ] });
      const { url } = await harness.listen();
      const bindings = await harness.getWorker("snowstead-nix").getEnv();
      const storage = async () => Object.fromEntries(await Promise.all([
        ["private", bindings.CACHE_BUCKET], ["public", bindings.PUBLIC_BUCKET],
      ].map(async ([name, bucket]) => {
        const objects = []; let cursor;
        do {
          const page = await bucket.list({ cursor });
          objects.push(...page.objects); cursor = page.truncated ? page.cursor : undefined;
        } while (cursor);
        return [name, { objects: objects.length, bytes: objects.reduce((n, o) => n + o.size, 0), narinfos: objects.filter(o => o.key.endsWith(".narinfo")).length, nars: objects.filter(o => o.key.endsWith(".nar")).length, staging: objects.filter(o => o.key.startsWith("staging/")).length }];
      })));
      result.reset.initialStorage = await storage();
      assert.equal(result.reset.initialStorage.private.objects, 0, "fresh private R2");
      assert.equal(result.reset.initialStorage.public.objects, 0, "fresh public R2");
      let recording = false, pushStart;
      const activePublications = new Set();
      result.maxPublicationConcurrency = 0;
      proxy = createServer(async (req, res) => {
        const start = performance.now();
        const phase = req.url.includes("/inline/batch") ? "inline-batch" : req.url.includes("upload-streams") ? "allocate" : req.url.includes("get-missing") ? "discovery" : req.url.includes("finalize") ? "finalize" : req.method === "PUT" ? "upload-part" : req.url.includes("/parts") ? "reserve-parts" : "other";
        const record = recording;
        const publication = record && ["inline-batch", "finalize"].includes(phase);
        const sample = { phase, startOffsetMs: start - pushStart };
        if (publication) {
          activePublications.add(sample);
          sample.publicationConcurrencyAtArrival = activePublications.size;
          sample.publicationConcurrencyMax = activePublications.size;
          result.maxPublicationConcurrency = Math.max(result.maxPublicationConcurrency, activePublications.size);
          for (const active of activePublications) active.publicationConcurrencyMax = Math.max(active.publicationConcurrencyMax, activePublications.size);
        }
        try {
          const chunks = [];
          for await (const chunk of req) chunks.push(chunk);
          const requestBody = Buffer.concat(chunks);
          if (record && phase === "inline-batch") {
            // The API frame is a u32 BE JSON length, the manifest, then NAR payloads.
            assert.ok(requestBody.length >= 4, "missing inline manifest length");
            const manifestSize = requestBody.readUInt32BE(0);
            assert.ok(manifestSize > 0 && 4 + manifestSize < requestBody.length, "invalid inline manifest length");
            const manifest = JSON.parse(requestBody.subarray(4, 4 + manifestSize).toString("utf8"));
            assert.ok(Array.isArray(manifest.uploads), "missing inline uploads");
            sample.inlineItemCount = manifest.uploads.length;
          }
          if (publication && requestDelayMs > 0) await delay(requestDelayMs);
          const headers = { ...req.headers }; delete headers.host;
          const response = await fetch(new URL(req.url, url), { method: req.method, headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : requestBody });
          let body = Buffer.from(await response.arrayBuffer());
          if (phase === "reserve-parts" && response.ok) {
            const grants = JSON.parse(body);
            for (const group of grants.results ?? [grants]) for (const part of group.parts ?? []) {
              const target = new URL(part.url);
              // Only emulator same-origin grants are redirected through the
              // observer. Never modify a signed external storage URL.
              if (target.origin === url.origin) part.url = new URL(target.pathname + target.search, origin).href;
            }
            body = Buffer.from(JSON.stringify(grants));
          }
          const returned = Object.fromEntries(response.headers);
          delete returned["transfer-encoding"]; delete returned["content-encoding"]; returned["content-length"] = body.length;
          res.writeHead(response.status, returned); res.end(body);
          Object.assign(sample, { status: response.status, bytes: body.length,
            timings: Object.fromEntries([...response.headers.get("server-timing")?.matchAll(/([a-z_]+);dur=([\d.]+)/g) ?? []].map(m => [m[1], Number(m[2])])) });
        } catch (error) {
          Object.assign(sample, { status: 599, error: error.message });
          res.writeHead(502); res.end("Benchmark proxy failure");
        } finally {
          if (publication) activePublications.delete(sample);
          if (record) {
            const end = performance.now();
            Object.assign(sample, { ms: end - start, endOffsetMs: end - pushStart });
            result.requests.push(sample);
          }
        }
      });
      await new Promise(resolve => proxy.listen(0, "127.0.0.1", resolve));
      const origin = `http://127.0.0.1:${proxy.address().port}`;
      const env = { ...process.env, HOME: home };
      const run = (...args) => exec(binary, args, { env, maxBuffer: 4 * 1024 * 1024, timeout: 120_000 });
      const login = run("login", "--token-stdin", "--name", "admin", "--url", origin);
      login.child.stdin.end(secrets.ADMIN_SECRET);
      await login;
      await run("cache", "create", "experiment", "--protocols", "nix", ...(mode === "private" ? ["--private"] : []));
      const { stdout: tokenOutput } = await run("token", "create", "benchmark", "--caches", "experiment", "--perms", "push,pull");
      const token = tokenOutput.trim().split("\n").at(-1);
      const authenticated = run("login", "--token-stdin", "--name", "uploader", "--url", origin);
      authenticated.child.stdin.end(token); await authenticated;
      const before = (await sqlLog()).length;
      const start = performance.now(); pushStart = start; recording = true;
      try {
        const pushed = await run("push", "experiment", ...workload.paths, "--no-deps", "--allow-drv", "--jobs", values.jobs, "--compression-level", "3");
        result.stdout = pushed.stdout; result.stderr = pushed.stderr;
        assert.match(pushed.stdout, new RegExp(`${workload.paths.length} pushed, 0 skipped`));
      } catch (error) { result.errors.push(error.message); }
      finally { result.seconds = (performance.now() - start) / 1000; recording = false; }
      const log = (await sqlLog()).slice(before);
      await writeFile(join(output, `${variant}-${result.workload}-${round}-sql.log`), log);
      const statements = [...log.matchAll(/duration: ([\d.]+) ms\s+(?:statement|execute [^:]*): ([^\n]+)/g)].map(m => ({ ms: Number(m[1]), sql: m[2] }));
      result.sql = log ? { calls: statements.length, executionMs: statements.reduce((n, s) => n + s.ms, 0), transactions: statements.filter(s => /^begin\b/i.test(s.sql)).length, reads: statements.filter(s => /^select\b/i.test(s.sql)).length, writes: statements.filter(s => /^(insert|update|delete)\b/i.test(s.sql)).length, locks: statements.filter(s => /^lock\b/i.test(s.sql)).length } : null;
      result.storage = await storage();
      if (!result.errors.length) {
        for (const path of workload.paths) {
          const hash = path.split("/").at(-1).slice(0, 32);
          const infoUrl = new URL(`/${mode === "private" ? "private/" : ""}experiment/${hash}.narinfo`, origin);
          let info;
          for (const phase of ["cold-narinfo", "warm-narinfo"]) {
            const start = performance.now();
            const response = await fetch(infoUrl, { headers: { authorization: `Bearer ${token}` } });
            info = await response.text();
            result.reads.push({ phase, ms: performance.now() - start, status: response.status });
            assert.equal(response.status, 200, info);
          }
          const start = performance.now();
          const response = await fetch(new URL(/^URL: (.+)$/m.exec(info)[1], infoUrl), { headers: { authorization: `Bearer ${token}` } });
          const bytes = Buffer.from(await response.arrayBuffer());
          result.reads.push({ phase: "nar-download", ms: performance.now() - start, status: response.status });
          assert.equal(response.status, 200);
          assert.equal(bytes.length, Number(/^FileSize: (\d+)$/m.exec(info)[1]));
          assert.equal(digest(bytes), /^FileHash: sha256:(.+)$/m.exec(info)[1]);
          result.compressedBytes = (result.compressedBytes ?? 0) + bytes.length;
          const decompressed = exec("zstd", ["-d", "-q", "-c"], { encoding: "buffer", maxBuffer: 64 * 1024 * 1024 });
          decompressed.child.stdin.end(bytes);
          const { stdout } = await decompressed;
          assert.equal(digest(stdout), originalNars.get(path).sha256);
          assert.equal(stdout.length, originalNars.get(path).size);
        }
        result.verifiedDownloads = workload.paths.length;
        result.pathsPerSecond = workload.paths.length / result.seconds;
        result.compressedBytesPerSecond = result.compressedBytes / result.seconds;
      }
    } catch (error) { result.errors.push(error.stack); }
    finally {
      if (proxy) await new Promise(resolve => proxy.close(resolve));
      if (harness) await harness.close();
      await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
      await rm(home, { recursive: true, force: true });
      result.reset.destroyed = true;
      await appendFile(join(output, "runs.jsonl"), JSON.stringify(result) + "\n");
      console.log(JSON.stringify({ variant: result.variant, workload: result.workload, round, seconds: result.seconds, errors: result.errors, sql: result.sql }));
      if (result.errors.length) failed++;
    }
    assert.notEqual(result.seconds, null, "benchmark setup failed; see retained trial errors");
  }
} finally { await admin.end(); }
assert.equal(failed, 0, `${failed} trials failed; retained in runs.jsonl`);
