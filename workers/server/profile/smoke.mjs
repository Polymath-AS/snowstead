// Run only with scripts/with-postgres.sh scripts/with-r2.sh; never live resources.
// Build snowstead-server first. Set SNOWSTEAD_EXPECT_PROFILE=0 for the off build.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { copyFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import { Client } from "pg";

const exec = promisify(execFile);
const binary = new URL("../../../target/release/snowstead-server", import.meta.url).pathname;
const enabled = process.env.SNOWSTEAD_EXPECT_PROFILE !== "0";
assert.ok(process.env.SNOWSTEAD_TEST_DATABASE_URL, "requires disposable Postgres wrapper");
assert.ok(process.env.SNOWSTEAD_TEST_R2_ENDPOINT, "requires disposable S3 wrapper");
assert.equal(process.env.R2_ENDPOINT, process.env.SNOWSTEAD_TEST_R2_ENDPOINT);
const admin = new Client({ connectionString: process.env.SNOWSTEAD_TEST_DATABASE_URL });
const name = `snowstead_profile_${process.pid}_${randomBytes(4).toString("hex")}`;
const directory = await mkdtemp(join(tmpdir(), "snowstead-profile-"));
const output = join(directory, "hotpath.json");
const operator = randomBytes(32).toString("hex");
let server;
let closed;
let db;
let created = false;
let stderr = "";
let stdout = "";
await admin.connect();
try {
  await admin.query(`CREATE DATABASE "${name}"`);
  created = true;
  const url = new URL(process.env.SNOWSTEAD_TEST_DATABASE_URL);
  url.pathname = `/${name}`;
  const env = {
    ...process.env, DATABASE_URL: url.toString(), DATABASE_MAX_CONNECTIONS: "8",
    ADMIN_SECRET: operator, JWT_SECRET: randomBytes(32).toString("hex"), AUTH_TOKEN: "",
    SIGNING_PRIVATE_KEY: randomBytes(32).toString("base64"), SIGNING_KEY_NAME: "profile-fixture",
    SIGNING_MASTER_KEY: "", REQUIRE_CACHE_SIGNING_KEYS: "false", UPSTREAM_CACHES: "",
    PUBLIC_URL: "", PUBLIC_CACHE_ORIGIN: "", CDN_ZONE_ID: "", CDN_PURGE_TOKEN: "",
    ANALYTICS_TOKEN: "", TRUSTED_PROXY_IPS: "", LISTEN_ADDR: "127.0.0.1:0", RUST_LOG: "info",
    HOTPATH_OUTPUT_PATH: output, HOTPATH_OUTPUT_FORMAT: "json", HOTPATH_METRICS_PORT: "0",
    HOTPATH_REPORT: "functions-timing,futures,streams", HOTPATH_LIMIT: "0", HOTPATH_FOCUS: "",
  };
  await exec(binary, ["migrate"], { env, timeout: 30_000 });
  await rm(output, { force: true });
  db = new Client({ connectionString: url.toString() });
  await db.connect();
  const { rows: [{ id }] } = await db.query("INSERT INTO caches(name) VALUES ('profile-private-sentinel') RETURNING id");
  await db.query("INSERT INTO cache_protocols(cache_id,protocol) VALUES ($1,'nix')", [id]);
  server = spawn(binary, [], { env, stdio: ["ignore", "pipe", "pipe"] });
  closed = once(server, "exit");
  server.stderr.on("data", bytes => { stderr += bytes; });
  server.stdout.on("data", bytes => { stdout += bytes; });
  const lines = createInterface({ input: server.stdout });
  let origin;
  for await (const line of lines) {
    const address = /127\.0\.0\.1:\d+/.exec(line)?.[0];
    if (address) { origin = `http://${address}`; break; }
  }
  assert.ok(origin, "server announces its disposable listener");
  const request = (path, options = {}) => fetch(`${origin}${path}`, {
    ...options, signal: AbortSignal.timeout(15_000),
  });
  const issued = await request("/_api/v1/admin/tokens", {
    method: "POST", headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
    body: JSON.stringify({ subject: "profile-user-sentinel", caches: ["profile-private-sentinel"], perms: ["pull", "push"] }),
  });
  assert.equal(issued.status, 201);
  const { token } = await issued.json();
  const headers = { authorization: `Bearer ${token}`, "content-type": "application/json", "snowstead-protocol-version": "2" };
  const contents = Buffer.concat([Buffer.from("profile-content-sentinel"), randomBytes(96 * 1024)]);
  const words = [Buffer.from("nix-archive-1"), Buffer.from("("), Buffer.from("type"), Buffer.from("regular"), Buffer.from("contents"), contents, Buffer.from(")")];
  const raw = Buffer.concat(words.flatMap(word => {
    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(word.length));
    return [length, word, Buffer.alloc((8 - word.length % 8) % 8)];
  }));
  const compress = exec("zstd", ["-q", "-c"], { encoding: "buffer", maxBuffer: 2 * 1024 * 1024 });
  compress.child.stdin.end(raw);
  const { stdout: compressed } = await compress;
  const hash = "0".repeat(32);
  const fileHash = createHash("sha256").update(compressed).digest("hex");
  await db.query("BEGIN");
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended('org:default',0))");
  const createInline = () => request("/_api/v1/caches/profile-private-sentinel/upload-streams/batch", {
    method: "POST", headers, body: JSON.stringify({ paths: [{
      storePath: `/nix/store/${hash}-profile-fixture`, storePathHash: hash,
      narHash: `sha256-${createHash("sha256").update(raw).digest("base64")}`,
      narSize: raw.length, compression: "zstd", references: [], inline: true,
    }] }),
  });
  // Org fences now fail fast rather than retaining a connection while waiting.
  // Exercise contention without relying on the old blocking-lock behavior.
  const contended = await createInline();
  assert.equal(contended.status, 503);
  assert.equal((await contended.json()).error, "Concurrent write; retry");
  assert.equal((await request("/healthz")).status, 200);
  await db.query("COMMIT");
  const response = await createInline();
  assert.equal(response.status, 201);
  const { sessions: [{ sessionId }] } = await response.json();
  const uploaded = await request(`/_api/v1/uploads/${sessionId}/inline?fileHash=${fileHash}`, {
    method: "POST", headers: { ...headers, "content-length": String(compressed.length) },
    duplex: "half",
    body: (async function* () {
      yield compressed.subarray(0, 4096);
      await sleep(150);
      yield compressed.subarray(4096);
    })(),
  });
  assert.equal(uploaded.status, 200);
  assert.equal((await uploaded.json()).published, true);
  const metadata = await request(`/profile-private-sentinel/${hash}.narinfo`, { headers });
  assert.equal(metadata.status, 200);
  const narinfo = await metadata.text();
  assert.match(narinfo, /^Sig: profile-fixture:[A-Za-z0-9+/]{86}==$/m);
  const download = await request(new URL(/^URL: (.+)$/m.exec(narinfo)[1], `${origin}/profile-private-sentinel/`).pathname, { headers });
  assert.equal(download.status, 200);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()), compressed);

  // Exercise durable multipart finalization too. An optional local fixture lets
  // the same disposable stack profile a large real NAR without live credentials.
  // Fixture JSON: { compressedPath, narHash, narSize }.
  const fixture = process.env.SNOWSTEAD_PROFILE_FIXTURE
    ? JSON.parse(await readFile(process.env.SNOWSTEAD_PROFILE_FIXTURE, "utf8"))
    : { narHash: `sha256-${createHash("sha256").update(raw).digest("base64")}`, narSize: raw.length };
  const multipart = fixture.compressedPath ? await readFile(fixture.compressedPath) : compressed;
  const multipartHash = createHash("sha256").update(multipart).digest("hex");
  const post = async (path, body) => {
    const response = await request(path, { method: "POST", headers, body: JSON.stringify(body) });
    const result = await response.json();
    assert.ok(response.ok, JSON.stringify(result));
    return result;
  };
  const multipartCreated = await post("/_api/v1/caches/profile-private-sentinel/upload-streams/batch", { paths: [{
    storePath: `/nix/store/${"a".repeat(32)}-multipart-profile`, storePathHash: "a".repeat(32),
    narHash: fixture.narHash, narSize: fixture.narSize, compression: "zstd", references: [], inline: false,
  }] });
  const multipartId = multipartCreated.sessions[0].sessionId;
  const parts = [];
  for (let offset = 0; offset < multipart.length; offset += 8 * 1024 * 1024) {
    const bytes = multipart.subarray(offset, offset + 8 * 1024 * 1024);
    const partNumber = parts.length + 1;
    const { parts: [grant] } = await post(`/_api/v1/uploads/${multipartId}/parts`, { parts: [{ partNumber, size: bytes.length }] });
    assert.equal(new URL(grant.url).origin, env.R2_ENDPOINT);
    const response = await fetch(grant.url, { method: "PUT", headers: grant.headers, body: bytes });
    assert.equal(response.status, 200, await response.text());
    parts.push({ partNumber, etag: response.headers.get("etag").replace(/^"|"$/g, "") });
  }
  const started = performance.now();
  await post("/_api/v1/uploads/finalize", { uploads: [{ sessionId: multipartId,
    narHash: fixture.narHash, narSize: fixture.narSize, fileHash: multipartHash, fileSize: multipart.length, parts }] });
  const deadline = performance.now() + 180_000;
  for (;;) {
    const { results: [result] } = await post("/_api/v1/uploads/status", { sessions: [multipartId] });
    if (result.published) break;
    assert.equal(result.status, 202, JSON.stringify(result));
    assert.ok(performance.now() < deadline, "multipart finalization timed out");
    await sleep(25);
  }
  console.log(JSON.stringify({ multipartBytes: multipart.length, narBytes: fixture.narSize,
    finalizationMs: performance.now() - started }));
  server.kill("SIGTERM");
  assert.equal((await closed)[0], 0, stderr);
  server = undefined;
  if (!enabled) {
    await assert.rejects(readFile(output), { code: "ENOENT" });
    assert.doesNotMatch(stderr + stdout, /\[snitch\]|hotpath|archive\.verify/);
    console.log("profiling off: same locked upload, native verification, signed metadata, and streamed download; no profiler report");
  } else {
    const reportText = await readFile(output, "utf8");
    if (process.env.SNOWSTEAD_PROFILE_OUTPUT) await copyFile(output, process.env.SNOWSTEAD_PROFILE_OUTPUT);
    const report = JSON.parse(reportText);
    const functions = report.functions_timing.data;
    for (const label of ["uploads.advisory_lock_wait", "storage.upload_body", "storage.object_body", "reads.nar_body", "uploads.verification_slot_wait", "uploads.destination_backpressure", "snowstead_server::uploads::verify", "snowstead_server::uploads::finalization::turn", "snowstead_server::signing::render_with_key"]) {
      assert.ok(functions.some(row => row.name === label && row.calls > 0), `missing timing: ${label}`);
    }
    // Inline bodies are buffered before storage now; their induced delay belongs
    // to the handler, not to the destination storage stream.
    for (const label of ["snowstead_server::uploads::inline"]) {
      const row = functions.find(row => row.name === label);
      const [value, unit] = row.total.split(" ");
      const milliseconds = Number(value) * ({ ns: 0.000001, "µs": 0.001, ms: 1, s: 1000 }[unit]);
      assert.ok(milliseconds >= 50, `${label} must include the induced wait, got ${row.total}`);
    }
    assert.ok(report.futures.data.some(row => row.label === "uploads.advisory_lock_wait" && row.call_count > 0));
    assert.ok(report.streams.data.some(row => row.label === "reads.nar_body" && row.items_yielded > 0));
    for (const label of ["native.verify.update", "archive.verify.decompress", "archive.verify.nar_hash", "Memory allocated per call"]) {
      assert.ok(stderr.includes(label), `missing native measurement: ${label}`);
    }
    for (const sentinel of [operator, token, fileHash, hash, "profile-content-sentinel", "profile-user-sentinel", "profile-private-sentinel"]) {
      assert.ok(!(reportText + stderr).includes(sentinel), "profiling output must not contain request data");
    }
    console.log(JSON.stringify({ functions: functions.length, futures: report.futures.data.length, streams: report.streams.data.length,
      measured: functions.filter(row => /advisory_lock_wait|health_sql|verification_read|storage.upload_body|reads.nar_body|uploads::verify|render_with_key/.test(row.name)),
      pending: report.futures.data.filter(row => /advisory_lock_wait|health_sql/.test(row.label)),
      bodies: report.streams.data.filter(row => /nar_body|object_body|upload_body/.test(row.label)) }, null, 2));
    console.log(stderr);
  }
} catch (error) {
  console.error(stderr);
  throw error;
} finally {
  if (db) { await db.query("ROLLBACK"); await db.end(); }
  if (server) { server.kill("SIGTERM"); await closed; }
  if (created) await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
  await admin.end();
  await rm(directory, { recursive: true, force: true });
}
