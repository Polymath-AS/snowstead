// Build both binaries first; run via scripts/with-postgres.sh scripts/with-r2.sh node --test <this file>.
import assert from "node:assert/strict";
import { createCipheriv, createHash, generateKeyPairSync, randomBytes, randomUUID, verify } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { lstat, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { test } from "node:test";
import { Client } from "pg";

const exec = promisify(execFile);
const cli = new URL("../../../target/debug/snowstead", import.meta.url).pathname;
const serverBinary = new URL("../../../target/debug/snowstead-server", import.meta.url).pathname;

test("unchanged CLI pushes a real NAR to Rust, verifies its signed download, and skips after restart", { timeout: 120_000 }, async () => {
  const base = process.env.SNOWSTEAD_TEST_DATABASE_URL;
  assert.ok(base, "run via scripts/with-postgres.sh");
  assert.equal(process.env.R2_ENDPOINT, process.env.SNOWSTEAD_TEST_R2_ENDPOINT, "run via scripts/with-r2.sh");
  assert.ok(process.env.SNOWSTEAD_TEST_R2_ENDPOINT, "requires disposable S3 buckets");
  const admin = new Client({ connectionString: base });
  await admin.connect();
  const name = `snowstead_server_cli_${process.pid}`;
  await admin.query(`CREATE DATABASE "${name}"`);
  const database = new URL(base);
  database.pathname = `/${name}`;
  const home = await mkdtemp(join(tmpdir(), "snowstead-server-cli-"));
  const master = randomBytes(32);
  const operator = randomBytes(32).toString("hex");
  const env = { ...process.env, DATABASE_URL: database.toString(),
    ADMIN_SECRET: operator, WEB_ASSERTIONS_DISABLED: "true", JWT_SECRET: randomBytes(32).toString("hex"), AUTH_TOKEN: "",
    SIGNING_MASTER_KEY: master.toString("base64"), REQUIRE_CACHE_SIGNING_KEYS: "true",
    PUBLIC_CACHE_ORIGIN: "", CDN_ZONE_ID: "", CDN_PURGE_TOKEN: "",
    ANALYTICS_TOKEN: "", TRUSTED_PROXY_IPS: "",
    DATABASE_MAX_CONNECTIONS: "2", PUSH_JOB_PUBLICATION_WORKERS: "1", LISTEN_ADDR: "127.0.0.1:0", RUST_LOG: "info", PUBLIC_URL: "", UPSTREAM_CACHES: "" };
  let server;
  let closed;
  const stop = async () => {
    if (!server) return;
    server.kill("SIGTERM");
    const [code] = await closed;
    server = undefined;
    assert.equal(code, 0);
  };
  const start = async () => {
    server = spawn(serverBinary, [], { env, stdio: ["ignore", "pipe", "inherit"] });
    closed = once(server, "exit");
    const lines = createInterface({ input: server.stdout });
    const [line] = await once(lines, "line");
    const address = /127\.0\.0\.1:\d+/.exec(line)?.[0];
    assert.ok(address, line);
    return `http://${address}`;
  };
  try {
    await exec(serverBinary, ["migrate"], { env });
    const db = new Client({ connectionString: database.toString() });
    await db.connect();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    try {
      for (const cache of ["native", "pipeline"]) {
        const { rows: [{ id }] } = await db.query("INSERT INTO caches(name) VALUES ($1) RETURNING id", [cache]);
        await db.query("INSERT INTO cache_protocols(cache_id,protocol) VALUES ($1,'nix')", [id]);
        const seed = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
        const publicBytes = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
        const keyId = randomUUID();
        const keyName = `server-fixture-${id}`;
        const publicName = `${keyName}:${publicBytes.toString("base64")}`;
        const iv = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", master, iv);
        cipher.setAAD(Buffer.from(JSON.stringify(["v2", id, keyId, keyName, publicName])));
        const material = Buffer.concat([iv, cipher.update(Buffer.concat([seed, publicBytes])), cipher.final(), cipher.getAuthTag()]);
        await db.query("UPDATE caches SET signing_key_name=$2,signing_public_key=$3,signing_key_sealed=$4 WHERE id=$1",
          [id, keyName, publicName, `v2:${keyId}:${material.toString("base64")}`]);
      }
    } finally { await db.end(); }
    let url = await start();
    const issued = await fetch(`${url}/_api/v1/admin/tokens`, {
      method: "POST",
      headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
      body: JSON.stringify({ subject: "cli-migration", caches: ["native", "pipeline"], perms: ["pull", "push"] }),
    });
    assert.equal(issued.status, 201);
    const { token: credential, jti } = await issued.json();
    assert.equal(typeof credential, "string");
    const run = (...args) => exec(cli, args, { env: { ...process.env, HOME: home, TMPDIR: join(home, "no-spooling") }, maxBuffer: 1024 * 1024 });
    const login = () => {
      const result = run("login", "--token-stdin", "--name", "migration", "--url", url);
      result.child.stdin.end(credential);
      return result;
    };
    await login();
    // Existing immutable store content: no writes to the Nix store.
    const path = /^(\/nix\/store\/[^/]+)/.exec(process.execPath)?.[1];
    assert.ok(path, "run inside nix develop");
    const pushed = await run("push", "native", path, "--no-deps", "--jobs", "2");
    assert.match(pushed.stdout, /1 pushed, 0 skipped/);
    assert.equal(pushed.stderr, "");
    await stop();
    url = await start();
    await login();
    const skipped = await run("push", "native", path, "--no-deps");
    assert.match(skipped.stdout, /0 pushed, 1 skipped/);
    const hash = path.split("/").at(-1).slice(0, 32);
    const infoUrl = new URL(`/native/${hash}.narinfo`, url);
    const response = await fetch(infoUrl);
    assert.equal(response.status, 200);
    const info = await response.text();
    const field = (name) => new RegExp(`^${name}: (.+)$`, "m").exec(info)?.[1];
    assert.equal(field("StorePath"), path);
    assert.equal(field("Compression"), "zstd");
    assert.match(field("Deriver"), /^[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+\.drv$/);
    const restoredMetadata = await exec("nix", [
      "--extra-experimental-features", "nix-command", "path-info",
      "--store", new URL("/native", url).toString(), path,
    ], { env: { ...process.env, HOME: home } });
    assert.equal(restoredMetadata.stdout.trim(), path);
    const refs = (field("References") ?? "").split(" ").filter(Boolean).map(r => `/nix/store/${r}`);
    const fingerprint = `1;${path};${field("NarHash")};${field("NarSize")};${refs.join(",")}`;
    const sig = field("Sig");
    assert.ok(sig);
    assert.ok(verify(null, Buffer.from(fingerprint), publicKey, Buffer.from(sig.split(":")[1], "base64")));
    const download = await fetch(new URL(field("URL"), infoUrl));
    assert.equal(download.status, 200);
    const compressed = Buffer.from(await download.arrayBuffer());
    assert.equal(compressed.length, Number(field("FileSize")));
    assert.equal(`sha256:${createHash("sha256").update(compressed).digest("hex")}`, field("FileHash"));
    async function digest(command, args, input) {
      const child = spawn(command, args, { stdio: [input ? "pipe" : "ignore", "pipe", "inherit"] });
      const sum = createHash("sha256");
      child.stdout.on("data", bytes => sum.update(bytes));
      if (input) child.stdin.end(input);
      assert.equal((await once(child, "close"))[0], 0);
      return sum.digest("hex");
    }
    assert.equal(await digest("zstd", ["-d", "-q", "-c"], compressed), await digest("nix-store", ["--dump", path]));
    // The explicit job mode must reach durable completion, not merely return a
    // preparation receipt. Resume needs neither paths on stdin nor local Nix queries.
    await stop();
    url = await start();
    await login();
    let small;
    for (const name of await readdir("/nix/store")) {
      if (name.endsWith(".drv")) continue;
      const candidate = join("/nix/store", name);
      const metadata = await lstat(candidate);
      if (metadata.isFile() && metadata.size < 4096) { small = candidate; break; }
    }
    assert.ok(small, "Nix shell must contain a small file output");
    const pipeline = await run("push", "pipeline", path, small, "--no-deps", "--resumable", "--jobs", "2");
    assert.match(pipeline.stdout, /2 pushed, 0 skipped.*0 failed/);
    const jobId = /Push job: ([a-z0-9-]+)/.exec(pipeline.stdout)?.[1];
    assert.ok(jobId, pipeline.stdout);
    const jobHeaders = { authorization: `Bearer ${credential}` };
    const completed = await (await fetch(`${url}/_api/v1/caches/pipeline/push-jobs/${jobId}`, { headers: jobHeaders })).json();
    assert.equal(completed.job.state, "completed");
    assert.equal(completed.available, true);
    assert.equal(completed.members.length, 2);
    for (const member of completed.members) assert.equal(member.session.status, "completed");
    const pipelineInfo = await fetch(`${url}/pipeline/${hash}.narinfo`, { headers: jobHeaders });
    assert.equal(pipelineInfo.status, 200);
    const pipelineMetadata = await pipelineInfo.text();
    const pipelineDownload = await fetch(new URL(/^URL: (.+)$/m.exec(pipelineMetadata)[1], pipelineInfo.url), { headers: jobHeaders });
    assert.equal(pipelineDownload.status, 200);
    assert.equal(await digest("zstd", ["-d", "-q", "-c"], Buffer.from(await pipelineDownload.arrayBuffer())), await digest("nix-store", ["--dump", path]));
    const smallInfo = await fetch(`${url}/pipeline/${small.split("/").at(-1).slice(0, 32)}.narinfo`, { headers: jobHeaders });
    assert.equal(smallInfo.status, 200);
    const smallMetadata = await smallInfo.text();
    const smallDownload = await fetch(new URL(/^URL: (.+)$/m.exec(smallMetadata)[1], smallInfo.url), { headers: jobHeaders });
    assert.equal(smallDownload.status, 200);
    assert.equal(await digest("zstd", ["-d", "-q", "-c"], Buffer.from(await smallDownload.arrayBuffer())), await digest("nix-store", ["--dump", small]));
    await stop();
    url = await start();
    await login();
    const resumed = await run("push", "pipeline", "--resume", jobId);
    assert.match(resumed.stdout, /0 pushed, 2 skipped.*0 failed/);
    const cached = await run("push", "pipeline", path, small, "--no-deps", "--resumable");
    assert.match(cached.stdout, /0 pushed, 2 skipped.*0 failed/);
    const closure = (await exec("nix-store", ["--query", "--requisites", small])).stdout.trim().split("\n");
    const cachedMembers = closure.filter(member => member === small || member === path).length;
    const fullClosure = await run("push", "pipeline", small, "--resumable");
    assert.match(fullClosure.stdout, new RegExp(`${closure.length - cachedMembers} pushed, ${cachedMembers} skipped.*0 failed`));
    await stop();
    env.PUSH_JOB_PUBLICATION_WORKERS = "0";
    url = await start();
    await login();
    let interrupted;
    await assert.rejects(run("push", "pipeline", small, "--no-deps", "--resumable"), error => {
      assert.match(error.stderr, /require server publication workers/);
      interrupted = /Push job: (\S+)/.exec(error.stdout)?.[1];
      assert.ok(interrupted, error.stdout);
      return true;
    });
    await stop();
    env.PUSH_JOB_PUBLICATION_WORKERS = "1";
    url = await start();
    await login();
    const recovered = await run("push", "pipeline", "--resume", interrupted);
    assert.match(recovered.stdout, /0 pushed, 1 skipped.*0 failed/);
    const removed = await fetch(`${url}/_api/v1/admin/caches/pipeline/paths/delete`, {
      method: "POST", headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
      body: JSON.stringify({ storePathHashes: [hash] }),
    });
    assert.equal(removed.status, 200);
    await assert.rejects(run("push", "pipeline", "--resume", jobId), /no longer fully available/);
    assert.equal((await fetch(`${url}/pipeline/${hash}.narinfo`, { headers: jobHeaders })).status, 404);
    const revoked = await fetch(`${url}/_api/v1/admin/tokens/${jti}/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "fixture complete" }),
    });
    assert.equal(revoked.status, 200);
    await assert.rejects(run("push", "native", path, "--no-deps"), /401|[Rr]evoked|[Uu]nauthorized/);
  } finally {
    await stop();
    await rm(home, { recursive: true, force: true });
    await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
    await admin.end();
  }
});
