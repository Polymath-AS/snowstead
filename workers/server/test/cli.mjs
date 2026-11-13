// Build both binaries first; run via scripts/with-postgres.sh scripts/with-r2.sh node --test <this file>.
import assert from "node:assert/strict";
import { createCipheriv, createHash, generateKeyPairSync, randomBytes, randomUUID, verify } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { lstat, mkdtemp, readdir, realpath, rm } from "node:fs/promises";
import { createServer, request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { test } from "node:test";
import { setTimeout } from "node:timers/promises";
import { Client } from "pg";

const exec = promisify(execFile);
const cli = process.env.SNOWSTEAD_TEST_CLI ?? new URL("../../../target/debug/snowstead", import.meta.url).pathname;
const serverBinary = process.env.SNOWSTEAD_TEST_SERVER ?? new URL("../../../target/debug/snowstead-server", import.meta.url).pathname;

test("real CLI uploads directly under bounded admission, verifies signed downloads, and resumes after restart", { timeout: 240_000 }, async t => {
  const base = process.env.SNOWSTEAD_TEST_DATABASE_URL;
  assert.ok(base, "run via scripts/with-postgres.sh");
  assert.equal(process.env.R2_ENDPOINT, process.env.SNOWSTEAD_TEST_R2_ENDPOINT, "run via scripts/with-r2.sh");
  assert.ok(process.env.SNOWSTEAD_TEST_R2_ENDPOINT, "requires disposable S3 buckets");
  assert.equal(new URL(process.env.R2_ENDPOINT).hostname, "127.0.0.1");
  assert.equal(process.env.R2_BUCKET_NAME, "snowstead-private");
  assert.equal(process.env.R2_PUBLIC_BUCKET_NAME, "snowstead-public");
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
    R2_BUCKET_NAME: `snowstead-private-cli-${process.pid}`, R2_PUBLIC_BUCKET_NAME: `snowstead-public-cli-${process.pid}`,
    UPLOAD_BUFFER_MIB: "32", MAX_UPLOAD_PART_MIB: "16", MAX_ACTIVE_VERIFICATIONS: "1",
    DATABASE_MAX_CONNECTIONS: "2", PUSH_JOB_PUBLICATION_WORKERS: "1", LISTEN_ADDR: "127.0.0.1:0", RUST_LOG: "info", PUBLIC_URL: "", UPSTREAM_CACHES: "" };
  let origin;
  let stallVerification = false;
  let verificationStalled = false;
  let restarting = false;
  const storageProxy = createServer((incoming, outgoing) => {
    // Only the service's verification GET is stalled. CLI UploadPart requests
    // and their signed headers pass through unchanged to disposable loopback S3.
    if (stallVerification && incoming.method === "GET" && incoming.url.includes("/staging/")) {
      verificationStalled = true;
      return;
    }
    const upstream = request(new URL(incoming.url, process.env.SNOWSTEAD_TEST_R2_ENDPOINT), {
      method: incoming.method, headers: incoming.headers,
    }, response => {
      outgoing.writeHead(response.statusCode, response.headers);
      response.pipe(outgoing);
    });
    upstream.on("error", error => outgoing.destroy(error));
    incoming.pipe(upstream);
  });
  storageProxy.listen(0, "127.0.0.1");
  await once(storageProxy, "listening");
  env.R2_ENDPOINT = `http://127.0.0.1:${storageProxy.address().port}`;
  const traffic = { relay: 0, inline: 0, grants: 0, sessions: new Set(), errors: [], finalize: 0, accepted: 0, polls: 0, deadlines: 0 };
  // Observe the API separately from streaming S3 traffic. Old relay grants
  // fail both the URL assertions and the no-relay request count.
  const proxy = createServer((incoming, outgoing) => {
    if (/\/uploads\/[^/]+\/part\/\d+/.test(incoming.url)) traffic.relay++;
    if (/\/uploads\/(?:inline\/batch|[^/]+\/inline)/.test(incoming.url)) traffic.inline++;
    if (incoming.url === "/_api/v1/uploads/finalize") traffic.finalize++;
    if (incoming.url === "/_api/v1/uploads/status") traffic.polls++;
    const upstream = request(new URL(incoming.url, origin), {
      method: incoming.method, headers: incoming.headers,
      signal: /\/_api\/v1\/uploads\/(finalize|status)$/.test(incoming.url) ? AbortSignal.timeout(2_000) : undefined,
    }, response => {
      if (incoming.url === "/_api/v1/uploads/finalize" && response.statusCode === 202) traffic.accepted++;
      outgoing.writeHead(response.statusCode, response.headers);
      if (incoming.method === "POST" && /\/uploads\/(?:parts|[^/]+\/parts)$/.test(incoming.url)) {
        const chunks = [];
        response.on("data", chunk => chunks.push(chunk));
        response.on("end", () => {
          try {
            const body = JSON.parse(Buffer.concat(chunks));
            for (const item of body.results ?? [body]) {
              for (const grant of item.parts ?? []) {
                const url = new URL(grant.url);
                assert.equal(url.origin, env.R2_ENDPOINT);
                assert.ok(url.pathname.startsWith(`/${env.R2_BUCKET_NAME}/`));
                assert.ok(url.searchParams.has("uploadId"));
                assert.ok(url.searchParams.has("partNumber"));
                assert.ok(url.searchParams.has("X-Amz-Signature"));
                assert.ok(url.searchParams.get("X-Amz-SignedHeaders").split(";").includes("content-length"));
                const headers = new Headers(grant.headers);
                assert.equal(headers.has("authorization"), false);
                assert.ok(Number(headers.get("content-length")) > 0);
                traffic.grants++;
                traffic.sessions.add(url.searchParams.get("uploadId"));
              }
            }
          } catch (error) { traffic.errors.push(error.message); }
        });
      }
      response.pipe(outgoing);
    });
    upstream.on("error", error => {
      if (error.name === "AbortError") traffic.deadlines++;
      else if (!restarting) traffic.errors.push(error.message);
      if (!outgoing.headersSent) outgoing.writeHead(error.name === "AbortError" ? 524 : 503);
      outgoing.end();
    });
    incoming.pipe(upstream);
  });
  proxy.listen(0, "127.0.0.1");
  await once(proxy, "listening");
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
    origin = `http://${address}`;
    return `http://127.0.0.1:${proxy.address().port}`;
  };
  try {
    // Restarts run orphan cleanup. Do not share buckets with another test DB.
    const storage = new URL(process.env.SNOWSTEAD_TEST_R2_ENDPOINT);
    storage.username = env.R2_ACCESS_KEY_ID;
    storage.password = env.R2_SECRET_ACCESS_KEY;
    await exec("mc", ["--config-dir", join(home, "mc"), "mb",
      `fixture/${env.R2_BUCKET_NAME}`, `fixture/${env.R2_PUBLIC_BUCKET_NAME}`],
    { env: { ...process.env, MC_HOST_fixture: storage.href } });
    await exec(serverBinary, ["migrate"], { env });
    const db = new Client({ connectionString: database.toString() });
    await db.connect();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    try {
      for (const cache of ["native", "pipeline", "direct"]) {
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
      body: JSON.stringify({ subject: "cli-migration", caches: ["native", "pipeline", "direct"], perms: ["pull", "push"] }),
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
    const nixBinary = await realpath((await exec("which", ["nix-store"])).stdout.trim());
    const nixPath = /^(\/nix\/store\/[^/]+)/.exec(nixBinary)?.[1];
    assert.ok(nixPath && nixPath !== path, "requires two distinct immutable Nix outputs");
    const requisites = (await exec("nix-store", ["--query", "--requisites", path, nixPath])).stdout.trim().split("\n");
    const closurePaths = [...new Set(requisites)].sort();
    const sizes = JSON.parse((await exec("nix", [
      "--extra-experimental-features", "nix-command", "path-info", "--json", ...closurePaths,
    ], { maxBuffer: 4 * 1024 * 1024 })).stdout);
    // Nix versions return either an array of records or an object keyed by
    // store path. Select existing outputs only; never build or mutate fixtures.
    const outputs = Array.isArray(sizes) ? sizes : Object.entries(sizes).map(([path, info]) => ({ ...info, path }));
    const directPaths = outputs.filter(info => info.path !== path && Number(info.narSize) > 1024 * 1024)
      .sort((a, b) => Number(b.narSize) - Number(a.narSize) || a.path.localeCompare(b.path)).slice(0, 32);
    assert.ok(directPaths.length > 8, "nix develop closures must exercise more than eight multipart preparations");
    // Intentionally omit --jobs and retry overrides: exercise the production
    // CLI default of 32 with the unchanged completion batching/retry policy.
    const directStarted = performance.now();
    const concurrent = await run("push", "direct", ...directPaths.map(info => info.path), "--no-deps");
    const directElapsed = performance.now() - directStarted;
    assert.match(concurrent.stdout, new RegExp(`${directPaths.length} pushed, 0 skipped`));
    assert.equal(concurrent.stderr, "");
    assert.deepEqual(traffic.errors, []);
    assert.equal(traffic.relay, 0, "NAR parts must never enter API body admission");
    assert.equal(traffic.inline, 0, "large immutable fixtures must exercise multipart, not inline");
    assert.ok(traffic.grants > directPaths.length, "must exercise multi-part NARs as well as concurrent outputs");
    assert.equal(traffic.sessions.size, directPaths.length, "every concurrent path must upload directly");
    const narMiB = directPaths.reduce((sum, info) => sum + Number(info.narSize), 0) / 1024 ** 2;
    t.diagnostic(`direct upload: ${directPaths.length} immutable outputs, ${narMiB.toFixed(1)} MiB NAR input in ${(directElapsed / 1000).toFixed(2)}s, ${traffic.grants} S3 grants, zero relay/inline API uploads, default jobs=32`);
    for (const output of directPaths) {
      const storePath = output.path;
      const response = await fetch(`${url}/direct/${storePath.split("/").at(-1).slice(0, 32)}.narinfo`);
      assert.equal(response.status, 200, storePath);
      const metadata = await response.text();
      const field = name => new RegExp(`^${name}: (.+)$`, "m").exec(metadata)?.[1];
      assert.equal(field("StorePath"), storePath);
      assert.equal(Number(field("NarSize")), Number(output.narSize));
      assert.equal(field("Compression"), "zstd");
      const downloaded = await fetch(new URL(field("URL"), response.url));
      assert.equal(downloaded.status, 200, storePath);
      const bytes = Buffer.from(await downloaded.arrayBuffer());
      assert.equal(bytes.length, Number(field("FileSize")), storePath);
      assert.equal(`sha256:${createHash("sha256").update(bytes).digest("hex")}`, field("FileHash"), storePath);
      assert.equal(await digest("zstd", ["-d", "-q", "-c"], bytes), await digest("nix-store", ["--dump", storePath]), storePath);
    }
    // Keep the real CLI alive across an actual service crash after durable
    // acceptance, while verification has not read even one staged byte.
    stallVerification = true;
    const beforeRestart = { finalize: traffic.finalize, accepted: traffic.accepted, polls: traffic.polls };
    let pushFinished = false;
    const pendingPush = run("push", "native", path, "--no-deps", "--jobs", "2")
      .then(result => ({ result }), error => ({ error }))
      .finally(() => { pushFinished = true; });
    const stallDeadline = Date.now() + 20_000;
    while (!verificationStalled || traffic.accepted === beforeRestart.accepted) {
      assert.equal(pushFinished, false, "CLI must wait for durable completion");
      assert.ok(Date.now() < stallDeadline, "verification must reach the loopback storage barrier");
      await setTimeout(25);
    }
    // Longer than the proxy's entire HTTP deadline, not just the CLI's retry
    // interval: a blocking finalize would receive 524 here.
    await setTimeout(2_250);
    assert.equal(pushFinished, false);
    assert.ok(traffic.polls > beforeRestart.polls, "CLI must poll accepted work");
    assert.equal(traffic.deadlines, 0, "acceptance and polling must beat the short API deadline");
    restarting = true;
    server.kill("SIGKILL");
    assert.deepEqual(await closed, [null, "SIGKILL"]);
    server = undefined;
    storageProxy.closeAllConnections();
    stallVerification = false;
    const recovery = new Client({ connectionString: database.toString() });
    await recovery.connect();
    try {
      // Advance only dead execution leases, not retained data or delegation.
      await recovery.query(`UPDATE upload_finalization_batches SET lease_expires_at=NOW()-INTERVAL '1 second';
        UPDATE nar_installations SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE phase='preparing'`);
    } finally { await recovery.end(); }
    url = await start();
    restarting = false;
    const outcome = await pendingPush;
    assert.ifError(outcome.error);
    const pushed = outcome.result;
    assert.match(pushed.stdout, /1 pushed, 0 skipped/);
    assert.equal(pushed.stderr, "");
    assert.equal(traffic.finalize, beforeRestart.finalize + 1, "restart must not replay finalize receipts");
    assert.equal(traffic.deadlines, 0);
    t.diagnostic("CLI completed through a 2-second API proxy after SIGKILL during stalled verification; one finalize, status-only recovery");
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
    const cutover = new Client({ connectionString: database.toString() });
    await cutover.connect();
    try {
      // Simulate persisted relay receipts from the deployed release. A new
      // server must refuse the cutover, not silently replace their source MPU.
      await cutover.query(`INSERT INTO upload_sessions
        (id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_size,compression,status,r2_upload_id,part_size,expires_at)
        SELECT 'relay-cutover',id,repeat('a',32),'/nix/store/'||repeat('a',32)||'-cutover',
          'sha256:test',1,1,'zstd','streaming','relay-cutover',8388608,NOW()+INTERVAL '1 hour'
        FROM caches WHERE name='native';
        INSERT INTO upload_parts(session_id,part_number,size,etag,storage_key)
        VALUES('relay-cutover',1,1,'old-receipt','staging/relay-cutover/old')`);
      for (const status of ["streaming", "finalizing"]) {
        await cutover.query("UPDATE upload_sessions SET status=$1 WHERE id='relay-cutover'", [status]);
        await assert.rejects(exec(serverBinary, ["check-upload-cutover"], { env }), /1 active relayed upload sessions/);
        await assert.rejects(exec(serverBinary, [], { env, timeout: 10_000 }), /1 active relayed upload sessions/);
        const { rows: [row] } = await cutover.query(`SELECT u.status,p.etag FROM upload_sessions u
          JOIN upload_parts p ON p.session_id=u.id WHERE u.id='relay-cutover'`);
        assert.deepEqual(row, { status, etag: "old-receipt" }, "preflight and startup must not change old uploads");
      }
      await cutover.query("UPDATE upload_sessions SET status='aborted' WHERE id='relay-cutover'");
      assert.match((await exec(serverBinary, ["check-upload-cutover"], { env })).stdout, /Upload cutover ready/);
    } finally { await cutover.end(); }
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
    const jobHeaders = { authorization: `Bearer ${credential}`, "snowstead-protocol-version": "2" };
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
    // Expiry must revoke the actual provider upload, not only SQL receipts.
    // A separate server process owns the startup maintenance sweep, avoiding
    // contention with other integration tests' process-wide maintenance lock.
    const expiryHash = "9".repeat(32);
    const headers = { ...jobHeaders, "content-type": "application/json" };
    const created = await fetch(`${url}/_api/v1/caches/native/upload-streams/batch`, {
      method: "POST", headers, body: JSON.stringify({ paths: [{
        storePath: `/nix/store/${expiryHash}-expiry`, storePathHash: expiryHash,
        narHash: `sha256-${Buffer.alloc(32).toString("base64")}`, narSize: 32,
        compression: "zstd", references: [], inline: false,
      }] }),
    });
    assert.equal(created.status, 201);
    const { sessions: [{ sessionId }] } = await created.json();
    const part = Buffer.from("expired staging fixture");
    const reserved = await fetch(`${url}/_api/v1/uploads/${sessionId}/parts`, {
      method: "POST", headers,
      body: JSON.stringify({ parts: [{ partNumber: 1, size: part.length }] }),
    });
    assert.equal(reserved.status, 200);
    const { parts: [grant] } = await reserved.json();
    const putPart = () => fetch(grant.url, { method: "PUT", headers: grant.headers, body: part });
    const uploaded = await putPart();
    assert.equal(uploaded.status, 200);
    await uploaded.arrayBuffer();
    await stop();
    const expiry = new Client({ connectionString: database.toString() });
    await expiry.connect();
    try {
      await expiry.query("UPDATE upload_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1", [sessionId]);
    } finally { await expiry.end(); }
    url = await start();
    let denied;
    for (let attempt = 0; attempt < 100; attempt++) {
      denied = await putPart();
      if (denied.status === 404) break;
      assert.equal(denied.status, 200);
      await denied.arrayBuffer();
      await setTimeout(50);
    }
    assert.equal(denied.status, 404, "expiry must cancel the provider MPU");
    assert.match(await denied.text(), /NoSuchUpload/);
    assert.equal((await fetch(`${url}/native/${expiryHash}.narinfo`, { headers: jobHeaders })).status, 404);
    const revoked = await fetch(`${url}/_api/v1/admin/tokens/${jti}/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "fixture complete" }),
    });
    assert.equal(revoked.status, 200);
    await assert.rejects(run("push", "native", path, "--no-deps"), /401|[Rr]evoked|[Uu]nauthorized/);
  } finally {
    stallVerification = false;
    storageProxy.closeAllConnections();
    await stop();
    proxy.closeAllConnections();
    await new Promise((resolve, reject) => proxy.close(error => error ? reject(error) : resolve()));
    storageProxy.closeAllConnections();
    await new Promise((resolve, reject) => storageProxy.close(error => error ? reject(error) : resolve()));
    await rm(home, { recursive: true, force: true });
    await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
    await admin.end();
  }
});
