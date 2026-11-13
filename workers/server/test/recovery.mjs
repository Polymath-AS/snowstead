// Build the server first; run via scripts/with-postgres.sh scripts/with-r2.sh node --test <this file>.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, request } from "node:http";
import { createConnection, createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "pg";

const binary = new URL("../../../target/debug/snowstead-server", import.meta.url).pathname;

async function recovery(fault) {
  const unconfirmed = fault === "prepare" || fault === "lease";
  const base = process.env.SNOWSTEAD_TEST_DATABASE_URL;
  assert.ok(base, "run via scripts/with-postgres.sh");
  const upstream = process.env.SNOWSTEAD_TEST_R2_ENDPOINT;
  assert.match(upstream ?? "", /^http:\/\/127\.0\.0\.1:/, "requires disposable S3");
  assert.equal(process.env.R2_ENDPOINT, upstream);
  const admin = new Client({ connectionString: base });
  await admin.connect();
  const name = `snowstead_server_recovery_${process.pid}_${fault}`;
  await admin.query(`CREATE DATABASE "${name}"`);
  const database = new URL(base);
  database.pathname = `/${name}`;
  const db = new Client({ connectionString: database.toString() });
  let connected = false;
  let id;
  let lostCommits = 0;
  let sqlProxy;
  const connections = new Set();
  const serverDatabase = new URL(database);
  if (fault === "commit") {
    // Parse complete backend messages, including fragmented headers/bodies.
    // Withhold the publication's CommandComplete and every following byte:
    // PostgreSQL committed, but SQLx cannot receive confirmation of COMMIT.
    sqlProxy = createTcpServer(client => {
      const backend = createConnection({ host: database.hostname, port: Number(database.port) });
      client.setNoDelay(true);
      backend.setNoDelay(true);
      connections.add(client);
      client.on("error", () => backend.destroy());
      backend.on("error", () => client.destroy());
      client.on("close", () => { backend.destroy(); connections.delete(client); });
      backend.on("end", () => client.end());
      client.pipe(backend);
      let buffered = Buffer.alloc(0);
      backend.on("data", async chunk => {
        backend.pause();
        buffered = Buffer.concat([buffered, chunk]);
        try {
          while (buffered.length >= 5) {
            const length = 1 + buffered.readUInt32BE(1);
            if (buffered.length < length) break;
            const message = buffered.subarray(0, length);
            buffered = buffered.subarray(length);
            if (!lostCommits && id && message[0] === 67 && message.subarray(5).toString() === "COMMIT\0") {
              const { rows: [session] } = await db.query("SELECT status FROM upload_sessions WHERE id=$1", [id]);
              if (session.status === "completed") {
                lostCommits++;
                client.destroy();
                backend.destroy();
                return;
              }
            }
            client.write(message);
          }
          backend.resume();
        } catch (error) {
          client.destroy(error);
          backend.destroy();
        }
      });
    });
    sqlProxy.listen(0, "127.0.0.1");
    await once(sqlProxy, "listening");
    serverDatabase.port = String(sqlProxy.address().port);
    serverDatabase.searchParams.set("sslmode", "disable");
  }
  const mcHome = await mkdtemp(join(tmpdir(), "snowstead-recovery-s3-"));
  let storageWork = 0;
  let stagingCompletions = 0;
  let lostStagingReplies = 0;
  let holdWrite = unconfirmed;
  let storedCandidate;
  let releaseWrite;
  const proxy = createServer((incoming, outgoing) => {
    const url = new URL(incoming.url, upstream);
    if ((url.pathname.includes("/nar/objects/") || url.pathname.includes("/staging/"))
      && ["GET", "PUT", "POST"].includes(incoming.method) && !url.searchParams.has("delete")) storageWork++;
    const forwarded = request(url, { method: incoming.method, headers: incoming.headers }, response => {
      if (incoming.method === "POST" && url.pathname.includes("/staging/") && url.searchParams.has("uploadId")) {
        // A retry may receive NoSuchUpload and reconcile the existing staged
        // object with HEAD. Only count the successful provider completion.
        if (response.statusCode === 200) {
          stagingCompletions++;
          if (lostStagingReplies === 0) {
            // Storage has committed, but the server never sees its XML reply.
            // Retry must reconcile NoSuchUpload with the staged object's HEAD.
            lostStagingReplies++;
            response.resume();
            response.on("end", () => outgoing.destroy());
            return;
          }
        }
      }
      // The process/lease fault targets only the final immutable object,
      // after the lost staging-completion response has been reconciled.
      const candidateWrite = url.pathname.includes("/nar/objects/")
        && ((incoming.method === "PUT" && !url.searchParams.has("partNumber"))
          || (incoming.method === "POST" && url.searchParams.has("uploadId")));
      if (holdWrite && candidateWrite) {
        assert.equal(response.statusCode, 200);
        const chunks = [];
        response.on("data", chunk => chunks.push(chunk));
        response.on("end", () => {
          storedCandidate = url.pathname;
          releaseWrite = () => { outgoing.writeHead(response.statusCode, response.headers); outgoing.end(Buffer.concat(chunks)); };
        });
        return;
      }
      outgoing.writeHead(response.statusCode, response.headers);
      response.pipe(outgoing);
    });
    forwarded.on("error", error => outgoing.destroy(error));
    incoming.pipe(forwarded);
  });
  proxy.listen(0, "127.0.0.1");
  await once(proxy, "listening");
  const env = { ...process.env, DATABASE_URL: serverDatabase.toString(),
    ALLOW_SHARED_AUTH_TOKEN: "true", AUTH_TOKEN: randomBytes(32).toString("hex"), ADMIN_SECRET: randomBytes(32).toString("hex"), WEB_ASSERTIONS_DISABLED: "true",    JWT_SECRET: "", SIGNING_MASTER_KEY: "", REQUIRE_CACHE_SIGNING_KEYS: "false",
    PUBLIC_CACHE_ORIGIN: "", CDN_ZONE_ID: "", CDN_PURGE_TOKEN: "", ANALYTICS_TOKEN: "",
    TRUSTED_PROXY_IPS: "", PUBLIC_URL: "", UPSTREAM_CACHES: "",
    DATABASE_MAX_CONNECTIONS: "1",
    R2_BUCKET_NAME: `recovery-private-${process.pid}-${fault}`, R2_PUBLIC_BUCKET_NAME: `recovery-public-${process.pid}-${fault}`,
    R2_ENDPOINT: `http://127.0.0.1:${proxy.address().port}`,
    LISTEN_ADDR: "127.0.0.1:0", RUST_LOG: "info" };
  delete env.DATABASE_READ_URL;
  let server;
  let closed;
  const start = async () => {
    server = spawn(binary, [], { env, stdio: ["ignore", "pipe", "inherit"] });
    closed = once(server, "exit");
    const lines = createInterface({ input: server.stdout });
    const [line] = await Promise.race([
      once(lines, "line"),
      closed.then(result => { throw new Error(`server exited before listening: ${result}`); }),
    ]);
    const address = /127\.0\.0\.1:\d+/.exec(line)?.[0];
    assert.ok(address, line);
    return `http://${address}`;
  };
  const stop = async signal => {
    server.kill(signal);
    const result = await closed;
    server = undefined;
    return result;
  };
  const post = async (origin, path, body) => {
    const response = await fetch(`${origin}${path}`, {
      method: "POST", headers: { authorization: `Bearer ${env.AUTH_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  try {
    // Every test database needs its own buckets: another database's orphan
    // sweep cannot distinguish these live objects from abandoned objects.
    const s3 = new URL(upstream);
    s3.username = process.env.R2_ACCESS_KEY_ID;
    s3.password = process.env.R2_SECRET_ACCESS_KEY;
    const buckets = spawnSync("mc", ["--config-dir", mcHome, "mb",
      `recovery/${env.R2_BUCKET_NAME}`, `recovery/${env.R2_PUBLIC_BUCKET_NAME}`],
    { env: { ...process.env, MC_HOST_recovery: s3.href } });
    assert.equal(buckets.status, 0, buckets.stderr.toString());
    const migration = spawn(binary, ["migrate"], { env, stdio: "inherit" });
    assert.equal((await once(migration, "exit"))[0], 0);
    await db.connect();
    connected = true;
    await db.query("INSERT INTO caches(name) VALUES('recovery'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches");
    let origin = await start();
    // Independent regular-file NAR encoding, including eight-byte framing.
    const words = ["nix-archive-1", "(", "type", "regular", "contents", "prepared bytes survive process death", ")"];
    const raw = Buffer.concat(words.flatMap(word => {
      const bytes = Buffer.from(word);
      const length = Buffer.alloc(8);
      length.writeBigUInt64LE(BigInt(bytes.length));
      return [length, bytes, Buffer.alloc((8 - bytes.length % 8) % 8)];
    }));
    const encoded = spawnSync("zstd", ["-q", "-3", "-c"], { input: raw });
    assert.equal(encoded.status, 0, encoded.stderr.toString());
    const compressed = encoded.stdout;
    const fileHash = createHash("sha256").update(compressed).digest("hex");
    const narHash = `sha256-${createHash("sha256").update(raw).digest("base64")}`;
    const hash = "a".repeat(32);
    const created = await post(origin, "/_api/v1/caches/recovery/upload-streams/batch", { paths: [{
      storePath: `/nix/store/${hash}-recovery`, storePathHash: hash, narHash, narSize: raw.length,
      compression: "zstd", references: [], inline: false,
    }] });
    assert.equal(created.status, 201, JSON.stringify(created));
    id = created.body.sessions[0].sessionId;
    const reserved = await post(origin, `/_api/v1/uploads/${id}/parts`, { parts: [{ partNumber: 1, size: compressed.length }] });
    assert.equal(reserved.status, 200, JSON.stringify(reserved));
    const [grant] = reserved.body.parts;
    const grantUrl = new URL(grant.url);
    assert.equal(grantUrl.origin, env.R2_ENDPOINT);
    assert.ok(grantUrl.pathname.startsWith(`/${env.R2_BUCKET_NAME}/staging/${id}/`));
    assert.ok(grantUrl.searchParams.has("uploadId"));
    assert.equal(grantUrl.searchParams.get("partNumber"), "1");
    assert.ok(grantUrl.searchParams.has("X-Amz-Signature"));
    assert.ok(grantUrl.searchParams.get("X-Amz-SignedHeaders").split(";").includes("content-length"));
    const grantHeaders = new Headers(grant.headers);
    assert.equal(grantHeaders.has("authorization"), false);
    assert.equal(grantHeaders.get("content-length"), String(compressed.length));
    const uploaded = await fetch(grantUrl, {
      method: "PUT", headers: grantHeaders, body: compressed,
    });
    assert.equal(uploaded.status, 200, await uploaded.text());
    const etag = uploaded.headers.get("etag")?.replace(/^"|"$/g, "");
    assert.ok(etag, "S3 UploadPart must return its receipt in the ETag header");
    const receipt = { sessionId: id, narHash, narSize: raw.length, fileHash, fileSize: compressed.length,
      parts: [{ partNumber: 1, etag }] };

    // Confirmed candidates pause inside publication SQL; unconfirmed ones
    // pause at the successful storage reply, before SQL confirmation starts.
    if (!unconfirmed) {
      await db.query(`CREATE FUNCTION pause_publication() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN PERFORM set_config('lock_timeout','0',true);
        PERFORM pg_advisory_xact_lock(78432::bigint); RETURN NEW; END $$;
      CREATE TRIGGER pause_publication BEFORE INSERT ON published_paths
      FOR EACH ROW EXECUTE FUNCTION pause_publication()`);
      await db.query("BEGIN; SELECT pg_advisory_xact_lock(78432::bigint)");
    }
    // Handle the expected disconnect immediately to avoid an unhandled rejection.
    const pending = post(origin, "/_api/v1/uploads/finalize", { uploads: [receipt] })
      .then(result => ({ result }), error => ({ error }));
    const deadline = Date.now() + 10_000;
    let backend;
    for (;;) {
      if (unconfirmed) {
        if (storedCandidate) break;
        assert.ok(Date.now() < deadline, "storage must finish before confirmation");
        await delay(10);
        continue;
      }
      const { rows } = await db.query(`SELECT pid FROM pg_locks
        WHERE locktype='advisory' AND classid=0 AND objid=78432 AND NOT granted`);
      if (rows.length) { backend = rows[0].pid; break; }
      assert.ok(Date.now() < deadline, "publisher must reach the insertion barrier");
      await delay(10);
    }
    const { rows: [candidate] } = await db.query("SELECT key,phase FROM nar_installations WHERE session_id=$1", [id]);
    assert.equal(lostStagingReplies, 1, "must lose the committed staging upload's reply");
    assert.equal(stagingCompletions, 1, "must reconcile staging completion without repeating the upload");
    assert.equal(candidate.phase, unconfirmed ? "preparing" : "ready");
    let before = storageWork;
    assert.ok(before > 0);
    if (fault !== "commit" && fault !== "lease") {
      const stored = spawnSync("mc", ["--config-dir", mcHome, "cat", `recovery/${env.R2_PUBLIC_BUCKET_NAME}/${candidate.key}`],
        { env: { ...process.env, MC_HOST_recovery: s3.href } });
      assert.equal(stored.status, 0, stored.stderr.toString());
      assert.deepEqual(stored.stdout, compressed, "the immutable object must exist before killing its writer");
      assert.deepEqual(await stop("SIGKILL"), [null, "SIGKILL"]);
      assert.ok((await pending).error, "the original caller must lose its response");
      if (!unconfirmed) await db.query("ROLLBACK; DROP TRIGGER pause_publication ON published_paths");
      holdWrite = false;
      // PostgreSQL must observe the closed socket and roll back the abandoned
      // transaction. Wait for that event, not an assumed process-start delay.
      const disconnected = Date.now() + 5_000;
      while ((await db.query("SELECT pid FROM pg_stat_activity WHERE pid=$1", [backend])).rowCount) {
        assert.ok(Date.now() < disconnected, "the crashed process must release its SQL transaction");
        await delay(10);
      }
      assert.equal((await db.query("SELECT count(*)::int AS n FROM published_paths")).rows[0].n, 0);
      assert.equal((await db.query("SELECT status FROM upload_sessions WHERE id=$1", [id])).rows[0].status, "finalizing");
      assert.deepEqual((await db.query("SELECT key,phase FROM nar_installations WHERE session_id=$1", [id])).rows[0], candidate);

      origin = await start();
      const missing = await fetch(`${origin}/recovery/${hash}.narinfo`);
      assert.equal(missing.status, 404, "uncommitted metadata must not survive the crash");
      await missing.arrayBuffer();
    } else if (fault === "commit") {
      await db.query("ROLLBACK");
      const original = await pending;
      assert.equal(lostCommits, 1, "the committed publication must lose its SQL acknowledgement");
      assert.equal(original.result?.status, 200, JSON.stringify(original));
      assert.equal(original.result.body.results[0].published, true, JSON.stringify(original));
      assert.equal(storageWork, before, "singleton recovery must not repeat preparation");
      assert.equal((await db.query("SELECT status FROM upload_sessions WHERE id=$1", [id])).rows[0].status, "completed");
      await db.query("DROP TRIGGER pause_publication ON published_paths");
      assert.deepEqual(await stop("SIGTERM"), [0, null]);
      origin = await start();
    }
    if (unconfirmed) {
      if (fault === "lease") {
        const { rows: [initial] } = await db.query("SELECT lease_expires_at FROM nar_installations WHERE session_id=$1", [id]);
        const renewalDeadline = Date.now() + 25_000;
        for (;;) {
          const { rows: [current] } = await db.query("SELECT lease_expires_at FROM nar_installations WHERE session_id=$1", [id]);
          if (current.lease_expires_at > initial.lease_expires_at) break;
          assert.ok(Date.now() < renewalDeadline, "a live worker must renew its execution lease during storage I/O");
          await delay(100);
        }
      }
      const busy = await post(origin, "/_api/v1/uploads/finalize", { uploads: [receipt] });
      assert.equal(busy.body.results[0].status, 503, JSON.stringify(busy));
      assert.equal(storageWork, before, "a live lease must prevent duplicate preparation");
      // Advance only the execution deadline, not session expiry. No sleep or
      // test-only runtime setting changes the production heartbeat interval.
      await db.query("UPDATE nar_installations SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE session_id=$1", [id]);
      holdWrite = false;
      if (fault === "prepare") {
        assert.deepEqual(await stop("SIGTERM"), [0, null]);
        origin = await start();
        const expiryDeadline = Date.now() + 5_000;
        while ((await db.query("SELECT key FROM nar_installations WHERE session_id=$1", [id])).rowCount) {
          assert.ok(Date.now() < expiryDeadline, "maintenance must retire an expired execution without a client retry");
          await delay(10);
        }
      }
    }
    const retried = await post(origin, "/_api/v1/uploads/finalize", { uploads: [receipt] });
    assert.equal(retried.status, 200, JSON.stringify(retried));
    assert.equal(retried.body.results[0].published, true, JSON.stringify(retried));
    if (unconfirmed) {
      assert.ok(storageWork > before, "unconfirmed preparation must be verified again");
      before = storageWork;
    } else assert.equal(storageWork, before, "a fresh process must not read or write prepared bytes again");
    if (fault === "lease") {
      releaseWrite();
      const stale = await pending;
      assert.equal(stale.result?.body.results[0].status, 409, JSON.stringify(stale));
      assert.equal(stale.result.body.results[0].published, false);
    }
    const replayed = await post(origin, "/_api/v1/uploads/finalize", { uploads: [receipt] });
    assert.deepEqual(replayed, retried);
    assert.equal(storageWork, before);
    const { rows: [totals] } = await db.query("SELECT path_count::int AS path_count,size::int AS size FROM caches WHERE name='recovery'");
    assert.deepEqual(totals, { path_count: 1, size: compressed.length });
    assert.equal((await db.query("SELECT count(*)::int AS n FROM nar_installations")).rows[0].n, 0);
    const { rows: [adopted] } = await db.query("SELECT public_key FROM blob_objects WHERE file_hash=$1", [fileHash]);
    if (unconfirmed) assert.notEqual(adopted.public_key, candidate.key);
    else assert.equal(adopted.public_key, candidate.key);
    if (unconfirmed) {
      assert.deepEqual(await stop("SIGTERM"), [0, null]);
      origin = await start();
      const cleanupDeadline = Date.now() + 5_000;
      for (;;) {
        const retired = spawnSync("mc", ["--config-dir", mcHome, "stat", "--json",
          `recovery/${env.R2_PUBLIC_BUCKET_NAME}/${candidate.key}`],
        { env: { ...process.env, MC_HOST_recovery: s3.href } });
        if (retired.status !== 0) {
          assert.equal(JSON.parse(retired.stdout).error.cause.message, "Object does not exist");
          break;
        }
        assert.ok(Date.now() < cleanupDeadline, "maintenance must delete the retired attempt, not the adopted object");
        await delay(10);
      }
    }
    const metadata = await fetch(`${origin}/recovery/${hash}.narinfo`);
    assert.equal(metadata.status, 200);
    assert.match(await metadata.text(), new RegExp(`^FileHash: sha256:${fileHash}$`, "m"));
    const download = await fetch(`${origin}/nar/${fileHash}/zstd.nar`);
    assert.equal(download.status, 200);
    assert.deepEqual(Buffer.from(await download.arrayBuffer()), compressed);
    assert.deepEqual(await stop("SIGTERM"), [0, null]);
  } finally {
    // Release the database barrier before cleanup, including assertion failures.
    if (connected) await db.query("ROLLBACK").catch(() => {});
    if (server) await stop("SIGKILL");
    if (sqlProxy) {
      for (const client of connections) client.destroy();
      await new Promise(resolve => sqlProxy.close(resolve));
    }
    await db.end();
    proxy.closeAllConnections();
    await new Promise(resolve => proxy.close(resolve));
    await rm(mcHome, { recursive: true, force: true });
    await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
    await admin.end();
  }
}

test("SIGKILL before publication commit preserves prepared bytes for a fresh process", { timeout: 60_000 }, () => recovery("kill"));
test("lost SQL COMMIT reply recovers the durable outcome without repeating preparation", { timeout: 60_000 }, () => recovery("commit"));
test("SIGKILL before preparation confirmation allows a fenced retry", { timeout: 60_000 }, () => recovery("prepare"));
test("an expired preparation worker cannot adopt or retire its replacement", { timeout: 60_000 }, () => recovery("lease"));
