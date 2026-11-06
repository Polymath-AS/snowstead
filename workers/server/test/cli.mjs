// Build both binaries first; run via scripts/with-postgres.sh scripts/with-r2.sh node --test <this file>.
import assert from "node:assert/strict";
import { createCipheriv, createHash, generateKeyPairSync, randomBytes, randomUUID, verify } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
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
    ADMIN_SECRET: operator, JWT_SECRET: randomBytes(32).toString("hex"), AUTH_TOKEN: "",
    SIGNING_MASTER_KEY: master.toString("base64"), REQUIRE_CACHE_SIGNING_KEYS: "true",
    PUBLIC_CACHE_ORIGIN: "", CDN_ZONE_ID: "", CDN_PURGE_TOKEN: "",
    ANALYTICS_TOKEN: "", TRUSTED_PROXY_IPS: "",
    DATABASE_MAX_CONNECTIONS: "2", LISTEN_ADDR: "127.0.0.1:0", RUST_LOG: "info", PUBLIC_URL: "", UPSTREAM_CACHES: "" };
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
      const { rows: [{ id }] } = await db.query("INSERT INTO caches(name) VALUES ('native') RETURNING id");
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
    } finally { await db.end(); }
    let url = await start();
    const issued = await fetch(`${url}/_api/v1/admin/tokens`, {
      method: "POST",
      headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
      body: JSON.stringify({ subject: "cli-migration", caches: ["native"], perms: ["pull", "push"] }),
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
