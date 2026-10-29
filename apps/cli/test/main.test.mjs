import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { promisify } from "node:util";
import { uploadBlobMultipart, uploadPresignedParts, uploadSingle } from "../dist/api.js";
import { limiter } from "../dist/batch.js";

const exec = promisify(execFile);
const cli = new URL("../dist/main.js", import.meta.url);
const requests = [];
const hash = "0123456789abcdfghijklmnpqrsvwxyz";
const storePath = `/nix/store/${hash}-hello`;
let home;
let server;

function run(...args) {
  return exec(process.execPath, [cli.pathname, ...args], {
    env: { ...process.env, HOME: home, PATH: `${home}/bin:${process.env.PATH}` },
  });
}

before(async () => {
  home = await mkdtemp(join(tmpdir(), "snowstead-cli-test-"));
  server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    const data = body ? JSON.parse(body) : undefined;
    requests.push({ path: req.url, token: req.headers.authorization, body: data });
    res.setHeader("content-type", "application/json");
    if (req.url === "/_api/v1/get-missing-paths") {
      res.end(JSON.stringify({ missing: [], upstream: [hash] }));
    } else if (req.url === "/_api/v1/admin/tokens") {
      res.end(JSON.stringify({ ...data, token: "issued-token", jti: "new-token", expiresAt: "2027-01-01" }));
    } else if (req.url === "/_api/v1/admin/caches" && req.method === "GET") {
      res.end(JSON.stringify({ caches: [{ name: "main", private: false, protocols: ["nix", "go"], createdAt: "2026-01-01" }] }));
    } else {
      res.end(JSON.stringify({ protocols: ["nix"], ...data, created: true }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  await run("login", "selected", url, "selected-token");
  await run("login", "default", url, "default-token");
  await mkdir(join(home, "bin"));
  // Exercise the real CLI and streaming pipeline without requiring a Nix store.
  await writeFile(join(home, "bin/nix"), `#!${process.execPath}
const args = process.argv.slice(2);
if (args[0] === "path-info" && args[1] === "-r" && args[2] === "/run/current-system") {
  console.log(${JSON.stringify(storePath)});
} else if (args[0] === "path-info" && args[1] === "--json") {
  console.log(JSON.stringify(Object.fromEntries(args.slice(2).map((path) => [path, {
    narHash: "sha256:" + "1".repeat(52), narSize: 19, references: [],
  }]))));
} else if (args[0] === "store" && args[1] === "dump-path") {
  process.stdout.write("identical NAR bytes");
} else process.exit(1);
`, { mode: 0o755 });
  await writeFile(join(home, "bin/zstd"), `#!${process.execPath}
process.stdin.pipe(process.stdout);
`, { mode: 0o755 });
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (home) await rm(home, { recursive: true, force: true });
});

test("server selection never becomes part of a token revocation reason", async () => {
  for (const args of [
    ["token", "revoke", "old-token", "employee", "offboarded", "--server", "selected"],
    ["--server", "selected", "token", "revoke", "old-token", "employee", "offboarded"],
    ["token", "revoke", "--server", "selected", "old-token", "employee", "offboarded"],
  ]) {
    await run(...args);
    assert.deepEqual(requests.at(-1), {
      path: "/_api/v1/admin/tokens/old-token/revoke",
      token: "Bearer selected-token",
      body: { reason: "employee offboarded" },
    });
  }
});

test("token options may precede positionals and -- preserves literal reason text", async () => {
  await run("token", "create", "--caches", "main, staging", "--perms", "push,pull", "--expires", "7", "ci-runner");
  assert.deepEqual(requests.at(-1).body, {
    subject: "ci-runner", caches: ["main", "staging"], perms: ["push", "pull"], expiresInDays: 7,
  });
  await run("token", "revoke", "old-token", "--", "--server", "is literal");
  assert.deepEqual(requests.at(-1).body, { reason: "--server is literal" });
  assert.equal(requests.at(-1).token, "Bearer default-token");
});

test("cache visibility flags leave the cache name positional", async () => {
  for (const [flag, isPrivate] of [["--private", true], ["--public", false]]) {
    await run("cache", "set", flag, "main", "--server", "selected");
    assert.deepEqual(requests.at(-1).body, { name: "main", private: isPrivate });
    assert.equal(requests.at(-1).token, "Bearer selected-token");
  }
});

test("cache creation requires explicit protocols and sends only the selected protocols", async () => {
  for (const [value, protocols] of [["nix", ["nix"]], ["go", ["go"]], ["nix,go", ["nix", "go"]]]) {
    const { stdout } = await run("cache", "create", "--protocols", value, "main", "--private");
    assert.deepEqual(requests.at(-1).body, { name: "main", private: true, protocols });
    assert.match(stdout, new RegExp(`protocols=${value}`));
  }
});

test("cache set can add protocols alone or together with visibility", async () => {
  await run("cache", "set", "main", "--protocols", "nix,go");
  assert.deepEqual(requests.at(-1).body, { name: "main", protocols: ["nix", "go"] });
  await run("cache", "set", "main", "--protocols", "go,nix", "--public");
  assert.deepEqual(requests.at(-1).body, { name: "main", protocols: ["go", "nix"], private: false });
  const { stdout } = await run("cache", "list");
  assert.match(stdout, /main  public  protocols=nix,go  created=2026-01-01/);
});

test("cache protocol validation rejects missing, empty, duplicate and unknown selections before HTTP", async () => {
  const count = requests.length;
  await assert.rejects(run("cache", "create", "main"), /--protocols/);
  await assert.rejects(run("cache", "set", "main"), /--protocols/);
  for (const subcommand of ["create", "set"]) {
    for (const value of ["", ",", "nix,", "nix,nix", "go,go", "nix,go,nix", "Nix", "rust"]) {
      await assert.rejects(run("cache", subcommand, "main", "--protocols", value), /--protocols/);
    }
    await assert.rejects(run("cache", subcommand, "main", "--protocols", "nix", "--private", "--public"), /cannot be combined/);
  }
  assert.equal(requests.length, count);
});

test("push flags support both explicit paths and closure resolution", async () => {
  for (const paths of [[storePath], ["--closure", "/run/current-system"]]) {
    const { stdout } = await run("push", "--server", "selected", "main", "--jobs", "2", ...paths);
    assert.deepEqual(requests.at(-1), {
      path: "/_api/v1/get-missing-paths", token: "Bearer selected-token",
      body: { cache: "main", storePathHashes: [hash] },
    });
    assert.match(stdout, /0 pushed, 1 skipped \(1 served upstream\), 0 failed/);
  }
});

test("malformed options fail before making an API request", async () => {
  const count = requests.length;
  for (const args of [
    ["token", "list", "--server"],
    ["push", "main", storePath, "--jobs", "2oops"],
    ["token", "create", "ci", "--expires", "1.5"],
    ["cache", "list", "--unknown"],
  ]) {
    await assert.rejects(run(...args), (err) => err.code === 1 && err.stderr.length > 0);
  }
  assert.equal(requests.length, count);
});

for (const method of ["direct", "presigned"]) {
  test(`push proves possession for each ${method} session, including shared NAR keys`, async () => {
    const paths = Array.from({ length: 4 }, (_, i) => `/nix/store/${String(i + 1).repeat(32)}-same-nar`);
    const sessions = new Map();
    const owner = new Map();
    const published = new Set();
    const uploaded = [];
    const api = createServer(async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      const send = (data) => res.end(JSON.stringify(data));
      if (req.method === "PUT") {
        const id = req.url.split("/").at(-2);
        const session = sessions.get(id);
        assert.ok(session, `unknown session ${id}`);
        assert.equal(createHash("sha256").update(bytes).digest("hex"), session.fileHash);
        assert.equal(bytes.length, session.fileSize);
        uploaded.push(id);
        owner.set(session.r2Key, id);
        return send({ uploaded: true });
      }
      const data = JSON.parse(bytes);
      if (req.url === "/_api/v1/get-missing-paths") return send({ missing: data.storePathHashes });
      if (req.url.endsWith("/upload-sessions/batch")) {
        return send({ sessions: data.paths.map((path) => {
          const id = String(sessions.size + 1);
          // Two sessions share a canonical key; the others are staged.
          const r2Key = sessions.size < 2 ? `nar/${path.fileHash}/zstd.nar` : `staging/${id}`;
          sessions.set(id, { ...path, r2Key });
          return {
            sessionId: id, r2Key, uploadMethod: method,
            uploadUrl: `http://127.0.0.1:${api.address().port}/presigned/${id}/blob`, uploadHeaders: {},
          };
        }) });
      }
      assert.equal(req.url, "/_api/v1/uploads/commit");
      return send({ results: data.sessionIds.map((id) => {
        const session = sessions.get(id);
        if (owner.get(session.r2Key) !== id) return { sessionId: id, error: "Upload incomplete", status: 400 };
        published.add(session.storePath);
        return { sessionId: id, published: true };
      }) });
    });
    await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
    try {
      await run("login", "upload", `http://127.0.0.1:${api.address().port}`, "push-token");
      const { stdout } = await run("push", "--server", "upload", "main", "--jobs", "4", ...paths);
      assert.match(stdout, /4 pushed, 0 skipped.*0 failed/);
      assert.deepEqual([...published].sort(), paths.sort());
      assert.equal(uploaded.length, 4);
      assert.equal(new Set(uploaded).size, 4);
    } finally {
      await new Promise((resolve) => api.close(resolve));
    }
  });
}

test("proxied and presigned parts share a concurrency budget, including after failure", async () => {
  const bytes = Buffer.from("0123456789abc");
  const file = join(home, "multipart.nar");
  await writeFile(file, bytes);
  const received = new Map();
  let active = 0;
  let peak = 0;
  const api = createServer(async (req, res) => {
    if (req.method === "POST") {
      req.resume();
      return res.end(JSON.stringify({ uploadId: "upload", r2Key: req.url }));
    }
    active++;
    peak = Math.max(peak, active);
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      received.set(req.url, Buffer.concat(chunks));
      // Hold the requests open so the test observes concurrent transfers.
      await new Promise((resolve) => setTimeout(resolve, 25));
      if (req.url.includes("/fail/")) res.statusCode = 400;
      res.setHeader("etag", '"part-etag"');
      res.end(JSON.stringify({ partNumber: 1, etag: "part-etag" }));
    } finally {
      active--;
    }
  });
  await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${api.address().port}`;
  const client = { server: url, token: "push-token" };
  const slot = limiter(2);
  try {
    const sessions = ["first", "fail", "second", "third"];
    const outcomes = await Promise.allSettled([
      ...sessions.map((id) => uploadBlobMultipart(client, id, file, slot)),
      uploadPresignedParts([1, 2, 3].map((partNumber) => ({ partNumber, url: `${url}/signed/${partNumber}` })), 5, file, slot),
    ]);
    assert.deepEqual(outcomes.map((r) => r.status), ["fulfilled", "rejected", "fulfilled", "fulfilled", "fulfilled"]);
    assert.match(outcomes[1].reason.message, /part upload failed \(400\)/);
    assert.deepEqual(outcomes[4].value, [1, 2, 3].map((partNumber) => ({ partNumber, etag: '"part-etag"' })));
    await uploadBlobMultipart(client, "after-failure", file, slot);
    assert.equal(peak, 2);
    assert.equal(received.size, 8);
    for (const id of [...sessions, "after-failure"]) assert.deepEqual(received.get(`/_api/v1/uploads/${id}/part/1`), bytes);
    for (const part of [1, 2, 3]) assert.deepEqual(received.get(`/signed/${part}`), bytes.subarray((part - 1) * 5, part * 5));
  } finally {
    await new Promise((resolve) => api.close(resolve));
  }
});

for (const method of ["direct", "presigned"]) {
  for (const outcome of ["collision", "own-upload", "bad-checksum", "forbidden", "commit-conflict", "bad-parts", "staged-conflict"]) {
    test(`${method} single PUT recovery: ${outcome}`, async () => {
      const bytes = Buffer.from("small collision proof");
      const file = join(home, `${method}-${outcome}.nar`);
      await writeFile(file, bytes);
      const calls = [];
      const api = createServer(async (req, res) => {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = Buffer.concat(chunks);
        calls.push(req.url);
        if (req.method === "PUT") {
          assert.deepEqual(body, bytes);
          if (req.url.endsWith("/blob")) {
            res.statusCode = outcome === "bad-checksum" ? 400 : outcome === "forbidden" ? 403 : 412;
            return res.end("upload refused");
          }
          assert.equal(req.url, "/_api/v1/uploads/same-session/part/1");
          res.statusCode = outcome === "bad-parts" ? 400 : 200;
          return res.end(JSON.stringify({ partNumber: 1, etag: "part-etag" }));
        }
        if (req.url === "/_api/v1/uploads/commit") {
          assert.deepEqual(JSON.parse(body), { sessionIds: ["same-session"] });
          return res.end(JSON.stringify({ results: [{ sessionId: "same-session", ...(outcome === "own-upload"
            ? { published: true }
            : outcome === "commit-conflict" ? { error: "Conflict", status: 409 }
              : { error: "Upload incomplete", status: 400 }) }] }));
        }
        assert.ok(req.url === "/_api/v1/uploads/same-session/multipart" || req.url === "/_api/v1/uploads/same-session/complete");
        return res.end(JSON.stringify({ uploadId: "multipart", r2Key: "staging/same-session" }));
      });
      await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
      const url = `http://127.0.0.1:${api.address().port}`;
      const session = {
        sessionId: "same-session", r2Key: outcome === "staged-conflict" ? "staging/same-session" : "nar/hash/zstd.nar",
        expiresAt: "2027-01-01", uploadMethod: method, uploadUrl: `${url}/signed/blob`, uploadHeaders: { "if-none-match": "*" },
      };
      try {
        const upload = uploadSingle({ server: url, token: "push-token" }, session, file, limiter(1));
        if (["bad-checksum", "forbidden", "bad-parts", "staged-conflict"].includes(outcome)) {
          await assert.rejects(upload, /upload failed/);
        } else {
          const result = await upload;
          if (outcome === "own-upload") assert.equal(result.published, true);
          else if (outcome === "commit-conflict") assert.equal(result.status, 409);
          else assert.equal(result, undefined);
        }
        const first = method === "direct" ? "/_api/v1/uploads/same-session/blob" : "/signed/blob";
        const expected = [first];
        if (!["bad-checksum", "forbidden", "staged-conflict"].includes(outcome)) expected.push("/_api/v1/uploads/commit");
        if (["collision", "bad-parts"].includes(outcome)) {
          expected.push("/_api/v1/uploads/same-session/multipart", "/_api/v1/uploads/same-session/part/1");
          if (outcome === "collision") expected.push("/_api/v1/uploads/same-session/complete");
        }
        assert.deepEqual(calls, expected);
      } finally {
        await new Promise((resolve) => api.close(resolve));
      }
    });
  }
}
