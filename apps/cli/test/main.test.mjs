import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { promisify } from "node:util";

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
    } else {
      res.end(JSON.stringify({ ...data, created: true }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  await run("login", "selected", url, "selected-token");
  await run("login", "default", url, "default-token");
  await mkdir(join(home, "bin"));
  // Closure resolution remains a subprocess; only Nix itself is a fixture.
  await writeFile(join(home, "bin/nix"), `#!/bin/sh
if [ "$1" != path-info ] || [ "$2" != -r ] || [ "$3" != /run/current-system ]; then exit 1; fi
printf '%s\\n' '${storePath}'
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
