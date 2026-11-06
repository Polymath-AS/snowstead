import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { test } from "node:test";
import { createTestHarness } from "wrangler";
import gatewayWorker from "../src/index.ts";

test("gateway streams authenticated binary requests and preserves redirects", { timeout: 30_000 }, async () => {
  const origin = createServer(async (request, response) => {
    if (request.url === "/_api/v1/redirect") {
      response.writeHead(307, { location: "/not-an-api-endpoint", "cache-control": "no-store" });
      response.end();
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    response.writeHead(201, { "content-type": "application/json", "cache-control": "no-store" });
    response.end(JSON.stringify({
      url: request.url, method: request.method, host: request.headers.host,
      authorization: request.headers.authorization, contentType: request.headers["content-type"],
      body: Buffer.concat(chunks).toString("base64"),
    }));
  });
  await new Promise(resolve => origin.listen(0, "127.0.0.1", resolve));
  const upstream = `http://127.0.0.1:${origin.address().port}`;
  process.env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = "false";
  const gateway = createTestHarness({
    root: new URL("../../../", import.meta.url).pathname,
    workers: [{ configPath: "wrangler.jsonc", env: "production", vars: { API_ORIGIN: upstream } }],
  });
  try {
    const { url } = await gateway.listen();
    const body = randomBytes(257 * 1024);
    for (const method of ["PUT", "POST", "PROPFIND", "MKCOL"]) {
      const path = "/_api/v1/sccache/default/compiler/a/b/c/" + "abc".padEnd(64, "d") + "?cursor=a%2Fb&cursor=c";
      const response = await fetch(new URL(path, url), {
        method, body,
        headers: { authorization: "Bearer forward-fixture", "content-type": "application/octet-stream" },
      });
      assert.equal(response.status, 201);
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.deepEqual(await response.json(), {
        url: path, method, host: new URL(upstream).host,
        authorization: "Bearer forward-fixture", contentType: "application/octet-stream",
        body: body.toString("base64"),
      });
    }
    // Wrangler's outbound proxy follows redirects despite redirect: manual.
    // Exercise the handler against the real origin without that proxy.
    const redirect = await gatewayWorker.fetch(new Request(new URL("/_api/v1/redirect", url)), { API_ORIGIN: upstream });
    assert.equal(redirect.status, 307);
    assert.equal(redirect.headers.get("location"), "/not-an-api-endpoint");
    assert.equal(redirect.headers.get("cache-control"), "no-store");
    await redirect.arrayBuffer();
    const unavailable = await gatewayWorker.fetch(new Request(url), { API_ORIGIN: "" });
    assert.equal(unavailable.status, 503);
  } finally {
    await gateway.close();
    await new Promise((resolve, reject) => origin.close(error => error ? reject(error) : resolve()));
  }
});
