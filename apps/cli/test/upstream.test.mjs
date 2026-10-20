import assert from "node:assert/strict";
import { test } from "node:test";
import { servedUpstream } from "../dist/upstream.js";

/** A stand-in upstream serving `served` (URLs). */
function upstream(served, failing = new Set()) {
  const asked = [];
  const fetcher = async (url, init) => {
    asked.push(`${init.method} ${url}`);
    if (failing.has(url)) throw new Error("unreachable");
    return new Response(null, { status: served.has(url) ? 200 : 404 });
  };
  return { asked, fetcher };
}

const hash = (c) => c.repeat(32);

test("finds the paths any upstream serves, asking with HEAD", async () => {
  const [a, b, c] = [hash("a"), hash("b"), hash("c")];
  const { asked, fetcher } = upstream(new Set([`https://up.example/${a}.narinfo`, `https://up2.example/${b}.narinfo`]));
  const served = await servedUpstream([a, b, c], ["https://up.example/", "https://up2.example"], fetcher);
  assert.deepEqual([...served].sort(), [a, b]);
  assert.ok(asked.every((r) => r.startsWith("HEAD ")));
});

test("counts a path whose lookup fails as not served, so it is pushed", async () => {
  const a = hash("a");
  const { fetcher } = upstream(new Set(), new Set([`https://up.example/${a}.narinfo`]));
  assert.deepEqual([...(await servedUpstream([a], ["https://up.example"], fetcher))], []);
});
