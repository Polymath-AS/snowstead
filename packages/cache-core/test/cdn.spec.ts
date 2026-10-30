import { env, SELF } from "cloudflare:test";
import { describe, it, expect, afterAll, afterEach, vi } from "vitest";
import { resolveConfig } from "../src/config.js";
import { purgeCache, purgeNarinfo, scheduleNarinfoPurge, retryCdnPurges } from "../src/cdn.js";
import { handleRequest as handleNix } from "../../../workers/nix/src/router.js";
import { handleRequest as handleControl } from "../../../workers/control/src/router.js";
import type { WorkerConfig } from "../src/config.js";

function handleRequest(request: Request, config: WorkerConfig): Promise<Response> {
	const path = new URL(request.url).pathname;
	return (path.startsWith("/_api/v1/admin/") || path.startsWith("/_api/v1/orgs/") ? handleControl : handleNix)(request, config);
}

const base = resolveConfig(env);
afterAll(() => base.close());
afterEach(() => vi.restoreAllMocks());
const config = { ...base, cdn: { zoneId: "zone1", token: "tok", origin: "https://cache.example.com" } };

/** A stand-in for Cloudflare's purge API, recording what it is asked. */
function api(status = 200, success = true) {
	const calls: { url: string; auth: string | null; body: { files?: string[]; prefixes?: string[] } }[] = [];
	const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
		calls.push({ url: String(input), auth: new Headers(init?.headers).get("authorization"), body: JSON.parse(String(init?.body)) });
		return Response.json({ success }, { status, headers: { "retry-after": "0" } });
	}) as typeof fetch;
	return { calls, fetcher };
}

describe("CDN purges", () => {
	it("purge each path's public narinfo URL, 100 to a request", async () => {
		const hashes = Array.from({ length: 150 }, (_, i) => String(i).padStart(32, "a"));
		const { calls, fetcher } = api();
		await purgeNarinfo(config, "acme/main", [...hashes, ...hashes.slice(0, 100)], fetcher);
		expect(calls.map((c) => c.body.files?.length)).toEqual([100, 50]);
		expect(calls[0].url).toBe("https://api.cloudflare.com/client/v4/zones/zone1/purge_cache");
		expect(calls[0].auth).toBe("Bearer tok");
		expect(calls[0].body.files?.[0]).toBe(`https://cache.example.com/acme/main/${hashes[0]}.narinfo`);
	});

	it("purge a whole cache by its prefix", async () => {
		const { calls, fetcher } = api();
		await purgeCache(config, "acme/main", fetcher);
		expect(calls[0].body).toEqual({ prefixes: ["cache.example.com/acme/main/"] });
	});

	it("say when Cloudflare refuses", async () => {
		const { calls, fetcher } = api(429);
		await expect(purgeNarinfo(config, "main", ["a".repeat(32)], fetcher)).rejects.toThrow("429");
		expect(calls).toHaveLength(3);
	});

	it.each([429, 503])("retries a transient %s before accepting a purge", async (status) => {
		let attempts = 0;
		const fetcher = (async () => Response.json({ success: ++attempts > 1 }, {
			status: attempts === 1 ? status : 200, headers: { "retry-after": "0" },
		})) as typeof fetch;
		await purgeNarinfo(config, "main", ["a".repeat(32)], fetcher);
		expect(attempts).toBe(2);
	});

	it.each([[403, false], [200, false]])("rejects permanent or unsuccessful responses (%s)", async (status, success) => {
		const { calls, fetcher } = api(status, success);
		await expect(purgeCache(config, "main", fetcher)).rejects.toThrow();
		expect(calls).toHaveLength(1);
	});

	it("retains a failed automatic purge and replays it after recovery", async () => {
		const hash = "1".repeat(32);
		const failed = api(403);
		await scheduleNarinfoPurge(config, "acme/main", [hash], failed.fetcher);
		const queued = await env.CACHE_BUCKET.list({ prefix: "cdn-purges/" });
		expect(queued.objects).toHaveLength(1);
		const record = await env.CACHE_BUCKET.get(queued.objects[0].key);
		expect(await record?.json()).toEqual({ cachePath: "acme/main", hashes: [hash] });
		expect((await env.PUBLIC_BUCKET.list({ prefix: "cdn-purges/" })).objects).toHaveLength(0);

		const recovered = api();
		expect(await retryCdnPurges(config, recovered.fetcher)).toBe(1);
		expect(recovered.calls[0].body.files).toEqual([`https://cache.example.com/acme/main/${hash}.narinfo`]);
		expect((await env.CACHE_BUCKET.list({ prefix: "cdn-purges/" })).objects).toHaveLength(0);
	});

	it("keeps long Retry-After delays across scheduled retries", async () => {
		let attempts = 0;
		const throttled = (async () => {
			attempts++;
			return Response.json({ success: false }, { status: 429, headers: { "retry-after": "3600" } });
		}) as typeof fetch;
		await scheduleNarinfoPurge(config, "main", ["2".repeat(32)], throttled);
		expect(attempts).toBe(1);
		const recovered = api();
		expect(await retryCdnPurges(config, recovered.fetcher)).toBe(0);
		expect(recovered.calls).toHaveLength(0);
		const pending = await env.CACHE_BUCKET.list({ prefix: "cdn-purges/" });
		expect(pending.objects).toHaveLength(1);
		await env.CACHE_BUCKET.delete(pending.objects.map((o) => o.key));
	});

	it("do nothing without a CDN configured", async () => {
		const { calls, fetcher } = api();
		await purgeNarinfo({ ...base, cdn: undefined }, "main", ["a".repeat(32)], fetcher);
		await purgeCache({ ...base, cdn: undefined }, "main", fetcher);
		expect(calls).toEqual([]);
	});

	it("queues a failed publish purge, recovers, and purges re-publishes and deletions", async () => {
		const connection = resolveConfig(env);
		const local: WorkerConfig = Object.assign(Object.create(connection), { cdn: config.cdn, upstreams: [], r2AccessKeyId: "", r2SecretAccessKey: "" });
		const name = `purge-flow-${crypto.randomUUID().slice(0, 8)}`;
		const hash = "3".repeat(32);
		const bytes = new Uint8Array([83, 14, 251]);
		const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
		const fileHash = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
		const post = (path: string, body: unknown, secret = "test-auth-token") => handleRequest(new Request(`http://example.com/_api/v1${path}`, {
			method: "POST", headers: { authorization: `Bearer ${secret}` }, body: JSON.stringify(body),
		}), local);
		const failed = api(503, false);
		const outbound = vi.spyOn(globalThis, "fetch").mockImplementation(failed.fetcher);
		try {
			expect((await post("/admin/caches", { name, protocols: ["nix"] }, "test-admin-secret")).status).toBe(201);
			const session = await (await post(`/caches/${name}/upload-sessions`, {
				storePathHash: hash, storePath: `/nix/store/${hash}-purged`, narHash: `sha256:${"1".repeat(52)}`,
				narSize: bytes.length, fileHash, fileSize: bytes.length, compression: "zstd",
			})).json<{ sessionId: string }>();
			expect((await handleRequest(new Request(`http://example.com/_api/v1/uploads/${session.sessionId}/blob`, {
				method: "PUT", headers: { authorization: "Bearer test-auth-token" }, body: bytes,
			}), local)).status).toBe(200);
			expect((await post(`/uploads/${session.sessionId}/complete`, {})).status).toBe(200);
			expect((await post(`/uploads/${session.sessionId}/publish`, {})).status).toBe(200);
			expect((await env.CACHE_BUCKET.list({ prefix: "cdn-purges/" })).objects).toHaveLength(1);
			const recovered = api();
			outbound.mockImplementation(recovered.fetcher);
			expect(await retryCdnPurges(local)).toBe(1);
			expect((await post(`/uploads/${session.sessionId}/publish`, {})).status).toBe(200);
			expect((await post(`/admin/caches/${name}/paths/delete`, { storePathHashes: [hash] }, "test-admin-secret")).status).toBe(200);
			expect(recovered.calls.map((call) => call.body.files)).toEqual(Array.from({ length: 3 }, () => [`https://cache.example.com/${name}/${hash}.narinfo`]));
			expect(await env.PUBLIC_BUCKET.head(`${name}/${hash}.narinfo`)).toBeNull();
			expect((await env.CACHE_BUCKET.list({ prefix: "cdn-purges/" })).objects).toHaveLength(0);
		} finally {
			await connection.close();
		}
	});
});

describe("org-scoped manual purges", () => {
	it("purges only its own cache, validates scope, and audits acceptance", async () => {
		const org = `purge-${crypto.randomUUID().slice(0, 8)}`;
		const other = `${org}-other`;
		const setup = (path: string, body: unknown) => SELF.fetch(`http://example.com/_api/v1/orgs/${path}`, {
			method: path.includes("/") ? "POST" : "PUT",
			headers: { authorization: "Bearer test-admin-secret" }, body: JSON.stringify(body),
		});
		for (const id of [org, other]) {
			expect((await setup(id, { slug: id })).status).toBe(200);
			expect((await setup(`${id}/caches`, { name: "main", protocols: ["nix"] })).status).toBe(201);
		}
		const key = await (await setup(`${org}/keys`, { name: "purger" })).json<{ key: string }>();
		const purge = (id: string, body: unknown) => handleRequest(new Request(`http://example.com/_api/v1/orgs/${id}/caches/main/purge`, {
			method: "POST", headers: { authorization: `Bearer ${key.key}` }, body: JSON.stringify(body),
		}), config);
		const { calls, fetcher } = api();
		vi.spyOn(globalThis, "fetch").mockImplementation(fetcher);
		expect((await purge(other, {})).status).toBe(403);
		for (const body of [null, [], { pathHashes: ["1".repeat(32)] }, { storePathHashes: [] }, { storePathHashes: [2] }]) {
			expect((await purge(org, body)).status).toBe(400);
		}
		expect(calls).toHaveLength(0);
		const res = await purge(org, { storePathHashes: ["1".repeat(32)] });
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ accepted: true, paths: ["1".repeat(32)] });
		expect(calls[0].body).toEqual({ files: [`https://cache.example.com/${org}/main/${"1".repeat(32)}.narinfo`] });
		expect((await purge(org, {})).status).toBe(200);
		expect(calls[1].body).toEqual({ prefixes: [`cache.example.com/${org}/main/`] });
		await config.close();
		const audit = await SELF.fetch(`http://example.com/_api/v1/orgs/${org}/audit`, { headers: { authorization: "Bearer test-admin-secret" } });
		expect((await audit.json<{ entries: { action: string; cache: string; status: number }[] }>()).entries).toContainEqual(expect.objectContaining({ action: "cache.purge", cache: "main", status: 200 }));
	});
});
