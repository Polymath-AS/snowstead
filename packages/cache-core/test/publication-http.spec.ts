import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { servePublication } from "../src/publication-http.js";
import { publicationKey, type ActiveGrant } from "../src/publication-protocol.js";

const payload = "aB3!efGH-01234567_Xyz";
const narinfo = "StorePath: /nix/store/fixture\nNarSize: 20\n";
const grant: ActiveGrant = {
	version: 2, nonce: "11111111-1111-4111-8111-111111111111", operationId: "22222222-2222-4222-8222-222222222222",
	orgId: "org_fixture", cacheId: 17, epoch: "33333333-3333-4333-8333-333333333333",
	storePathHash: "0".repeat(32), publicationId: "44444444-4444-4444-8444-444444444444",
	state: "active", fileHash: "1".repeat(52), compression: "none", fileSize: payload.length,
	narinfoSize: narinfo.length, narEtag: '"nar-fixture"', narinfoEtag: '"narinfo-fixture"', publishedAt: 1_750_000_000,
};
const published = new Date(grant.publishedAt * 1000).toUTCString();
const older = new Date((grant.publishedAt - 1) * 1000).toUTCString();
const newer = new Date((grant.publishedAt + 1) * 1000).toUTCString();

function request(headers: HeadersInit = {}, method = "GET") {
	return new Request("https://customer.invalid/anything?secret=yes", { method, headers });
}

function noStore(response: Response) {
	expect(response.headers.get("cache-control")).toBe("no-store");
	expect(response.headers.get("cloudflare-cdn-cache-control")).toBe("no-store");
}

function nativeBytes() {
	const fetch = vi.fn(async (input: RequestInfo | URL) => {
		const req = input instanceof Request ? input : new Request(input);
		const prefix = "/test-v2/private/";
		const path = new URL(req.url).pathname;
		if (!path.startsWith(prefix)) return new Response(null, { status: 404 });
		const object = await env.CACHE_BUCKET.get(path.slice(prefix.length));
		return object ? new Response(object.body, { headers: { "content-length": String(object.size), "cache-control": "public, max-age=31536000", "set-cookie": "internal=secret" } }) : new Response(null, { status: 404 });
	});
	return { fetch, options: { service: { fetch } as unknown as Fetcher, maxBytes: 1024, namespace: "test-v2", visibility: "private" as const } };
}

beforeEach(async () => {
	await env.CACHE_BUCKET.put(publicationKey(grant, "nar"), payload);
	await env.CACHE_BUCKET.put(publicationKey(grant, "narinfo"), narinfo);
});

describe("authorized immutable publication HTTP", () => {
	it.each(["nar", "narinfo"] as const)("streams the exact %s representation, using grant metadata rather than the R2 ETag", async (representation) => {
		const response = await servePublication(request(), grant, representation, env.CACHE_BUCKET);
		expect(response.status).toBe(200);
		expect(response.headers.get("etag")).toBe(representation === "nar" ? grant.narEtag : grant.narinfoEtag);
		expect(response.headers.get("last-modified")).toBe(published);
		expect(response.headers.get("content-type")).toBe(representation === "nar" ? "application/x-nix-nar" : "text/x-nix-narinfo");
		expect(response.headers.get("content-length")).toBe(String(representation === "nar" ? payload.length : narinfo.length));
		noStore(response);
		expect(await response.text()).toBe(representation === "nar" ? payload : narinfo);
	});

	it.each([
		[{ "if-match": 'W/"nar-fixture"' }, 412],
		[{ "if-match": '"other"', "if-none-match": "*" }, 412],
		[{ "if-match": '"other", "nar-fixture"', "if-unmodified-since": older }, 200],
		[{ "if-match": "*", "if-unmodified-since": older }, 200],
		[{ "if-unmodified-since": older }, 412],
		[{ "if-unmodified-since": published }, 200],
		[{ "if-none-match": 'W/"nar-fixture"' }, 304],
		[{ "if-none-match": '"other", W/"nar-fixture"' }, 304],
		[{ "if-none-match": "*" }, 304],
		[{ "if-none-match": '"other"', "if-modified-since": newer }, 200],
		[{ "if-modified-since": published }, 304],
		[{ "if-modified-since": older }, 200],
		[{ "if-modified-since": "invalid date" }, 200],
	] as const)("evaluates conditional precedence %j", async (headers, status) => {
		const response = await servePublication(request(headers), grant, "nar", env.CACHE_BUCKET);
		expect(response.status).toBe(status);
		noStore(response);
		expect(await response.text()).toBe(status === 200 ? payload : "");
	});

	it("evaluates conditions before reading missing bytes or invoking native fill", async () => {
		await env.CACHE_BUCKET.delete(publicationKey(grant, "nar"));
		const { fetch, options } = nativeBytes();
		for (const [headers, status] of [[{ "if-none-match": grant.narEtag }, 304], [{ "if-match": '"wrong"' }, 412]] as const) {
			const response = await servePublication(request(headers), grant, "nar", env.CACHE_BUCKET, options);
			expect(response.status).toBe(status);
			noStore(response);
		}
		expect(fetch).not.toHaveBeenCalled();
	});

	it.each([
		["bytes=2-6", 2, 7], ["bytes=7-", 7, payload.length],
		["bytes=-5", payload.length - 5, payload.length], ["bytes=-999", 0, payload.length],
		["bytes=0-999", 0, payload.length], ["bytes=0-0", 0, 1],
	])("serves the real R2 slice %s", async (range, start, end) => {
		const { fetch, options } = nativeBytes();
		const response = await servePublication(request({ range }), grant, "nar", env.CACHE_BUCKET, options);
		expect(response.status).toBe(206);
		expect(response.headers.get("content-range")).toBe(`bytes ${start}-${end - 1}/${payload.length}`);
		expect(response.headers.get("content-length")).toBe(String(end - start));
		expect(await response.text()).toBe(payload.slice(start, end));
		noStore(response);
		expect(fetch).not.toHaveBeenCalled();
	});

	it.each(["bytes=0-1,3-4", "bytes=", "bytes=-", "bytes=-0", "bytes=9-2", "bytes=999-", "bytes=9007199254740992-", "items=0-1", "bytes=1.5-3"])("rejects invalid or multiple ranges %s", async (range) => {
		const response = await servePublication(request({ range }), grant, "nar", env.CACHE_BUCKET);
		expect(response.status).toBe(416);
		expect(response.headers.get("content-range")).toBe(`bytes */${payload.length}`);
		expect(await response.text()).toBe("");
		noStore(response);
	});

	it.each([[grant.narEtag, 206], [published, 206], [newer, 200], ['W/"nar-fixture"', 200], ['"wrong"', 200], [older, 200], ["nonsense", 200]] as const)("handles If-Range %s without native fill", async (ifRange, status) => {
		const { fetch, options } = nativeBytes();
		const response = await servePublication(request({ range: "bytes=3-8", "if-range": ifRange }), grant, "nar", env.CACHE_BUCKET, options);
		expect(response.status).toBe(status);
		expect(await response.text()).toBe(status === 206 ? payload.slice(3, 9) : payload);
		expect(fetch).not.toHaveBeenCalled();
	});

	it.each([{}, { range: "bytes=2-5" }])("HEAD returns full metadata without a body or a native fill %j", async (headers) => {
		const { fetch, options } = nativeBytes();
		const response = await servePublication(request(headers, "HEAD"), grant, "nar", env.CACHE_BUCKET, options);
		expect(response.status).toBe(200);
		expect(response.headers.get("content-length")).toBe(String(payload.length));
		expect(await response.text()).toBe("");
		noStore(response);
		expect(fetch).not.toHaveBeenCalled();
	});

	it("fills only a constructed binding URL, without customer headers, and strips internal response metadata", async () => {
		const { fetch, options } = nativeBytes();
		const response = await servePublication(request({ authorization: "Bearer secret", cookie: "session=secret", "x-arbitrary": "secret" }), grant, "nar", env.CACHE_BUCKET, options);
		expect(await response.text()).toBe(payload);
		expect(fetch).toHaveBeenCalledTimes(1);
		const internal = fetch.mock.calls[0][0] as Request;
		expect(internal.url).toBe(`https://bytes.internal/test-v2/private/${publicationKey(grant, "nar")}`);
		expect(internal.method).toBe("GET");
		expect([...internal.headers]).toEqual([]);
		expect(response.headers.get("set-cookie")).toBeNull();
		noStore(response);
	});

	it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1, payload.length - 1])("bypasses native for invalid or insufficient verified maximum %s", async (maxBytes) => {
		const { fetch, options } = nativeBytes();
		const response = await servePublication(request(), grant, "nar", env.CACHE_BUCKET, { ...options, maxBytes });
		expect(await response.text()).toBe(payload);
		expect(fetch).not.toHaveBeenCalled();
	});

	it.each(["GET", "HEAD"])("fails closed for missing or wrong-sized bytes (%s)", async (method) => {
		const key = publicationKey(grant, "nar");
		for (const body of [null, "short"]) {
			if (body === null) await env.CACHE_BUCKET.delete(key);
			else await env.CACHE_BUCKET.put(key, body);
			const response = await servePublication(request({}, method), grant, "nar", env.CACHE_BUCKET);
			expect(response.status).toBe(503);
			expect(response.headers.has("content-length")).toBe(false);
			noStore(response);
		}
	});

	it("does not mistake the R2 total size for the ranged response length", async () => {
		await env.CACHE_BUCKET.put(publicationKey(grant, "nar"), "x".repeat(payload.length + 3));
		const response = await servePublication(request({ range: "bytes=1-2" }), grant, "nar", env.CACHE_BUCKET);
		expect(response.status).toBe(503);
		noStore(response);
	});

	it("rejects missing and mismatched native bytes without exposing internal errors", async () => {
		const { options } = nativeBytes();
		await env.CACHE_BUCKET.delete(publicationKey(grant, "nar"));
		const missing = await servePublication(request(), grant, "nar", env.CACHE_BUCKET, options);
		expect(missing.status).toBe(503);
		noStore(missing);
		await env.CACHE_BUCKET.put(publicationKey(grant, "nar"), "short");
		const mismatch = await servePublication(request(), grant, "nar", env.CACHE_BUCKET, options);
		expect(mismatch.status).toBe(503);
		noStore(mismatch);
	});

	it("supports empty publications, but no byte range is satisfiable", async () => {
		const empty = { ...grant, fileSize: 0 };
		await env.CACHE_BUCKET.put(publicationKey(empty, "nar"), "");
		for (const method of ["GET", "HEAD"]) {
			const response = await servePublication(request({}, method), empty, "nar", env.CACHE_BUCKET);
			expect(response.status).toBe(200);
			expect(response.headers.get("content-length")).toBe("0");
			expect(await response.text()).toBe("");
		}
		for (const range of ["bytes=0-0", "bytes=0-", "bytes=-1"]) {
			const response = await servePublication(request({ range }), empty, "nar", env.CACHE_BUCKET);
			expect(response.status).toBe(416);
			expect(response.headers.get("content-range")).toBe("bytes */0");
			noStore(response);
		}
	});
});
