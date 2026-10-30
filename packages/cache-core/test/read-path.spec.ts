import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll, vi } from "vitest";
import { testDb } from "./db.js";
import { createCache, createBlobObject, createPublishedPath } from "../src/db/repository.js";
import { handleRequest } from "../../../workers/nix/src/router.js";
import { resolveConfig } from "../src/config.js";

const STORE_PATH_HASH = "0".repeat(32);
// SHA-256 of R2_BODY, independently computed with sha256sum.
const FILE_HASH = "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a";
const NAR_HASH = `sha256:${"1".repeat(52)}`;
const R2_KEY = `nars/sha256/${FILE_HASH}/zstd.nar`;
const R2_BODY = new Uint8Array([1, 2, 3, 4]);

const db = testDb();

function getDb() {
	return db;
}

beforeAll(async () => {
	const db = getDb();

	const cache = await createCache(db, "test-cache");

	const blob = await createBlobObject(db, {
		fileHash: FILE_HASH,
		fileSize: R2_BODY.byteLength,
		compression: "zstd",
		r2Key: R2_KEY,
	});

	await createPublishedPath(db, {
		cacheId: cache.id,
		storePathHash: STORE_PATH_HASH,
		storePath: `/nix/store/${STORE_PATH_HASH}-hello`,
		narHash: NAR_HASH,
		narSize: 2048,
		blobObjectId: blob.id,
		referencesJson: "[]",
		deriver: null,
		system: null,
		signaturesJson: "[]",
	});

	await env.CACHE_BUCKET.put(R2_KEY, R2_BODY);

	// Paths written straight to the database get their narinfo from the backfill.
	const backfill = await SELF.fetch("http://example.com/_api/v1/admin/narinfo/backfill", {
		method: "POST",
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: JSON.stringify({ limit: 1000 }),
	});
	expect(backfill.status).toBe(200);
});

describe("nix-cache-info", () => {
	it("returns cache info for existing populated and empty Nix caches", async () => {
		const created = await SELF.fetch("http://example.com/_api/v1/admin/caches", {
			method: "POST",
			headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
			body: JSON.stringify({ name: "info-only", protocols: ["nix"] }),
		});
		expect(created.status).toBe(201);
		for (const name of ["test-cache", "info-only"]) {
			const res = await SELF.fetch(`http://example.com/${name}/nix-cache-info`);
			expect(res.status).toBe(200);
			expect(res.headers.get("content-type")).toBe("text/x-nix-cache-info");
			expect(await res.text()).toContain("StoreDir: /nix/store\n");
		}
	});

	it("returns 404 for a cache that has not been created", async () => {
		expect((await SELF.fetch("http://example.com/nonexistent/nix-cache-info")).status).toBe(404);
	});

	it("never hands missing or protocol-disabled caches to the CDN", async () => {
		expect((await SELF.fetch("http://example.com/_api/v1/admin/caches", {
			method: "POST", headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
			body: JSON.stringify({ name: "handoff-go-only", protocols: ["go"] }),
		})).status).toBe(201);
		for (const method of ["GET", "HEAD"]) {
			for (const name of ["handoff-go-only", "no-handoff-cache"]) {
				for (const suffix of ["nix-cache-info", `${STORE_PATH_HASH}.narinfo`, `nar/${FILE_HASH}/zstd.nar`]) {
					const response = await SELF.fetch(`http://example.com/${name}/${suffix}`, { method, headers: { "x-snowstead-cdn-read": "1" } });
					expect(response.status).toBe(404);
					expect(response.headers.get("x-snowstead-cdn-read")).toBeNull();
				}
			}
		}
	});
});

describe("narinfo", () => {
	it("hands hosted public metadata to the CDN without reading stale local entries or R2", async () => {
		const config = resolveConfig(env);
		const url = `http://revalidate.example/test-cache/${STORE_PATH_HASH}.narinfo`;
		const missing = `http://revalidate.example/test-cache/${"b".repeat(32)}.narinfo`;
		const cache = await caches.open("snowstead-narinfo");
		const get = vi.spyOn(config.publicBucket, "get");
		const head = vi.spyOn(config.publicBucket, "head");
		try {
			await cache.put(url, new Response("Not Found", { status: 404, headers: { "cache-control": "public, max-age=60" } }));
			await cache.put(missing, new Response("stale metadata", { headers: { "cache-control": "public, max-age=300" } }));
			for (const method of ["GET", "HEAD"]) {
				for (const path of [url, missing, "http://revalidate.example/test-cache/nix-cache-info", `http://revalidate.example/test-cache/nar/${FILE_HASH}/zstd.nar`]) {
					const response = await handleRequest(new Request(path, { method, headers: { "x-snowstead-cdn-read": "1" } }), config);
					expect(response.status).toBe(204);
					expect(response.headers.get("x-snowstead-cdn-read")).toBe("1");
					expect(response.headers.get("cache-control")).toBe("no-store");
					expect(await response.text()).toBe("");
				}
			}
			expect(get).not.toHaveBeenCalled();
			expect(head).not.toHaveBeenCalled();
		} finally {
			vi.restoreAllMocks();
			await cache.delete(url);
			await cache.delete(missing);
			await config.close();
		}
	});

	it("uses only R2 metadata for cold HEAD and never poisons GET", async () => {
		const config = resolveConfig(env);
		const url = `http://cold-head.example/test-cache/${STORE_PATH_HASH}.narinfo`;
		const get = vi.spyOn(config.publicBucket, "get");
		const head = vi.spyOn(config.publicBucket, "head");
		try {
			const response = await handleRequest(new Request(url, { method: "HEAD" }), config);
			expect(response.status).toBe(200);
			expect(await response.text()).toBe("");
			expect(head).toHaveBeenCalledTimes(1);
			expect(get).not.toHaveBeenCalled();
			const body = await handleRequest(new Request(url), config);
			expect(await body.text()).toContain(`StorePath: /nix/store/${STORE_PATH_HASH}-hello`);
			expect(get).toHaveBeenCalledTimes(1);
		} finally {
			vi.restoreAllMocks();
			await config.close();
		}
	});

	it("preserves metadata validators and ignores ranges on cold and warm reads", async () => {
		const config = resolveConfig(env);
		const url = `http://validators.example/test-cache/${STORE_PATH_HASH}.narinfo`;
		const initial = await handleRequest(new Request(url), config);
		const etag = initial.headers.get("etag")!;
		const modified = initial.headers.get("last-modified")!;
		expect(etag).toBeTruthy();
		expect(modified).toBeTruthy();
		const body = await initial.text();
		const cache = await caches.open("snowstead-narinfo");
		try {
			for (const warm of [false, true]) {
				await cache.delete(url);
				if (warm) await cache.put(url, new Response(body, { headers: initial.headers }));
				for (const method of ["GET", "HEAD"]) {
					for (const [headers, status] of [
						[{ "if-none-match": etag }, 304],
						[{ "if-none-match": `W/${etag}` }, 304],
						[{ "if-modified-since": modified }, 304],
						[{ "if-match": '"wrong"' }, 412],
						[{ "if-match": `W/${etag}` }, 412],
						[{ "if-unmodified-since": "Thu, 01 Jan 1970 00:00:00 GMT" }, 412],
						[{ "if-none-match": '"different"', "if-modified-since": modified }, 200],
						[{ "if-match": etag, "if-unmodified-since": "Thu, 01 Jan 1970 00:00:00 GMT" }, 200],
						[{ range: "bytes=0-8", "if-range": etag }, 200],
					] as const) {
						const response = await handleRequest(new Request(url, { method, headers }), config);
						expect(response.status, `${warm}/${method}/${JSON.stringify(headers)}`).toBe(status);
						expect(await response.text()).toBe(method === "HEAD" || status !== 200 ? "" : body);
					}
				}
			}
		} finally {
			await cache.delete(url);
			await config.close();
		}
	});

	it("serves published metadata, with identical headers and no body for HEAD", async () => {
		const res = await SELF.fetch(`http://example.com/test-cache/${STORE_PATH_HASH}.narinfo`);

		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("text/x-nix-narinfo");
		const body = await res.text();
		expect(body).toContain(`StorePath: /nix/store/${STORE_PATH_HASH}-hello\n`);
		expect(body).toContain(`NarHash: ${NAR_HASH}\n`);
		expect(body).toContain(`FileHash: sha256:${FILE_HASH}\n`);
		expect(body).toContain("Compression: zstd");
		// A public cache shares its NARs: the narinfo points one level up.
		expect(body).toContain(`URL: ../nar/${FILE_HASH}/zstd.nar\n`);
		expect(res.headers.get("cache-control")).toBe("public, max-age=300");
		expect((await env.PUBLIC_BUCKET.head(`test-cache/${STORE_PATH_HASH}.narinfo`))?.httpMetadata?.cacheControl).toBe("public, max-age=300");

		// Inspect the handler's response: HTTP transport can strip a HEAD body
		// even when the handler incorrectly returns one.
		const config = resolveConfig(env);
		const head = await handleRequest(new Request(`http://example.com/test-cache/${STORE_PATH_HASH}.narinfo`, { method: "HEAD" }), config);
		await config.close();
		expect(head.status).toBe(200);
		for (const header of ["content-type", "cache-control"]) {
			expect(head.headers.get(header)).toBe(res.headers.get(header));
		}
		expect(head.headers.get("content-length")).toBe(String(new TextEncoder().encode(body).byteLength));
		expect(await head.text()).toBe("");
	});

	it("returns 404 for a valid hash that is not published", async () => {
		const res = await SELF.fetch(`http://example.com/test-cache/${"a".repeat(32)}.narinfo`);

		expect(res.status).toBe(404);
	});

	it("returns 404 for an invalid hash format", async () => {
		const res = await SELF.fetch("http://example.com/test-cache/INVALID.narinfo");

		expect(res.status).toBe(404);
	});

	it("returns 404 when the cache does not exist", async () => {
		const res = await SELF.fetch(`http://example.com/noexist/${STORE_PATH_HASH}.narinfo`);

		expect(res.status).toBe(404);
	});
});

describe("nar download", () => {
	it("returns the nar blob for a valid request", async () => {
		const res = await SELF.fetch(`http://example.com/test-cache/nar/${FILE_HASH}/zstd.nar`);

		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("application/x-nix-nar");
		expect(res.headers.get("cache-control")).toContain("immutable");
		const body = new Uint8Array(await res.arrayBuffer());
		expect(body).toEqual(R2_BODY);
	});

	it("checks public NAR membership for each cache and org, even after a warm read", async () => {
		await createCache(db, "empty-cache");
		const org = "read-isolation";
		const api = (path: string, method: string, body: unknown) => SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, {
			method, headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" }, body: JSON.stringify(body),
		});
		expect((await api("", "PUT", { slug: org })).status).toBe(200);
		expect((await api("/caches", "POST", { name: "test-cache", protocols: ["nix"] })).status).toBe(201);
		const suffix = `nar/${FILE_HASH}/zstd.nar`;
		const warm = await SELF.fetch(`http://example.com/test-cache/${suffix}`);
		expect(warm.status).toBe(200);
		expect(new Uint8Array(await warm.arrayBuffer())).toEqual(R2_BODY);
		for (const method of ["GET", "HEAD"]) {
			for (const path of ["empty-cache", `${org}/test-cache`, "missing-cache"]) {
				expect((await SELF.fetch(`http://example.com/${path}/${suffix}`, { method })).status).toBe(404);
				expect((await SELF.fetch(`http://example.com/${path}/${suffix}`, { method, headers: { "x-snowstead-cdn-read": "1" } })).status).toBe(404);
			}
			expect((await SELF.fetch(`http://example.com/test-cache/${suffix}`, { method })).status).toBe(200);
			expect((await SELF.fetch(`http://example.com/test-cache/${suffix}`, { method, headers: { "x-snowstead-cdn-read": "1" } })).status).toBe(204);
		}
	});

	it("returns 404 for a non-existent blob", async () => {
		const res = await SELF.fetch(`http://example.com/test-cache/nar/${"b".repeat(64)}/zstd.nar`);

		expect(res.status).toBe(404);
	});

	it("returns 404 for an invalid file hash", async () => {
		const res = await SELF.fetch("http://example.com/test-cache/nar/invalid/zstd.nar");

		expect(res.status).toBe(404);
	});

	it("returns 404 for an invalid compression", async () => {
		const res = await SELF.fetch(`http://example.com/test-cache/nar/${FILE_HASH}/gzip.nar`);

		expect(res.status).toBe(404);
	});
});
