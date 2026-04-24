import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { drizzle } from "drizzle-orm/d1";
import { createCache, createBlobObject, createPublishedPath } from "../src/db/repository.js";
import { handleRequest } from "../src/router.js";
import { resolveConfig } from "../src/config.js";

const STORE_PATH_HASH = "0".repeat(32);
const FILE_HASH = "a".repeat(64);
const NAR_HASH = `sha256:${"1".repeat(52)}`;
const R2_KEY = `nars/sha256/${FILE_HASH}/zstd.nar`;
const R2_BODY = new Uint8Array([1, 2, 3, 4]);

function getDb() {
	return drizzle(env.CACHE_DB);
}

beforeAll(async () => {
	const db = getDb();

	const cache = await createCache(db, "test-cache");

	const blob = await createBlobObject(db, {
		fileHash: FILE_HASH,
		fileSize: 1024,
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
});

describe("nix-cache-info", () => {
	it("returns cache info for an existing cache", async () => {
		const res = await SELF.fetch("http://example.com/test-cache/nix-cache-info");

		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("text/x-nix-cache-info");
		const body = await res.text();
		expect(body).toContain("StoreDir: /nix/store");
	});

	it("returns 200 for any cache path", async () => {
		const res = await SELF.fetch("http://example.com/nonexistent/nix-cache-info");

		expect(res.status).toBe(200);
	});
});

describe("narinfo", () => {
	it("returns narinfo for a published path", async () => {
		const res = await SELF.fetch(`http://example.com/test-cache/${STORE_PATH_HASH}.narinfo`);

		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("text/x-nix-narinfo");
		const body = await res.text();
		expect(body).toContain("StorePath:");
		expect(body).toContain("NarHash:");
		expect(body).toContain("FileHash:");
		expect(body).toContain("Compression: zstd");
		expect(body).toContain("URL: nar/");
	});

	it("HEAD returns 200 with headers but no body", async () => {
		const request = new Request(`http://example.com/test-cache/${STORE_PATH_HASH}.narinfo`, {
			method: "HEAD",
		});
		const config = resolveConfig(env);
		const res = await handleRequest(request, config);

		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("text/x-nix-narinfo");
		expect(res.headers.get("content-length")).toBeTruthy();
		expect(res.headers.get("cache-control")).toContain("immutable");
		const body = await res.text();
		expect(body).toBe("");
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
