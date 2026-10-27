import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { testDb } from "./db.js";
import { createCache, createBlobObject, createPublishedPath } from "../src/db/repository.js";
import { handleRequest } from "../../../workers/nix/src/router.js";
import { resolveConfig } from "../src/config.js";

const STORE_PATH_HASH = "0".repeat(32);
const FILE_HASH = "a".repeat(64);
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

	// Paths written straight to the database get their narinfo from the backfill.
	const backfill = await SELF.fetch("http://example.com/_api/v1/admin/narinfo/backfill", {
		method: "POST",
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: JSON.stringify({ limit: 1000 }),
	});
	expect(backfill.status).toBe(200);
});

describe("nix-cache-info", () => {
	it("returns cache info even for a cache that has not been created", async () => {
		for (const name of ["test-cache", "nonexistent"]) {
			const res = await SELF.fetch(`http://example.com/${name}/nix-cache-info`);
			expect(res.status).toBe(200);
			expect(res.headers.get("content-type")).toBe("text/x-nix-cache-info");
			expect(await res.text()).toContain("StoreDir: /nix/store\n");
		}
	});
});

describe("narinfo", () => {
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
