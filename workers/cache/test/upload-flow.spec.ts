import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { drizzle } from "drizzle-orm/d1";
import { createCache, findPublishedPath, findCacheByName } from "../src/db/repository.js";

const CACHE_NAME = "upload-test";
const AUTH_TOKEN = "test-auth-token";
const BLOB_DATA = new Uint8Array([1, 2, 3, 4]);

function getDb() {
	return drizzle(env.CACHE_DB);
}

function post(path: string, body: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${AUTH_TOKEN}`,
		},
		body: JSON.stringify(body),
	});
}

function sessionBody(overrides: { fileHash: string; storePathHash: string }) {
	return {
		storePath: `/nix/store/${overrides.storePathHash}-hello`,
		storePathHash: overrides.storePathHash,
		narHash: `sha256:${"1".repeat(52)}`,
		narSize: 2048,
		fileHash: overrides.fileHash,
		fileSize: BLOB_DATA.byteLength,
		compression: "zstd",
	};
}

function uniqueFileHash() {
	return crypto.randomUUID().replace(/-/g, "").slice(0, 64).padEnd(64, "0");
}

let storePathCounter = 1;
function uniqueStorePathHash() {
	const c = String(storePathCounter++);
	return c.repeat(32).slice(0, 32);
}

async function createSessionAndUpload(fileHash: string, storePathHash: string) {
	const createRes = await post(
		`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
		sessionBody({ fileHash, storePathHash }),
	);
	expect(createRes.status).toBe(201);
	const session = await createRes.json<{ sessionId: string; r2Key: string }>();

	const blobRes = await SELF.fetch(`http://example.com/_api/v1/uploads/${session.sessionId}/blob`, {
		method: "PUT",
		headers: { authorization: `Bearer ${AUTH_TOKEN}` },
		body: BLOB_DATA,
	});
	expect(blobRes.status).toBe(200);

	const completeRes = await post(`/_api/v1/uploads/${session.sessionId}/complete`, {});
	expect(completeRes.status).toBe(200);

	return session;
}

beforeAll(async () => {
	const db = getDb();
	await createCache(db, CACHE_NAME);
});

describe("create upload session", () => {
	it("creates a session and returns 201 with expected fields", async () => {
		const res = await post(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			sessionBody({ fileHash: uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
		);

		expect(res.status).toBe(201);
		const body = await res.json<Record<string, unknown>>();
		expect(body).toHaveProperty("sessionId");
		expect(body).toHaveProperty("r2Key");
		expect(body).toHaveProperty("uploadMethod", "direct");
		expect(body).toHaveProperty("expiresAt");
	});

	it("returns 404 for non-existent cache", async () => {
		const res = await post(
			"/_api/v1/caches/no-such-cache/upload-sessions",
			sessionBody({ fileHash: uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
		);

		expect(res.status).toBe(404);
	});

	it("returns 400 for missing required fields", async () => {
		const res = await post(`/_api/v1/caches/${CACHE_NAME}/upload-sessions`, {});

		expect(res.status).toBe(400);
	});
});

describe("complete upload (direct)", () => {
	it("completes a direct upload flow", async () => {
		const fileHash = uniqueFileHash();
		const storePathHash = uniqueStorePathHash();

		const createRes = await post(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			sessionBody({ fileHash, storePathHash }),
		);
		expect(createRes.status).toBe(201);
		const session = await createRes.json<{ sessionId: string; r2Key: string }>();

		const blobRes = await SELF.fetch(`http://example.com/_api/v1/uploads/${session.sessionId}/blob`, {
			method: "PUT",
			headers: { authorization: `Bearer ${AUTH_TOKEN}` },
			body: BLOB_DATA,
		});
		expect(blobRes.status).toBe(200);

		const completeRes = await post(`/_api/v1/uploads/${session.sessionId}/complete`, {});
		expect(completeRes.status).toBe(200);
		const completeBody = await completeRes.json<{ status: string }>();
		expect(completeBody.status).toBe("completed");
	});

	it("returns 404 for non-existent session", async () => {
		const res = await post("/_api/v1/uploads/00000000-0000-0000-0000-000000000000/complete", {});

		expect(res.status).toBe(404);
	});

	it("returns 409 for already-completed session", async () => {
		const session = await createSessionAndUpload(uniqueFileHash(), uniqueStorePathHash());

		const res = await post(`/_api/v1/uploads/${session.sessionId}/complete`, {});
		expect(res.status).toBe(409);
	});

	it("returns 409 when session has not uploaded a blob yet", async () => {
		const createRes = await post(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			sessionBody({ fileHash: uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
		);
		expect(createRes.status).toBe(201);
		const session = await createRes.json<{ sessionId: string }>();

		const res = await post(`/_api/v1/uploads/${session.sessionId}/complete`, {});
		expect(res.status).toBe(409);
	});
});

describe("publish", () => {
	it("publishes a completed upload and path is readable", async () => {
		const fileHash = uniqueFileHash();
		const storePathHash = uniqueStorePathHash();
		const session = await createSessionAndUpload(fileHash, storePathHash);

		const publishRes = await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});
		expect(publishRes.status).toBe(200);
		const publishBody = await publishRes.json<{ published: boolean; storePathHash: string }>();
		expect(publishBody.published).toBe(true);
		expect(publishBody.storePathHash).toBe(storePathHash);

		const db = getDb();
		const cache = await findCacheByName(db, CACHE_NAME);
		expect(cache).toBeDefined();
		const published = await findPublishedPath(db, cache!.id, storePathHash);
		expect(published).toBeDefined();
	});

	it("returns 409 for uncompleted session", async () => {
		const createRes = await post(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			sessionBody({ fileHash: uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
		);
		expect(createRes.status).toBe(201);
		const session = await createRes.json<{ sessionId: string }>();

		const res = await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});
		expect(res.status).toBe(409);
	});

	it("concurrent duplicate publish does not create duplicate paths", async () => {
		const session = await createSessionAndUpload(uniqueFileHash(), uniqueStorePathHash());

		const [r1, r2] = await Promise.all([
			post(`/_api/v1/uploads/${session.sessionId}/publish`, {}),
			post(`/_api/v1/uploads/${session.sessionId}/publish`, {}),
		]);

		expect(r1.status).toBe(200);
		expect(r2.status).toBe(200);
		const b1 = await r1.json<{ published: boolean; alreadyExisted?: boolean }>();
		const b2 = await r2.json<{ published: boolean; alreadyExisted?: boolean }>();
		expect(b1.published).toBe(true);
		expect(b2.published).toBe(true);
	});

	it("duplicate publish is idempotent", async () => {
		const session = await createSessionAndUpload(uniqueFileHash(), uniqueStorePathHash());

		const first = await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});
		expect(first.status).toBe(200);

		const second = await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});
		expect(second.status).toBe(200);
		const body = await second.json<{ alreadyExisted: boolean }>();
		expect(body.alreadyExisted).toBe(true);
	});
});

describe("get-missing-paths", () => {
	it("returns only unpublished paths as missing", async () => {
		const storePathHash = uniqueStorePathHash();
		const session = await createSessionAndUpload(uniqueFileHash(), storePathHash);
		await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});

		const randomHash = "x".repeat(32).replace(/x/g, () => "abcdfg0123456789"[Math.floor(Math.random() * 16)]);

		const res = await post("/_api/v1/get-missing-paths", {
			cache: CACHE_NAME,
			storePathHashes: [storePathHash, randomHash],
		});
		expect(res.status).toBe(200);
		const body = await res.json<{ missing: string[] }>();
		expect(body.missing).not.toContain(storePathHash);
		expect(body.missing).toContain(randomHash);
	});

	it("returns 404 for non-existent cache", async () => {
		const res = await post("/_api/v1/get-missing-paths", {
			cache: "nonexistent-cache",
			storePathHashes: ["0".repeat(32)],
		});

		expect(res.status).toBe(404);
	});
});
