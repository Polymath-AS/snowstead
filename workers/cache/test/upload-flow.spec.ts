import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { testDb } from "./db.js";
import { createCache, findPublishedPath, findCacheByName } from "../src/db/repository.js";

const CACHE_NAME = "upload-test";
const AUTH_TOKEN = "test-auth-token";
// R2 checks every upload against its file hash, so bodies are real: each
// uniqueFileHash() makes a fresh body and returns its SHA-256.
const BLOB_SIZE = 16;
const blobs = new Map<string, Uint8Array>();

function blob(fileHash: string): Uint8Array {
	const body = blobs.get(fileHash);
	if (!body) throw new Error(`no body for ${fileHash}`);
	return body;
}

const db = testDb();

function getDb() {
	return db;
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
		fileSize: BLOB_SIZE,
		compression: "zstd",
	};
}

async function uniqueFileHash(): Promise<string> {
	const body = crypto.getRandomValues(new Uint8Array(BLOB_SIZE));
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
	const hash = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
	blobs.set(hash, body);
	return hash;
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
		body: blob(fileHash),
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
			sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
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
			sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
		);

		expect(res.status).toBe(404);
	});

	it("returns 400 for missing required fields", async () => {
		const res = await post(`/_api/v1/caches/${CACHE_NAME}/upload-sessions`, {});

		expect(res.status).toBe(400);
	});

	it.each([
		{ label: "a bare-hash reference", patch: { references: ["0".repeat(32)] } },
		{ label: "a store path for another hash", patch: { storePath: `/nix/store/${"0".repeat(32)}-hello` } },
		{ label: "a newline in the deriver", patch: { deriver: "x.drv\nSig: forged" } },
		{ label: "an MD5 NAR hash", patch: { narHash: `md5:${"0".repeat(32)}` } },
	])("returns 400 for $label", async ({ patch }) => {
		const res = await post(`/_api/v1/caches/${CACHE_NAME}/upload-sessions`, {
			...sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
			...patch,
		});

		expect(res.status).toBe(400);
	});
});

describe("complete upload (direct)", () => {
	it("completes a direct upload flow", async () => {
		const fileHash = await uniqueFileHash();
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
			body: blob(fileHash),
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
		const session = await createSessionAndUpload(await uniqueFileHash(), uniqueStorePathHash());

		const res = await post(`/_api/v1/uploads/${session.sessionId}/complete`, {});
		expect(res.status).toBe(409);
	});

	// A session may have been uploaded to straight from a presigned URL, so
	// completing it checks the object, which is not there yet.
	it("returns 400 when nothing has been uploaded yet", async () => {
		const createRes = await post(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
		);
		expect(createRes.status).toBe(201);
		const session = await createRes.json<{ sessionId: string }>();

		const res = await post(`/_api/v1/uploads/${session.sessionId}/complete`, {});
		expect(res.status).toBe(400);
		expect(await res.json()).toMatchObject({ error: "Upload incomplete" });
	});
});

describe("publish", () => {
	it("shows a path right after publish, even after a cached miss", async () => {
		const storePathHash = uniqueStorePathHash();
		const url = `http://example.com/${CACHE_NAME}/${storePathHash}.narinfo`;
		expect((await SELF.fetch(url)).status).toBe(404);

		const session = await createSessionAndUpload(await uniqueFileHash(), storePathHash);
		expect((await post(`/_api/v1/uploads/${session.sessionId}/publish`, {})).status).toBe(200);

		expect((await SELF.fetch(url)).status).toBe(200);
	});

	// What `nix path-info --json` prints: SRI hashes, full reference paths
	// (which the CLI reduces to basenames).
	it("serves the narinfo Nix expects for an SRI hash and references", async () => {
		const fileHash = await uniqueFileHash();
		const storePathHash = uniqueStorePathHash();
		const ref = `${"1".repeat(32)}-dep`;
		const createRes = await post(`/_api/v1/caches/${CACHE_NAME}/upload-sessions`, {
			...sessionBody({ fileHash: fileHash, storePathHash }),
			narHash: "sha256-L5spLmHxo4zwWB8LQ5ZMgJqzfnjpt/GDVZ0nnobVmQk=",
			references: [ref],
		});
		expect(createRes.status).toBe(201);
		const { sessionId } = await createRes.json<{ sessionId: string }>();
		await SELF.fetch(`http://example.com/_api/v1/uploads/${sessionId}/blob`, {
			method: "PUT",
			headers: { authorization: `Bearer ${AUTH_TOKEN}` },
			body: blob(fileHash),
		});
		expect((await post(`/_api/v1/uploads/${sessionId}/complete`, {})).status).toBe(200);
		expect((await post(`/_api/v1/uploads/${sessionId}/publish`, {})).status).toBe(200);

		const res = await SELF.fetch(`http://example.com/${CACHE_NAME}/${storePathHash}.narinfo`, {
			headers: { authorization: `Bearer ${AUTH_TOKEN}` },
		});
		expect(res.status).toBe(200);
		const narinfo = await res.text();
		expect(narinfo).toContain("NarHash: sha256:02crsn39w9wxan1z3dz9g1zb76l09jb462qzb3q8r8zic4p2k6rg\n");
		expect(narinfo).toContain(`References: ${ref}\n`);
	});

	it("publishes a completed upload and path is readable", async () => {
		const fileHash = await uniqueFileHash();
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
			sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() }),
		);
		expect(createRes.status).toBe(201);
		const session = await createRes.json<{ sessionId: string }>();

		const res = await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});
		expect(res.status).toBe(409);
	});

	it("concurrent duplicate publish does not create duplicate paths", async () => {
		const session = await createSessionAndUpload(await uniqueFileHash(), uniqueStorePathHash());

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
		const session = await createSessionAndUpload(await uniqueFileHash(), uniqueStorePathHash());

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
		const session = await createSessionAndUpload(await uniqueFileHash(), storePathHash);
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
