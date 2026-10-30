import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { testDb } from "./db.js";
import { createCache, findPublishedPath, findCache, createUploadSessions, findUploadSession } from "../src/db/repository.js";
import { uploadSessions } from "../src/db/schema.js";
import { eq } from "drizzle-orm";

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
	const session = await createRes.json<{ sessionId: string; r2Key: string; uploadMethod: string; expiresAt: string }>();
	expect(session.r2Key).toBe(`staging/${session.sessionId}`);
	expect(session.uploadMethod).toBe("direct");
	expect(Date.parse(session.expiresAt)).toBeGreaterThan(Date.now());

	const blobRes = await SELF.fetch(`http://example.com/_api/v1/uploads/${session.sessionId}/blob`, {
		method: "PUT",
		headers: { authorization: `Bearer ${AUTH_TOKEN}` },
		body: blob(fileHash),
	});
	expect(blobRes.status).toBe(200);

	const completeRes = await post(`/_api/v1/uploads/${session.sessionId}/complete`, {});
	expect(completeRes.status).toBe(200);
	expect(await completeRes.json()).toMatchObject({ status: "completed" });

	return session;
}

beforeAll(async () => {
	const db = getDb();
	await createCache(db, CACHE_NAME);
});

describe("create upload session", () => {
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
		const published = await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});
		expect(published.status).toBe(200);
		expect(await published.json()).toMatchObject({ published: true, storePathHash });

		const narinfo = await SELF.fetch(url);
		expect(narinfo.status).toBe(200);
		expect(await narinfo.text()).toContain(`StorePath: /nix/store/${storePathHash}-hello\n`);
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

	it("refuses a session expiring by now whose NAR the blob sweep took, and takes one whose NAR is there", async () => {
		const expire = (id: string) => getDb().update(uploadSessions).set({ expiresAt: new Date(Date.now() + 60_000) }).where(eq(uploadSessions.id, id));

		const swept = await createSessionAndUpload(await uniqueFileHash(), uniqueStorePathHash());
		await expire(swept.sessionId);
		const receipt = await findUploadSession(getDb(), swept.sessionId);
		await env.PUBLIC_BUCKET.delete(`nar/${receipt!.fileHash}/zstd.nar`);
		const refused = await post(`/_api/v1/uploads/${swept.sessionId}/publish`, {});
		expect(refused.status).toBe(400);
		expect(await refused.text()).toContain("the stored NAR is gone");
		const cache = await findCache(getDb(), "default", CACHE_NAME);
		expect(await findPublishedPath(getDb(), cache!.id, (await findUploadSession(getDb(), swept.sessionId))!.storePathHash)).toBeUndefined();

		const kept = await createSessionAndUpload(await uniqueFileHash(), uniqueStorePathHash());
		await expire(kept.sessionId);
		expect((await post(`/_api/v1/uploads/${kept.sessionId}/publish`, {})).status).toBe(200);
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

	it("publishes once under concurrent requests and sequential retries", async () => {
		const stats = () => SELF.fetch(`http://example.com/_api/v1/admin/caches/${CACHE_NAME}`, {
			headers: { authorization: "Bearer test-admin-secret" },
		}).then((r) => r.json<{ paths: number }>());
		const before = await stats();
		const storePathHash = uniqueStorePathHash();
		const session = await createSessionAndUpload(await uniqueFileHash(), storePathHash);

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

		const second = await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});
		expect(second.status).toBe(200);
		expect(await second.json()).toMatchObject({ published: true, alreadyExisted: true, storePathHash });
		expect((await stats()).paths).toBe(before.paths + 1);
	});
});

describe("get-missing-paths", () => {
	it("returns only unpublished paths as missing", async () => {
		const storePathHash = uniqueStorePathHash();
		const session = await createSessionAndUpload(await uniqueFileHash(), storePathHash);
		await post(`/_api/v1/uploads/${session.sessionId}/publish`, {});

		const missingHash = "z".repeat(32);

		const res = await post("/_api/v1/get-missing-paths", {
			cache: CACHE_NAME,
			storePathHashes: [storePathHash, missingHash],
		});
		expect(res.status).toBe(200);
		const body = await res.json<{ missing: string[] }>();
		expect(body.missing).toEqual([missingHash]);
	});

	it("returns 404 for non-existent cache", async () => {
		const res = await post("/_api/v1/get-missing-paths", {
			cache: "nonexistent-cache",
			storePathHashes: ["0".repeat(32)],
		});

		expect(res.status).toBe(404);
	});
});

describe("batches", () => {
	async function createBatch(paths: unknown[]) {
		return post(`/_api/v1/caches/${CACHE_NAME}/upload-sessions/batch`, { paths });
	}

	async function putBlob(sessionId: string, fileHash: string) {
		const res = await SELF.fetch(`http://example.com/_api/v1/uploads/${sessionId}/blob`, {
			method: "PUT",
			headers: { authorization: `Bearer ${AUTH_TOKEN}` },
			body: blob(fileHash),
		});
		expect(res.status).toBe(200);
	}

	type CommitResult = { sessionId: string; published?: boolean; alreadyExisted?: boolean; error?: string; status?: number };

	async function commit(sessionIds: string[]) {
		const res = await post("/_api/v1/uploads/commit", { sessionIds });
		expect(res.status).toBe(200);
		return (await res.json<{ results: CommitResult[] }>()).results;
	}

	it("creates sessions in the order asked", async () => {
		const bodies = await Promise.all([1, 2, 3].map(async () => sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() })));
		const res = await createBatch(bodies);
		expect(res.status).toBe(201);
		const { sessions } = await res.json<{ sessions: Array<{ sessionId: string; r2Key: string; uploadMethod: string }> }>();
		expect(sessions.map((s) => s.r2Key)).toEqual(sessions.map((s) => `staging/${s.sessionId}`));
		const persisted = await Promise.all(sessions.map(s => findUploadSession(getDb(), s.sessionId)));
		expect(persisted.map(s => s?.fileHash)).toEqual(bodies.map(b => b.fileHash));
		expect(new Set(sessions.map((s) => s.sessionId)).size).toBe(3);
	});

	it("refuses a batch with an invalid path, naming it", async () => {
		const good = sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() });
		const res = await createBatch([good, { ...good, narSize: "big" }]);
		expect(res.status).toBe(400);
		expect(await res.text()).toContain("paths[1]");
	});

	it("refuses empty and oversized batches", async () => {
		expect((await createBatch([])).status).toBe(400);
		const body = sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() });
		expect((await createBatch(Array.from({ length: 101 }, () => body))).status).toBe(400);
	});

	it("completes and publishes uploaded sessions, and reports the rest per session", async () => {
		const bodies = await Promise.all([1, 2, 3, 4].map(async () => sessionBody({ fileHash: await uniqueFileHash(), storePathHash: uniqueStorePathHash() })));
		const { sessions } = await (await createBatch(bodies)).json<{ sessions: Array<{ sessionId: string }> }>();
		await Promise.all(sessions.slice(0, 3).map((s, i) => putBlob(s.sessionId, bodies[i].fileHash)));

		const unknown = crypto.randomUUID();
		const results = await commit([...sessions.map((s) => s.sessionId), unknown]);
		expect(results.slice(0, 3).map((r) => r.published)).toEqual([true, true, true]);
		expect(results[3]).toMatchObject({ error: "Upload incomplete", status: 400 });
		expect(results[4]).toMatchObject({ sessionId: unknown, status: 404 });

		for (const b of bodies.slice(0, 3)) {
			const res = await SELF.fetch(`http://example.com/${CACHE_NAME}/${b.storePathHash}.narinfo`);
			expect(res.status).toBe(200);
			expect(await res.text()).toContain(`FileHash: sha256:${b.fileHash}`);
		}
		const cache = await findCache(getDb(), "default", CACHE_NAME);
		expect(await findPublishedPath(getDb(), cache!.id, bodies[3].storePathHash)).toBeUndefined();

		// Committing again publishes nothing new.
		const again = await commit([sessions[0].sessionId]);
		expect(again[0]).toMatchObject({ published: true, alreadyExisted: true });
	});

	it("publishes a path once when a batch carries it twice", async () => {
		const storePathHash = uniqueStorePathHash();
		const bodies = [
			sessionBody({ fileHash: await uniqueFileHash(), storePathHash }),
			sessionBody({ fileHash: await uniqueFileHash(), storePathHash }),
		];
		const { sessions } = await (await createBatch(bodies)).json<{ sessions: Array<{ sessionId: string }> }>();
		await Promise.all(sessions.map((s, i) => putBlob(s.sessionId, bodies[i].fileHash)));

		const results = await commit(sessions.map((s) => s.sessionId));
		expect(results).toEqual(sessions.map((s) => expect.objectContaining({ sessionId: s.sessionId, published: true })));
		const cache = await findCache(getDb(), "default", CACHE_NAME);
		expect(await findPublishedPath(getDb(), cache!.id, storePathHash)).toBeDefined();
	});
});

describe("staged uploads", () => {
	// What session creation does for a large NAR when presigning is configured;
	// the test Worker has no R2 credentials, so the parts go through the binding.
	async function stagedSession(fileHash: string, body: Uint8Array) {
		const cache = await findCache(getDb(), "default", CACHE_NAME);
		const id = crypto.randomUUID();
		const key = `staging/${id}`;
		const multipart = await env.CACHE_BUCKET.createMultipartUpload(key, { customMetadata: { session: id } });
		const storePathHash = uniqueStorePathHash();
		await createUploadSessions(getDb(), [{
			id,
			cacheId: cache!.id,
			storePathHash,
			storePath: `/nix/store/${storePathHash}-big`,
			narHash: `sha256:${"1".repeat(52)}`,
			narSize: 4096,
			fileHash,
			fileSize: body.byteLength,
			compression: "zstd",
			referencesJson: "[]",
			deriver: null,
			system: null,
			status: "uploading",
			r2UploadKey: key,
			r2UploadId: multipart.uploadId,
			expiresAt: new Date(Date.now() + 3600_000),
		}]);
		const part = await multipart.uploadPart(1, body);
		return { id, key, storePathHash, parts: [{ partNumber: 1, etag: part.etag }] };
	}

	async function commitStaged(id: string, parts: unknown) {
		const res = await post("/_api/v1/uploads/commit", { sessionIds: [id], parts: { [id]: parts } });
		expect(res.status).toBe(200);
		return (await res.json<{ results: Array<{ published?: boolean; error?: string; status?: number }> }>()).results[0];
	}

	it.each(["complete", "commit"])("validates parts before %s, then assembles and publishes the NAR", async (endpoint) => {
		const fileHash = await uniqueFileHash();
		const staged = await stagedSession(fileHash, blob(fileHash));

		const finish = (parts: unknown) => endpoint === "complete"
			? post(`/_api/v1/uploads/${staged.id}/complete`, { parts })
			: post("/_api/v1/uploads/commit", { sessionIds: [staged.id], parts: { [staged.id]: parts } });
		for (const parts of [
			{}, [null], [{ partNumber: 0, etag: "x" }], [{ partNumber: 10_001, etag: "x" }],
			[{ partNumber: 1.5, etag: "x" }], [{ partNumber: 1, etag: 123 }],
			[{ partNumber: 1, etag: '""' }], [staged.parts[0], staged.parts[0]],
		]) {
			const rejected = await finish(parts);
			expect(rejected.status).toBe(400);
			expect((await rejected.json<{ error: string }>()).error).toContain("parts");
		}
		expect((await findUploadSession(getDb(), staged.id))?.status).toBe("uploading");
		const finished = await finish(staged.parts.map((p) => ({ ...p, etag: `"${p.etag}"` })));
		expect(finished.status).toBe(200);
		if (endpoint === "complete") {
			expect(await finished.json()).toMatchObject({ status: "completed" });
			expect((await post(`/_api/v1/uploads/${staged.id}/publish`, {})).status).toBe(200);
		} else {
			expect(await finished.json()).toMatchObject({ results: [{ published: true }] });
		}
		const nar = await env.PUBLIC_BUCKET.get(`nar/${fileHash}/zstd.nar`);
		expect(new Uint8Array(await nar!.arrayBuffer())).toEqual(blob(fileHash));
		const source = await env.CACHE_BUCKET.head(staged.key);
		expect(source?.customMetadata).toEqual({ session: staged.id });
		expect(await commitStaged(staged.id, staged.parts)).toMatchObject({ published: true });
		expect((await env.CACHE_BUCKET.head(staged.key))?.version).toBe(source?.version);
		const res = await SELF.fetch(`http://example.com/${CACHE_NAME}/${staged.storePathHash}.narinfo`);
		expect(res.status).toBe(200);
	});

	it("refuses parts that are not the file the session names", async () => {
		const fileHash = await uniqueFileHash();
		const staged = await stagedSession(fileHash, crypto.getRandomValues(new Uint8Array(BLOB_SIZE)));

		expect(await commitStaged(staged.id, staged.parts)).toMatchObject({ error: "File hash mismatch", status: 400 });
		expect(await env.PUBLIC_BUCKET.head(`nar/${fileHash}/zstd.nar`)).toBeNull();
		const source = await env.CACHE_BUCKET.head(staged.key);
		expect(source).not.toBeNull();
		expect(await commitStaged(staged.id, staged.parts)).toMatchObject({ error: "File hash mismatch", status: 400 });
		expect((await env.CACHE_BUCKET.head(staged.key))?.version).toBe(source?.version);
		expect((await findUploadSession(getDb(), staged.id))?.status).toBe("uploading");
	});

	it("needs the parts to commit, and a commit to complete", async () => {
		const fileHash = await uniqueFileHash();
		const staged = await stagedSession(fileHash, blob(fileHash));

		const res = await post("/_api/v1/uploads/commit", { sessionIds: [staged.id] });
		expect((await res.json<{ results: Array<{ status?: number }> }>()).results[0].status).toBe(409);
		expect((await post(`/_api/v1/uploads/${staged.id}/complete`, {})).status).toBe(409);
	});
});
