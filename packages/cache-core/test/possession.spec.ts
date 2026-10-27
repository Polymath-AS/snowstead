import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createCache } from "../src/db/repository.js";
import { narKey } from "../src/layout.js";
import { eq } from "drizzle-orm";
import { uploadSessions } from "../src/db/schema.js";
import { runGarbageCollection } from "../../../workers/control/src/gc.js";
import { resolveConfig } from "../src/config.js";

// NARs are shared by every cache that has them. These push one into one
// cache, then try to get it into another without having its bytes.

const db = testDb();
const AUTH = { authorization: "Bearer test-auth-token" };
const SIZE = 16;

function post(path: string, body: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com${path}`, {
		method: "POST",
		headers: { ...AUTH, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

function put(path: string, body: Uint8Array): Promise<Response> {
	return SELF.fetch(`http://example.com${path}`, { method: "PUT", headers: AUTH, body });
}

async function nar(): Promise<{ bytes: Uint8Array; fileHash: string }> {
	const bytes = crypto.getRandomValues(new Uint8Array(SIZE));
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
	return { bytes, fileHash: [...digest].map((b) => b.toString(16).padStart(2, "0")).join("") };
}

let counter = 0;
function storePathHash(): string {
	counter++;
	return `${"p".repeat(30)}${String(counter).padStart(2, "0")}`.replace(/[eotu]/g, "a");
}

async function freshCache(): Promise<string> {
	return (await createCache(db, `possess-${crypto.randomUUID().slice(0, 8)}`)).name;
}

async function session(cache: string, fileHash: string): Promise<{ sessionId: string; r2Key: string; hash: string }> {
	const hash = storePathHash();
	const res = await post(`/_api/v1/caches/${cache}/upload-sessions`, {
		storePath: `/nix/store/${hash}-shared`,
		storePathHash: hash,
		narHash: `sha256:${"1".repeat(52)}`,
		narSize: 64,
		fileHash,
		fileSize: SIZE,
		compression: "zstd",
	});
	expect(res.status).toBe(201);
	return { ...(await res.json<{ sessionId: string; r2Key: string }>()), hash };
}

async function commit(sessionId: string): Promise<{ published?: boolean; error?: string; status?: number }> {
	const res = await post("/_api/v1/uploads/commit", { sessionIds: [sessionId] });
	expect(res.status).toBe(200);
	return (await res.json<{ results: { published?: boolean; error?: string; status?: number }[] }>()).results[0];
}

async function narinfoStatus(cache: string, hash: string): Promise<number> {
	return (await SELF.fetch(`http://example.com/${cache}/${hash}.narinfo`)).status;
}

/** A NAR pushed properly into a cache of its own: what the others try to claim. */
async function storedNar() {
	const { bytes, fileHash } = await nar();
	const owner = await freshCache();
	const s = await session(owner, fileHash);
	expect((await put(`/_api/v1/uploads/${s.sessionId}/blob`, bytes)).status).toBe(200);
	expect(await commit(s.sessionId)).toMatchObject({ published: true });
	return { bytes, fileHash };
}

async function storedBytes(fileHash: string): Promise<Uint8Array | null> {
	const object = await env.PUBLIC_BUCKET.get(narKey(fileHash, "zstd", false));
	return object ? new Uint8Array(await object.arrayBuffer()) : null;
}

describe("proof of possession", () => {
	it("won't publish a stored NAR into another cache without its bytes", async () => {
		const { fileHash } = await storedNar();
		const cache = await freshCache();

		const s = await session(cache, fileHash);
		expect(s.r2Key).toMatch(/^staging\//);
		expect(await commit(s.sessionId)).toMatchObject({ status: 400 });
		expect(await narinfoStatus(cache, s.hash)).toBe(404);
	});

	it("publishes it once the bytes are uploaded", async () => {
		const { bytes, fileHash } = await storedNar();
		const cache = await freshCache();

		const s = await session(cache, fileHash);
		expect((await put(`/_api/v1/uploads/${s.sessionId}/blob`, bytes)).status).toBe(200);
		expect(await commit(s.sessionId)).toMatchObject({ published: true });
		expect(await narinfoStatus(cache, s.hash)).toBe(200);
	});

	it("refuses other bytes, and leaves the stored NAR alone", async () => {
		const { bytes, fileHash } = await storedNar();
		const cache = await freshCache();

		const s = await session(cache, fileHash);
		const junk = crypto.getRandomValues(new Uint8Array(SIZE));
		expect((await put(`/_api/v1/uploads/${s.sessionId}/blob`, junk)).ok).toBe(false);
		expect(await commit(s.sessionId)).toMatchObject({ status: 400 });
		expect(await storedBytes(fileHash)).toEqual(bytes);
	});

	it("can't overwrite a stored NAR through parts", async () => {
		const { bytes, fileHash } = await storedNar();
		const cache = await freshCache();

		const s = await session(cache, fileHash);
		const started = await post(`/_api/v1/uploads/${s.sessionId}/multipart`, {});
		expect(await started.json()).toMatchObject({ r2Key: expect.stringMatching(/^staging\//) });
		expect((await put(`/_api/v1/uploads/${s.sessionId}/part/1`, crypto.getRandomValues(new Uint8Array(SIZE)))).status).toBe(200);

		const done = await post(`/_api/v1/uploads/${s.sessionId}/complete`, {});
		expect(done.status).toBe(400);
		expect(await done.json()).toEqual({ error: "File hash mismatch" });
		expect(await storedBytes(fileHash)).toEqual(bytes);
	});

	it("takes the right bytes through parts", async () => {
		const { bytes, fileHash } = await storedNar();
		const cache = await freshCache();

		const s = await session(cache, fileHash);
		await post(`/_api/v1/uploads/${s.sessionId}/multipart`, {});
		expect((await put(`/_api/v1/uploads/${s.sessionId}/part/1`, bytes)).status).toBe(200);
		expect((await post(`/_api/v1/uploads/${s.sessionId}/complete`, {})).status).toBe(200);
		expect(await commit(s.sessionId)).toMatchObject({ published: true });
	});

	it("won't complete a session on an upload another session made", async () => {
		const { bytes, fileHash } = await nar();
		const [first, second] = [await freshCache(), await freshCache()];
		// Both before the NAR is stored, so both upload to its own key.
		const a = await session(first, fileHash);
		const b = await session(second, fileHash);
		expect(b.r2Key).not.toMatch(/^staging\//);

		expect((await put(`/_api/v1/uploads/${a.sessionId}/blob`, bytes)).status).toBe(200);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		expect(await commit(b.sessionId)).toMatchObject({ status: 400, error: "Upload incomplete" });
		expect(await narinfoStatus(second, b.hash)).toBe(404);

		// The abandoned session names the same canonical key as the published
		// path. Expiring it must not withdraw somebody else's bytes.
		await db.update(uploadSessions).set({ expiresAt: new Date(0) }).where(eq(uploadSessions.id, b.sessionId));
		const config = resolveConfig(env);
		try {
			expect((await runGarbageCollection(config)).errors).toEqual([]);
			expect(await storedBytes(fileHash)).toEqual(bytes);
		} finally {
			await config.close();
		}
	});
});
