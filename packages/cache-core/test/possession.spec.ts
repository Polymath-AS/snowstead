import { env, SELF, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createCache, createUploadSessions, findCache, findUploadSession } from "../src/db/repository.js";
import { narKey } from "../src/layout.js";
import { eq } from "drizzle-orm";
import { uploadSessions } from "../src/db/schema.js";
import { runGarbageCollection } from "../../../workers/control/src/gc.js";
import { resolveConfig } from "../src/config.js";
import nix from "../../../workers/nix/src/index.js";

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
	return SELF.fetch(`http://example.com${path}`, { method: "PUT", headers: AUTH, body: body.slice() });
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
		// Even before a NAR exists, each session must prove its own upload.
		const a = await session(first, fileHash);
		const b = await session(second, fileHash);
		expect(a.r2Key).toBe(`staging/${a.sessionId}`);
		expect(b.r2Key).toBe(`staging/${b.sessionId}`);

		expect((await put(`/_api/v1/uploads/${a.sessionId}/blob`, bytes)).status).toBe(200);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		expect(await commit(b.sessionId)).toMatchObject({ status: 400, error: "Upload incomplete" });
		expect(await narinfoStatus(second, b.hash)).toBe(404);

		// Expiring an abandoned staging reservation must not withdraw a NAR.
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

describe("canonical and staged upload interleaving", () => {
	// Real duplicate NARs from the reported closure: nix-store --dump on
	// either PAM path yields the same 1152 bytes; zstd -q -c -T1 yields this.
	const bytes = Uint8Array.from(atob("KLUv/QRYnQsABpZDITBN3cA0Zcqg5f0J3CyRsUCGQ14VwTho0nkfwaA8qOY6BTgAPgA5AMtsNdobG9rtUJ5VUojGTVrP8TnHsJACf9bn53Igu0URQjsFMjMVVp8BaZAAmckkOu3juiXUchIE1HJcyHquUMuRITXIqt+OTp09bMQUykJhEqnBhIq8UcJESA0nPLgG4TxMFfEo+MSzjcUDqYkFajQUmPZ7Z1QS7q0BQVGxNhVrs3BvkPHe6zCqfoU2UizQ+/f6Wdet40Rfz0d++83tsz4fGRZyHAfLsjDMam36GayZmZl5wEysC1nLwsTaNO31rBK/3omVSQ0y98oWNFrH4efWc2VidXd1WMjxsGrnWi3oRVFk2PQLJyCgIpkR4w1bRIANH4wmYEkNjL205g1mJ2ZcZxfJyGYbgBBQpUBsndI0lGCjTyS3S3agScUBdsP1itFTsQRlnAANNMAWP6fEP0DnodiNUUXglJSvXaO4I0YNZGAG9giDagNjm63H"), c => c.charCodeAt(0));
	const fileHash = "f0db3d2a2fadbc56937dde94e78d4a2d73a945d00511a5211d66fe370a940eb3";
	const canonical = narKey(fileHash, "zstd", false);
	const paths = [
		"7kmbcwnb53sc5s2scg1qimxags7xaair-userdel.pam",
		"l1n3aywf08rj0jv62ryc2nc3hnyz9hch-useradd.pam",
	];

	async function pamSession(cache: string, index: number) {
		const response = await post(`/_api/v1/caches/${cache}/upload-sessions`, {
			storePath: `/nix/store/${paths[index]}`, storePathHash: paths[index].slice(0, 32),
			narHash: "sha256-0CszDDh/wN3/LZKd90rIIRYLmGc0kOKYCTxZcQcq0Fk=", narSize: 1152,
			fileHash, fileSize: bytes.length, compression: "zstd",
			references: ["9qqk0zxph7qihzs9hjy1hfgacb6ndmj1-linux-pam-1.7.2"],
		});
		expect(response.status).toBe(201);
		return response.json<{ sessionId: string; r2Key: string }>();
	}

	/** A persisted pre-upgrade reservation, not a newly created API session. */
	async function legacyPamSession(cacheName: string, index: number) {
		const cache = await findCache(db, "default", cacheName);
		const sessionId = crypto.randomUUID();
		await createUploadSessions(db, [{
			id: sessionId, cacheId: cache!.id,
			storePath: `/nix/store/${paths[index]}`, storePathHash: paths[index].slice(0, 32),
			narHash: "sha256-0CszDDh/wN3/LZKd90rIIRYLmGc0kOKYCTxZcQcq0Fk=", narSize: 1152,
			fileHash, fileSize: bytes.length, compression: "zstd",
			referencesJson: JSON.stringify(["9qqk0zxph7qihzs9hjy1hfgacb6ndmj1-linux-pam-1.7.2"]),
			deriver: null, system: null, status: "pending", r2UploadKey: canonical,
			expiresAt: new Date(Date.now() + 3600_000),
		}]);
		return { sessionId, r2Key: canonical };
	}

	async function upload(s: { sessionId: string; r2Key: string }, method: string) {
		if (method === "presigned") {
			// The S3 transport leaves the session pending. Supply the object R2
			// stores, including its verified checksum and signed session metadata.
			await (s.r2Key.startsWith("staging/") ? env.CACHE_BUCKET : env.PUBLIC_BUCKET).put(s.r2Key, bytes, {
				sha256: fileHash, customMetadata: { session: s.sessionId },
			});
		} else if (method === "multipart") {
			expect((await post(`/_api/v1/uploads/${s.sessionId}/multipart`, {})).status).toBe(200);
			expect((await put(`/_api/v1/uploads/${s.sessionId}/part/1`, bytes)).status).toBe(200);
		} else {
			expect((await put(`/_api/v1/uploads/${s.sessionId}/blob`, bytes)).status).toBe(200);
		}
	}

	it("signs session-scoped private staging PUTs even before the NAR exists", async () => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const cache = await freshCache();
		for (const index of [0, 1]) {
			const ctx = createExecutionContext();
			const request = new Request(`http://example.com/_api/v1/caches/${cache}/upload-sessions`, {
				method: "POST", headers: { ...AUTH, "content-type": "application/json" },
				body: JSON.stringify({
					storePath: `/nix/store/${paths[index]}`, storePathHash: paths[index].slice(0, 32),
					narHash: "sha256-0CszDDh/wN3/LZKd90rIIRYLmGc0kOKYCTxZcQcq0Fk=", narSize: 1152,
					fileHash, fileSize: bytes.length, compression: "zstd",
				}),
			});
			const response = await nix.fetch(request as Parameters<typeof nix.fetch>[0], {
				...env, R2_ACCESS_KEY_ID: "test-signing-key", R2_SECRET_ACCESS_KEY: "test-signing-secret", R2_ENDPOINT: "https://example.r2.cloudflarestorage.com",
			}, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(201);
			const s = await response.json<{ sessionId: string; r2Key: string; uploadMethod: string; uploadUrl: string; uploadHeaders: Record<string, string> }>();
			expect(s.uploadMethod).toBe("presigned");
			expect(s.r2Key).toBe(`staging/${s.sessionId}`);
			expect(s.uploadHeaders["if-none-match"]).toBeUndefined();
			expect(new URL(s.uploadUrl).searchParams.get("X-Amz-SignedHeaders")?.split(";").includes("if-none-match")).toBe(false);
			expect(s.uploadHeaders["x-amz-meta-session"]).toBe(s.sessionId);
			if (index === 0) await upload(s, "presigned");
			expect(await env.PUBLIC_BUCKET.head(canonical)).toBeNull();
		}
	});

	it.each(["direct", "presigned", "multipart"])("publishes simultaneous new %s sessions without canonical upload collisions", async method => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const [first, second] = [await freshCache(), await freshCache()];
		const a = await pamSession(first, 0);
		const b = await pamSession(second, 1);
		for (const s of [a, b]) {
			expect(s.r2Key).toBe(`staging/${s.sessionId}`);
			await upload(s, method);
		}
		expect(await env.PUBLIC_BUCKET.head(canonical)).toBeNull();
		if (method === "multipart") {
			expect((await post(`/_api/v1/uploads/${b.sessionId}/complete`, {})).status).toBe(200);
			expect((await post(`/_api/v1/uploads/${a.sessionId}/complete`, {})).status).toBe(200);
		}
		expect(await commit(b.sessionId)).toMatchObject({ published: true });
		const installed = await env.PUBLIC_BUCKET.head(canonical);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		for (const [s, cache, index] of [[a, first, 0], [b, second, 1]] as const) {
			const source = await env.CACHE_BUCKET.head(s.r2Key);
			expect(source?.customMetadata).toEqual({ session: s.sessionId });
			const receipt = await findUploadSession(db, s.sessionId);
			expect((await put(`/_api/v1/uploads/${s.sessionId}/blob`, bytes)).status).toBe(409);
			expect((await post(`/_api/v1/uploads/${s.sessionId}/multipart`, {})).status).toBe(409);
			expect(await commit(s.sessionId)).toMatchObject({ published: true });
			expect(await findUploadSession(db, s.sessionId)).toEqual(receipt);
			expect((await env.CACHE_BUCKET.head(s.r2Key))?.version).toBe(source?.version);
			expect(await narinfoStatus(cache, paths[index].slice(0, 32))).toBe(200);
		}
		expect((await env.PUBLIC_BUCKET.head(canonical))?.version).toBe(installed?.version);
		expect(await storedBytes(fileHash)).toEqual(bytes);
	});

	it.each([
		["direct", false], ["direct", true], ["presigned", false], ["presigned", true],
	] as const)("recovers pre-upgrade canonical %s collisions with the same reservation (bad parts %s)", async (method, badParts) => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const cache = await freshCache();
		const a = await legacyPamSession(cache, 0);
		const b = await legacyPamSession(cache, 1);
		expect(a.r2Key).toBe(canonical);
		expect(b.r2Key).toBe(canonical);
		const before = await findUploadSession(db, b.sessionId);
		await upload(a, "direct");
		const winner = await env.PUBLIC_BUCKET.head(canonical);
		if (method === "direct") {
			expect((await put(`/_api/v1/uploads/${b.sessionId}/blob`, bytes)).status).toBe(412);
		} else {
			// Exercise R2's conditional object state without simulating S3 signing.
			expect(await env.PUBLIC_BUCKET.put(canonical, bytes, {
				sha256: fileHash, customMetadata: { session: b.sessionId }, onlyIf: { etagDoesNotMatch: "*" },
			})).toBeNull();
			expect((await findUploadSession(db, b.sessionId))?.status).toBe("pending");
		}
		expect(await commit(b.sessionId)).toMatchObject({ error: "Upload incomplete", status: 400 });
		const start = await post(`/_api/v1/uploads/${b.sessionId}/multipart`, {});
		expect(start.status).toBe(200);
		const instructions = await start.json<{ uploadId: string; r2Key: string }>();
		expect(instructions.r2Key).toBe(`staging/${b.sessionId}`);
		expect(await (await post(`/_api/v1/uploads/${b.sessionId}/multipart`, {})).json()).toEqual(instructions);
		const after = await findUploadSession(db, b.sessionId);
		expect(after).toMatchObject({ id: before?.id, fileSize: before?.fileSize, expiresAt: before?.expiresAt, status: "uploading" });
		expect((await put(`/_api/v1/uploads/${b.sessionId}/blob`, bytes)).status).toBe(409);
		expect((await put(`/_api/v1/uploads/${b.sessionId}/part/1`, badParts ? new Uint8Array(bytes.length) : bytes)).status).toBe(200);
		const complete = await post(`/_api/v1/uploads/${b.sessionId}/complete`, {});
		expect(complete.status).toBe(badParts ? 400 : 200);
		if (!badParts) {
			expect(await commit(b.sessionId)).toMatchObject({ published: true });
			expect(await commit(b.sessionId)).toMatchObject({ published: true });
		}
		expect((await env.PUBLIC_BUCKET.head(canonical))?.version).toBe(winner?.version);
		expect(await storedBytes(fileHash)).toEqual(bytes);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
	});

	it("recognizes its own canonical upload after a lost response without overwriting it", async () => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const a = await legacyPamSession(await freshCache(), 0);
		await upload(a, "direct");
		const winner = await env.PUBLIC_BUCKET.head(canonical);
		expect((await put(`/_api/v1/uploads/${a.sessionId}/blob`, bytes)).status).toBe(412);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		expect((await env.PUBLIC_BUCKET.head(canonical))?.version).toBe(winner?.version);
	});

	it.each([
		["complete", "direct"], ["commit", "direct"], ["complete", "presigned"], ["commit", "presigned"],
	])("fences a stale %s after %s multipart retarget", async (endpoint, method) => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const a = await legacyPamSession(await freshCache(), 0);
		await upload(a, method);
		let retargeted = false;
		const bucket = new Proxy(env.PUBLIC_BUCKET, {
			get(target, property) {
				if (property === "head") return async (key: string) => {
					const observed = await target.head(key);
					if (key === canonical && !retargeted) {
						retargeted = true;
						expect((await post(`/_api/v1/uploads/${a.sessionId}/multipart`, {})).status).toBe(200);
					}
					return observed;
				};
				const value = Reflect.get(target, property, target);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
		const ctx = createExecutionContext();
		const request = new Request(`http://example.com/_api/v1/uploads/${endpoint === "commit" ? "commit" : `${a.sessionId}/complete`}`, {
			method: "POST", headers: { ...AUTH, "content-type": "application/json" },
			body: JSON.stringify(endpoint === "commit" ? { sessionIds: [a.sessionId] } : {}),
		});
		const response = await nix.fetch(request as Parameters<typeof nix.fetch>[0], { ...env, PUBLIC_BUCKET: bucket }, ctx);
		await waitOnExecutionContext(ctx);
		expect(retargeted).toBe(true);
		if (endpoint === "commit") {
			expect(await response.json()).toMatchObject({ results: [{ status: 409 }] });
		} else {
			expect(response.status).toBe(409);
		}
		expect(await findUploadSession(db, a.sessionId)).toMatchObject({ status: "uploading", r2UploadKey: `staging/${a.sessionId}` });
		expect(await commit(a.sessionId)).toMatchObject({ status: 409 });
		// The stale verification must not complete the empty multipart session.
		expect((await put(`/_api/v1/uploads/${a.sessionId}/part/1`, bytes)).status).toBe(200);
		expect((await post(`/_api/v1/uploads/${a.sessionId}/complete`, {})).status).toBe(200);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
	});

	it("aborts the losing multipart allocation and returns the active instructions", async () => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const a = await pamSession(await freshCache(), 0);
		let active: unknown;
		let aborted = false;
		const bucket = new Proxy(env.CACHE_BUCKET, {
			get(target, property) {
				if (property === "createMultipartUpload") return async (key: string, options?: R2MultipartOptions) => {
					const orphan = await target.createMultipartUpload(key, options);
					const winner = await post(`/_api/v1/uploads/${a.sessionId}/multipart`, {});
					expect(winner.status).toBe(200);
					active = await winner.json();
					return new Proxy(orphan, {
						get(upload, property) {
							if (property === "abort") return async () => { aborted = true; await upload.abort(); };
							const value = Reflect.get(upload, property, upload);
							return typeof value === "function" ? value.bind(upload) : value;
						},
					});
				};
				const value = Reflect.get(target, property, target);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
		const ctx = createExecutionContext();
		const request = new Request(`http://example.com/_api/v1/uploads/${a.sessionId}/multipart`, {
			method: "POST", headers: { ...AUTH, "content-type": "application/json" }, body: "{}",
		});
		const response = await nix.fetch(request as Parameters<typeof nix.fetch>[0], { ...env, CACHE_BUCKET: bucket }, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual(active);
		expect(aborted).toBe(true);
		expect((await put(`/_api/v1/uploads/${a.sessionId}/part/1`, bytes)).status).toBe(200);
		expect((await post(`/_api/v1/uploads/${a.sessionId}/complete`, {})).status).toBe(200);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
	});

	it.each([
		["direct", "direct"], ["direct", "presigned"], ["direct", "multipart"],
		["presigned", "direct"], ["presigned", "presigned"], ["presigned", "multipart"],
	])("keeps canonical %s proof when staged %s completes first", async (firstMethod, secondMethod) => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const [first, second] = [await freshCache(), await freshCache()];
		const a = await legacyPamSession(first, 0);
		expect(a.r2Key).toBe(canonical);
		await upload(a, firstMethod);
		const before = await env.PUBLIC_BUCKET.head(canonical);
		expect(before?.customMetadata).toEqual({ session: a.sessionId });

		const b = await pamSession(second, 1);
		expect(b.r2Key).toMatch(/^staging\//);
		await upload(b, secondMethod);
		// Exercise both completion contracts, without publishing A early.
		if (secondMethod === "multipart") {
			expect((await post(`/_api/v1/uploads/${b.sessionId}/complete`, {})).status).toBe(200);
			expect((await post(`/_api/v1/uploads/${b.sessionId}/publish`, {})).status).toBe(200);
		} else {
			expect(await commit(b.sessionId)).toMatchObject({ published: true });
		}
		const after = await env.PUBLIC_BUCKET.head(canonical);
		expect(after?.version).toBe(before?.version);
		expect(after?.customMetadata).toEqual({ session: a.sessionId });
		expect((await env.CACHE_BUCKET.head(b.r2Key))?.customMetadata).toEqual({ session: b.sessionId });
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		expect(await commit(b.sessionId)).toMatchObject({ published: true });
		for (const [cache, index] of [[first, 0], [second, 1]] as const) {
			expect(await narinfoStatus(cache, paths[index].slice(0, 32))).toBe(200);
		}
		expect(await storedBytes(fileHash)).toEqual(bytes);
	});

	it.each([false, true])("doesn't clobber a canonical PUT arriving during promotion (bad parts: %s)", async badParts => {
		await env.PUBLIC_BUCKET.delete(canonical);
		const [first, second] = [await freshCache(), await freshCache()];
		const a = await legacyPamSession(first, 0);
		const b = await pamSession(second, 1);
		// A predates the upgrade; new B never receives a canonical write URL.
		expect((await post(`/_api/v1/uploads/${b.sessionId}/multipart`, {})).status).toBe(200);
		const body = badParts ? new Uint8Array(bytes.length).fill(1) : bytes;
		const uploaded = await put(`/_api/v1/uploads/${b.sessionId}/part/1`, body);
		expect(uploaded.status).toBe(200);
		const part = await uploaded.json<{ partNumber: number; etag: string }>();
		let interleaved = false;
		const bucket = new Proxy(env.PUBLIC_BUCKET, {
			get(target, property) {
				if (property === "head") return async (key: string) => {
					const observed = await target.head(key);
					if (key === canonical && !interleaved) {
						expect(observed).toBeNull();
						interleaved = true;
						await upload(a, "direct");
					}
					return observed;
				};
				const value = Reflect.get(target, property, target);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
		const ctx = createExecutionContext();
		// Real public Worker routing/auth/DB/R2; only delay the HEAD result so
		// another real API request installs A before B's conditional PUT.
		const request = new Request("http://example.com/_api/v1/uploads/commit", {
			method: "POST", headers: { ...AUTH, "content-type": "application/json" },
			body: JSON.stringify({ sessionIds: [b.sessionId], parts: { [b.sessionId]: [part] } }),
		});
		// Test-created requests have no incoming Cloudflare metadata.
		const response = await nix.fetch(request as Parameters<typeof nix.fetch>[0], { ...env, PUBLIC_BUCKET: bucket }, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ results: [badParts
			? { error: "File hash mismatch", status: 400 }
			: { published: true }] });
		// Invalid staging is rejected before even inspecting the destination.
		expect(interleaved).toBe(!badParts);
		if (badParts) {
			expect(await env.PUBLIC_BUCKET.head(canonical)).toBeNull();
			expect(await env.CACHE_BUCKET.head(b.r2Key)).not.toBeNull();
			await upload(a, "direct");
		}
		expect((await env.PUBLIC_BUCKET.head(canonical))?.customMetadata).toEqual({ session: a.sessionId });
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		expect(await storedBytes(fileHash)).toEqual(bytes);
	});

	it("keeps private cross-org proof and refuses another org's session", async () => {
		const key = narKey(fileHash, "zstd", true);
		await env.CACHE_BUCKET.delete(key);
		await env.PUBLIC_BUCKET.delete(canonical);
		async function request(path: string, method: string, body: unknown, token: string) {
			return SELF.fetch(`http://example.com/_api/v1${path}`, {
				method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
				body: JSON.stringify(body),
			});
		}
		async function client() {
			const org = `possession-${crypto.randomUUID().slice(0, 8)}`;
			expect((await request(`/orgs/${org}`, "PUT", { slug: org }, "test-admin-secret")).status).toBe(200);
			expect((await request(`/orgs/${org}/caches`, "POST", { name: "team", private: true, protocols: ["nix"] }, "test-admin-secret")).status).toBe(201);
			const response = await request(`/orgs/${org}/tokens`, "POST", { subject: "possession", caches: ["team"], perms: ["push", "pull"] }, "test-admin-secret");
			expect(response.status).toBe(201);
			const { token } = await response.json<{ token: string }>();
			const create = async (index: number) => {
				const response = await request("/caches/team/upload-sessions", "POST", {
					storePath: `/nix/store/${paths[index]}`, storePathHash: paths[index].slice(0, 32),
					narHash: "sha256-0CszDDh/wN3/LZKd90rIIRYLmGc0kOKYCTxZcQcq0Fk=", narSize: 1152,
					fileHash, fileSize: bytes.length, compression: "zstd",
				}, token);
				expect(response.status).toBe(201);
				return response.json<{ sessionId: string; r2Key: string }>();
			};
			return { token, create };
		}
		const [first, second] = [await client(), await client()];
		const a = await first.create(0);
		expect((await SELF.fetch(`http://example.com/_api/v1/uploads/${a.sessionId}/blob`, {
			method: "PUT", headers: { authorization: `Bearer ${first.token}` }, body: bytes,
		})).status).toBe(200);
		const b = await second.create(1);
		expect(b.r2Key).toMatch(/^staging\//);
		expect((await SELF.fetch(`http://example.com/_api/v1/uploads/${b.sessionId}/blob`, {
			method: "PUT", headers: { authorization: `Bearer ${second.token}` }, body: bytes,
		})).status).toBe(200);
		for (const endpoint of ["complete", "publish", "multipart"]) {
			expect((await request(`/uploads/${a.sessionId}/${endpoint}`, "POST", {}, second.token)).status).toBe(403);
		}
		const refused = await request("/uploads/commit", "POST", { sessionIds: [a.sessionId] }, second.token);
		expect(await refused.json()).toMatchObject({ results: [{ error: "Forbidden", status: 403 }] });
		for (const [s, owner] of [[b, second], [a, first]] as const) {
			const response = await request("/uploads/commit", "POST", { sessionIds: [s.sessionId] }, owner.token);
			expect(await response.json()).toMatchObject({ results: [{ published: true }] });
		}
		expect(await env.CACHE_BUCKET.head(key)).not.toBeNull();
		for (const s of [a, b]) {
			expect((await env.CACHE_BUCKET.head(s.r2Key))?.customMetadata).toEqual({ session: s.sessionId });
		}
		expect(await env.PUBLIC_BUCKET.head(canonical)).toBeNull();
	});

	it.each(["size", "hash"])("refuses staged %s tampering without replacing another session's object", async mismatch => {
		const { bytes, fileHash } = await nar();
		const [first, second] = [await freshCache(), await freshCache()];
		const a = await session(first, fileHash);
		expect((await put(`/_api/v1/uploads/${a.sessionId}/blob`, bytes)).status).toBe(200);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		const canonical = narKey(fileHash, "zstd", false);
		const before = await env.PUBLIC_BUCKET.head(canonical);
		const b = await session(second, fileHash);
		// Fault injection bypasses PUT's checksum to exercise completion itself.
		await env.CACHE_BUCKET.put(b.r2Key, mismatch === "size" ? bytes.slice(1) : new Uint8Array(SIZE), { customMetadata: { session: b.sessionId } });
		expect(await commit(b.sessionId)).toMatchObject({ status: 400, error: mismatch === "size" ? "File size mismatch" : "File hash mismatch" });
		expect(await env.CACHE_BUCKET.head(b.r2Key)).not.toBeNull();
		expect((await env.PUBLIC_BUCKET.head(canonical))?.version).toBe(before?.version);
		expect(await commit(a.sessionId)).toMatchObject({ published: true });
		expect(await narinfoStatus(second, b.hash)).toBe(404);
	});
});
