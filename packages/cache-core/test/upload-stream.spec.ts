import { abortAllDurableObjects, createExecutionContext, env, runInDurableObject, SELF, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { testDb } from "./db.js";
import { uploadSessions } from "../src/db/schema.js";
import { createCache, ensureCache, findUploadParts, findUploadSession, orgUsage, putOrg } from "../src/db/repository.js";
import { signJwt, TOKEN_ISSUER, TOKEN_AUDIENCE } from "../src/jwt.js";
import nix from "../../../workers/nix/src/index.js";

const db = testDb();
const AUTH = "test-auth-token";
const narHash = `sha256:${"1".repeat(52)}`;
const narSize = 512;

function post(path: string, body: unknown, token = AUTH): Promise<Response> {
	return SELF.fetch(`http://example.com${path}`, {
		method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body),
	});
}

async function stream(cache: string, token = AUTH) {
	const hash = crypto.randomUUID().replaceAll("-", "").replace(/[eotu]/g, "a");
	const response = await post(`/_api/v1/caches/${cache}/upload-streams/batch`, {
		paths: [{ storePath: `/nix/store/${hash}-stream`, storePathHash: hash, narHash, narSize, compression: "zstd", references: [] }],
	}, token);
	expect(response.status).toBe(201);
	const { sessions } = await response.json<{ sessions: { sessionId: string; partSize: number }[] }>();
	return { ...sessions[0], hash };
}

async function upload(sessionId: string, bytes: Uint8Array, token = AUTH) {
	const response = await post(`/_api/v1/uploads/${sessionId}/parts`, { parts: [{ partNumber: 1, size: bytes.length }] }, token);
	expect(response.status).toBe(200);
	const { parts } = await response.json<{ parts: { partNumber: number; url: string; headers: Record<string, string> }[] }>();
	const part = parts[0];
	const sent = await SELF.fetch(part.url, { method: "PUT", headers: part.headers, body: bytes.slice() });
	expect(sent.status).toBe(200);
	const etag = sent.headers.get("etag");
	expect(etag).toBeTruthy();
	return { partNumber: 1, etag: etag!.replaceAll('"', "") };
}

async function digest(bytes: Uint8Array) {
	return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(n => n.toString(16).padStart(2, "0")).join("");
}

describe("streaming upload contract", () => {
	it("rejects full staging without SQL orphans and admits a retry after an existing upload aborts", async () => {
		const org = `stream-full-${crypto.randomUUID().slice(0, 8)}`;
		await putOrg(db, org, org, {});
		const { cache } = await ensureCache(db, "main", true, org);
		const token = await signJwt({ jti: crypto.randomUUID(), sub: "full-staging", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE,
			caches: ["*"], perms: ["push"], org, iat: Math.floor(Date.now() / 1000) }, env.JWT_SECRET);
		const existing = await stream(cache.name, token);
		const coordinator = env.UPLOAD_COORDINATOR.getByName(org);
		// Fill the real SQLite admission table without creating 8,191 R2 MPUs.
		await runInDurableObject(coordinator, async (_instance, state) => {
			state.storage.sql.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 8191)
				INSERT INTO streams_v2 (id, payload, status, expires)
				SELECT 'fixture-' || n.i, s.payload, 'streaming', s.expires FROM n CROSS JOIN streams_v2 s LIMIT 8191`);
		});
		const path = { storePath: `/nix/store/${"2".repeat(32)}-retry`, storePathHash: "2".repeat(32), narHash, narSize, compression: "zstd" };
		const create = () => post(`/_api/v1/caches/${cache.name}/upload-streams/batch`, { paths: [path] }, token);
		await abortAllDurableObjects();
		for (let retry = 0; retry < 2; retry++) {
			const rejected = await create();
			expect(rejected.status).toBe(429);
			expect(await db.select({ id: uploadSessions.id }).from(uploadSessions).where(eq(uploadSessions.cacheId, cache.id)))
				.toEqual([{ id: existing.sessionId }]);
		}
		expect((await post(`/_api/v1/uploads/${existing.sessionId}/abort`, {}, token)).status).toBe(200);
		const admitted = await create();
		expect(admitted.status).toBe(201);
		const { sessions } = await admitted.json<{ sessions: { sessionId: string }[] }>();
		expect((await findUploadSession(db, sessions[0].sessionId))?.status).toBe("streaming");
	});

	it("publishes verified bytes, replays finalization, and refuses mutations or legacy bypasses", async () => {
		const cache = await createCache(db, `stream-${crypto.randomUUID().slice(0, 8)}`);
		const s = await stream(cache.name);
		expect(s.partSize).toBe(8 * 1024 ** 2);
		const bytes = new Uint8Array([31, 7, 219, 84, 2]);
		const receipt = await upload(s.sessionId, bytes);
		for (const endpoint of ["multipart", "complete", "publish"]) {
			expect((await post(`/_api/v1/uploads/${s.sessionId}/${endpoint}`, {})).status).toBe(404);
		}
		const changed = await post(`/_api/v1/uploads/${s.sessionId}/parts`, { parts: [{ partNumber: 1, size: bytes.length + 1 }] });
		expect(changed.status).toBe(409);
		const item = { sessionId: s.sessionId, narHash, narSize, fileHash: await digest(bytes), fileSize: bytes.length, parts: [receipt] };
		const finalize = (input = item) => post("/_api/v1/uploads/finalize", { uploads: [input] });
		const invalid = await finalize({ ...item, fileSize: bytes.length + 1 });
		expect(await invalid.json()).toMatchObject({ results: [{ status: 400 }] });
		for (let i = 0; i < 2; i++) expect(await (await finalize()).json()).toMatchObject({ results: [{ published: true }] });
		expect((await findUploadSession(db, s.sessionId))?.status).toBe("completed");
		expect(await (await finalize({ ...item, fileHash: "a".repeat(64) })).json()).toMatchObject({ results: [{ status: 409 }] });
		const info = await SELF.fetch(`http://example.com/${cache.name}/${s.hash}.narinfo`);
		expect(info.status).toBe(200);
		const stored = await env.PUBLIC_BUCKET.get(`nar/${item.fileHash}/zstd.nar`);
		expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(bytes);
	});

	it("requires this session's bytes even when another cache already stores the hash", async () => {
		const cache = await createCache(db, `stream-proof-${crypto.randomUUID().slice(0, 8)}`);
		const bytes = new Uint8Array([77, 19, 4]);
		const fileHash = await digest(bytes);
		await env.PUBLIC_BUCKET.put(`nar/${fileHash}/zstd.nar`, bytes, { sha256: fileHash });
		const s = await stream(cache.name);
		const receipt = await upload(s.sessionId, new Uint8Array([77, 19, 5]));
		const response = await post("/_api/v1/uploads/finalize", { uploads: [{ sessionId: s.sessionId, narHash, narSize, fileHash, fileSize: bytes.length, parts: [receipt] }] });
		expect(await response.json()).toMatchObject({ results: [{ published: false, status: 400 }] });
		expect((await SELF.fetch(`http://example.com/${cache.name}/${s.hash}.narinfo`)).status).toBe(404);
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(`nar/${fileHash}/zstd.nar`))!.arrayBuffer())).toEqual(bytes);
	});

	it("keeps batch results ordered and rejects gaps or short non-final parts before sealing", async () => {
		const cache = await createCache(db, `stream-parts-${crypto.randomUUID().slice(0, 8)}`);
		const good = await stream(cache.name);
		const bad = await stream(cache.name);
		const bytes = new Uint8Array([63, 8, 197]);
		const receipt = await upload(good.sessionId, bytes);
		const metadata = { narHash, narSize, fileHash: await digest(bytes), fileSize: bytes.length };
		const reserve = (parts: { partNumber: number; size: number }[]) => post(`/_api/v1/uploads/${bad.sessionId}/parts`, { parts });
		expect((await reserve([{ partNumber: 2, size: 1 }])).status).toBe(200);
		const badItem = { ...metadata, sessionId: bad.sessionId, fileSize: 1, parts: [{ partNumber: 2, etag: "not-uploaded" }] };
		const response = await post("/_api/v1/uploads/finalize", { uploads: [badItem, { ...metadata, sessionId: good.sessionId, parts: [receipt] }] });
		expect(await response.json()).toMatchObject({ results: [{ sessionId: bad.sessionId, status: 400 }, { sessionId: good.sessionId, published: true }] });
		expect((await findUploadSession(db, bad.sessionId))?.status).toBe("streaming");
		expect((await reserve([{ partNumber: 1, size: 2 }])).status).toBe(200);
		const short = await post("/_api/v1/uploads/finalize", { uploads: [{ ...badItem, fileSize: 3, parts: [{ partNumber: 1, etag: "short" }, ...badItem.parts] }] });
		expect(await short.json()).toMatchObject({ results: [{ status: 400 }] });
		expect((await findUploadSession(db, bad.sessionId))?.status).toBe("streaming");
		expect((await post(`/_api/v1/uploads/${bad.sessionId}/abort`, {})).status).toBe(200);
	});

	it("isolates invalid metadata, receipts, and unauthorized sessions in an ordered finalize batch", async () => {
		const cache = await createCache(db, `stream-mixed-${crypto.randomUUID().slice(0, 8)}`);
		const other = await createCache(db, `stream-denied-${crypto.randomUUID().slice(0, 8)}`);
		const now = Math.floor(Date.now() / 1000);
		const token = await signJwt({ jti: crypto.randomUUID(), sub: "mixed-test", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, caches: [cache.name], perms: ["push", "pull"], org: "default", iat: now, exp: now + 600 }, env.JWT_SECRET);
		const before = await orgUsage(db, "default", new Date());
		const sessions = [];
		for (let i = 0; i < 5; i++) {
			const s = await stream(i === 2 ? other.name : cache.name);
			const bytes = new Uint8Array([193, 65, 12, i, 230]);
			const receipt = await upload(s.sessionId, bytes);
			sessions.push({ ...s, bytes, item: { sessionId: s.sessionId, narHash, narSize, fileHash: await digest(bytes), fileSize: bytes.length, parts: [receipt] } });
		}
		const unauthorizedBefore = await findUploadSession(db, sessions[2].sessionId);
		const receiptsBefore = await findUploadParts(db, sessions[2].sessionId);
		const uploads = sessions.map(s => s.item);
		uploads[0] = { ...uploads[0], narSize: narSize + 1 };
		uploads[3] = { ...uploads[3], parts: [{ ...uploads[3].parts[0], partNumber: 2 }] };
		// The forbidden item is otherwise valid: authorization must precede sealing.
		for (let replay = 0; replay < 2; replay++) {
			const response = await post("/_api/v1/uploads/finalize", { uploads }, token);
			expect(response.status).toBe(200);
			expect(await response.json()).toMatchObject({ results: [
				{ sessionId: sessions[0].sessionId, published: false, status: 400 },
				{ sessionId: sessions[1].sessionId, published: true },
				{ sessionId: sessions[2].sessionId, published: false, status: 403 },
				{ sessionId: sessions[3].sessionId, published: false, status: 400 },
				{ sessionId: sessions[4].sessionId, published: true },
			] });
			expect(await findUploadSession(db, sessions[2].sessionId)).toEqual(unauthorizedBefore);
			expect(await findUploadParts(db, sessions[2].sessionId)).toEqual(receiptsBefore);
			for (const [i, s] of sessions.entries()) {
				const published = i === 1 || i === 4;
				const info = await SELF.fetch(`http://example.com/${i === 2 ? other.name : cache.name}/${s.hash}.narinfo`);
				expect(info.status).toBe(published ? 200 : 404);
				expect((await findUploadSession(db, s.sessionId))?.status).toBe(published ? "completed" : "streaming");
				const object = await env.PUBLIC_BUCKET.get(`nar/${s.item.fileHash}/zstd.nar`);
				if (published) {
					expect(await info.text()).toContain(`StorePath: /nix/store/${s.hash}-stream`);
					expect(object).not.toBeNull();
					expect(new Uint8Array(await object!.arrayBuffer())).toEqual(s.bytes);
				} else {
					expect(object).toBeNull();
				}
			}
			expect(await orgUsage(db, "default", new Date())).toEqual({ used: before.used + 10, pending: before.pending });
		}
		// Corrected metadata and receipts, and the authorized owner, can still finish.
		const repaired = await post("/_api/v1/uploads/finalize", { uploads: [sessions[3].item, sessions[2].item, sessions[0].item] });
		expect(await repaired.json()).toMatchObject({ results: [3, 2, 0].map(i => ({ sessionId: sessions[i].sessionId, published: true })) });
		expect(await orgUsage(db, "default", new Date())).toEqual({ used: before.used + 25, pending: before.pending });
	});

	it("publishes eight sessions sharing compressed bytes in one batch and replays without charging twice", async () => {
		const cache = await createCache(db, `stream-shared-${crypto.randomUUID().slice(0, 8)}`);
		const before = await orgUsage(db, "default", new Date());
		const bytes = new Uint8Array([201, 29, 78, 106, 3, 44, 229]);
		const fileHash = await digest(bytes);
		const sessions = [];
		for (let i = 0; i < 8; i++) {
			const s = await stream(cache.name);
			const receipt = await upload(s.sessionId, bytes);
			sessions.push({ ...s, item: { sessionId: s.sessionId, narHash, narSize, fileHash, fileSize: bytes.length, parts: [receipt] } });
		}
		// Part metadata stays local until seal, rather than synchronously dual-writing.
		expect(await orgUsage(db, "default", new Date())).toEqual(before);
		const ordered = [...sessions].reverse();
		for (let replay = 0; replay < 2; replay++) {
			const response = await post("/_api/v1/uploads/finalize", { uploads: ordered.map(s => s.item) });
			expect(response.status).toBe(200);
			expect(await response.json()).toMatchObject({ results: ordered.map(s => ({ sessionId: s.sessionId, published: true })) });
			for (const s of sessions) {
				expect((await findUploadSession(db, s.sessionId))?.status).toBe("completed");
				const info = await SELF.fetch(`http://example.com/${cache.name}/${s.hash}.narinfo`);
				expect(info.status).toBe(200);
				expect(await info.text()).toContain(`StorePath: /nix/store/${s.hash}-stream`);
			}
			const stored = await env.PUBLIC_BUCKET.get(`nar/${fileHash}/zstd.nar`);
			expect(stored).not.toBeNull();
			expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(bytes);
			expect(await orgUsage(db, "default", new Date())).toEqual({ used: before.used + 8 * bytes.length, pending: before.pending });
		}
	});

	it("isolates denied, terminal, and invalid reservations and preserves exact grants on retries", async () => {
		const cache = await createCache(db, `reserve-${crypto.randomUUID().slice(0, 8)}`);
		const other = await createCache(db, `reserve-denied-${crypto.randomUUID().slice(0, 8)}`);
		const now = Math.floor(Date.now() / 1000);
		const token = await signJwt({ jti: crypto.randomUUID(), sub: "reserve-test", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, caches: [cache.name], perms: ["push"], org: "default", iat: now, exp: now + 600 }, env.JWT_SECRET);
		const sessions = [];
		for (let i = 0; i < 7; i++) sessions.push(await stream(i === 2 ? other.name : cache.name));
		expect((await post(`/_api/v1/uploads/${sessions[3].sessionId}/abort`, {})).status).toBe(200);
		const before = await orgUsage(db, "default", new Date());
		const deniedBefore = await findUploadSession(db, sessions[2].sessionId);
		const uploads = sessions.map((s, i) => ({ sessionId: s.sessionId, parts: [{ partNumber: 1, size: i === 0 ? s.partSize + 1 : i + 1 }] }));
		uploads[4].parts = [{ partNumber: 1, size: 1 }, { partNumber: 1, size: 1 }];
		uploads[5].parts = [{ partNumber: 0, size: 1 }];
		const expected = [400, 200, 403, 409, 400, 400, 200];
		for (let retry = 0; retry < 2; retry++) {
			const response = await post("/_api/v1/uploads/parts", { uploads }, token);
			expect(response.status).toBe(200);
			const { results } = await response.json<{ results: { sessionId: string; status?: number; error?: string; parts?: { partNumber: number; url: string; headers: Record<string, string> }[] }[] }>();
			expect(results.map(r => r.sessionId)).toEqual(uploads.map(u => u.sessionId));
			expect(results.map(r => r.status ?? 200)).toEqual(expected);
			for (const [i, result] of results.entries()) {
				if (expected[i] !== 200) {
					expect(result.parts).toBeUndefined();
					expect(await findUploadParts(db, result.sessionId)).toEqual([]);
					expect((await findUploadSession(db, result.sessionId))?.fileSize).toBe(0);
				} else {
					expect(result.parts).toEqual([{ partNumber: 1, url: `http://example.com/_api/v1/uploads/${result.sessionId}/part/1`, headers: { "content-length": String(i + 1), authorization: `Bearer ${token}` } }]);
					expect(await findUploadParts(db, result.sessionId)).toEqual([]);
					expect((await findUploadSession(db, result.sessionId))?.fileSize).toBe(0);
				}
			}
			expect(await findUploadSession(db, sessions[2].sessionId)).toEqual(deniedBefore);
			expect(await orgUsage(db, "default", new Date())).toEqual(before);
		}
		// A changed retry rejects the whole item's new bytes, not its neighbors.
		const changed = await post("/_api/v1/uploads/parts", { uploads: [
			{ sessionId: sessions[1].sessionId, parts: [{ partNumber: 1, size: 3 }, { partNumber: 2, size: 10 }] },
			{ sessionId: sessions[6].sessionId, parts: [{ partNumber: 1, size: 7 }, { partNumber: 2, size: 3 }] },
		] }, token);
		expect(await changed.json()).toMatchObject({ results: [{ status: 409 }, { parts: [{ partNumber: 1, headers: { "content-length": "7" } }, { partNumber: 2, headers: { "content-length": "3" } }] }] });
		// The rejected item's second part was not reserved with the wrong size.
		expect((await post(`/_api/v1/uploads/${sessions[1].sessionId}/parts`, { parts: [{ partNumber: 2, size: 11 }] }, token)).status).toBe(200);
		expect(await orgUsage(db, "default", new Date())).toEqual(before);
		const scalar = await post(`/_api/v1/uploads/${sessions[6].sessionId}/parts`, { parts: [{ partNumber: 2, size: 3 }] }, token);
		expect(scalar.status).toBe(200);
		expect(await scalar.json()).toMatchObject({ parts: [{ partNumber: 2, headers: { "content-length": "3" } }] });
		for (const parts of [[], Array.from({ length: 101 }, (_, i) => ({ partNumber: i + 1, size: 1 })), [{ partNumber: 10_001, size: 1 }]]) {
			const response = await post("/_api/v1/uploads/parts", { uploads: [{ sessionId: sessions[0].sessionId, parts }, uploads[1]] }, token);
			expect(await response.json()).toMatchObject({ results: [{ status: 400 }, { parts: [{ partNumber: 1, headers: { "content-length": "2" } }] }] });
			expect(await findUploadParts(db, sessions[0].sessionId)).toEqual([]);
		}
		for (const invalid of [[], [uploads[1], uploads[1]], Array.from({ length: 101 }, () => ({ sessionId: crypto.randomUUID(), parts: [{ partNumber: 1, size: 1 }] }))]) {
			expect((await post("/_api/v1/uploads/parts", { uploads: invalid }, token)).status).toBe(400);
		}
	});

	it("stages competing batches beyond retained capacity and refuses an individually oversized object", async () => {
		const org = `batch-quota-${crypto.randomUUID().slice(0, 8)}`;
		const admin = (path: string, method: string, body: unknown) => SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, {
			method, headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" }, body: JSON.stringify(body),
		});
		expect((await admin("", "PUT", { slug: org, storageLimit: 10 })).status).toBe(200);
		expect((await admin("/caches", "POST", { name: "batch", protocols: ["nix"] })).status).toBe(201);
		const now = Math.floor(Date.now() / 1000);
		const token = await signJwt({ jti: crypto.randomUUID(), sub: "batch-quota", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, caches: ["*"], perms: ["push"], org, iat: now, exp: now + 600 }, env.JWT_SECRET);
		const batches = [];
		for (const sizes of [[8, 7, 2], [6, 5, 4]]) {
			const uploads = [];
			for (const size of sizes) uploads.push({ sessionId: (await stream("batch", token)).sessionId, parts: [{ partNumber: 1, size }] });
			batches.push(uploads);
		}
		const responses = await Promise.all(batches.map(uploads => post("/_api/v1/uploads/parts", { uploads }, token)));
		const bodies = await Promise.all(responses.map(r => r.json<{ results: { sessionId: string; status?: number; parts?: { partNumber: number; headers: Record<string, string> }[] }[] }>()));
		for (const [index, body] of bodies.entries()) {
			expect(body.results.map(r => r.sessionId)).toEqual(batches[index].map(u => u.sessionId));
			expect(body.results.map(r => r.status ?? 200)).toEqual([200, 200, 200]);
			for (const [i, result] of body.results.entries()) {
				const size = batches[index][i].parts[0].size;
				expect(result.parts).toMatchObject([{ partNumber: 1, headers: { "content-length": String(size) } }]);
			}
		}
		const extra = await stream("batch", token);
		expect((await post(`/_api/v1/uploads/${extra.sessionId}/parts`, { parts: [{ partNumber: 1, size: 11 }] }, token)).status).toBe(413);
		const replay = await post("/_api/v1/uploads/parts", { uploads: batches[0] }, token);
		expect(await replay.json()).toMatchObject({ results: batches[0].map(() => ({ parts: [{ partNumber: 1 }] })) });
		expect(await orgUsage(db, org, new Date())).toEqual({ used: 0, pending: 0 });
	});

	it("isolates orgs and preserves aborts across competing staged streams", async () => {
		const org = `stream-org-${crypto.randomUUID().slice(0, 8)}`;
		const admin = (path: string, method: string, body: unknown) => SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, {
			method, headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" }, body: JSON.stringify(body),
		});
		expect((await admin("", "PUT", { slug: org, storageLimit: 10 })).status).toBe(200);
		expect((await admin("/caches", "POST", { name: "stream", private: true, protocols: ["nix"] })).status).toBe(201);
		const now = Math.floor(Date.now() / 1000);
		const token = await signJwt({ jti: crypto.randomUUID(), sub: "stream-test", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, caches: ["*"], perms: ["push", "pull"], org, iat: now, exp: now + 600 }, env.JWT_SECRET);
		const outsider = await signJwt({ jti: crypto.randomUUID(), sub: "other-org", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, caches: ["*"], perms: ["push"], org: "default", iat: now, exp: now + 600 }, env.JWT_SECRET);
		const a = await stream("stream", token);
		const b = await stream("stream", token);
		const reserve = (id: string, t = token) => post(`/_api/v1/uploads/${id}/parts`, { parts: [{ partNumber: 1, size: 6 }] }, t);
		expect((await reserve(a.sessionId, outsider)).status).toBe(403);
		const responses = await Promise.all([reserve(a.sessionId), reserve(b.sessionId)]);
		expect(responses.map(r => r.status)).toEqual([200, 200]);
		const usage = () => SELF.fetch(`http://example.com/_api/v1/orgs/${org}`, { headers: { authorization: "Bearer test-admin-secret" } }).then(r => r.json());
		expect(await usage()).toMatchObject({ used: 0, pending: 12 });
		expect((await reserve(a.sessionId)).status).toBe(200);
		for (let i = 0; i < 2; i++) expect((await post(`/_api/v1/uploads/${a.sessionId}/abort`, {}, token)).status).toBe(200);
		await abortAllDurableObjects();
		expect((await reserve(b.sessionId)).status).toBe(200);
		expect((await reserve(a.sessionId)).status).toBe(409);
		expect(await usage()).toMatchObject({ used: 0, pending: 6 });
		const bytes = new Uint8Array([13, 92, 51, 240, 6, 9]);
		const receipt = await upload(b.sessionId, bytes, token);
		const first = { sessionId: b.sessionId, narHash, narSize, fileHash: await digest(bytes), fileSize: bytes.length, parts: [receipt] };
		expect(await (await post("/_api/v1/uploads/finalize", { uploads: [first] }, token)).json()).toMatchObject({ results: [{ published: true }] });
		expect(await usage()).toMatchObject({ used: 6, pending: 0 });
		const read = (hash: string) => SELF.fetch(`http://example.com/private/${org}/stream/${hash}.narinfo`, { headers: { authorization: `Bearer ${token}` } });
		expect((await read(b.hash)).status).toBe(200);
		const replacement = await stream("stream", token);
		const replacementBytes = new Uint8Array([23, 4, 92, 84, 3, 6, 11]);
		const replacementReceipt = await upload(replacement.sessionId, replacementBytes, token);
		expect(await usage()).toMatchObject({ used: 6, pending: 7 });
		expect((await read(b.hash)).status).toBe(200);
		const item = { sessionId: replacement.sessionId, narHash, narSize, fileHash: await digest(replacementBytes), fileSize: 7, parts: [replacementReceipt] };
		expect(await (await post("/_api/v1/uploads/finalize", { uploads: [item] }, token)).json()).toMatchObject({ results: [{ published: true }] });
		expect(await usage()).toMatchObject({ used: 7, pending: 0 });
		expect((await read(b.hash)).status).toBe(404);
		expect((await read(replacement.hash)).status).toBe(200);
		// A completed-session replay must restore its SQL row with its narinfo,
		// not resurrect an untracked public path after eviction.
		expect(await (await post("/_api/v1/uploads/finalize", { uploads: [first] }, token)).json()).toMatchObject({ results: [{ published: true }] });
		expect(await usage()).toMatchObject({ used: 6, pending: 0 });
		expect((await read(b.hash)).status).toBe(200);
		expect((await read(replacement.hash)).status).toBe(404);
	});

	it("recovers durable grants and sealed receipts after restart and failed SQL synchronization", async () => {
		const cache = await createCache(db, `stream-restart-${crypto.randomUUID().slice(0, 8)}`);
		const s = await stream(cache.name);
		const bytes = new Uint8Array([13, 92, 51, 240, 6]);
		const receipt = await upload(s.sessionId, bytes);
		await abortAllDurableObjects();
		expect((await post(`/_api/v1/uploads/${s.sessionId}/parts`, { parts: [{ partNumber: 1, size: bytes.length + 1 }] })).status).toBe(409);
		const item = { sessionId: s.sessionId, narHash, narSize, fileHash: await digest(bytes), fileSize: bytes.length, parts: [receipt] };
		const request = () => new Request("http://example.com/_api/v1/uploads/finalize", {
			method: "POST", headers: { authorization: `Bearer ${AUTH}`, "content-type": "application/json" }, body: JSON.stringify({ uploads: [item] }),
		});
		const ctx = createExecutionContext();
		const failed = await nix.fetch(request(), { ...env, HYPERDRIVE: { ...env.HYPERDRIVE, connectionString: "postgres://postgres:postgres@127.0.0.1:1/unavailable" } }, ctx);
		expect(await failed.json()).toMatchObject({ results: [{ published: false, status: 500 }] });
		await waitOnExecutionContext(ctx);
		expect((await post(`/_api/v1/uploads/${s.sessionId}/abort`, {})).status).toBe(409);
		await abortAllDurableObjects();
		for (let replay = 0; replay < 2; replay++) {
			expect(await (await SELF.fetch(request())).json()).toMatchObject({ results: [{ published: true }] });
		}
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(`nar/${item.fileHash}/zstd.nar`))!.arrayBuffer())).toEqual(bytes);
	});
});
