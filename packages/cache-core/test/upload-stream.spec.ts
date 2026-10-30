import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { testDb } from "./db.js";
import { createCache, findUploadSession, orgUsage } from "../src/db/repository.js";
import { signJwt, TOKEN_ISSUER, TOKEN_AUDIENCE } from "../src/jwt.js";

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
	it("publishes verified bytes, replays finalization, and refuses mutations or legacy bypasses", async () => {
		const cache = await createCache(db, `stream-${crypto.randomUUID().slice(0, 8)}`);
		const s = await stream(cache.name);
		expect(s.partSize).toBe(8 * 1024 ** 2);
		const bytes = new Uint8Array([31, 7, 219, 84, 2]);
		const receipt = await upload(s.sessionId, bytes);
		for (const endpoint of ["multipart", "complete", "publish"]) {
			expect((await post(`/_api/v1/uploads/${s.sessionId}/${endpoint}`, {})).status).toBe(409);
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

	it("reserves quota once across retries and competing streams, isolates orgs, and releases aborts", async () => {
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
		expect(responses.map(r => r.status).sort()).toEqual([200, 507]);
		const winner = responses[0].status === 200 ? a : b;
		const loser = winner === a ? b : a;
		expect((await reserve(winner.sessionId)).status).toBe(200);
		expect(await orgUsage(db, org, new Date())).toEqual({ used: 0, pending: 6 });
		for (let i = 0; i < 2; i++) expect((await post(`/_api/v1/uploads/${winner.sessionId}/abort`, {}, token)).status).toBe(200);
		expect((await reserve(loser.sessionId)).status).toBe(200);
		expect((await reserve(winner.sessionId)).status).toBe(409);
	});
});
