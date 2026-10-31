import { env, SELF, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { eq } from "drizzle-orm";
import { testDb } from "./db.js";
import { createCache, createUploadSessions } from "../src/db/repository.js";
import { uploadSessions } from "../src/db/schema.js";
import { runGarbageCollection } from "../../../workers/control/src/gc.js";
import { resolveConfig } from "../src/config.js";
import nix from "../../../workers/nix/src/index.js";
import { createStream, digest, finalizeUploads, postUpload, stageUpload } from "./upload.js";

const db = testDb();
function path() {
	const hash = crypto.randomUUID().replaceAll("-", "").replace(/[eotu]/g, "a");
	return { storePath: `/nix/store/${hash}-shared`, storePathHash: hash, narHash: `sha256:${"1".repeat(52)}`, narSize: 64, compression: "zstd" };
}
async function cache() { return createCache(db, `possess-${crypto.randomUUID().slice(0, 8)}`); }
const bytes = () => crypto.getRandomValues(new Uint8Array(16));

describe("proof of possession", () => {
	it("requires each session's own upload even when another cache already stores the NAR", async () => {
		const body = bytes();
		const a = await cache();
		const b = await cache();
		const owner = await stageUpload(a.name, path(), body);
		expect(await finalizeUploads([owner])).toMatchObject([{ published: true }]);
		const metadata = path();
		const other = await createStream(b.name, metadata);
		expect((await postUpload(`/uploads/${other.sessionId}/parts`, { parts: [{ partNumber: 1, size: body.length }] })).status).toBe(200);
		const claim = { ...owner, sessionId: other.sessionId };
		expect(await finalizeUploads([claim])).toMatchObject([{ published: false }]);
		expect((await SELF.fetch(`http://example.com/${b.name}/${metadata.storePathHash}.narinfo`)).status).toBe(404);
		// Expiring an abandoned proof must not withdraw the other cache's NAR.
		await db.update(uploadSessions).set({ expiresAt: new Date(0) }).where(eq(uploadSessions.id, other.sessionId));
		const config = resolveConfig(env);
		try { expect((await runGarbageCollection(config)).errors).toEqual([]); }
		finally { await config.close(); }
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(`nar/${owner.fileHash}/zstd.nar`))!.arrayBuffer())).toEqual(body);
	});
	it.each(["hash", "size"])("refuses %s tampering without replacing another session's canonical object", async mismatch => {
		const body = bytes();
		const a = await cache();
		const b = await cache();
		const owner = await stageUpload(a.name, path(), body);
		expect(await finalizeUploads([owner])).toMatchObject([{ published: true }]);
		const key = `nar/${owner.fileHash}/zstd.nar`;
		const before = await env.PUBLIC_BUCKET.head(key);
		const metadata = path();
		const wrong = await stageUpload(b.name, metadata, mismatch === "hash" ? new Uint8Array(body.length) : body);
		const claim = { ...wrong, fileHash: owner.fileHash, fileSize: body.length + (mismatch === "size" ? 1 : 0) };
		for (let retry = 0; retry < 2; retry++) expect(await finalizeUploads([claim])).toMatchObject([{ published: false, status: 400 }]);
		expect((await env.PUBLIC_BUCKET.head(key))?.version).toBe(before?.version);
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(key))!.arrayBuffer())).toEqual(body);
		expect((await SELF.fetch(`http://example.com/${b.name}/${metadata.storePathHash}.narinfo`)).status).toBe(404);
	});
	it("publishes simultaneous duplicate streams and replays without canonical collisions", async () => {
		const body = bytes();
		const caches = [await cache(), await cache()];
		const metadata = [path(), path()];
		const items = await Promise.all(caches.map((c, i) => stageUpload(c.name, metadata[i], body)));
		const results = await Promise.all(items.map(item => finalizeUploads([item])));
		expect(results.some(result => result[0].published)).toBe(true);
		for (const result of results) if (!result[0].published) expect(result[0]).toMatchObject({ published: false, status: 503, error: "NAR installation busy; retry" });
		for (let i = 0; i < items.length; i++) {
			expect(await finalizeUploads([items[i]])).toMatchObject([{ published: true }]);
			expect((await SELF.fetch(`http://example.com/${caches[i].name}/${metadata[i].storePathHash}.narinfo`)).status).toBe(200);
		}
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(`nar/${items[0].fileHash}/zstd.nar`))!.arrayBuffer())).toEqual(body);
	});
	it.each([false, true])("does not clobber an outstanding canonical grant during promotion (invalid proof: %s)", async invalid => {
		const body = bytes();
		const a = await cache();
		const b = await cache();
		const owner = await stageUpload(a.name, path(), body);
		const challenger = await stageUpload(b.name, path(), invalid ? new Uint8Array(body.length) : body);
		const claim = { ...challenger, fileHash: owner.fileHash };
		const key = `nar/${owner.fileHash}/zstd.nar`;
		let interleaved = false;
		let version: string | undefined;
		const bucket = new Proxy(env.PUBLIC_BUCKET, {
			get(target, property) {
				if (property === "put") return async (requested: string, value: Parameters<R2Bucket["put"]>[1], options?: R2PutOptions) => {
					if (requested === key && !interleaved) {
						interleaved = true;
						// A signed URL issued before cutover may still write directly to R2.
						await target.put(key, body, { sha256: owner.fileHash, customMetadata: { session: "outstanding-grant" }, onlyIf: { etagDoesNotMatch: "*" } });
						version = (await target.head(key))?.version;
					}
					return target.put(requested, value, options);
				};
				const value = Reflect.get(target, property, target);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
		const ctx = createExecutionContext();
		const request = new Request("http://example.com/_api/v1/uploads/finalize", {
			method: "POST", headers: { authorization: "Bearer test-auth-token", "content-type": "application/json" }, body: JSON.stringify({ uploads: [claim] }),
		});
		const response = await nix.fetch(request as Parameters<typeof nix.fetch>[0], { ...env, PUBLIC_BUCKET: bucket }, ctx);
		await waitOnExecutionContext(ctx);
		expect(await response.json()).toMatchObject({ results: [invalid ? { published: false, status: 400 } : { published: true }] });
		expect(interleaved).toBe(!invalid);
		if (invalid) expect(await finalizeUploads([owner])).toMatchObject([{ published: true }]);
		else expect((await env.PUBLIC_BUCKET.head(key))?.version).toBe(version);
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(key))!.arrayBuffer())).toEqual(body);
	});
	it("keeps private cross-org proof and rejects another org's reserve, PUT, finalize, and abort", async () => {
		async function client() {
			const org = `possession-${crypto.randomUUID().slice(0, 8)}`;
			const admin = (suffix: string, method: string, body: unknown) => SELF.fetch(`http://example.com/_api/v1/orgs/${org}${suffix}`, {
				method, headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" }, body: JSON.stringify(body),
			});
			expect((await admin("", "PUT", { slug: org })).status).toBe(200);
			expect((await admin("/caches", "POST", { name: "team", private: true, protocols: ["nix"] })).status).toBe(201);
			const { token } = await (await admin("/tokens", "POST", { subject: "test", caches: ["team"], perms: ["push", "pull"] })).json<{ token: string }>();
			return { org, token };
		}
		const [a, b] = [await client(), await client()];
		const body = bytes();
		const metadata = path();
		const owner = await stageUpload("team", metadata, body, a.token);
		expect((await postUpload(`/uploads/${owner.sessionId}/parts`, { parts: [{ partNumber: 1, size: body.length }] }, b.token)).status).toBe(403);
		expect((await SELF.fetch(`http://example.com/_api/v1/uploads/${owner.sessionId}/part/1`, { method: "PUT", headers: { authorization: `Bearer ${b.token}` }, body })).status).toBe(403);
		expect(await finalizeUploads([owner], b.token)).toMatchObject([{ status: 403 }]);
		expect((await postUpload(`/uploads/${owner.sessionId}/abort`, {}, b.token)).status).toBe(403);
		expect(await finalizeUploads([owner], a.token)).toMatchObject([{ published: true }]);
		const otherPath = path();
		const other = await createStream("team", otherPath, b.token);
		expect((await postUpload(`/uploads/${other.sessionId}/parts`, { parts: [{ partNumber: 1, size: body.length }] }, b.token)).status).toBe(200);
		expect(await finalizeUploads([{ ...owner, sessionId: other.sessionId }], b.token)).toMatchObject([{ published: false }]);
		const proven = await stageUpload("team", path(), body, b.token);
		expect(await finalizeUploads([proven], b.token)).toMatchObject([{ published: true }]);
		expect(await env.PUBLIC_BUCKET.head(`nar/${owner.fileHash}/zstd.nar`)).toBeNull();
		expect(new Uint8Array(await (await env.CACHE_BUCKET.get(`nars/sha256/${owner.fileHash}/zstd.nar`))!.arrayBuffer())).toEqual(body);
	});
	it("does not recover non-s2 session IDs from SQL", async () => {
		const c = await cache();
		const metadata = path();
		const id = crypto.randomUUID();
		await createUploadSessions(db, [{ id, cacheId: c.id, ...metadata, fileHash: null, fileSize: 0,
			referencesJson: "[]", deriver: null, system: null, status: "streaming", partSize: 8 * 1024 ** 2,
			r2UploadKey: `staging/${id}`, r2UploadId: "retired", expiresAt: new Date(Date.now() + 3600_000) }]);
		expect((await postUpload(`/uploads/${id}/parts`, { parts: [{ partNumber: 1, size: 1 }] })).status).toBe(404);
		expect(await finalizeUploads([{ sessionId: id, narHash: metadata.narHash, narSize: metadata.narSize, fileHash: await digest(new Uint8Array([1])), fileSize: 1, parts: [{ partNumber: 1, etag: "old" }] }])).toMatchObject([{ status: 404 }]);
		expect((await SELF.fetch(`http://example.com/_api/v1/uploads/${id}/part/1`, { method: "PUT", headers: { authorization: "Bearer test-auth-token" }, body: new Uint8Array([1]) })).status).toBe(404);
		expect((await postUpload(`/uploads/${id}/abort`, {})).status).toBe(404);
	});
});
