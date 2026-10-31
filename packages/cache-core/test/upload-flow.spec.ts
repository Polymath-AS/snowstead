import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { testDb } from "./db.js";
import { createCache, findCache, findPublishedPath, findUploadSession } from "../src/db/repository.js";
import { createStream, digest, finalizeUploads, postUpload, stageUpload, uploadPart } from "./upload.js";
import type { Stream } from "./upload.js";

const CACHE = "upload-test";
const db = testDb();
let counter = 0;
function path() {
	const hash = String(++counter).padStart(32, "0");
	return { storePath: `/nix/store/${hash}-hello`, storePathHash: hash, narHash: `sha256:${"1".repeat(52)}`, narSize: 2048, compression: "zstd" };
}
const bytes = () => crypto.getRandomValues(new Uint8Array(16));
const createBatch = (paths: unknown[]) => postUpload(`/caches/${CACHE}/upload-streams/batch`, { paths });
beforeAll(() => createCache(db, CACHE));

describe("create upload streams", () => {
	it("returns 404 for a missing cache and 400 for missing fields", async () => {
		expect((await postUpload("/caches/no-such-cache/upload-streams/batch", { paths: [path()] })).status).toBe(404);
		expect((await postUpload(`/caches/${CACHE}/upload-streams/batch`, {})).status).toBe(400);
	});
	it.each([
		{ references: ["0".repeat(32)] }, { storePath: `/nix/store/${"a".repeat(32)}-hello` },
		{ deriver: "x.drv\nSig: forged" }, { narHash: `md5:${"0".repeat(32)}` },
	])("rejects invalid metadata %j", async patch => {
		expect((await createBatch([{ ...path(), ...patch }])).status).toBe(400);
	});
	it("creates distinct sessions in input order without claiming compressed bytes", async () => {
		const paths = [path(), path(), path()];
		const response = await createBatch(paths);
		expect(response.status).toBe(201);
		const { sessions } = await response.json<{ sessions: Stream[] }>();
		expect(new Set(sessions.map(s => s.sessionId)).size).toBe(3);
		const rows = await Promise.all(sessions.map(s => findUploadSession(db, s.sessionId)));
		expect(rows.map(s => s?.storePathHash)).toEqual(paths.map(p => p.storePathHash));
		expect(rows.map(s => s?.fileSize)).toEqual([0, 0, 0]);
	});
	it("rejects invalid, empty, and oversized batches", async () => {
		const good = path();
		const invalid = await createBatch([good, { ...good, narSize: "big" }]);
		expect(invalid.status).toBe(400);
		for (const paths of [[], Array.from({ length: 101 }, () => good)]) expect((await createBatch(paths)).status).toBe(400);
	});
});

describe("finalization and reads", () => {
	it("replaces a cached miss immediately and serves Nix SRI hashes and reference basenames", async () => {
		const metadata = { ...path(), narHash: "sha256-L5spLmHxo4zwWB8LQ5ZMgJqzfnjpt/GDVZ0nnobVmQk=", references: [`${"1".repeat(32)}-dep`] };
		const url = `http://example.com/${CACHE}/${metadata.storePathHash}.narinfo`;
		expect((await SELF.fetch(url)).status).toBe(404);
		const body = bytes();
		const item = await stageUpload(CACHE, metadata, body);
		expect(await finalizeUploads([item])).toMatchObject([{ published: true }]);
		const response = await SELF.fetch(url);
		expect(response.status).toBe(200);
		const info = await response.text();
		expect(info).toContain(`StorePath: ${metadata.storePath}\n`);
		expect(info).toContain("NarHash: sha256:02crsn39w9wxan1z3dz9g1zb76l09jb462qzb3q8r8zic4p2k6rg\n");
		expect(info).toContain(`References: ${metadata.references[0]}\n`);
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(`nar/${item.fileHash}/zstd.nar`))!.arrayBuffer())).toEqual(body);
	});
	it("publishes once under concurrent finalizations and sequential retries", async () => {
		const metadata = path();
		const item = await stageUpload(CACHE, metadata, bytes());
		const stats = () => SELF.fetch(`http://example.com/_api/v1/admin/caches/${CACHE}`, { headers: { authorization: "Bearer test-admin-secret" } }).then(r => r.json<{ paths: number }>());
		const before = await stats();
		const results = await Promise.all([finalizeUploads([item]), finalizeUploads([item])]);
		expect(results.some(result => result[0].published)).toBe(true);
		for (const result of results) {
			if (!result[0].published) expect(result[0]).toMatchObject({ published: false, status: 503, error: "NAR installation busy; retry" });
		}
		expect(await finalizeUploads([item])).toMatchObject([{ published: true, alreadyExisted: true }]);
		expect((await stats()).paths).toBe(before.paths + 1);
	});
	it("isolates absent bytes and unknown sessions from valid uploads in a batch", async () => {
		const metadata = path();
		const body = bytes();
		const good = await stageUpload(CACHE, metadata, body);
		const absentPath = path();
		const absent = await createStream(CACHE, absentPath);
		expect((await postUpload(`/uploads/${absent.sessionId}/parts`, { parts: [{ partNumber: 1, size: body.length }] })).status).toBe(200);
		const missing = { ...good, sessionId: absent.sessionId, parts: [{ partNumber: 1, etag: "not-uploaded" }] };
		const unknown = { ...good, sessionId: `s2.default.${crypto.randomUUID()}` };
		expect(await finalizeUploads([good, missing, unknown])).toMatchObject([{ published: true }, { published: false }, { status: 404 }]);
		const cache = await findCache(db, "default", CACHE);
		expect(await findPublishedPath(db, cache!.id, absentPath.storePathHash)).toBeUndefined();
	});
	it("publishes a store path once when two sessions name it", async () => {
		const metadata = path();
		const items = await Promise.all([stageUpload(CACHE, metadata, bytes()), stageUpload(CACHE, metadata, bytes())]);
		expect(await finalizeUploads(items)).toMatchObject([{ published: true }, { published: true }]);
		const cache = await findCache(db, "default", CACHE);
		expect(await findPublishedPath(db, cache!.id, metadata.storePathHash)).toBeDefined();
	});
	it("rejects malformed receipts before sealing, then accepts the correct receipt", async () => {
		const metadata = path();
		const body = bytes();
		const stream = await createStream(CACHE, metadata);
		const receipt = await uploadPart(stream.sessionId, body);
		const item = { sessionId: stream.sessionId, narHash: metadata.narHash, narSize: metadata.narSize, fileHash: await digest(body), fileSize: body.length, parts: [receipt] };
		for (const parts of [{}, [null], [{ partNumber: 0, etag: "x" }], [{ partNumber: 10001, etag: "x" }], [{ partNumber: 1.5, etag: "x" }], [{ partNumber: 1, etag: 123 }], [receipt, receipt]]) {
			const response = await postUpload("/uploads/finalize", { uploads: [{ ...item, parts }] });
			expect(response.status).toBe(400);
		}
		expect((await findUploadSession(db, stream.sessionId))?.status).toBe("streaming");
		expect(await finalizeUploads([item])).toMatchObject([{ published: true }]);
	});
});

describe("get-missing-paths", () => {
	it("returns only unpublished paths", async () => {
		const metadata = path();
		expect(await finalizeUploads([await stageUpload(CACHE, metadata, bytes())])).toMatchObject([{ published: true }]);
		const response = await postUpload("/get-missing-paths", { cache: CACHE, storePathHashes: [metadata.storePathHash, "z".repeat(32)] });
		expect(await response.json()).toMatchObject({ missing: ["z".repeat(32)] });
	});
	it("returns 404 for a missing cache", async () => {
		expect((await postUpload("/get-missing-paths", { cache: "nonexistent-cache", storePathHashes: ["0".repeat(32)] })).status).toBe(404);
	});
});
