import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import {
	createCache,
	findCache,
	createBlobObject,
	findBlobObject,
	createPublishedPath,
	findPublishedPath,
	createUploadSession,
	findUploadSession,
	transitionSessionStatus,
	findExpiredSessions,
	upsertUploadPart,
	findUploadParts,
	createGcMark,
	findGcMarks,
	deleteGcMark,
	createPublishedPaths,
	deletePublishedPaths,
	listCacheStats,
} from "../src/db/repository.js";
import { createApiToken, listApiTokens, ensureCache } from "../src/db/repository.js";
import { DEFAULT_ORG_ID } from "../src/db/schema.js";

const db = testDb();

function getDb() {
	return db;
}

function makeSessionParams(overrides: {
	readonly id: string;
	readonly cacheId: number;
	readonly expiresAt?: Date;
	readonly storePathHash?: string;
}) {
	return {
		id: overrides.id,
		cacheId: overrides.cacheId,
		storePathHash: overrides.storePathHash ?? crypto.randomUUID(),
		storePath: `/nix/store/${crypto.randomUUID()}`,
		narHash: `sha256:${crypto.randomUUID()}`,
		narSize: 1024,
		fileHash: `sha256:${crypto.randomUUID()}`,
		fileSize: 512,
		compression: "zstd",
		referencesJson: "[]",
		deriver: null,
		system: null,
		r2UploadKey: null,
		r2UploadId: null,
		expiresAt: overrides.expiresAt ?? new Date("2099-01-01T00:00:00.000Z"),
	};
}

describe("caches", () => {
	it("creates a public cache and reads it back", async () => {
		const name = `cache-create-${crypto.randomUUID()}`;
		const row = await createCache(getDb(), name);

		expect(row.name).toBe(name);
		expect(row.isPublic).toBe(true);
		expect(typeof row.id).toBe("number");
		expect(row.createdAt).toBeInstanceOf(Date);
		expect(await findCache(getDb(), "default", name)).toEqual(row);
	});

	it("findCache returns undefined for non-existent name", async () => {
		const found = await findCache(getDb(), "default", `no-such-cache-${crypto.randomUUID()}`);
		expect(found).toBeUndefined();
	});

	it("createCache with duplicate name throws", async () => {
		const name = `cache-dup-${crypto.randomUUID()}`;
		await createCache(getDb(), name);

		await expect(createCache(getDb(), name)).rejects.toThrow();
	});
});

describe("blob_objects", () => {
	it("stores and finds blobs by hash and compression", async () => {
		const fileHash = `sha256:${crypto.randomUUID()}`;
		const rows = [];
		for (const [compression, fileSize] of [["zstd", 2048], ["none", 4096]] as const) {
			const r2Key = `blobs/${crypto.randomUUID()}`;
			const row = await createBlobObject(getDb(), { fileHash, fileSize, compression, r2Key });
			expect(row).toMatchObject({ fileHash, fileSize, compression, r2Key });
			expect(typeof row.id).toBe("number");
			expect(row.createdAt).toBeInstanceOf(Date);
			rows.push(row);
		}
		// Same hash, different compression: a hash-only lookup is wrong.
		for (const row of rows) {
			expect(await findBlobObject(getDb(), fileHash, row.compression)).toEqual(row);
		}
	});

	it("findBlobObject returns undefined for non-existent", async () => {
		const found = await findBlobObject(getDb(), `sha256:${crypto.randomUUID()}`, "zstd");
		expect(found).toBeUndefined();
	});

	it("createBlobObject with same fileHash+compression throws", async () => {
		const fileHash = `sha256:${crypto.randomUUID()}`;
		await createBlobObject(getDb(), {
			fileHash,
			fileSize: 100,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});

		await expect(
			createBlobObject(getDb(), {
				fileHash,
				fileSize: 200,
				compression: "zstd",
				r2Key: `blobs/${crypto.randomUUID()}`,
			}),
		).rejects.toThrow();
	});
});

describe("published_paths", () => {
	it("keep each cache's path count and size as the paths add up, through batched inserts and deletes", async () => {
		const [a, b] = [await createCache(getDb(), `totals-a-${crypto.randomUUID()}`), await createCache(getDb(), `totals-b-${crypto.randomUUID()}`)];
		const blob = (fileSize: number) => createBlobObject(getDb(), { fileHash: crypto.randomUUID(), fileSize, compression: "zstd", r2Key: `blobs/${crypto.randomUUID()}` });
		const [small, big] = [await blob(100), await blob(7000)];
		const path = (cacheId: number, blobObjectId: number) => {
			const hash = crypto.randomUUID().replaceAll("-", "").slice(0, 32);
			return { cacheId, storePathHash: hash, storePath: `/nix/store/${hash}-x`, narHash: "sha256:x", narSize: 1, blobObjectId, referencesJson: "[]", deriver: null, system: null, signaturesJson: "[]" };
		};
		// One statement over both caches; the big NAR shared between them counts in each.
		const rows = [path(a.id, small.id), path(a.id, big.id), path(b.id, big.id), path(b.id, small.id), path(b.id, small.id)];
		await createPublishedPaths(getDb(), rows);
		await deletePublishedPaths(getDb(), b.id, { storePathHashes: [rows[3].storePathHash, rows[4].storePathHash] }, async () => {});

		const stats = await listCacheStats(getDb(), new Date(0));
		const of = (id: number) => stats.find((s) => s.cache.id === id);
		expect([of(a.id)?.paths, of(a.id)?.size]).toEqual([2, 7100]);
		expect([of(b.id)?.paths, of(b.id)?.size]).toEqual([1, 7000]);
	});

	it("creates a published path and reads it back", async () => {
		const cache = await createCache(getDb(), `pp-create-${crypto.randomUUID()}`);
		const blob = await createBlobObject(getDb(), {
			fileHash: `sha256:${crypto.randomUUID()}`,
			fileSize: 500,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});
		const storePathHash = crypto.randomUUID();

		const row = await createPublishedPath(getDb(), {
			cacheId: cache.id,
			storePathHash,
			storePath: `/nix/store/${storePathHash}`,
			narHash: `sha256:${crypto.randomUUID()}`,
			narSize: 4096,
			blobObjectId: blob.id,
			referencesJson: "[]",
			deriver: null,
			system: "x86_64-linux",
			signaturesJson: "[]",
		});

		expect(row.cacheId).toBe(cache.id);
		expect(row.storePathHash).toBe(storePathHash);
		expect(row.blobObjectId).toBe(blob.id);
		expect(row.system).toBe("x86_64-linux");
		expect(typeof row.id).toBe("number");
		expect(row.createdAt).toBeInstanceOf(Date);
		expect(await findPublishedPath(getDb(), cache.id, storePathHash)).toEqual(row);
	});

	it("keeps sizes past 2 GiB exact", async () => {
		const cache = await createCache(getDb(), `pp-large-${crypto.randomUUID()}`);
		const fileSize = 3 * 2 ** 30;
		const narSize = 5 * 2 ** 30 + 1;
		const blob = await createBlobObject(getDb(), {
			fileHash: `sha256:${crypto.randomUUID()}`,
			fileSize,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});
		const storePathHash = crypto.randomUUID();
		await createPublishedPath(getDb(), {
			cacheId: cache.id,
			storePathHash,
			storePath: `/nix/store/${storePathHash}`,
			narHash: `sha256:${crypto.randomUUID()}`,
			narSize,
			blobObjectId: blob.id,
			referencesJson: "[]",
			deriver: null,
			system: null,
			signaturesJson: "[]",
		});

		const found = await findPublishedPath(getDb(), cache.id, storePathHash);
		expect(found?.narSize).toBe(narSize);
		expect((await findBlobObject(getDb(), blob.fileHash, "zstd"))?.fileSize).toBe(fileSize);
	});

	it("findPublishedPath returns undefined for non-existent", async () => {
		const found = await findPublishedPath(getDb(), 999999, crypto.randomUUID());
		expect(found).toBeUndefined();
	});

	it("createPublishedPath with same cache+storePathHash throws", async () => {
		const cache = await createCache(getDb(), `pp-dup-${crypto.randomUUID()}`);
		const blob = await createBlobObject(getDb(), {
			fileHash: `sha256:${crypto.randomUUID()}`,
			fileSize: 500,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});
		const storePathHash = crypto.randomUUID();
		const common = {
			cacheId: cache.id,
			storePathHash,
			storePath: `/nix/store/${storePathHash}`,
			narHash: `sha256:${crypto.randomUUID()}`,
			narSize: 4096,
			blobObjectId: blob.id,
			referencesJson: "[]",
			deriver: null,
			system: null,
			signaturesJson: "[]",
		};

		await createPublishedPath(getDb(), common);
		await expect(createPublishedPath(getDb(), common)).rejects.toThrow();
	});
});

describe("upload_sessions", () => {
	it("creates, reads and conditionally transitions a session", async () => {
		const cache = await createCache(getDb(), `us-create-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		const row = await createUploadSession(getDb(), makeSessionParams({ id: sessionId, cacheId: cache.id }));

		expect(row.id).toBe(sessionId);
		expect(row.cacheId).toBe(cache.id);
		expect(row.status).toBe("pending");
		expect(row.createdAt).toBeInstanceOf(Date);
		expect(await findUploadSession(getDb(), sessionId)).toEqual(row);

		const updated = await transitionSessionStatus(getDb(), sessionId, "pending", "uploading");
		expect(updated).toMatchObject({ id: sessionId, status: "uploading" });
		expect(await findUploadSession(getDb(), sessionId)).toEqual(updated);
		expect(await transitionSessionStatus(getDb(), sessionId, "pending", "completed")).toBeUndefined();
		expect((await findUploadSession(getDb(), sessionId))?.status).toBe("uploading");
	});

	it("findExpiredSessions returns only expired non-completed sessions", async () => {
		const cache = await createCache(getDb(), `us-expired-${crypto.randomUUID()}`);

		const expiredId = crypto.randomUUID();
		await createUploadSession(
			getDb(),
			makeSessionParams({ id: expiredId, cacheId: cache.id, expiresAt: new Date("2020-01-01T00:00:00.000Z") }),
		);

		const freshId = crypto.randomUUID();
		await createUploadSession(
			getDb(),
			makeSessionParams({ id: freshId, cacheId: cache.id, expiresAt: new Date("2099-01-01T00:00:00.000Z") }),
		);

		const sessionId = crypto.randomUUID();
		await createUploadSession(
			getDb(),
			makeSessionParams({ id: sessionId, cacheId: cache.id, expiresAt: new Date("2020-01-01T00:00:00.000Z") }),
		);
		await transitionSessionStatus(getDb(), sessionId, "pending", "completed");

		const expired = await findExpiredSessions(getDb(), new Date());
		const expiredIds = expired.map((s) => s.id);

		expect(expiredIds).toContain(expiredId);
		expect(expiredIds).not.toContain(freshId);
		expect(expiredIds).not.toContain(sessionId);
	});
});

describe("upload_parts", () => {
	it("stores parts and reads them back in part-number order", async () => {
		const cache = await createCache(getDb(), `up-create-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		await createUploadSession(getDb(), makeSessionParams({ id: sessionId, cacheId: cache.id }));

		const row = await upsertUploadPart(getDb(), {
			sessionId,
			partNumber: 3,
			etag: "etag-abc",
			size: 1024,
		});

		expect(row.sessionId).toBe(sessionId);
		expect(row.partNumber).toBe(3);
		expect(row.etag).toBe("etag-abc");
		expect(row.size).toBe(1024);
		expect(typeof row.id).toBe("number");

		await upsertUploadPart(getDb(), { sessionId, partNumber: 1, etag: "e1", size: 100 });
		await upsertUploadPart(getDb(), { sessionId, partNumber: 2, etag: "e2", size: 200 });

		const parts = await findUploadParts(getDb(), sessionId);

		expect(parts).toEqual([
			expect.objectContaining({ sessionId, partNumber: 1, etag: "e1", size: 100 }),
			expect.objectContaining({ sessionId, partNumber: 2, etag: "e2", size: 200 }),
			row,
		]);
	});
});

describe("gc_marks", () => {
	it("createGcMark creates a mark with expected fields", async () => {
		const targetId = crypto.randomUUID();
		const row = await createGcMark(getDb(), {
			targetType: "blob",
			targetId,
			reason: "orphaned",
		});

		expect(row.targetType).toBe("blob");
		expect(row.targetId).toBe(targetId);
		expect(row.reason).toBe("orphaned");
		expect(typeof row.id).toBe("number");
		expect(row.markedAt).toBeInstanceOf(Date);
	});

	it("findGcMarks returns only marks matching targetType", async () => {
		const blobId = crypto.randomUUID();
		const sessionId = crypto.randomUUID();

		await createGcMark(getDb(), { targetType: "blob_find", targetId: blobId, reason: "orphaned" });
		await createGcMark(getDb(), { targetType: "session_find", targetId: sessionId, reason: "expired" });

		const blobMarks = await findGcMarks(getDb(), "blob_find");

		expect(blobMarks).toHaveLength(1);
		expect(blobMarks[0].targetId).toBe(blobId);
	});

	it("deleteGcMark removes the mark", async () => {
		const targetId = crypto.randomUUID();
		await createGcMark(getDb(), { targetType: "blob_del", targetId, reason: "orphaned" });

		await deleteGcMark(getDb(), "blob_del", targetId);

		const marks = await findGcMarks(getDb(), "blob_del");
		expect(marks).toHaveLength(0);
	});

	it("createGcMark with same target_type+target_id throws", async () => {
		const targetId = crypto.randomUUID();
		await createGcMark(getDb(), { targetType: "blob_idem", targetId, reason: "orphaned" });

		await expect(
			createGcMark(getDb(), { targetType: "blob_idem", targetId, reason: "orphaned again" }),
		).rejects.toThrow();
	});
});

describe("api tokens", () => {
	const token = (orgId: string | null) => createApiToken(db, {
		jti: crypto.randomUUID(),
		subject: "fk",
		caches: [],
		permsJson: "[\"pull\"]",
		expiresAt: new Date(Date.now() + 86400_000),
		createdBy: "test",
		orgId,
	});

	it("belong to an org that exists, or to none", async () => {
		await expect(token(DEFAULT_ORG_ID)).resolves.toMatchObject({ orgId: DEFAULT_ORG_ID });
		await expect(token(null)).resolves.toMatchObject({ orgId: null });
		await expect(token("no-such-org")).rejects.toThrow();
	});
});

describe("token caches", () => {
	const create = (caches: string[]) => createApiToken(db, {
		jti: crypto.randomUUID(),
		subject: "entries",
		caches,
		permsJson: "[\"pull\"]",
		expiresAt: new Date(Date.now() + 86400_000),
		createdBy: "test",
		orgId: null,
	});

	it("record each entry, by cache for ids, and list them back in order", async () => {
		const { cache } = await ensureCache(db, "token-entries");
		const token = await create([`id:${cache.id}`, "team-*", "main"]);
		const listed = (await listApiTokens(db)).find((t) => t.jti === token.jti);
		expect(listed?.caches).toEqual([`id:${cache.id}`, "team-*", "main"]);
		// Still written, for a Worker from before token_caches.
		expect(JSON.parse(listed?.cachesJson ?? "null")).toEqual([`id:${cache.id}`, "team-*", "main"]);
	});

	it("refuse an id entry for a cache that does not exist, and record nothing", async () => {
		const jti = crypto.randomUUID();
		await expect(createApiToken(db, {
			jti, subject: "missing", caches: ["id:999999"], permsJson: "[]",
			expiresAt: new Date(Date.now() + 86400_000), createdBy: "test", orgId: null,
		})).rejects.toThrow();
		expect((await listApiTokens(db)).some((t) => t.jti === jti)).toBe(false);
	});
});
