import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { drizzle } from "drizzle-orm/d1";
import {
	createCache,
	findCacheByName,
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
} from "../src/db/repository.js";

function getDb() {
	return drizzle(env.CACHE_DB);
}

function makeSessionParams(overrides: {
	readonly id: string;
	readonly cacheId: number;
	readonly expiresAt?: string;
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
		expiresAt: overrides.expiresAt ?? "2099-01-01T00:00:00.000Z",
	};
}

describe("caches", () => {
	it("createCache creates a public cache with expected fields", async () => {
		const name = `cache-create-${crypto.randomUUID()}`;
		const row = await createCache(getDb(), name);

		expect(row.name).toBe(name);
		expect(typeof row.id).toBe("number");
		expect(typeof row.createdAt).toBe("string");
	});

	it("findCacheByName returns a matching cache", async () => {
		const name = `cache-find-${crypto.randomUUID()}`;
		const created = await createCache(getDb(), name);
		const found = await findCacheByName(getDb(), name);

		expect(found).toBeDefined();
		expect(found!.id).toBe(created.id);
		expect(found!.name).toBe(name);
	});

	it("findCacheByName returns undefined for non-existent name", async () => {
		const found = await findCacheByName(getDb(), `no-such-cache-${crypto.randomUUID()}`);
		expect(found).toBeUndefined();
	});

	it("createCache with duplicate name throws", async () => {
		const name = `cache-dup-${crypto.randomUUID()}`;
		await createCache(getDb(), name);

		await expect(createCache(getDb(), name)).rejects.toThrow();
	});
});

describe("blob_objects", () => {
	it("createBlobObject creates a row with expected fields", async () => {
		const fileHash = `sha256:${crypto.randomUUID()}`;
		const row = await createBlobObject(getDb(), {
			fileHash,
			fileSize: 2048,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});

		expect(row.fileHash).toBe(fileHash);
		expect(row.fileSize).toBe(2048);
		expect(row.compression).toBe("zstd");
		expect(typeof row.id).toBe("number");
		expect(typeof row.createdAt).toBe("string");
	});

	it("findBlobObject returns a matching blob", async () => {
		const fileHash = `sha256:${crypto.randomUUID()}`;
		const created = await createBlobObject(getDb(), {
			fileHash,
			fileSize: 100,
			compression: "none",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});
		const found = await findBlobObject(getDb(), fileHash, "none");

		expect(found).toBeDefined();
		expect(found!.id).toBe(created.id);
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
	it("createPublishedPath creates a row with expected fields", async () => {
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
		expect(typeof row.createdAt).toBe("string");
	});

	it("findPublishedPath returns a matching path", async () => {
		const cache = await createCache(getDb(), `pp-find-${crypto.randomUUID()}`);
		const blob = await createBlobObject(getDb(), {
			fileHash: `sha256:${crypto.randomUUID()}`,
			fileSize: 500,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});
		const storePathHash = crypto.randomUUID();

		const created = await createPublishedPath(getDb(), {
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
		});
		const found = await findPublishedPath(getDb(), cache.id, storePathHash);

		expect(found).toBeDefined();
		expect(found!.id).toBe(created.id);
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
	it("createUploadSession creates a session with status pending", async () => {
		const cache = await createCache(getDb(), `us-create-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		const row = await createUploadSession(getDb(), makeSessionParams({ id: sessionId, cacheId: cache.id }));

		expect(row.id).toBe(sessionId);
		expect(row.cacheId).toBe(cache.id);
		expect(row.status).toBe("pending");
		expect(typeof row.createdAt).toBe("string");
	});

	it("findUploadSession returns a matching session", async () => {
		const cache = await createCache(getDb(), `us-find-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		await createUploadSession(getDb(), makeSessionParams({ id: sessionId, cacheId: cache.id }));
		const found = await findUploadSession(getDb(), sessionId);

		expect(found).toBeDefined();
		expect(found!.id).toBe(sessionId);
	});

	it("transitionSessionStatus updates and returns the session", async () => {
		const cache = await createCache(getDb(), `us-update-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		await createUploadSession(getDb(), makeSessionParams({ id: sessionId, cacheId: cache.id }));

		const updated = await transitionSessionStatus(getDb(), sessionId, "pending", "uploading");

		expect(updated).toBeDefined();
		expect(updated!.status).toBe("uploading");
		expect(updated!.id).toBe(sessionId);
	});

	it("findExpiredSessions returns only expired non-completed sessions", async () => {
		const cache = await createCache(getDb(), `us-expired-${crypto.randomUUID()}`);

		const expiredId = crypto.randomUUID();
		await createUploadSession(
			getDb(),
			makeSessionParams({ id: expiredId, cacheId: cache.id, expiresAt: "2020-01-01T00:00:00.000Z" }),
		);

		const freshId = crypto.randomUUID();
		await createUploadSession(
			getDb(),
			makeSessionParams({ id: freshId, cacheId: cache.id, expiresAt: "2099-01-01T00:00:00.000Z" }),
		);

		const expired = await findExpiredSessions(getDb(), new Date().toISOString());
		const expiredIds = expired.map((s) => s.id);

		expect(expiredIds).toContain(expiredId);
		expect(expiredIds).not.toContain(freshId);
	});

	it("findExpiredSessions excludes completed sessions even if expired", async () => {
		const cache = await createCache(getDb(), `us-exp-compl-${crypto.randomUUID()}`);

		const sessionId = crypto.randomUUID();
		await createUploadSession(
			getDb(),
			makeSessionParams({ id: sessionId, cacheId: cache.id, expiresAt: "2020-01-01T00:00:00.000Z" }),
		);
		await transitionSessionStatus(getDb(), sessionId, "pending", "completed");

		const expired = await findExpiredSessions(getDb(), new Date().toISOString());
		const expiredIds = expired.map((s) => s.id);

		expect(expiredIds).not.toContain(sessionId);
	});
});

describe("upload_parts", () => {
	it("upsertUploadPart creates a part with expected fields", async () => {
		const cache = await createCache(getDb(), `up-create-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		await createUploadSession(getDb(), makeSessionParams({ id: sessionId, cacheId: cache.id }));

		const row = await upsertUploadPart(getDb(), {
			sessionId,
			partNumber: 1,
			etag: "etag-abc",
			size: 1024,
		});

		expect(row.sessionId).toBe(sessionId);
		expect(row.partNumber).toBe(1);
		expect(row.etag).toBe("etag-abc");
		expect(row.size).toBe(1024);
		expect(typeof row.id).toBe("number");
	});

	it("findUploadParts returns parts ordered by partNumber", async () => {
		const cache = await createCache(getDb(), `up-find-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		await createUploadSession(getDb(), makeSessionParams({ id: sessionId, cacheId: cache.id }));

		await upsertUploadPart(getDb(), { sessionId, partNumber: 3, etag: "e3", size: 300 });
		await upsertUploadPart(getDb(), { sessionId, partNumber: 1, etag: "e1", size: 100 });
		await upsertUploadPart(getDb(), { sessionId, partNumber: 2, etag: "e2", size: 200 });

		const parts = await findUploadParts(getDb(), sessionId);

		expect(parts).toHaveLength(3);
		expect(parts[0].partNumber).toBe(1);
		expect(parts[1].partNumber).toBe(2);
		expect(parts[2].partNumber).toBe(3);
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
		expect(typeof row.markedAt).toBe("string");
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