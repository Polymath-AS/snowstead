import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { drizzle } from "drizzle-orm/d1";
import {
	createCache,
	createUploadSession,
	createBlobObject,
	createPublishedPath,
	findUploadSession,
	findBlobObjectById,
} from "../src/db/repository.js";
import { runGarbageCollection } from "../src/gc.js";
import type { WorkerConfig } from "../src/config.js";

function getConfig(): WorkerConfig {
	return {
		bucket: env.CACHE_BUCKET,
		db: drizzle(env.CACHE_DB),
	};
}

function makeSessionParams(overrides: {
	readonly id: string;
	readonly cacheId: number;
	readonly expiresAt?: string;
	readonly r2UploadKey?: string | null;
}) {
	return {
		id: overrides.id,
		cacheId: overrides.cacheId,
		storePathHash: crypto.randomUUID(),
		storePath: `/nix/store/${crypto.randomUUID()}`,
		narHash: `sha256:${crypto.randomUUID()}`,
		narSize: 1024,
		fileHash: `sha256:${crypto.randomUUID()}`,
		fileSize: 512,
		compression: "zstd",
		referencesJson: "[]",
		deriver: null,
		system: null,
		r2UploadKey: overrides.r2UploadKey ?? null,
		r2UploadId: null,
		expiresAt: overrides.expiresAt ?? "2099-01-01T00:00:00.000Z",
	};
}

describe("gc: expire abandoned sessions", () => {
	it("expires and deletes sessions past their expiresAt", async () => {
		const config = getConfig();
		const cache = await createCache(config.db, `gc-expire-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		await createUploadSession(
			config.db,
			makeSessionParams({ id: sessionId, cacheId: cache.id, expiresAt: "2020-01-01T00:00:00.000Z" }),
		);

		const result = await runGarbageCollection(config);

		expect(result.expiredSessions).toBeGreaterThanOrEqual(1);
		expect(result.errors).toHaveLength(0);

		const found = await findUploadSession(config.db, sessionId);
		expect(found).toBeUndefined();
	});
});

describe("gc: delete unreferenced blobs", () => {
	it("deletes blob objects not referenced by any published path", async () => {
		const config = getConfig();
		const blob = await createBlobObject(config.db, {
			fileHash: `sha256:${crypto.randomUUID()}`,
			fileSize: 2048,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});

		const result = await runGarbageCollection(config);

		expect(result.deletedBlobs).toBeGreaterThanOrEqual(1);
		expect(result.errors).toHaveLength(0);

		const found = await findBlobObjectById(config.db, blob.id);
		expect(found).toBeUndefined();
	});
});

describe("gc: keep referenced blobs", () => {
	it("preserves blob objects that are referenced by a published path", async () => {
		const config = getConfig();
		const cache = await createCache(config.db, `gc-keep-${crypto.randomUUID()}`);
		const blob = await createBlobObject(config.db, {
			fileHash: `sha256:${crypto.randomUUID()}`,
			fileSize: 2048,
			compression: "zstd",
			r2Key: `blobs/${crypto.randomUUID()}`,
		});
		const storePathHash = crypto.randomUUID();
		await createPublishedPath(config.db, {
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

		const result = await runGarbageCollection(config);

		const found = await findBlobObjectById(config.db, blob.id);
		expect(found).toBeDefined();
	});
});

describe("gc: keep active sessions", () => {
	it("does not expire sessions with future expiresAt", async () => {
		const config = getConfig();
		const cache = await createCache(config.db, `gc-active-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		await createUploadSession(
			config.db,
			makeSessionParams({ id: sessionId, cacheId: cache.id, expiresAt: "2099-01-01T00:00:00.000Z" }),
		);

		const result = await runGarbageCollection(config);

		expect(result.expiredSessions).toBe(0);

		const found = await findUploadSession(config.db, sessionId);
		expect(found).toBeDefined();
	});
});
