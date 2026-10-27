import { env } from "cloudflare:test";
import { describe, it, expect, afterAll } from "vitest";
import {
	createCache,
	createBlobObject,
	createUploadSession,
	findBlobObject,
	findUploadSession,
	transitionSessionStatus,
	createPublishedPath,
} from "../src/db/repository.js";
import { runGarbageCollection } from "../../../workers/control/src/gc.js";
import { resolveConfig } from "../src/config.js";

const config = resolveConfig(env);
afterAll(() => config.close());

function makeSessionParams(overrides: {
	readonly id: string;
	readonly cacheId: number;
	readonly expiresAt?: Date;
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
		expiresAt: overrides.expiresAt ?? new Date("2099-01-01T00:00:00.000Z"),
	};
}

describe("gc: expire abandoned sessions", () => {
	it("removes expired sessions and their staged bytes, but keeps active uploads", async () => {
		const cache = await createCache(config.db, `gc-expire-${crypto.randomUUID()}`);
		const sessionId = crypto.randomUUID();
		const activeId = crypto.randomUUID();
		const expiredKey = `staging/${sessionId}`;
		const activeKey = `staging/${activeId}`;
		await createUploadSession(
			config.db,
			makeSessionParams({ id: sessionId, cacheId: cache.id, expiresAt: new Date("2020-01-01T00:00:00.000Z"), r2UploadKey: expiredKey }),
		);
		await createUploadSession(config.db, makeSessionParams({ id: activeId, cacheId: cache.id, r2UploadKey: activeKey }));
		const bytes = new Uint8Array([31, 7, 219]);
		await env.CACHE_BUCKET.put(expiredKey, bytes);
		await env.CACHE_BUCKET.put(activeKey, bytes);

		const result = await runGarbageCollection(config);

		// The database is shared across files; other expired fixtures may exist.
		expect(result.expiredSessions).toBeGreaterThanOrEqual(1);
		expect(result.errors).toHaveLength(0);
		expect(await findUploadSession(config.db, sessionId)).toBeUndefined();
		expect(await env.CACHE_BUCKET.head(expiredKey)).toBeNull();
		expect((await findUploadSession(config.db, activeId))?.status).toBe("pending");
		const active = await env.CACHE_BUCKET.get(activeKey);
		expect(new Uint8Array(await active!.arrayBuffer())).toEqual(bytes);
	});

	it("deletes expired completed sessions, sweeping a NAR no path took and keeping a published one", async () => {
		const cache = await createCache(config.db, `gc-completed-${crypto.randomUUID()}`);
		const session = async (expiresAt: Date) => {
			const id = crypto.randomUUID();
			const fileHash = crypto.randomUUID().replaceAll("-", "").padEnd(64, "0");
			const key = `nar/${fileHash}/zstd.nar`;
			await env.PUBLIC_BUCKET.put(key, "nar");
			await createUploadSession(config.db, { ...makeSessionParams({ id, cacheId: cache.id, expiresAt, r2UploadKey: key }), fileHash });
			await transitionSessionStatus(config.db, id, "pending", "completed");
			return { id, fileHash, key };
		};
		const unpublished = await session(new Date(0));
		const published = await session(new Date(0));
		const live = await session(new Date("2099-01-01T00:00:00.000Z"));
		const blob = await createBlobObject(config.db, { fileHash: published.fileHash, fileSize: 512, compression: "zstd", r2Key: published.key });
		await createPublishedPath(config.db, {
			cacheId: cache.id, storePathHash: crypto.randomUUID(), storePath: "/nix/store/x", narHash: "sha256:x", narSize: 1,
			blobObjectId: blob.id, referencesJson: "[]", deriver: null, system: null, signaturesJson: "[]",
		});

		expect((await runGarbageCollection(config)).errors).toEqual([]);
		expect(await findUploadSession(config.db, unpublished.id)).toBeUndefined();
		expect(await findUploadSession(config.db, published.id)).toBeUndefined();
		expect((await findUploadSession(config.db, live.id))?.status).toBe("completed");
		expect(await env.PUBLIC_BUCKET.head(unpublished.key)).toBeNull();
		expect(await env.PUBLIC_BUCKET.head(published.key)).not.toBeNull();
	});

	it("retries a partially failed NAR deletion on the next GC run", async () => {
		const fileHash = crypto.randomUUID().replaceAll("-", "").padEnd(64, "0");
		const key = `nar/${fileHash}/zstd.nar`;
		await createBlobObject(config.db, { fileHash, fileSize: 3, compression: "zstd", r2Key: key });
		await env.PUBLIC_BUCKET.put(key, "nar");
		await env.CACHE_BUCKET.put(`nars/sha256/${fileHash}/zstd.nar`, "nar");
		const unavailable: R2Bucket = Object.create(config.publicBucket);
		unavailable.delete = async () => { throw new Error("R2 unavailable"); };
		const failed = await runGarbageCollection({ ...config, publicBucket: unavailable });
		expect(failed.errors).not.toEqual([]);
		expect(await findBlobObject(config.db, fileHash, "zstd")).toBeDefined();

		expect((await runGarbageCollection(config)).errors).toEqual([]);
		expect(await env.PUBLIC_BUCKET.head(key)).toBeNull();
		expect(await env.CACHE_BUCKET.head(`nars/sha256/${fileHash}/zstd.nar`)).toBeNull();
		expect(await findBlobObject(config.db, fileHash, "zstd")).toBeUndefined();
	});

	it.each(["nar/", "nars/sha256/"])("collects an abandoned canonical upload under %s without a blob row", async (prefix) => {
		const cache = await createCache(config.db, `gc-orphan-${crypto.randomUUID()}`);
		const fileHash = crypto.randomUUID().replaceAll("-", "").padEnd(64, "0");
		const key = `${prefix}${fileHash}/zstd.nar`;
		const bucket = prefix === "nar/" ? env.PUBLIC_BUCKET : env.CACHE_BUCKET;
		const id = crypto.randomUUID();
		await bucket.put(key, "abandoned bytes");
		await createUploadSession(config.db, {
			...makeSessionParams({ id, cacheId: cache.id, expiresAt: new Date(0), r2UploadKey: key }),
			fileHash,
		});
		expect((await runGarbageCollection(config)).errors).toEqual([]);
		expect(await findUploadSession(config.db, id)).toBeUndefined();
		expect(await bucket.head(key)).toBeNull();
	});
});
