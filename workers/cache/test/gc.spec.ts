import { env } from "cloudflare:test";
import { describe, it, expect, afterAll } from "vitest";
import {
	createCache,
	createUploadSession,
	findUploadSession,
} from "../src/db/repository.js";
import { runGarbageCollection } from "../src/gc.js";
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

		expect(result.expiredSessions).toBe(1);
		expect(result.errors).toHaveLength(0);
		expect(await findUploadSession(config.db, sessionId)).toBeUndefined();
		expect(await env.CACHE_BUCKET.head(expiredKey)).toBeNull();
		expect((await findUploadSession(config.db, activeId))?.status).toBe("pending");
		const active = await env.CACHE_BUCKET.get(activeKey);
		expect(new Uint8Array(await active!.arrayBuffer())).toEqual(bytes);
	});
});
