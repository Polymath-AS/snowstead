import { eq, inArray, sql } from "drizzle-orm";
import type { WorkerConfig } from "./config.js";
import type { CacheAt } from "./db/repository.js";
import { caches, pins, uploadSessions, goEntries, sccacheEntries } from "./db/schema.js";
import { deleteCachePaths } from "./path-deletion.js";
import { uuidv7 } from "./uuid.js";

/** Logical deletion is atomic; external deletes are idempotent and precede commit. */
export async function evictCache(config: WorkerConfig, cache: CacheAt, origin: string) {
	return config.db.transaction(async tx => {
		await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + cache.orgId}, 0))`);
		// Match Nix's session-publication fence before locking the cache row.
		await tx.execute(sql`lock table upload_sessions in share row exclusive mode`);
		const [current] = await tx.select().from(caches).where(eq(caches.id, cache.id)).for("update");
		if (!current) return { evicted: true, name: cache.name, removed: { nix: 0, go: 0, sccache: 0 }, pinsDeleted: 0 };
		await tx.execute(sql`select set_config('snowstead.eviction_reason','evict',true)`);
		const pinsDeleted = (await tx.delete(pins).where(eq(pins.cacheId, cache.id)).returning({ id: pins.id })).length;
		await tx.update(caches).set({ goGeneration: uuidv7(), sccacheGeneration: uuidv7() }).where(eq(caches.id, cache.id));
		// Keep cleanup records; a late Nix finalization rechecks status under the org fence.
		await tx.update(uploadSessions).set({ status: "aborted", expiresAt: new Date() }).where(eq(uploadSessions.cacheId, cache.id));
		const removed = { nix: 0, go: 0, sccache: 0 };
		for (;;) {
			const batch = await deleteCachePaths({ ...config, db: tx }, cache, { before: new Date("9999-01-01"), limit: 500 }, origin);
			removed.nix += batch.length;
			if (batch.length < 500) break;
		}
		for (const product of ["go", "sccache"] as const) {
			const table = product === "go" ? goEntries : sccacheEntries;
			for (;;) {
				const rows = await tx.select({ id: table.id, key: table.r2Key }).from(table).where(eq(table.cacheId, cache.id)).limit(500).for("update");
				if (!rows.length) break;
				await config.bucket.delete(rows.map(row => row.key));
				await tx.delete(table).where(inArray(table.id, rows.map(row => row.id)));
				removed[product] += rows.length;
			}
		}
		return { evicted: true, name: cache.name, removed, pinsDeleted };
	});
}
