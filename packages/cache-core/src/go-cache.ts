import { and, eq, gt, isNotNull, isNull, lt, ne, or, sql } from "drizzle-orm";
import type { WorkerConfig } from "./config.js";
import type { Cache } from "./db/types.js";
import { caches as cacheRows, goEntries } from "./db/schema.js";
import { findCache } from "./db/repository.js";
import { errorResponse, jsonResponse } from "./responses.js";

export function activeGoEntries(cache: Cache, now = new Date()) {
	return and(eq(goEntries.cacheId, cache.id), eq(goEntries.generation, cache.goGeneration), gt(goEntries.expiresAt, now));
}

/** Exact live, completed Go totals; pending transfers are never dashboard entries. */
async function stats(config: WorkerConfig, cache: Cache) {
	const [row] = await config.db.select({
		entries: sql`count(*)`.mapWith(Number),
		size: sql`coalesce(sum(${goEntries.size}), 0)`.mapWith(Number),
		lastAddedAt: sql<string | null>`max(${goEntries.uploadedAt})`,
	}).from(goEntries).where(and(activeGoEntries(cache), isNotNull(goEntries.uploadedAt)));
	return { ...row, lastAddedAt: row?.lastAddedAt ? new Date(row.lastAddedAt).toISOString() : null, retentionDays: 7 };
}

/** Called only after the org management API has authorized the caller. */
export async function handleGoManagement(config: WorkerConfig, org: string, name: string, reset: boolean): Promise<Response> {
	const cache = await findCache(config.db, org, name);
	if (!cache) return errorResponse("Not Found", 404);
	if (reset) {
		const [updated] = await config.db.update(cacheRows).set({ goGeneration: crypto.randomUUID() })
			.where(eq(cacheRows.id, cache.id)).returning();
		if (!updated) return errorResponse("Not Found", 404);
		return jsonResponse(await stats(config, updated));
	}
	return jsonResponse(await stats(config, cache));
}

/** Bounded SQL-driven sweep, including resets, deletions, and failed uploads. */
export async function sweepGoEntries(config: WorkerConfig): Promise<number> {
	return config.db.transaction(async tx => {
		const entries = await tx.select({ entry: goEntries }).from(goEntries)
			.leftJoin(cacheRows, eq(goEntries.cacheId, cacheRows.id))
			.where(or(lt(goEntries.expiresAt, new Date()), isNull(goEntries.cacheId), ne(goEntries.generation, cacheRows.goGeneration)))
			.limit(500).for("update", { of: goEntries, skipLocked: true });
		if (entries.length === 0) return 0;
		await config.bucket.delete(entries.map(({ entry }) => entry.r2Key));
		for (const { entry } of entries) await tx.delete(goEntries).where(eq(goEntries.id, entry.id));
		return entries.length;
	});
}
