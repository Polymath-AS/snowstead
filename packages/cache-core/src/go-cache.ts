import { and, eq, gt, isNotNull, isNull, lt, ne, or, sql } from "drizzle-orm";
import type { WorkerConfig } from "./config.js";
import type { Cache } from "./db/types.js";
import type { Db } from "./db/connection.js";
import { caches as cacheRows, goEntries } from "./db/schema.js";
import { findCache, findOrg, lockOrgStorageLimit, checkOrgStorageLimit } from "./db/repository.js";
import { errorResponse, jsonResponse } from "./responses.js";
import { PRIVATE_CACHES_REFUSED } from "./visibility.js";

export function activeGoEntries(cache: Pick<Cache, "id" | "goGeneration">, now = new Date()) {
	return and(eq(goEntries.cacheId, cache.id), eq(goEntries.generation, cache.goGeneration), gt(goEntries.expiresAt, now));
}

/** Reserve quota and a cleanup record; never read the request body or touch R2. */
export async function reserveGoUpload(db: Db, cache: Cache, action: string, output: string, size: number) {
	return db.transaction(async (tx) => {
		const initialOrg = await findOrg(tx, cache.orgId);
		if (!initialOrg) return errorResponse("Not Found", 404);
		const org = await lockOrgStorageLimit(tx, initialOrg);
		if (!org) return errorResponse("Not Found", 404);
		const [current] = await tx.select().from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
		if (!current || current.goGeneration !== cache.goGeneration) return errorResponse("Cache changed; retry", 409);
		if (!current.isPublic && !org.privateCaches) return errorResponse(PRIVATE_CACHES_REFUSED, 403);
		const now = new Date();
		// Expired entries lose their action slot, not their cleanup record/key.
		await tx.update(goEntries).set({ cacheId: null }).where(and(eq(goEntries.cacheId, cache.id),
			eq(goEntries.generation, cache.goGeneration), eq(goEntries.action, action), lt(goEntries.expiresAt, now)));
		const [existing] = await tx.select().from(goEntries).where(and(activeGoEntries(cache, now), eq(goEntries.action, action)));
		if (existing) return existing;
		if (await checkOrgStorageLimit(tx, org, size)) return errorResponse("Not enough storage", 413);
		const id = crypto.randomUUID();
		const [entry] = await tx.insert(goEntries).values({ id, cacheId: cache.id, generation: cache.goGeneration, action,
			r2Key: `go/${cache.id}/${cache.goGeneration}/${action}/${id}`, output, size,
			expiresAt: new Date(now.getTime() + 3600_000),
		}).onConflictDoNothing({ target: [goEntries.cacheId, goEntries.generation, goEntries.action] }).returning();
		if (entry) return entry;
		// The unique action index also fences writers from an older deployment.
		const [winner] = await tx.select().from(goEntries).where(and(activeGoEntries(cache), eq(goEntries.action, action)));
		return winner ?? errorResponse("Action changed; retry", 409);
	});
}

/** Exact live, completed Go totals; pending transfers are never dashboard entries. */
async function stats(config: WorkerConfig, cache: Pick<Cache, "id" | "goGeneration">) {
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
		if (!cache.protocols.includes("go")) return errorResponse("Not Found", 404);
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
