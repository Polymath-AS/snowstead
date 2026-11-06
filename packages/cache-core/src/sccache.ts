import { and, eq, gt, isNotNull, isNull, lte, sql } from "drizzle-orm";
import type { WorkerConfig } from "./config.js";
import type { Cache } from "./db/types.js";
import type { Db } from "./db/connection.js";
import { caches as cacheRows, sccacheEntries, orgs } from "./db/schema.js";
import { cacheColumns, findCache, findOrg } from "./db/repository.js";
import { errorResponse, jsonResponse } from "./responses.js";
import { PRIVATE_CACHES_REFUSED } from "./visibility.js";
import { CapacityError, withOrgCapacity } from "./capacity.js";
import { uuidv7 } from "./uuid.js";

const SCCACHE_RETENTION_MS = 7 * 86400_000;
export const SCCACHE_MAX_BYTES = 64 * 1024 * 1024;

export function activeSccacheEntries(cache: Pick<Cache, "id" | "sccacheGeneration">, now = new Date()) {
	return and(eq(sccacheEntries.cacheId, cache.id), eq(sccacheEntries.generation, cache.sccacheGeneration), gt(sccacheEntries.expiresAt, now));
}

/** Keep the cache on a miss so the protocol can authenticate private misses. */
export async function findSccacheTarget(db: Db, org: string, name: string, action: string) {
	const [target] = await db.select({ cache: cacheColumns, entry: sccacheEntries }).from(cacheRows)
		.innerJoin(orgs, eq(cacheRows.orgId, orgs.id))
		.leftJoin(sccacheEntries, and(eq(sccacheEntries.cacheId, cacheRows.id), eq(sccacheEntries.generation, cacheRows.sccacheGeneration), gt(sccacheEntries.expiresAt, new Date()),
			eq(sccacheEntries.action, action), isNotNull(sccacheEntries.uploadedAt)))
		.where(and(eq(orgs.slug, org), eq(cacheRows.name, name))).limit(1);
	return target;
}

/** Call only after releasing transfer locks; publication owns org -> cache -> entry. */
export async function publishSccacheUpload(config: WorkerConfig, cache: Cache, id: string, uploaded: Date, origin: string): Promise<void> {
	await withOrgCapacity(config, cache.orgId, [{ cacheId: cache.id, storePathHash: `sccache:${id}` }], async tx => {
		const [current] = await tx.select().from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
		if (!current || current.sccacheGeneration !== cache.sccacheGeneration) throw new CapacityError("Cache changed; retry", 503);
		const [entry] = await tx.select().from(sccacheEntries).where(eq(sccacheEntries.id, id)).for("update");
		if (!entry || entry.cacheId !== cache.id || entry.expiresAt.getTime() <= Date.now()) throw new CapacityError("Upload expired; retry", 503);
		if (!entry.uploadedAt) await tx.update(sccacheEntries).set({ uploadedAt: uploaded,
			expiresAt: new Date(uploaded.getTime() + SCCACHE_RETENTION_MS) }).where(eq(sccacheEntries.id, entry.id));
	}, { origin });
}

/** Only reservation SQL is serialized per org; payloads never enter the coordinator. */
export async function reserveSccacheUpload(db: Db, cache: Cache, action: string, size: number) {
	return db.transaction(async tx => {
		await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + cache.orgId}, 0))`);
		const org = await findOrg(tx, cache.orgId);
		if (!org) return errorResponse("Not Found", 404);
		const [current] = await tx.select().from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
		if (!current || current.sccacheGeneration !== cache.sccacheGeneration) return errorResponse("Cache changed; retry", 409);
		if (!current.isPublic && !org.privateCaches) return errorResponse(PRIVATE_CACHES_REFUSED, 403);
		const now = new Date();
		await tx.update(sccacheEntries).set({ cacheId: null }).where(and(eq(sccacheEntries.cacheId, cache.id),
			eq(sccacheEntries.generation, cache.sccacheGeneration), eq(sccacheEntries.action, action), lte(sccacheEntries.expiresAt, now)));
		const [existing] = await tx.select().from(sccacheEntries).where(and(activeSccacheEntries(cache, now), eq(sccacheEntries.action, action)));
		if (existing) return existing;
		if (org.storageLimit !== null && size > org.storageLimit) return errorResponse("Artifact exceeds retained capacity", 413);
		// Bound staging independently of retained capacity. The partial index
		// excludes completed archives, so this never scans the retained cache.
		const [staging] = await tx.select({ bytes: sql`coalesce(sum(${sccacheEntries.size}), 0)`.mapWith(Number),
			count: sql`count(*)`.mapWith(Number) })
			.from(sccacheEntries).innerJoin(cacheRows, eq(sccacheEntries.cacheId, cacheRows.id))
			.where(and(eq(cacheRows.orgId, cache.orgId), isNull(sccacheEntries.uploadedAt), gt(sccacheEntries.expiresAt, now)));
		if (staging.count >= 256 || staging.bytes + size > (org.storageLimit ?? 1024 * 1024 * 1024)) {
			return errorResponse("Upload staging is busy; retry", 503, { "retry-after": "1" });
		}
		const id = uuidv7();
		const [entry] = await tx.insert(sccacheEntries).values({ id, cacheId: cache.id, generation: cache.sccacheGeneration, action,
			r2Key: `sccache/${cache.id}/${cache.sccacheGeneration}/${action}/${id}`, size,
			expiresAt: new Date(now.getTime() + 3600_000),
		}).onConflictDoNothing().returning();
		if (entry) return entry;
		const [winner] = await tx.select().from(sccacheEntries).where(and(activeSccacheEntries(cache), eq(sccacheEntries.action, action)));
		return winner ?? errorResponse("Action changed; retry", 409);
	});
}

/** Called after org-management authorization. */
export async function handleSccacheManagement(config: WorkerConfig, org: string, name: string, reset: boolean): Promise<Response> {
	let cache = await findCache(config.db, org, name);
	if (!cache || !cache.protocols.includes("sccache")) return errorResponse("Not Found", 404);
	if (reset) {
		const [updated] = await config.db.update(cacheRows).set({ sccacheGeneration: uuidv7() })
			.where(eq(cacheRows.id, cache.id)).returning();
		if (!updated) return errorResponse("Not Found", 404);
		cache = { ...cache, ...updated };
	}
	const [row] = await config.db.select({
		entries: sql`count(*)`.mapWith(Number),
		size: sql`coalesce(sum(${sccacheEntries.size}), 0)`.mapWith(Number),
		lastAddedAt: sql<string | null>`max(${sccacheEntries.uploadedAt})`,
	}).from(sccacheEntries).where(and(activeSccacheEntries(cache), isNotNull(sccacheEntries.uploadedAt)));
	return jsonResponse({ ...row, lastAddedAt: row.lastAddedAt ? new Date(row.lastAddedAt).toISOString() : null, retentionDays: 7 });
}

/** Reclaim abandoned attempts in bounded pages, including crashes after R2 PUT.
 * Reservation IDs are never reused. While a reservation exists, keep all of its
 * attempts: even an uncommitted adoption or a stalled transfer remains safe.
 * A crashed loser can therefore remain until its reservation's retention ends.
 */
export async function sweepSccacheAttempts(config: WorkerConfig): Promise<number> {
	const cursorKey = "gc:sccache-attempts";
	const cursor = await config.authKv.get(cursorKey);
	const page = await config.bucket.list({ prefix: "sccache-attempt/", limit: 500, cursor: cursor ?? undefined });
	const ids = [...new Set(page.objects.map(object => object.key.split("/")[1]))];
	const entries = ids.length ? await config.db.select({ id: sccacheEntries.id }).from(sccacheEntries)
		.where(sql`${sccacheEntries.id} = ANY(${sql.param(ids)}::text[])`) : [];
	const live = new Set(entries.map(entry => entry.id));
	const garbage = page.objects.filter(object => !live.has(object.key.split("/")[1])).map(object => object.key);
	if (garbage.length) await config.bucket.delete(garbage);
	if (page.truncated) await config.authKv.put(cursorKey, page.cursor);
	else await config.authKv.delete(cursorKey);
	return garbage.length;
}

/** Entry locks fence the sweep against adoption and publication, not transfers. */
export async function sweepSccacheEntries(config: WorkerConfig): Promise<number> {
	return config.db.transaction(async tx => {
		const now = new Date();
		const columns = { id: sccacheEntries.id, r2Key: sccacheEntries.r2Key };
		// Separate index ranges instead of an OR across a join. The categories
		// are disjoint, and all three share a single 500-entry budget.
		const entries = await tx.select(columns).from(sccacheEntries)
			.where(lte(sccacheEntries.expiresAt, now))
			.limit(500).for("update", { of: sccacheEntries, skipLocked: true });
		if (entries.length < 500) entries.push(...await tx.select(columns).from(sccacheEntries)
			.where(and(isNull(sccacheEntries.cacheId), gt(sccacheEntries.expiresAt, now)))
			.limit(500 - entries.length).for("update", { of: sccacheEntries, skipLocked: true }));
		if (entries.length < 500) {
			const remaining = 500 - entries.length;
			// Two generation ranges let the (cache_id, generation, ...) index
			// skip the entire live generation, even when there is no garbage.
			const obsolete = await tx.execute<{ id: string; r2Key: string }>(sql`
				select e.id, e.r2_key as "r2Key" from ${cacheRows} c cross join lateral (
					select * from (select e.id, e.r2_key from ${sccacheEntries} e
					 where e.cache_id = c.id and e.generation < c.sccache_generation and e.expires_at > ${now}
					 order by e.generation, e.expires_at
					 limit ${remaining} for update of e skip locked) earlier
					union all
					select * from (select e.id, e.r2_key from ${sccacheEntries} e
					 where e.cache_id = c.id and e.generation > c.sccache_generation and e.expires_at > ${now}
					 order by e.generation, e.expires_at
					 limit ${remaining} for update of e skip locked) later
				) e limit ${remaining}`);
			entries.push(...obsolete.rows);
		}
		if (!entries.length) return 0;
		await config.bucket.delete(entries.map(entry => entry.r2Key));
		await tx.delete(sccacheEntries).where(sql`${sccacheEntries.id} = ANY(${sql.param(entries.map(entry => entry.id))}::text[])`);
		return entries.length;
	});
}
