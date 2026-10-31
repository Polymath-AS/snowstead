import { and, eq, sql } from "drizzle-orm";
import type { Db } from "./db/connection.js";
import { caches, pins, pinRevisions, pinPaths } from "./db/schema.js";

export type PinKeep = "forever" | { days: number } | { revisions: number };
export class PinError extends Error {
	constructor(message: string, readonly status: 404 | 409 | 413) { super(message); }
}

/** Serialize with publication, retention, explicit deletion and cache eviction. */
export async function lockPinCache(tx: Db, org: string, cacheId: number): Promise<void> {
	await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + org}, 0))`);
	const [cache] = await tx.select({ id: caches.id }).from(caches).where(and(eq(caches.id, cacheId), eq(caches.orgId, org))).for("update");
	if (!cache) throw new PinError("Cache not found", 404);
}

export async function listPins(db: Db, cacheId: number) {
	const rows = await db.execute<{
		name: string; keepKind: "forever" | "days" | "revisions"; keepValue: number | null;
		currentRevision: number; revision: number; storePath: string; createdAt: Date; supersededAt: Date | null; pinned: boolean;
	}>(sql`select p.name, p.keep_kind as "keepKind", p.keep_value as "keepValue", p.current_revision as "currentRevision",
		r.revision, r.store_path as "storePath", r.created_at as "createdAt", r.superseded_at as "supersededAt",
		(r.revision=p.current_revision or p.keep_kind='forever'
		or (p.keep_kind='revisions' and r.revision>p.current_revision-p.keep_value)
		or (p.keep_kind='days' and r.superseded_at>now()-p.keep_value*interval '1 day')) as pinned
		from pins p join pin_revisions r on r.pin_id=p.id where p.cache_id=${cacheId} order by p.name, r.revision desc`);
	const result = new Map<string, { name: string; keep: PinKeep; currentRevision: number; history: { revision: number; storePath: string; createdAt: Date; supersededAt: Date | null; pinned: boolean }[] }>();
	for (const row of rows.rows) {
		let pin = result.get(row.name);
		if (!pin) {
			pin = { name: row.name, keep: row.keepKind === "forever" ? "forever" : row.keepKind === "days" ? { days: row.keepValue! } : { revisions: row.keepValue! }, currentRevision: row.currentRevision, history: [] };
			result.set(row.name, pin);
		}
		pin.history.push({ revision: row.revision, storePath: row.storePath, createdAt: row.createdAt, supersededAt: row.supersededAt, pinned: row.pinned });
	}
	return [...result.values()];
}

/** Closure membership is computed once per revision, never by eviction scans. */
export async function putPin(db: Db, org: string, cacheId: number, name: string, storePath: string, keep: PinKeep) {
	return db.transaction(async tx => {
		await lockPinCache(tx, org, cacheId);
		const [existing] = await tx.select().from(pins).where(and(eq(pins.cacheId, cacheId), eq(pins.name, name)));
		const [current] = existing ? await tx.select().from(pinRevisions).where(and(eq(pinRevisions.pinId, existing.id), eq(pinRevisions.revision, existing.currentRevision))) : [];
		// UNION deduplicates cycles; bound the recursive output before joining it.
		const closure = await tx.execute<{ hash: string; storePath: string | null }>(sql`
			with recursive closure(store_path) as (
				select ${storePath}::text
				union
				select case when ref.value like '/nix/store/%' then ref.value else '/nix/store/' || ref.value end
				from closure c join published_paths p on p.cache_id=${cacheId} and p.store_path_hash=substr(c.store_path,12,32) and p.store_path=c.store_path
				cross join lateral jsonb_array_elements_text(p.references_json::jsonb) ref(value)
			), bounded as materialized (select store_path from closure limit 10001)
			select substr(c.store_path,12,32) as hash, p.store_path as "storePath" from bounded c
			left join published_paths p on p.cache_id=${cacheId} and p.store_path_hash=substr(c.store_path,12,32) and p.store_path=c.store_path`);
		if (closure.rows.length > 10000) throw new PinError("Pin closure exceeds 10000 paths", 413);
		if (closure.rows.some(row => row.storePath === null) || !closure.rows.some(row => row.storePath === storePath)) {
			throw new PinError("The root and its entire closure must be published in this cache", 409);
		}
		const id = existing?.id ?? crypto.randomUUID();
		const revision = current?.storePath === storePath ? existing!.currentRevision : (existing?.currentRevision ?? 0) + 1;
		const policy = { keepKind: keep === "forever" ? "forever" as const : "days" in keep ? "days" as const : "revisions" as const,
			keepValue: keep === "forever" ? null : "days" in keep ? keep.days : keep.revisions };
		await tx.insert(pins).values({ id, cacheId, name, currentRevision: revision, ...policy })
			.onConflictDoUpdate({ target: [pins.cacheId, pins.name], set: { currentRevision: revision, ...policy } });
		if (!current || current.storePath !== storePath) {
			if (current) await tx.update(pinRevisions).set({ supersededAt: new Date() }).where(eq(pinRevisions.id, current.id));
			const revisionId = crypto.randomUUID();
			await tx.insert(pinRevisions).values({ id: revisionId, pinId: id, revision, storePath });
			// Bounded set insert, no per-dependency round trips.
			await tx.insert(pinPaths).values(closure.rows.map(row => ({ revisionId, cacheId, storePathHash: row.hash })));
		}
		// A wider policy must not silently resurrect revisions whose closure was GC'd.
		const missing = await tx.execute(sql`select 1 from pin_paths m join pin_revisions r on r.id=m.revision_id
			join pins p on p.id=r.pin_id where p.id=${id} and (r.revision=p.current_revision or p.keep_kind='forever'
			or (p.keep_kind='revisions' and r.revision>p.current_revision-p.keep_value)
			or (p.keep_kind='days' and r.superseded_at>now()-p.keep_value*interval '1 day'))
			and not exists (select 1 from published_paths p where p.cache_id=m.cache_id and p.store_path_hash=m.store_path_hash)
			limit 1`);
		if (missing.rows.length) throw new PinError("A retained revision has missing paths; restore its closure before extending keep", 409);
		return { created: !existing, pin: (await listPins(tx, cacheId)).find(pin => pin.name === name)! };
	});
}

export async function deletePin(db: Db, org: string, cacheId: number, name: string): Promise<void> {
	await db.transaction(async tx => {
		await lockPinCache(tx, org, cacheId);
		await tx.delete(pins).where(and(eq(pins.cacheId, cacheId), eq(pins.name, name)));
	});
}
