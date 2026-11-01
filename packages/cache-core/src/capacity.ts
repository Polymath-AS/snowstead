import { and, eq, inArray, lt, or, isNull, sql } from "drizzle-orm";
import type { WorkerConfig } from "./config.js";
import type { Db } from "./db/connection.js";
import { goEntries, orgs, publishedPaths, sccacheEntries } from "./db/schema.js";
import { orgUsage } from "./db/repository.js";
import { deleteCachePaths } from "./path-deletion.js";
import { cachePath } from "./cache-path.js";
import { evictionCandidates } from "./eviction.js";
import type { Protection, Victim } from "./eviction.js";

export class CapacityError extends Error {
	constructor(message: string, readonly status: 413 | 503) { super(message); }
	get retryable(): boolean { return this.status === 503; }
}

const VICTIM_BUDGET = 256;
const ACCESS_INTERVAL_MS = 5 * 60_000;

/**
 * Lock order: org, then publication's cache/session/entry locks. The callback
 * must use tx, not config.db. Protect every incoming Nix path; Go uses go:<id>.
 * Never call this from inside a transaction already holding publication locks.
 * External publication runs after admission, before releasing the org lock,
 * so a concurrent eviction cannot race a late narinfo write.
 */
export async function withOrgCapacity<T>(config: WorkerConfig, orgId: string, protect: readonly Protection[], publish: (tx: Db) => Promise<T>, publication: { origin?: string; afterAdmission?: () => Promise<void> } = {}): Promise<T> {
	return config.db.transaction(async tx => {
		// Even unlimited orgs serialize publication with finite policy transitions.
		await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + orgId}, 0))`);
		const [org] = await tx.select().from(orgs).where(eq(orgs.id, orgId)).for("share");
		if (!org) throw new CapacityError("Organization disappeared; retry", 503);
		const result = await publish(tx);
		if (org.storageLimit === null) {
			await publication.afterAdmission?.();
			return result;
		}
		const now = new Date();
		const usage = await orgUsage(tx, orgId, now);
		if (usage.used <= org.storageLimit) {
			await publication.afterAdmission?.();
			return result;
		}
		const protectedRows = sql`jsonb_to_recordset(${JSON.stringify(protect)}::jsonb) as p("cacheId" integer, "storePathHash" text)`;
		const protectedBytes = await tx.execute(sql`
			select coalesce(sum(n), 0)::text as bytes from (
				select b.file_size as n from published_paths e join caches c on c.id=e.cache_id
				join blob_objects b on b.id=e.blob_object_id
				where c.org_id=${orgId} and exists (select 1 from ${protectedRows} where p."cacheId"=c.id and p."storePathHash"=e.store_path_hash)
				union all select e.size from go_entries e join caches c on c.id=e.cache_id
				where c.org_id=${orgId} and e.generation=c.go_generation and e.uploaded_at is not null and e.expires_at>${now}
				and exists (select 1 from ${protectedRows} where p."cacheId"=c.id and p."storePathHash"='go:' || e.id)
				union all select e.size from sccache_entries e join caches c on c.id=e.cache_id
				where c.org_id=${orgId} and e.generation=c.sccache_generation and e.uploaded_at is not null and e.expires_at>${now}
				and exists (select 1 from ${protectedRows} where p."cacheId"=c.id
					and p."storePathHash" like 'sccache:%' and e.id=substr(p."storePathHash", 9))
			) incoming`);
		if (Number(protectedBytes.rows[0].bytes) > org.storageLimit) throw new CapacityError("Incoming objects exceed retained capacity", 413);
		// Both branches take row locks before any withdrawal. A busy or pinned
		// path is not a victim. Bound candidates AND external deletion work.
		// A global top-256 cannot need more than 256 from one cache/protocol.
		// Keep exclusions as set filters so each LRU scan can stop early.
		const candidates = await evictionCandidates(tx, orgId, now, protect, VICTIM_BUDGET);
		const available = new Set<string>();
		// Lock the bounded candidate set in at most three statements, not one
		// round trip per victim. SKIP LOCKED preserves progress around transfers.
		for (const kind of ["nix", "go", "sccache"] as const) {
			const ids = candidates.filter(candidate => candidate.kind === kind).map(candidate => candidate.id);
			if (!ids.length) continue;
			const table = kind === "nix" ? sql`published_paths` : kind === "go" ? sql`go_entries` : sql`sccache_entries`;
			const selected = kind === "nix" ? sql`${sql.param(ids)}::bigint[]` : sql`${sql.param(ids)}::text[]`;
			const eligible = kind === "nix" ? sql`
				not nix_path_pinned(e.cache_id,e.store_path_hash,${now}) and
				not exists (select 1 from upload_sessions u where u.cache_id=e.cache_id and u.store_path_hash=e.store_path_hash
					and (u.status='finalizing' or (u.status in ('pending','uploading','streaming') and u.expires_at>${now})))
				and not exists (select 1 from nar_installations i join blob_objects b on b.id=e.blob_object_id
					where i.file_hash=b.file_hash and i.compression=b.compression)`
				: sql`e.uploaded_at is not null and e.expires_at>${now} and e.generation=${kind === "go" ? sql`c.go_generation` : sql`c.sccache_generation`}`;
			const locked = await tx.execute<{ id: string }>(sql`select e.id::text as id from ${table} e join caches c on c.id=e.cache_id
				where e.id=ANY(${selected}) and c.org_id=${orgId} and ${eligible} order by e.id for update of e skip locked`);
			for (const row of locked.rows) available.add(`${kind}:${row.id}`);
		}
		const victims: Victim[] = [];
		let freed = 0;
		for (const candidate of candidates) {
			if (!available.has(`${candidate.kind}:${candidate.id}`)) continue;
			victims.push(candidate);
			freed += Number(candidate.size);
			if (usage.used - freed <= org.storageLimit) break;
		}
		if (usage.used - freed > org.storageLimit) throw new CapacityError("Capacity victims are busy or exceed the eviction budget; retry", 503);
		await tx.execute(sql`select set_config('snowstead.eviction_reason','capacity',true)`);
		// No external deletions before the complete plan has been proven to fit.
		for (const victim of victims) {
			if (victim.kind === "nix") {
				await deleteCachePaths({ ...config, db: tx }, { id: victim.cacheId, orgId, isPublic: victim.isPublic,
					path: cachePath(org.slug, victim.name) }, { storePathHashes: [victim.hash] }, publication.origin);
			}
		}
		for (const kind of ["go", "sccache"] as const) {
			const ids = victims.filter(victim => victim.kind === kind).map(victim => victim.id);
			if (!ids.length) continue;
			const table = kind === "go" ? goEntries : sccacheEntries;
			// One transition-table trigger invocation for the whole product batch.
			await tx.update(table).set({ cacheId: null }).where(inArray(table.id, ids));
		}
		await publication.afterAdmission?.();
		return result;
	});
}

/** Coalesced in SQL, with no isolate-local per-object map or permanent state. */
export function recordNixAccess(config: WorkerConfig, cacheId: number, hash: string): void {
	const now = new Date();
	config.defer(config.db.update(publishedPaths).set({ lastAccessedAt: now }).where(and(
		eq(publishedPaths.cacheId, cacheId), eq(publishedPaths.storePathHash, hash),
		or(isNull(publishedPaths.lastAccessedAt), lt(publishedPaths.lastAccessedAt, new Date(now.getTime() - ACCESS_INTERVAL_MS))),
	)).then(() => {}).catch(() => {}));
}

export function recordGoAccess(config: WorkerConfig, id: string): void {
	const now = new Date();
	config.defer(config.db.update(goEntries).set({ lastAccessedAt: now }).where(and(eq(goEntries.id, id),
		or(isNull(goEntries.lastAccessedAt), lt(goEntries.lastAccessedAt, new Date(now.getTime() - ACCESS_INTERVAL_MS))),
	)).then(() => {}).catch(() => {}));
}

export function recordSccacheAccess(config: WorkerConfig, entry: { id: string; lastAccessedAt: Date | null }): void {
	const now = new Date();
	if (entry.lastAccessedAt && entry.lastAccessedAt.getTime() >= now.getTime() - ACCESS_INTERVAL_MS) return;
	config.afterResponse(db => db.update(sccacheEntries).set({ lastAccessedAt: now }).where(and(eq(sccacheEntries.id, entry.id),
		or(isNull(sccacheEntries.lastAccessedAt), lt(sccacheEntries.lastAccessedAt, new Date(now.getTime() - ACCESS_INTERVAL_MS))),
	)).then(() => {}));
}
