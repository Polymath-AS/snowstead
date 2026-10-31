import { sql } from "drizzle-orm";
import type { SQL } from "drizzle-orm";
import type { Db } from "./db/connection.js";

export type Protection = { cacheId: number; storePathHash: string };
export type EvictionCursor = { used: string; kind: string; id: string };
export type Victim = { kind: "nix" | "go" | "sccache"; id: string; cacheId: number; hash: string; size: string;
	name: string; isPublic: boolean; key: string; lastAccessedAt: Date | null; used: string };

/** Shared by capacity admission and its read-only preview; bounds each cache's candidate output. */
export async function evictionCandidates(tx: Db, orgId: string, now: Date, protect: readonly Protection[], limit: number, cursor?: EvictionCursor): Promise<Victim[]> {
	const protectedRows = sql`jsonb_to_recordset(${JSON.stringify(protect)}::jsonb) as p("cacheId" integer, "storePathHash" text)`;
	const after = (used: SQL, kind: string, id: SQL) => cursor
		? sql`(${used}, ${kind}::text, ${id}) > (to_timestamp(${cursor.used}::double precision), ${cursor.kind}::text, ${cursor.id}::text)` : sql`true`;
	const result = await tx.execute<Victim>(sql`
		with active as materialized (
			select u.cache_id, u.store_path_hash from upload_sessions u join caches c on c.id=u.cache_id
			where c.org_id=${orgId} and (u.status='finalizing' or (u.status in ('pending','uploading','streaming') and u.expires_at>${now}))
		)
		select kind,id,"cacheId",hash,size,name,"isPublic",key,"lastAccessedAt",extract(epoch from used)::text as used from (
			select 'nix' as kind, e.id, c.id as "cacheId", e.hash, e.size, c.name, c.is_public as "isPublic", e.key, e.last_accessed_at as "lastAccessedAt", e.used
			from caches c cross join lateral (
				select e.id::text, e.store_path_hash as hash, b.file_size::text as size, e.store_path as key, e.last_accessed_at, greatest(e.last_pushed_at,e.last_accessed_at) as used
				from published_paths e join blob_objects b on b.id=e.blob_object_id
				where e.cache_id=c.id and ${after(sql`greatest(e.last_pushed_at,e.last_accessed_at)`, "nix", sql`e.id::text`)}
				and not nix_path_pinned(e.cache_id,e.store_path_hash,${now})
				and e.store_path_hash <> all(array(select p."storePathHash" from ${protectedRows} where p."cacheId"=c.id and p."storePathHash" is not null))
				and e.store_path_hash <> all(array(select u.store_path_hash from active u where u.cache_id=c.id))
				and (b.file_hash,b.compression) not in (select i.file_hash,i.compression from nar_installations i)
				order by greatest(e.last_pushed_at,e.last_accessed_at), e.id::text limit ${limit}
			) e where c.org_id=${orgId}
			union all
			select 'go',e.id,c.id,'go:' || e.id,e.size::text,c.name,c.is_public,e.action,e.last_accessed_at,greatest(e.uploaded_at,e.last_accessed_at)
			from caches c cross join lateral (
				select e.* from go_entries e where e.cache_id=c.id and e.generation=c.go_generation and e.uploaded_at is not null and e.expires_at>${now}
				and ${after(sql`greatest(e.uploaded_at,e.last_accessed_at)`, "go", sql`e.id`)}
				and 'go:' || e.id <> all(array(select p."storePathHash" from ${protectedRows} where p."cacheId"=c.id and p."storePathHash" is not null))
				order by greatest(e.uploaded_at,e.last_accessed_at), e.id limit ${limit}
			) e where c.org_id=${orgId}
			union all
			select 'sccache',e.id,c.id,'sccache:' || e.id,e.size::text,c.name,c.is_public,e.action,e.last_accessed_at,greatest(e.uploaded_at,e.last_accessed_at)
			from caches c cross join lateral (
				select e.* from sccache_entries e where e.cache_id=c.id and e.generation=c.sccache_generation and e.uploaded_at is not null and e.expires_at>${now}
				and ${after(sql`greatest(e.uploaded_at,e.last_accessed_at)`, "sccache", sql`e.id`)}
				and 'sccache:' || e.id <> all(array(select p."storePathHash" from ${protectedRows} where p."cacheId"=c.id and p."storePathHash" is not null))
				order by greatest(e.uploaded_at,e.last_accessed_at), e.id limit ${limit}
			) e where c.org_id=${orgId}
		) victims order by victims.used,kind,id limit ${limit}`);
	return result.rows;
}
