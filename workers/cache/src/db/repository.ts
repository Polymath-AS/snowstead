import { eq, and, notInArray, inArray, lt, gt, isNull, isNotNull, sql, desc } from "drizzle-orm";
import type { Db } from "./connection.js";
import {
	orgs,
	caches,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
	apiTokens,
	auditLogs,
	upstreamPaths,
} from "./schema.js";
import type {
	Org,
	Cache,
	BlobObject,
	PublishedPath,
	UploadSession,
	UploadPart,
	GcMark,
	ApiToken,
	UploadSessionStatus,
} from "./types.js";

/** The first row a query returns, if any. */
async function first<T>(rows: Promise<T[]>): Promise<T | undefined> {
	return (await rows)[0];
}

/** The first row of a write with RETURNING, which must produce one. */
async function returned<T>(rows: Promise<T[]>): Promise<T> {
	const [row] = await rows;
	if (row === undefined) {
		throw new Error("write returned no row");
	}
	return row;
}

export async function findCacheByName(
	db: Db,
	name: string,
): Promise<Cache | undefined> {
	return first(db.select().from(caches).where(eq(caches.name, name)).limit(1));
}

export async function findCacheById(
	db: Db,
	id: number,
): Promise<Cache | undefined> {
	return first(db.select().from(caches).where(eq(caches.id, id)).limit(1));
}

export async function createCache(
	db: Db,
	name: string,
): Promise<Cache> {
	return returned(db.insert(caches).values({ name }).returning());
}

/** Creates `name` unless it exists; returns the cache and whether it is new. */
export async function ensureCache(
	db: Db,
	name: string,
	isPublic = true,
	orgId: string | null = null,
): Promise<{ cache: Cache; created: boolean }> {
	const inserted = await first(db.insert(caches).values({ name, isPublic, orgId }).onConflictDoNothing().returning());
	if (inserted) return { cache: inserted, created: true };
	const existing = await findCacheByName(db, name);
	if (!existing) throw new Error(`cache ${name} vanished`);
	return { cache: existing, created: false };
}

export async function cacheHasPaths(db: Db, cacheId: number): Promise<boolean> {
	return (await first(db.select({ id: publishedPaths.id }).from(publishedPaths).where(eq(publishedPaths.cacheId, cacheId)).limit(1))) !== undefined;
}

export async function setCachePublic(db: Db, name: string, isPublic: boolean): Promise<void> {
	await db.update(caches).set({ isPublic }).where(eq(caches.name, name));
}

export async function listCaches(db: Db): Promise<Cache[]> {
	return db.select().from(caches).orderBy(caches.name);
}

export interface CacheStats {
	readonly cache: Cache;
	readonly paths: number;
	/** Bytes of the compressed NARs its paths point at; a NAR shared with another cache counts in both. */
	readonly size: number;
	readonly addedSince: number;
	readonly lastAddedAt: Date | null;
}

/** Every cache with its published paths counted, or just the one named, or an org's. */
export async function listCacheStats(db: Db, since: Date, filter: { name?: string; orgId?: string } = {}): Promise<CacheStats[]> {
	return db
		.select({
			cache: caches,
			paths: sql`count(${publishedPaths.id})`.mapWith(Number),
			size: sql`coalesce(sum(${blobObjects.fileSize}), 0)`.mapWith(Number),
			addedSince: sql`count(${publishedPaths.id}) filter (where ${publishedPaths.createdAt} >= ${since.toISOString()}::timestamptz)`.mapWith(Number),
			lastAddedAt: sql<Date | null>`max(${publishedPaths.createdAt})`.mapWith(publishedPaths.createdAt),
		})
		.from(caches)
		.leftJoin(publishedPaths, eq(publishedPaths.cacheId, caches.id))
		.leftJoin(blobObjects, eq(publishedPaths.blobObjectId, blobObjects.id))
		.where(and(
			filter.name === undefined ? undefined : eq(caches.name, filter.name),
			filter.orgId === undefined ? undefined : eq(caches.orgId, filter.orgId),
		))
		.groupBy(caches.id)
		.orderBy(caches.name);
}

export async function findOrg(db: Db, id: string): Promise<Org | undefined> {
	return first(db.select().from(orgs).where(eq(orgs.id, id)).limit(1));
}

/** Creates the org, or changes its storage limit. */
export async function putOrg(db: Db, id: string, storageLimit: number | null): Promise<Org> {
	return returned(
		db.insert(orgs).values({ id, storageLimit })
			.onConflictDoUpdate({ target: orgs.id, set: { storageLimit } })
			.returning(),
	);
}

export interface OrgUsage {
	/** Bytes its caches hold, counted as in CacheStats.size. */
	readonly used: number;
	/** Bytes of uploads under way that would add to it. */
	readonly pending: number;
}

export async function orgUsage(db: Db, orgId: string, now: Date): Promise<OrgUsage> {
	const [used, pending] = await Promise.all([
		first(
			db.select({ bytes: sql`coalesce(sum(${blobObjects.fileSize}), 0)`.mapWith(Number) })
				.from(publishedPaths)
				.innerJoin(caches, eq(publishedPaths.cacheId, caches.id))
				.innerJoin(blobObjects, eq(publishedPaths.blobObjectId, blobObjects.id))
				.where(eq(caches.orgId, orgId)),
		),
		first(
			db.select({ bytes: sql`coalesce(sum(${uploadSessions.fileSize}), 0)`.mapWith(Number) })
				.from(uploadSessions)
				.innerJoin(caches, eq(uploadSessions.cacheId, caches.id))
				.where(and(
					eq(caches.orgId, orgId),
					sql`${uploadSessions.status} in ('pending', 'uploading')`,
					gt(uploadSessions.expiresAt, now),
				)),
		),
	]);
	return { used: used?.bytes ?? 0, pending: pending?.bytes ?? 0 };
}

/**
 * Records upload sessions for an org's cache unless they would take it past
 * its storage limit; returns the usage that refused them, or undefined once
 * they are recorded. Locked per org, so concurrent pushes can't both fit
 * into the same space.
 */
export async function createUploadSessionsWithinLimit(
	db: Db,
	orgId: string,
	rows: Parameters<typeof createUploadSessions>[1],
): Promise<(OrgUsage & { readonly limit: number; readonly requested: number }) | undefined> {
	return db.transaction(async (tx) => {
		await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + orgId}, 0))`);
		const org = await findOrg(tx, orgId);
		const limit = org?.storageLimit ?? null;
		if (limit !== null) {
			const usage = await orgUsage(tx, orgId, new Date());
			const requested = rows.reduce((sum, r) => sum + r.fileSize, 0);
			if (usage.used + usage.pending + requested > limit) {
				return { ...usage, limit, requested };
			}
		}
		await createUploadSessions(tx, rows);
		return undefined;
	});
}

/** A cache's most recently published paths, newest first. */
export async function listRecentPaths(
	db: Db,
	cacheId: number,
	limit: number,
): Promise<{ storePath: string; fileSize: number; createdAt: Date }[]> {
	return db
		.select({ storePath: publishedPaths.storePath, fileSize: blobObjects.fileSize, createdAt: publishedPaths.createdAt })
		.from(publishedPaths)
		.innerJoin(blobObjects, eq(publishedPaths.blobObjectId, blobObjects.id))
		.where(eq(publishedPaths.cacheId, cacheId))
		.orderBy(desc(publishedPaths.createdAt), desc(publishedPaths.id))
		.limit(limit);
}

export async function findBlobObject(
	db: Db,
	fileHash: string,
	compression: string,
): Promise<BlobObject | undefined> {
	return first(
		db
			.select()
			.from(blobObjects)
			.where(and(eq(blobObjects.fileHash, fileHash), eq(blobObjects.compression, compression)))
			.limit(1),
	);
}

export async function findBlobObjectById(
	db: Db,
	id: number,
): Promise<BlobObject | undefined> {
	return first(db.select().from(blobObjects).where(eq(blobObjects.id, id)).limit(1));
}

export async function createBlobObject(
	db: Db,
	params: {
		readonly fileHash: string;
		readonly fileSize: number;
		readonly compression: string;
		readonly r2Key: string;
	},
): Promise<BlobObject> {
	return returned(db.insert(blobObjects).values(params).returning());
}

/** Published paths after `afterId`, in id order, with what rendering their narinfo needs. */
export async function listPublishedPathsAfter(
	db: Db,
	afterId: number,
	limit: number,
): Promise<{ path: PublishedPath; blob: BlobObject; cacheName: string }[]> {
	return db
		.select({ path: publishedPaths, blob: blobObjects, cacheName: caches.name })
		.from(publishedPaths)
		.innerJoin(blobObjects, eq(publishedPaths.blobObjectId, blobObjects.id))
		.innerJoin(caches, eq(publishedPaths.cacheId, caches.id))
		.where(gt(publishedPaths.id, afterId))
		.orderBy(publishedPaths.id)
		.limit(limit);
}

export async function findPublishedPath(
	db: Db,
	cacheId: number,
	storePathHash: string,
): Promise<PublishedPath | undefined> {
	return first(
		db
			.select()
			.from(publishedPaths)
			.where(
				and(
					eq(publishedPaths.cacheId, cacheId),
					eq(publishedPaths.storePathHash, storePathHash),
				),
			)
			.limit(1),
	);
}

export async function createPublishedPath(
	db: Db,
	params: {
		readonly cacheId: number;
		readonly storePathHash: string;
		readonly storePath: string;
		readonly narHash: string;
		readonly narSize: number;
		readonly blobObjectId: number;
		readonly referencesJson: string;
		readonly deriver: string | null;
		readonly system: string | null;
		readonly signaturesJson: string;
	},
): Promise<PublishedPath> {
	return returned(db.insert(publishedPaths).values(params).returning());
}

export async function findPublishedHashes(
	db: Db,
	cacheId: number,
	storePathHashes: string[],
): Promise<string[]> {
	if (storePathHashes.length === 0) return [];

	// The hashes go as one array parameter: an IN list with a placeholder per
	// hash costs Drizzle a type check per element to build, which profiling
	// showed dominating the request. sql.param keeps the array whole.
	const rows = await db
		.select({ storePathHash: publishedPaths.storePathHash })
		.from(publishedPaths)
		.where(
			and(
				eq(publishedPaths.cacheId, cacheId),
				sql`${publishedPaths.storePathHash} = ANY(${sql.param(storePathHashes)}::text[])`,
			),
		);
	return rows.map((r) => r.storePathHash);
}

export async function findUploadSession(
	db: Db,
	sessionId: string,
): Promise<UploadSession | undefined> {
	return first(db.select().from(uploadSessions).where(eq(uploadSessions.id, sessionId)).limit(1));
}

export async function createUploadSession(
	db: Db,
	params: {
		readonly id: string;
		readonly cacheId: number;
		readonly storePathHash: string;
		readonly storePath: string;
		readonly narHash: string;
		readonly narSize: number;
		readonly fileHash: string;
		readonly fileSize: number;
		readonly compression: string;
		readonly referencesJson: string;
		readonly deriver: string | null;
		readonly system: string | null;
		readonly r2UploadKey: string | null;
		readonly r2UploadId: string | null;
		readonly expiresAt: Date;
	},
): Promise<UploadSession> {
	return returned(db.insert(uploadSessions).values(params).returning());
}

export async function transitionSessionStatus(
	db: Db,
	sessionId: string,
	fromStatus: UploadSessionStatus,
	toStatus: UploadSessionStatus,
): Promise<UploadSession | undefined> {
	return first(
		db
			.update(uploadSessions)
			.set({ status: toStatus })
			.where(and(eq(uploadSessions.id, sessionId), eq(uploadSessions.status, fromStatus)))
			.returning(),
	);
}

export async function transitionToMultipart(
	db: Db,
	sessionId: string,
	r2UploadId: string,
): Promise<UploadSession | undefined> {
	return first(
		db
			.update(uploadSessions)
			.set({ status: "uploading", r2UploadId })
			.where(and(eq(uploadSessions.id, sessionId), eq(uploadSessions.status, "pending")))
			.returning(),
	);
}

export async function findExpiredSessions(
	db: Db,
	now: Date,
): Promise<UploadSession[]> {
	return db
		.select()
		.from(uploadSessions)
		.where(
			and(
				notInArray(uploadSessions.status, ["completed", "expired"]),
				lt(uploadSessions.expiresAt, now),
			),
		);
}

export async function upsertUploadPart(
	db: Db,
	params: {
		readonly sessionId: string;
		readonly partNumber: number;
		readonly etag: string;
		readonly size: number;
	},
): Promise<UploadPart> {
	return returned(
		db
			.insert(uploadParts)
			.values(params)
			.onConflictDoUpdate({
				target: [uploadParts.sessionId, uploadParts.partNumber],
				set: { etag: params.etag, size: params.size },
			})
			.returning(),
	);
}

export async function upsertUploadParts(
	db: Db,
	sessionId: string,
	parts: ReadonlyArray<{
		readonly partNumber: number;
		readonly etag: string;
		readonly size: number;
	}>,
): Promise<void> {
	if (parts.length === 0) return;
	// One multi-row statement for all parts.
	await db
		.insert(uploadParts)
		.values(parts.map((part) => ({ sessionId, partNumber: part.partNumber, etag: part.etag, size: part.size })))
		.onConflictDoUpdate({
			target: [uploadParts.sessionId, uploadParts.partNumber],
			set: { etag: sql`excluded.etag`, size: sql`excluded.size` },
		});
}

export async function findUploadParts(
	db: Db,
	sessionId: string,
): Promise<UploadPart[]> {
	return db
		.select()
		.from(uploadParts)
		.where(eq(uploadParts.sessionId, sessionId))
		.orderBy(uploadParts.partNumber);
}

/**
 * Deletes blobs no published path points at and no live upload session
 * names, up to `limit`, and returns them. A session's NAR may already sit at
 * its blob's key, about to be published: deleting the blob would take that
 * NAR from under the narinfo publishing writes.
 */
export async function deleteUnreferencedBlobObjects(
	db: Db,
	now: Date,
	limit: number,
): Promise<BlobObject[]> {
	const unreferenced = db
		.select({ id: blobObjects.id })
		.from(blobObjects)
		.where(and(
			sql`not exists (select 1 from ${publishedPaths} where ${publishedPaths.blobObjectId} = ${blobObjects.id})`,
			sql`not exists (select 1 from ${uploadSessions} where ${uploadSessions.fileHash} = ${blobObjects.fileHash} and ${uploadSessions.compression} = ${blobObjects.compression} and ${uploadSessions.expiresAt} > ${now.toISOString()}::timestamptz)`,
		))
		.limit(limit);
	return db.delete(blobObjects).where(inArray(blobObjects.id, unreferenced)).returning();
}

/**
 * Deletes a cache's published paths, the ones named or the oldest published
 * before a time, and returns the hashes it deleted. `withdraw` runs with the
 * rows deleted but not committed: if it fails, they stay.
 */
export async function deletePublishedPaths(
	db: Db,
	cacheId: number,
	which: { readonly storePathHashes: readonly string[] } | { readonly before: Date; readonly limit: number },
	withdraw: (storePathHashes: readonly string[]) => Promise<void>,
): Promise<string[]> {
	return db.transaction(async (tx) => {
		const match = "storePathHashes" in which
			? sql`${publishedPaths.storePathHash} = ANY(${sql.param([...which.storePathHashes])}::text[])`
			: inArray(
				publishedPaths.id,
				tx.select({ id: publishedPaths.id })
					.from(publishedPaths)
					.where(and(eq(publishedPaths.cacheId, cacheId), lt(publishedPaths.createdAt, which.before)))
					.orderBy(publishedPaths.createdAt, publishedPaths.id)
					.limit(which.limit),
			);
		const rows = await tx
			.delete(publishedPaths)
			.where(and(eq(publishedPaths.cacheId, cacheId), match))
			.returning({ storePathHash: publishedPaths.storePathHash });
		const deleted = rows.map((r) => r.storePathHash);
		await withdraw(deleted);
		return deleted;
	});
}

export async function deleteUploadSession(
	db: Db,
	sessionId: string,
): Promise<void> {
	await db.transaction(async (tx) => {
		await tx.delete(uploadParts).where(eq(uploadParts.sessionId, sessionId));
		await tx.delete(uploadSessions).where(eq(uploadSessions.id, sessionId));
	});
}

export async function createGcMark(
	db: Db,
	params: {
		readonly targetType: string;
		readonly targetId: string;
		readonly reason: string;
	},
): Promise<GcMark> {
	return returned(db.insert(gcMarks).values(params).returning());
}

export async function findGcMarks(
	db: Db,
	targetType: string,
): Promise<GcMark[]> {
	return db
		.select()
		.from(gcMarks)
		.where(eq(gcMarks.targetType, targetType));
}

export async function deleteGcMark(
	db: Db,
	targetType: string,
	targetId: string,
): Promise<void> {
	await db
		.delete(gcMarks)
		.where(and(eq(gcMarks.targetType, targetType), eq(gcMarks.targetId, targetId)));
}

export async function createApiToken(
	db: Db,
	params: {
		readonly jti: string;
		readonly subject: string;
		readonly cachesJson: string;
		readonly permsJson: string;
		readonly expiresAt: Date;
		readonly createdBy: string;
		readonly orgId?: string | null;
	},
): Promise<ApiToken> {
	return returned(db.insert(apiTokens).values(params).returning());
}

export async function findApiToken(
	db: Db,
	jti: string,
): Promise<ApiToken | undefined> {
	return first(db.select().from(apiTokens).where(eq(apiTokens.jti, jti)).limit(1));
}

export async function listApiTokens(
	db: Db,
	orgId?: string,
): Promise<ApiToken[]> {
	return db.select().from(apiTokens).where(orgId === undefined ? undefined : eq(apiTokens.orgId, orgId));
}

export async function revokeApiToken(
	db: Db,
	jti: string,
	revokedBy: string,
	reason: string,
): Promise<ApiToken | undefined> {
	return first(
		db
			.update(apiTokens)
			.set({
				revokedAt: new Date(),
				revokedBy,
				revocationReason: reason,
			})
			.where(and(eq(apiTokens.jti, jti), isNull(apiTokens.revokedAt)))
			.returning(),
	);
}

export async function listRevokedTokens(db: Db, now: Date): Promise<ApiToken[]> {
	return db
		.select()
		.from(apiTokens)
		.where(and(isNotNull(apiTokens.revokedAt), gt(apiTokens.expiresAt, now)));
}

export async function deleteExpiredApiTokens(
	db: Db,
	now: Date,
): Promise<number> {
	const result = await db
		.delete(apiTokens)
		.where(lt(apiTokens.expiresAt, now));
	return result.rowCount ?? 0;
}

export async function createAuditLog(
	db: Db,
	params: {
		readonly actor: string;
		readonly action: string;
		readonly cacheName: string | null;
		readonly detail: string;
		readonly ip: string | null;
		readonly status: number;
	},
): Promise<void> {
	// No RETURNING: audit inserts are fire-and-forget on the hot write path,
	// and skipping the row round trip keeps them as cheap as possible.
	await db.insert(auditLogs).values(params);
}

export async function deleteExpiredAuditLogs(
	db: Db,
	cutoff: Date,
): Promise<number> {
	const result = await db
		.delete(auditLogs)
		.where(lt(auditLogs.timestamp, cutoff));
	return result.rowCount ?? 0;
}

export async function createUploadSessions(
	db: Db,
	rows: ReadonlyArray<Parameters<typeof createUploadSession>[1] & { readonly status?: UploadSessionStatus }>,
): Promise<void> {
	if (rows.length === 0) return;
	await db.insert(uploadSessions).values([...rows]);
}

export async function findUploadSessions(db: Db, ids: readonly string[]): Promise<UploadSession[]> {
	if (ids.length === 0) return [];
	return db
		.select()
		.from(uploadSessions)
		.where(sql`${uploadSessions.id} = ANY(${sql.param([...ids])}::text[])`);
}

/**
 * Marks uploaded sessions completed: presigned ones are still pending,
 * the others uploading. Returns the ids that moved.
 */
export async function completeUploadSessions(db: Db, ids: readonly string[]): Promise<string[]> {
	if (ids.length === 0) return [];
	const rows = await db
		.update(uploadSessions)
		.set({ status: "completed" })
		.where(
			and(
				sql`${uploadSessions.id} = ANY(${sql.param([...ids])}::text[])`,
				sql`${uploadSessions.status} IN ('pending', 'uploading')`,
			),
		)
		.returning({ id: uploadSessions.id });
	return rows.map((r) => r.id);
}

export async function findPublishedPaths(
	db: Db,
	cacheId: number,
	storePathHashes: readonly string[],
): Promise<PublishedPath[]> {
	if (storePathHashes.length === 0) return [];
	return db
		.select()
		.from(publishedPaths)
		.where(
			and(
				eq(publishedPaths.cacheId, cacheId),
				sql`${publishedPaths.storePathHash} = ANY(${sql.param([...storePathHashes])}::text[])`,
			),
		);
}

export async function findBlobObjectsByIds(db: Db, ids: readonly number[]): Promise<BlobObject[]> {
	if (ids.length === 0) return [];
	return db
		.select()
		.from(blobObjects)
		.where(sql`${blobObjects.id} = ANY(${sql.param([...ids])}::bigint[])`);
}

/** Records blobs not yet recorded, and returns every one of them. */
export async function ensureBlobObjects(
	db: Db,
	rows: ReadonlyArray<Parameters<typeof createBlobObject>[1]>,
): Promise<BlobObject[]> {
	if (rows.length === 0) return [];
	await db.insert(blobObjects).values([...rows]).onConflictDoNothing();
	const found = await db
		.select()
		.from(blobObjects)
		.where(sql`${blobObjects.fileHash} = ANY(${sql.param(rows.map((r) => r.fileHash))}::text[])`);
	return found.filter((b) => rows.some((r) => r.fileHash === b.fileHash && r.compression === b.compression));
}

/** Inserts paths not yet published; returns the store path hashes inserted. */
export async function createPublishedPaths(
	db: Db,
	rows: ReadonlyArray<Parameters<typeof createPublishedPath>[1]>,
): Promise<string[]> {
	if (rows.length === 0) return [];
	const inserted = await db
		.insert(publishedPaths)
		.values([...rows])
		.onConflictDoNothing()
		.returning({ storePathHash: publishedPaths.storePathHash });
	return inserted.map((r) => r.storePathHash);
}

/** The hashes among `storePathHashes` known to be served by one of `upstreams`. */
export async function findUpstreamHashes(
	db: Db,
	storePathHashes: readonly string[],
	upstreams: readonly string[],
): Promise<string[]> {
	if (storePathHashes.length === 0 || upstreams.length === 0) return [];
	const rows = await db
		.select({ storePathHash: upstreamPaths.storePathHash })
		.from(upstreamPaths)
		.where(
			and(
				sql`${upstreamPaths.storePathHash} = ANY(${sql.param([...storePathHashes])}::text[])`,
				sql`${upstreamPaths.upstream} = ANY(${sql.param([...upstreams])}::text[])`,
			),
		);
	return rows.map((r) => r.storePathHash);
}

export async function recordUpstreamPaths(
	db: Db,
	rows: ReadonlyArray<{ readonly storePathHash: string; readonly upstream: string }>,
): Promise<void> {
	if (rows.length === 0) return;
	await db.insert(upstreamPaths).values([...rows]).onConflictDoNothing();
}
