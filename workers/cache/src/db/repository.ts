import { eq, and, notInArray, lt, gt, isNull, isNotNull, sql } from "drizzle-orm";
import type { Db } from "./connection.js";
import {
	caches,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
	apiTokens,
	auditLogs,
} from "./schema.js";
import type {
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
): Promise<{ cache: Cache; created: boolean }> {
	const inserted = await first(db.insert(caches).values({ name, isPublic }).onConflictDoNothing().returning());
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

export async function findUnreferencedBlobObjects(
	db: Db,
): Promise<BlobObject[]> {
	const referenced = db
		.select({ id: publishedPaths.blobObjectId })
		.from(publishedPaths);

	return db
		.select()
		.from(blobObjects)
		.where(notInArray(blobObjects.id, referenced));
}

export async function deleteBlobObject(
	db: Db,
	id: number,
): Promise<void> {
	await db.delete(blobObjects).where(eq(blobObjects.id, id));
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
): Promise<ApiToken[]> {
	return db.select().from(apiTokens);
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
