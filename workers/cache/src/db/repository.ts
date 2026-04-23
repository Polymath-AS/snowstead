import { eq, and, notInArray, lt, inArray } from "drizzle-orm";
import type { DrizzleD1Database } from "drizzle-orm/d1";
import {
	caches,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
} from "./schema.js";
import type {
	Cache,
	BlobObject,
	PublishedPath,
	UploadSession,
	UploadPart,
	GcMark,
	UploadSessionStatus,
} from "./types.js";

// ── Caches ──

export async function findCacheByName(
	db: DrizzleD1Database,
	name: string,
): Promise<Cache | undefined> {
	return db.select().from(caches).where(eq(caches.name, name)).get();
}

export async function createCache(
	db: DrizzleD1Database,
	name: string,
	isPublic: boolean,
): Promise<Cache> {
	return db
		.insert(caches)
		.values({ name, isPublic: isPublic ? 1 : 0 })
		.returning()
		.get();
}

// ── Blob Objects ──

export async function findBlobObject(
	db: DrizzleD1Database,
	fileHash: string,
	compression: string,
): Promise<BlobObject | undefined> {
	return db
		.select()
		.from(blobObjects)
		.where(and(eq(blobObjects.fileHash, fileHash), eq(blobObjects.compression, compression)))
		.get();
}

export async function findBlobObjectById(
	db: DrizzleD1Database,
	id: number,
): Promise<BlobObject | undefined> {
	return db.select().from(blobObjects).where(eq(blobObjects.id, id)).get();
}

export async function createBlobObject(
	db: DrizzleD1Database,
	params: {
		readonly fileHash: string;
		readonly fileSize: number;
		readonly compression: string;
		readonly r2Key: string;
	},
): Promise<BlobObject> {
	return db
		.insert(blobObjects)
		.values(params)
		.returning()
		.get();
}

// ── Published Paths ──

export async function findPublishedPath(
	db: DrizzleD1Database,
	cacheId: number,
	storePathHash: string,
): Promise<PublishedPath | undefined> {
	return db
		.select()
		.from(publishedPaths)
		.where(
			and(
				eq(publishedPaths.cacheId, cacheId),
				eq(publishedPaths.storePathHash, storePathHash),
			),
		)
		.get();
}

export async function createPublishedPath(
	db: DrizzleD1Database,
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
	return db
		.insert(publishedPaths)
		.values(params)
		.returning()
		.get();
}

export async function findPublishedHashes(
	db: DrizzleD1Database,
	cacheId: number,
	storePathHashes: string[],
): Promise<string[]> {
	if (storePathHashes.length === 0) return [];

	// D1 has a lower effective parameter limit than SQLite's 999
	const results: string[] = [];
	for (let i = 0; i < storePathHashes.length; i += 75) {
		const chunk = storePathHashes.slice(i, i + 75);
		const rows = await db
			.select({ storePathHash: publishedPaths.storePathHash })
			.from(publishedPaths)
			.where(
				and(
					eq(publishedPaths.cacheId, cacheId),
					inArray(publishedPaths.storePathHash, chunk),
				),
			)
			.all();

		for (const r of rows) {
			results.push(r.storePathHash);
		}
	}

	return results;
}

// ── Upload Sessions ──

export async function findUploadSession(
	db: DrizzleD1Database,
	sessionId: string,
): Promise<UploadSession | undefined> {
	return db
		.select()
		.from(uploadSessions)
		.where(eq(uploadSessions.id, sessionId))
		.get();
}

export async function createUploadSession(
	db: DrizzleD1Database,
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
		readonly expiresAt: string;
	},
): Promise<UploadSession> {
	return db
		.insert(uploadSessions)
		.values(params)
		.returning()
		.get();
}

export async function updateUploadSessionStatus(
	db: DrizzleD1Database,
	sessionId: string,
	status: UploadSessionStatus,
): Promise<UploadSession | undefined> {
	return db
		.update(uploadSessions)
		.set({ status })
		.where(eq(uploadSessions.id, sessionId))
		.returning()
		.get();
}

export async function findExpiredSessions(
	db: DrizzleD1Database,
	now: string,
): Promise<UploadSession[]> {
	return db
		.select()
		.from(uploadSessions)
		.where(
			and(
				notInArray(uploadSessions.status, ["completed", "expired"]),
				lt(uploadSessions.expiresAt, now),
			),
		)
		.all();
}

// ── Upload Parts ──

export async function createUploadPart(
	db: DrizzleD1Database,
	params: {
		readonly sessionId: string;
		readonly partNumber: number;
		readonly etag: string;
		readonly size: number;
	},
): Promise<UploadPart> {
	return db
		.insert(uploadParts)
		.values(params)
		.returning()
		.get();
}

export async function findUploadParts(
	db: DrizzleD1Database,
	sessionId: string,
): Promise<UploadPart[]> {
	return db
		.select()
		.from(uploadParts)
		.where(eq(uploadParts.sessionId, sessionId))
		.orderBy(uploadParts.partNumber)
		.all();
}

// ── Blob Object Cleanup ──

export async function findUnreferencedBlobObjects(
	db: DrizzleD1Database,
): Promise<BlobObject[]> {
	const referenced = db
		.select({ id: publishedPaths.blobObjectId })
		.from(publishedPaths);

	return db
		.select()
		.from(blobObjects)
		.where(notInArray(blobObjects.id, referenced))
		.all();
}

export async function deleteBlobObject(
	db: DrizzleD1Database,
	id: number,
): Promise<void> {
	await db.delete(blobObjects).where(eq(blobObjects.id, id)).run();
}

// ── Upload Session Cleanup ──

export async function deleteUploadSession(
	db: DrizzleD1Database,
	sessionId: string,
): Promise<void> {
	await db.delete(uploadParts).where(eq(uploadParts.sessionId, sessionId)).run();
	await db.delete(uploadSessions).where(eq(uploadSessions.id, sessionId)).run();
}

// ── GC Marks ──

export async function createGcMark(
	db: DrizzleD1Database,
	params: {
		readonly targetType: string;
		readonly targetId: string;
		readonly reason: string;
	},
): Promise<GcMark> {
	return db
		.insert(gcMarks)
		.values(params)
		.returning()
		.get();
}

export async function findGcMarks(
	db: DrizzleD1Database,
	targetType: string,
): Promise<GcMark[]> {
	return db
		.select()
		.from(gcMarks)
		.where(eq(gcMarks.targetType, targetType))
		.all();
}

export async function deleteGcMark(
	db: DrizzleD1Database,
	targetType: string,
	targetId: string,
): Promise<void> {
	await db
		.delete(gcMarks)
		.where(and(eq(gcMarks.targetType, targetType), eq(gcMarks.targetId, targetId)))
		.run();
}
