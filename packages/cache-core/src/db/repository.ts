import { eq, and, or, notInArray, inArray, lt, gt, gte, isNull, isNotNull, sql, desc } from "drizzle-orm";
import type { AnyColumn, SQL } from "drizzle-orm";
import type { Db } from "./connection.js";
import { cachePath } from "../cache-path.js";
import {
	orgs,
	orgApiKeys,
	caches,
	cacheSigningKeys,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
	apiTokens,
	tokenCaches,
	auditLogs,
	upstreamPaths,
	bandwidthDaily,
	goEntries,
	DEFAULT_ORG_ID,
} from "./schema.js";
import { CACHE_ID_PREFIX, cacheIdEntry } from "../jwt.js";
import type { NewCacheKey } from "../cache-keys.js";
import type {
	AuditLog,
	Org,
	OrgApiKey,
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

/**
 * `column = ANY($1)`, with the values as one array parameter: an IN list
 * with a placeholder per value costs Drizzle a type check per element to
 * build, which profiling showed dominating requests.
 */
function anyOf(column: AnyColumn, values: readonly (string | number)[], type: "text" | "bigint" = "text"): SQL {
	return sql`${column} = ANY(${sql.param([...values])}::${sql.raw(type)}[])`;
}

/** The first row of a write with RETURNING, which must produce one. */
async function returned<T>(rows: Promise<T[]>): Promise<T> {
	const [row] = await rows;
	if (row === undefined) {
		throw new Error("write returned no row");
	}
	return row;
}

/** A cache, with the path it's served at (cache-path.ts). */
export type CacheAt = Cache & { readonly path: string };

function located(row: { cache: Cache; slug: string }): CacheAt {
	return { ...row.cache, path: cachePath(row.slug, row.cache.name) };
}

function selectCachesAt(db: Db) {
	return db.select({ cache: caches, slug: orgs.slug }).from(caches).innerJoin(orgs, eq(caches.orgId, orgs.id));
}

/** An org's cache by its name. */
export async function findCache(db: Db, orgId: string, name: string): Promise<CacheAt | undefined> {
	const row = await first(selectCachesAt(db).where(and(eq(caches.orgId, orgId), eq(caches.name, name))).limit(1));
	return row && located(row);
}

/** The cache at a path, as a read names it. */
export async function findCacheByPath(db: Db, slug: string, name: string): Promise<CacheAt | undefined> {
	const row = await first(selectCachesAt(db).where(and(eq(orgs.slug, slug), eq(caches.name, name))).limit(1));
	return row && located(row);
}

export async function findCacheById(db: Db, id: number): Promise<CacheAt | undefined> {
	const row = await first(selectCachesAt(db).where(eq(caches.id, id)).limit(1));
	return row && located(row);
}

/** A cache of the default org, as a self-hosted install has them. */
export async function createCache(
	db: Db,
	name: string,
): Promise<CacheAt> {
	await db.insert(caches).values({ name });
	const cache = await findCache(db, DEFAULT_ORG_ID, name);
	if (!cache) throw new Error(`cache ${name} vanished`);
	return cache;
}

/** Creates the org's cache `name` unless it exists; returns the cache and whether it is new. */
export async function ensureCache(
	db: Db,
	name: string,
	isPublic = true,
	orgId: string = DEFAULT_ORG_ID,
): Promise<{ cache: CacheAt; created: boolean }> {
	const inserted = await first(db.insert(caches).values({ name, isPublic, orgId }).onConflictDoNothing().returning({ id: caches.id }));
	const cache = await findCache(db, orgId, name);
	if (!cache) throw new Error(`cache ${name} vanished`);
	return { cache, created: inserted !== undefined };
}

/** Gives a cache its own signing key, once. */
export async function setCacheSigningKey(
	db: Db,
	cacheId: number,
	key: NewCacheKey,
): Promise<void> {
	await db.transaction(async tx => {
		const updated = await tx.update(caches).set({
			signingKeyName: key.signingKeyName,
			signingPublicKey: key.signingPublicKey,
			signingKeySealed: key.signingKeySealed,
		}).where(and(eq(caches.id, cacheId), isNull(caches.signingKeySealed))).returning({ id: caches.id });
		if (updated.length) await tx.insert(cacheSigningKeys).values({ ...key, cacheId, state: "active" });
	});
}

export async function cacheHasPaths(db: Db, cacheId: number): Promise<boolean> {
	return (await first(db.select({ id: publishedPaths.id }).from(publishedPaths).where(eq(publishedPaths.cacheId, cacheId)).limit(1))) !== undefined;
}

/** Live Go entries and reservations both prevent changing shared visibility. */
export async function cacheHasGoEntries(db: Db, cacheId: number): Promise<boolean> {
	return (await first(db.select({ id: goEntries.id }).from(goEntries)
		.innerJoin(caches, eq(goEntries.cacheId, caches.id)).where(and(eq(caches.id, cacheId),
			eq(goEntries.generation, caches.goGeneration), gt(goEntries.expiresAt, new Date()),
		)).limit(1))) !== undefined;
}

export async function setCachePublic(db: Db, cacheId: number, isPublic: boolean): Promise<boolean> {
	return db.transaction(async tx => {
		// Go reservation and publication take this row's lock as well.
		const [cache] = await tx.select().from(caches).where(eq(caches.id, cacheId)).for("update");
		if (!cache || (cache.isPublic !== isPublic && await cacheHasGoEntries(tx, cacheId))) return false;
		await tx.update(caches).set({ isPublic }).where(eq(caches.id, cacheId));
		return true;
	});
}

/** Every cache, or one org's. */
export async function listCaches(db: Db, orgId?: string): Promise<CacheAt[]> {
	return (await selectCachesAt(db).where(orgId === undefined ? undefined : eq(caches.orgId, orgId)).orderBy(caches.id)).map(located);
}

export interface CacheStats {
	readonly cache: CacheAt;
	readonly paths: number;
	/** Bytes of the compressed NARs its paths point at; a NAR shared with another cache counts in both. */
	readonly size: number;
	readonly addedSince: number;
	readonly lastAddedAt: Date | null;
}

/** Every cache with its published paths counted, or just the one named, or an org's. */
export async function listCacheStats(db: Db, since: Date, filter: { name?: string; orgId?: string } = {}): Promise<CacheStats[]> {
	const rows = await db
		.select({
			cache: caches,
			slug: orgs.slug,
			paths: sql`${caches.pathCount}`.mapWith(Number),
			size: sql`${caches.size}`.mapWith(Number),
			addedSince: sql`count(${publishedPaths.id}) filter (where ${publishedPaths.createdAt} >= ${since.toISOString()}::timestamptz)`.mapWith(Number),
			lastAddedAt: sql<Date | null>`max(${publishedPaths.createdAt})`.mapWith(publishedPaths.createdAt),
		})
		.from(caches)
		.innerJoin(orgs, eq(caches.orgId, orgs.id))
		.leftJoin(publishedPaths, eq(publishedPaths.cacheId, caches.id))
		.where(and(
			filter.name === undefined ? undefined : eq(caches.name, filter.name),
			filter.orgId === undefined ? undefined : eq(caches.orgId, filter.orgId),
		))
		.groupBy(caches.id, orgs.slug)
		.orderBy(caches.name);
	return rows.map(({ slug, ...stats }) => ({ ...stats, cache: located({ cache: stats.cache, slug }) }));
}

export async function findOrg(db: Db, id: string): Promise<Org | undefined> {
	return first(db.select().from(orgs).where(eq(orgs.id, id)).limit(1));
}

/** The org that has this slug, or is still moving its caches away from it. */
export async function findOrgHoldingSlug(db: Db, slug: string): Promise<Org | undefined> {
	const row = await first(db.select({ id: orgs.id }).from(orgs).where(or(eq(orgs.slug, slug), eq(orgs.movingFrom, slug))).limit(1));
	return row && findOrg(db, row.id);
}

/** Gives the org a new slug, keeping the old one while its objects move (slug-move.ts). */
export async function startSlugMove(db: Db, id: string, slug: string, from: string): Promise<void> {
	await db.update(orgs).set({ slug, movingFrom: from }).where(eq(orgs.id, id));
}

export async function finishSlugMove(db: Db, id: string): Promise<void> {
	await db.update(orgs).set({ movingFrom: null }).where(eq(orgs.id, id));
}

/** Which of these store path hashes the cache still has published. */
export async function publishedHashes(db: Db, cacheId: number, hashes: readonly string[]): Promise<Set<string>> {
	if (hashes.length === 0) return new Set();
	const rows = await db.select({ hash: publishedPaths.storePathHash }).from(publishedPaths)
		.where(and(eq(publishedPaths.cacheId, cacheId), inArray(publishedPaths.storePathHash, [...hashes])));
	return new Set(rows.map((r) => r.hash));
}

/** Creates an org or updates only the supplied limits. */
export async function putOrg(db: Db, id: string, slug: string, limits: Partial<Pick<Org, "storageLimit" | "privateCaches" | "customSigningKeys">>): Promise<boolean> {
	// Arbitrate every unique constraint: simultaneous inserts of the same id
	// and slug can conflict on the slug index before the id index. A separate
	// UPDATE sees the winning row once ON CONFLICT has waited for it to commit.
	const inserted = await first(db.insert(orgs).values({ id, slug, ...limits }).onConflictDoNothing().returning({ id: orgs.id }));
	if (inserted) return true;
	// Undefined is omitted from SET: a stale registration must not replace a
	// concurrent limits update with creation defaults (or old limits).
	return (await db.update(orgs).set({ slug, ...limits }).where(eq(orgs.id, id)).returning({ id: orgs.id })).length > 0;
}

export async function listOrgs(db: Db): Promise<Pick<Org, "id" | "slug" | "storageLimit" | "privateCaches" | "customSigningKeys">[]> {
	return db.select({ id: orgs.id, slug: orgs.slug, storageLimit: orgs.storageLimit, privateCaches: orgs.privateCaches, customSigningKeys: orgs.customSigningKeys }).from(orgs).orderBy(orgs.id);
}

export async function createOrgApiKey(
	db: Db,
	params: { readonly id: string; readonly orgId: string; readonly name: string; readonly secretHash: string },
): Promise<OrgApiKey> {
	return returned(db.insert(orgApiKeys).values(params).returning());
}

export async function findOrgApiKey(db: Db, id: string): Promise<OrgApiKey | undefined> {
	return first(db.select().from(orgApiKeys).where(eq(orgApiKeys.id, id)).limit(1));
}

export async function listOrgApiKeys(db: Db, orgId: string): Promise<OrgApiKey[]> {
	return db.select().from(orgApiKeys).where(eq(orgApiKeys.orgId, orgId)).orderBy(orgApiKeys.createdAt);
}

/** Revokes the org's key; false when it has no such key, revoked or not. */
export async function revokeOrgApiKey(db: Db, orgId: string, id: string): Promise<boolean> {
	const key = await first(
		db.update(orgApiKeys)
			.set({ revokedAt: sql`coalesce(${orgApiKeys.revokedAt}, now())` })
			.where(and(eq(orgApiKeys.id, id), eq(orgApiKeys.orgId, orgId)))
			.returning({ id: orgApiKeys.id }),
	);
	return key !== undefined;
}

export interface OrgUsage {
	/** Bytes its caches hold, counted as in CacheStats.size. */
	readonly used: number;
	/** Bytes of uploads under way that would add to it. */
	readonly pending: number;
}

/** Operator-only totals. No customer names, paths, credentials, or identities. */
export async function globalOverview(db: Db, now: Date) {
	const [row] = await db.select({
		orgs: sql`(select count(*) from ${orgs})`.mapWith(Number),
		caches: sql`(select count(*) from ${caches})`.mapWith(Number),
		paths: sql`(select coalesce(sum(${caches.pathCount}), 0) from ${caches})`.mapWith(Number),
		storedBytes: sql`(select coalesce(sum(${caches.size}), 0) from ${caches})`.mapWith(Number),
		physicalStoredBytes: sql`(select coalesce(sum(${blobObjects.fileSize}), 0) from ${blobObjects})`.mapWith(Number),
		pendingBytes: sql`(select coalesce(sum(${uploadSessions.fileSize}), 0) from ${uploadSessions} where ${uploadSessions.status} in ('pending', 'uploading') and ${uploadSessions.expiresAt} > ${now})`.mapWith(Number),
		uploadsPending: sql`(select count(*) from ${uploadSessions} where ${uploadSessions.status} in ('pending', 'uploading') and ${uploadSessions.expiresAt} > ${now})`.mapWith(Number),
		privateServedThisMonth: sql`(select coalesce(sum(${bandwidthDaily.bytes}), 0) from ${bandwidthDaily} where ${bandwidthDaily.day} >= ${`${now.toISOString().slice(0, 7)}-01`})`.mapWith(Number),
		activeTokens: sql`(select count(*) from ${apiTokens} where ${apiTokens.revokedAt} is null and (${apiTokens.expiresAt} is null or ${apiTokens.expiresAt} > ${now}))`.mapWith(Number),
		apiKeys: sql`(select count(*) from ${orgApiKeys} where ${orgApiKeys.revokedAt} is null)`.mapWith(Number),
	}).from(sql`(select 1) as singleton`);
	return row;
}

export async function orgUsage(db: Db, orgId: string, now: Date): Promise<OrgUsage> {
	const [used, pending, go] = await Promise.all([
		first(
			db.select({ bytes: sql`coalesce(sum(${caches.size}), 0)`.mapWith(Number) })
				.from(caches)
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
		first(db.select({
			used: sql`coalesce(sum(${goEntries.size}) filter (where ${goEntries.uploadedAt} is not null), 0)`.mapWith(Number),
			pending: sql`coalesce(sum(${goEntries.size}) filter (where ${goEntries.uploadedAt} is null), 0)`.mapWith(Number),
		}).from(goEntries).innerJoin(caches, eq(goEntries.cacheId, caches.id)).where(and(
			eq(caches.orgId, orgId), eq(goEntries.generation, caches.goGeneration), gt(goEntries.expiresAt, now),
		))),
	]);
	return { used: (used?.bytes ?? 0) + (go?.used ?? 0), pending: (pending?.bytes ?? 0) + (go?.pending ?? 0) };
}

/** Adds bytes served for an org to its count for the UTC day of `now`. */
export async function recordBandwidth(db: Db, orgId: string, bytes: number, now: Date): Promise<void> {
	await db.insert(bandwidthDaily)
		.values({ orgId, day: now.toISOString().slice(0, 10), bytes })
		.onConflictDoUpdate({
			target: [bandwidthDaily.orgId, bandwidthDaily.day],
			set: { bytes: sql`${bandwidthDaily.bytes} + excluded.bytes` },
		});
}

/** Bytes served for an org in the UTC month of `now`. */
export async function bandwidthThisMonth(db: Db, orgId: string, now: Date): Promise<number> {
	const row = await first(
		db.select({ bytes: sql`coalesce(sum(${bandwidthDaily.bytes}), 0)`.mapWith(Number) })
			.from(bandwidthDaily)
			.where(and(eq(bandwidthDaily.orgId, orgId), gte(bandwidthDaily.day, `${now.toISOString().slice(0, 7)}-01`))),
	);
	return row?.bytes ?? 0;
}

/**
 * Serialize finite-quota reservations across protocols. Call inside the
 * transaction that records the reservation, before taking any cache locks.
 * A limit set on an unlimited org meanwhile applies from the next push.
 */
export async function lockOrgStorageLimit(tx: Db, org: Org): Promise<Org | undefined> {
	if (org.storageLimit === null) return org;
	await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + org.id}, 0))`);
	return findOrg(tx, org.id);
}

/** Check live Nix and Go usage while holding the finite-quota reservation lock. */
export async function checkOrgStorageLimit(
	db: Db,
	org: Org,
	requested: number,
): Promise<(OrgUsage & { readonly limit: number; readonly requested: number }) | undefined> {
	if (org.storageLimit === null) return undefined;
	const usage = await orgUsage(db, org.id, new Date());
	if (usage.used + usage.pending + requested > org.storageLimit) {
		return { ...usage, limit: org.storageLimit, requested };
	}
	return undefined;
}

/**
 * Records upload sessions for an org's cache unless they would take it past
 * its storage limit; returns the usage that refused them, or undefined once
 * they are recorded. Locked per org, so concurrent pushes can't both fit
 * into the same space. An org without a limit, such as a self-hosted
 * install's default org, takes no lock.
 */
export async function createUploadSessionsWithinLimit(
	db: Db,
	orgId: string,
	rows: Parameters<typeof createUploadSessions>[1],
): Promise<(OrgUsage & { readonly limit: number; readonly requested: number }) | undefined> {
	const org = await findOrg(db, orgId);
	if (org?.storageLimit == null) {
		// A limit set meanwhile applies from the next push.
		await createUploadSessions(db, rows);
		return undefined;
	}
	return db.transaction(async (tx) => {
		const current = await lockOrgStorageLimit(tx, org);
		const refused = current && await checkOrgStorageLimit(tx, current, rows.reduce((sum, r) => sum + r.fileSize, 0));
		if (refused) return refused;
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
	// The newest paths first, then their blobs: joining before the limit
	// looked up the blob of every path in the cache to keep `limit` of them.
	const recent = db
		.select({ storePath: publishedPaths.storePath, blobObjectId: publishedPaths.blobObjectId, createdAt: publishedPaths.createdAt, id: publishedPaths.id })
		.from(publishedPaths)
		.where(eq(publishedPaths.cacheId, cacheId))
		.orderBy(desc(publishedPaths.createdAt), desc(publishedPaths.id))
		.limit(limit)
		.as("recent");
	return db
		.select({ storePath: recent.storePath, fileSize: blobObjects.fileSize, createdAt: recent.createdAt })
		.from(recent)
		.innerJoin(blobObjects, eq(recent.blobObjectId, blobObjects.id))
		.orderBy(desc(recent.createdAt), desc(recent.id));
}

export type PathMatch = {
	id: number;
	storePath: string;
	storePathHash: string;
	fileSize: number;
	narSize: number;
	createdAt: Date;
	lastPushedAt: Date;
};

/**
 * A cache's paths whose name, the store path after its directory, contains
 * `query`, ignoring case: a hash prefix and a package name both match, and
 * /nix/store itself matches nothing. Every path when `query` is empty.
 * Newest first, `limit` at a time, below the id `before`.
 */
export async function searchPublishedPaths(
	db: Db,
	cacheId: number,
	query: string,
	limit: number,
	before?: number,
): Promise<PathMatch[]> {
	const pattern = `%${query.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
	return db
		.select({
			id: publishedPaths.id,
			storePath: publishedPaths.storePath,
			storePathHash: publishedPaths.storePathHash,
			fileSize: blobObjects.fileSize,
			narSize: publishedPaths.narSize,
			createdAt: publishedPaths.createdAt,
			lastPushedAt: publishedPaths.lastPushedAt,
		})
		.from(publishedPaths)
		.innerJoin(blobObjects, eq(publishedPaths.blobObjectId, blobObjects.id))
		.where(and(
			eq(publishedPaths.cacheId, cacheId),
			query === "" ? undefined : sql`regexp_replace(${publishedPaths.storePath}, '^.*/', '') ILIKE ${pattern}`,
			before === undefined ? undefined : lt(publishedPaths.id, before),
		))
		.orderBy(desc(publishedPaths.id))
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
): Promise<{ path: PublishedPath; blob: BlobObject; cache: CacheAt }[]> {
	const rows = await db
		.select({ path: publishedPaths, blob: blobObjects, cache: caches, slug: orgs.slug })
		.from(publishedPaths)
		.innerJoin(blobObjects, eq(publishedPaths.blobObjectId, blobObjects.id))
		.innerJoin(caches, eq(publishedPaths.cacheId, caches.id))
		.innerJoin(orgs, eq(caches.orgId, orgs.id))
		.where(gt(publishedPaths.id, afterId))
		.orderBy(publishedPaths.id)
		.limit(limit);
	return rows.map((r) => ({ path: r.path, blob: r.blob, cache: located(r) }));
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

	const rows = await db
		.select({ storePathHash: publishedPaths.storePathHash })
		.from(publishedPaths)
		.where(
			and(
				eq(publishedPaths.cacheId, cacheId),
				anyOf(publishedPaths.storePathHash, storePathHashes),
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
	r2UploadKey: string,
): Promise<UploadSession | undefined> {
	return first(
		db
			.update(uploadSessions)
			.set({ status: "uploading", r2UploadId, r2UploadKey })
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

/** Uploads may run together, but not across a canonical NAR deletion. */
export async function withUploadSessionLock<T>(db: Db, run: (db: Db) => Promise<T>): Promise<T> {
	return db.transaction(async (tx) => {
		await tx.execute(sql`lock table upload_sessions in row exclusive mode`);
		return run(tx);
	});
}

/**
 * Withdraw unreferenced NARs before committing their row deletion. On any
 * failure the rows remain as durable retry records. Fence session creation
 * and upload finalization until all external deletes have settled.
 */
export async function deleteUnreferencedBlobObjects(
	db: Db,
	limit: number,
	withdraw: (blobs: readonly BlobObject[]) => Promise<void>,
): Promise<BlobObject[]> {
	return db.transaction(async (tx) => {
		await tx.execute(sql`lock table upload_sessions in share mode`);
		const now = new Date();
		const unreferenced = tx
			.select({ id: blobObjects.id })
			.from(blobObjects)
			.where(and(
				sql`not exists (select 1 from ${publishedPaths} where ${publishedPaths.blobObjectId} = ${blobObjects.id})`,
				sql`not exists (select 1 from ${uploadSessions} where ${uploadSessions.fileHash} = ${blobObjects.fileHash} and ${uploadSessions.compression} = ${blobObjects.compression} and ${uploadSessions.expiresAt} > ${now.toISOString()}::timestamptz)`,
			))
			.limit(limit);
		const blobs = await tx.delete(blobObjects).where(inArray(blobObjects.id, unreferenced)).returning();
		await withdraw(blobs);
		return blobs;
	});
}

/**
 * Deletes a cache's published paths, the ones named or the oldest published
 * before a time, and returns the hashes it deleted. `withdraw` runs with the
 * rows deleted but not committed: if it fails, they stay.
 */
/** Which of a cache's paths to delete: named ones, or the oldest published or pushed before a time. */
export type PathSelection =
	| { readonly storePathHashes: readonly string[] }
	| { readonly before: Date; readonly limit: number }
	| { readonly lastPushedBefore: Date; readonly limit: number };

/**
 * Marks paths a push included as pushed today, which keeps them from
 * retention. Once a day at most per path, so pushes rarely write.
 */
export async function touchPublishedPaths(db: Db, cacheId: number, storePathHashes: readonly string[], now: Date): Promise<void> {
	if (storePathHashes.length === 0) return;
	await db.update(publishedPaths)
		.set({ lastPushedAt: now })
		.where(and(
			eq(publishedPaths.cacheId, cacheId),
			anyOf(publishedPaths.storePathHash, storePathHashes),
			lt(publishedPaths.lastPushedAt, new Date(now.getTime() - 24 * 60 * 60 * 1000)),
		));
}

export async function listCachesWithRetention(db: Db): Promise<CacheAt[]> {
	return (await selectCachesAt(db).where(isNotNull(caches.retentionDays)).orderBy(caches.id)).map(located);
}

export async function setCacheRetention(db: Db, cacheId: number, retentionDays: number | null): Promise<void> {
	await db.update(caches).set({ retentionDays }).where(eq(caches.id, cacheId));
}

export async function deletePublishedPaths(
	db: Db,
	cacheId: number,
	which: PathSelection,
	withdraw: (storePathHashes: readonly string[]) => Promise<void>,
): Promise<string[]> {
	return db.transaction(async (tx) => {
		const column = "lastPushedBefore" in which ? publishedPaths.lastPushedAt : publishedPaths.createdAt;
		const before = "lastPushedBefore" in which ? which.lastPushedBefore : "before" in which ? which.before : undefined;
		const match = "storePathHashes" in which
			? anyOf(publishedPaths.storePathHash, which.storePathHashes)
			: inArray(
				publishedPaths.id,
				tx.select({ id: publishedPaths.id })
					.from(publishedPaths)
					.where(and(eq(publishedPaths.cacheId, cacheId), lt(column, before ?? new Date(0))))
					.orderBy(column, publishedPaths.id)
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

/** Up to `limit` completed sessions past their expiry, which nothing reads again. */
export async function findExpiredCompletedSessions(db: Db, now: Date, limit: number): Promise<UploadSession[]> {
	return db.select().from(uploadSessions)
		.where(and(eq(uploadSessions.status, "completed"), lt(uploadSessions.expiresAt, now)))
		.limit(limit);
}

/** Deletes sessions and their parts. */
export async function deleteUploadSessions(db: Db, ids: readonly string[]): Promise<void> {
	if (ids.length === 0) return;
	await db.transaction(async (tx) => {
		await tx.delete(uploadParts).where(anyOf(uploadParts.sessionId, ids));
		await tx.delete(uploadSessions).where(anyOf(uploadSessions.id, ids));
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

/** A token with the entries of its caches claim, as token_caches records them. */
export type ApiTokenWithCaches = ApiToken & { readonly caches: string[] };

/** Records a token and its cache entries together, or neither. */
export async function createApiToken(
	db: Db,
	params: {
		readonly jti: string;
		readonly subject: string;
		readonly caches: readonly string[];
		readonly permsJson: string;
		readonly expiresAt: Date | null;
		readonly createdBy: string;
		readonly orgId?: string | null;
	},
): Promise<ApiTokenWithCaches> {
	const { caches: entries, ...token } = params;
	return db.transaction(async (tx) => {
		const row = await returned(tx.insert(apiTokens).values({ ...token, cachesJson: JSON.stringify(entries) }).returning());
		if (entries.length > 0) {
			await tx.insert(tokenCaches).values(entries.map((entry) => tokenCacheRow(params.jti, entry)));
		}
		return { ...row, caches: [...entries] };
	});
}

function tokenCacheRow(tokenJti: string, entry: string): typeof tokenCaches.$inferInsert {
	return entry.startsWith(CACHE_ID_PREFIX)
		? { tokenJti, cacheId: Number(entry.slice(CACHE_ID_PREFIX.length)) }
		: { tokenJti, pattern: entry };
}

/** The cache entries of tokens, by jti, in the order they were given. */
async function cacheEntriesOf(db: Db, jtis: readonly string[]): Promise<Map<string, string[]>> {
	const entries = new Map(jtis.map((jti) => [jti, [] as string[]]));
	if (jtis.length === 0) return entries;
	const rows = await db
		.select()
		.from(tokenCaches)
		.where(anyOf(tokenCaches.tokenJti, jtis))
		.orderBy(tokenCaches.id);
	for (const row of rows) {
		entries.get(row.tokenJti)?.push(row.cacheId === null ? (row.pattern ?? "") : cacheIdEntry(row.cacheId));
	}
	return entries;
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
): Promise<ApiTokenWithCaches[]> {
	const tokens = await db.select().from(apiTokens).where(orgId === undefined ? undefined : eq(apiTokens.orgId, orgId));
	const entries = await cacheEntriesOf(db, tokens.map((t) => t.jti));
	return tokens.map((t) => ({ ...t, caches: entries.get(t.jti) ?? [] }));
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
		.where(and(isNotNull(apiTokens.revokedAt), or(isNull(apiTokens.expiresAt), gt(apiTokens.expiresAt, now))));
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
		readonly orgId: string | null;
	},
): Promise<void> {
	// No RETURNING: audit inserts are fire-and-forget on the hot write path,
	// and skipping the row round trip keeps them as cheap as possible.
	await db.insert(auditLogs).values(params);
}

/** An org's audit entries, newest first, before the entry `before` when given. */
export async function listAuditLogs(db: Db, orgId: string, limit: number, before?: number): Promise<AuditLog[]> {
	return db.select().from(auditLogs)
		.where(and(eq(auditLogs.orgId, orgId), before === undefined ? undefined : lt(auditLogs.id, before)))
		.orderBy(desc(auditLogs.id))
		.limit(limit);
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
		.where(anyOf(uploadSessions.id, ids));
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
				anyOf(uploadSessions.id, ids),
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
				anyOf(publishedPaths.storePathHash, storePathHashes),
			),
		);
}

export async function findBlobObjectsByIds(db: Db, ids: readonly number[]): Promise<BlobObject[]> {
	if (ids.length === 0) return [];
	return db
		.select()
		.from(blobObjects)
		.where(anyOf(blobObjects.id, ids, "bigint"));
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
		.where(anyOf(blobObjects.fileHash, rows.map((r) => r.fileHash)));
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
				anyOf(upstreamPaths.storePathHash, storePathHashes),
				anyOf(upstreamPaths.upstream, upstreams),
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

/** Whether a path of the cache uses the NAR with this file hash. */
export async function cacheHasNar(db: Db, cacheId: number, fileHash: string, compression: string): Promise<boolean> {
	const row = await first(
		db
			.select({ id: publishedPaths.id })
			.from(publishedPaths)
			.innerJoin(blobObjects, eq(publishedPaths.blobObjectId, blobObjects.id))
			.where(and(eq(publishedPaths.cacheId, cacheId), eq(blobObjects.fileHash, fileHash), eq(blobObjects.compression, compression)))
			.limit(1),
	);
	return row !== undefined;
}

/**
 * Removes an emptied cache's row and its upload sessions. A session's
 * canonical upload is adopted as a blob object, as GC does for abandoned
 * ones, so the sweep deletes it once nothing points at it; staged uploads
 * are returned for the caller to delete. False when a path was published
 * since the cache was emptied: the row is locked first, so none can be
 * while this runs, and the caller empties it again.
 */
export async function deleteEmptyCache(db: Db, cacheId: number): Promise<{ deleted: boolean; staged: string[] }> {
	return db.transaction(async (tx) => {
		await tx.execute(sql`select id from ${caches} where ${caches.id} = ${cacheId} for update`);
		const [published] = await tx.select({ id: publishedPaths.id }).from(publishedPaths).where(eq(publishedPaths.cacheId, cacheId)).limit(1);
		if (published) return { deleted: false, staged: [] };

		const sessions = await tx.select().from(uploadSessions).where(eq(uploadSessions.cacheId, cacheId));
		const canonical = sessions.filter((s) => s.r2UploadKey !== null && !s.r2UploadKey.startsWith("staging/"));
		if (canonical.length > 0) {
			await tx.insert(blobObjects).values(canonical.map((s) => ({
				fileHash: s.fileHash, fileSize: s.fileSize, compression: s.compression, r2Key: s.r2UploadKey ?? "",
			}))).onConflictDoNothing();
		}
		if (sessions.length > 0) {
			await tx.delete(uploadParts).where(inArray(uploadParts.sessionId, sessions.map((s) => s.id)));
			await tx.delete(uploadSessions).where(eq(uploadSessions.cacheId, cacheId));
		}
		await tx.delete(caches).where(eq(caches.id, cacheId));
		return { deleted: true, staged: sessions.flatMap((s) => (s.r2UploadKey?.startsWith("staging/") ? [s.r2UploadKey] : [])) };
	});
}
