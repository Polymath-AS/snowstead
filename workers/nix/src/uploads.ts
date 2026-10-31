import * as v from "valibot";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import type { AuthIdentity } from "@snowstead/cache-core/auth";
import { hasCacheAccess, isOrgsToken } from "@snowstead/cache-core/jwt";
import {
	findCache,
	findCacheById,
	findUploadSessions,
	completeUploadSessions,
	ensureBlobObjects,
	findBlobObjectsByIds,
	createPublishedPaths,
	findPublishedPaths,
	findPublishedHashes,
	touchPublishedPaths,
	findOrg,
	lockUploadSessions,
	abortUploadStream,
} from "@snowstead/cache-core/db/repository";
import { installStagedNars, INSTALLATION_BUSY, INSTALLATION_INCOMPLETE } from "@snowstead/cache-core/nar-install";
import type { BlobObject, PublishedPath, UploadSession } from "@snowstead/cache-core/db/types";
import type { CacheAt } from "@snowstead/cache-core/db/repository";
import { DEFAULT_ORG_ID } from "@snowstead/cache-core/db/schema";
import { storeNarinfo, narinfoCacheKey } from "@snowstead/cache-core/narinfo";
import { scheduleNarinfoPurge } from "@snowstead/cache-core/cdn";
import { bucketFor, narKey } from "@snowstead/cache-core/layout";
import { createPresignedPartPut } from "@snowstead/cache-core/presign";
import { PRIVATE_CACHES_REFUSED, isPrivateCache, privateCache } from "@snowstead/cache-core/visibility";
import { checkUpstream, knownUpstream } from "@snowstead/cache-core/upstream";
import { jsonResponse, errorResponse, messageOf } from "@snowstead/cache-core/responses";
import { FileHash, NarHash, StorePathBasename, StorePathHash, parseBody, valueOf } from "@snowstead/cache-core/schemas";
import type { Db } from "@snowstead/cache-core/db/connection";
import { errorForLog } from "@snowstead/cache-core/logging";
import { bridgeUploadStreams, streamSessionId, streamSessionOrg } from "@snowstead/cache-core/upload-stream";
import type { StreamPart, StreamReceipt } from "@snowstead/cache-core/upload-stream";
import { CapacityError, withOrgCapacity } from "@snowstead/cache-core/capacity";

// Module-scope cache: cache ID → cache, with its path. Its access and
// visibility don't change once it has paths. Its path does when its org's
// slug changes, so publishing looks the cache up afresh, and the old path
// stays marked private for a private cache (slug-move.ts), which is all the
// session-scoped requests use it for. Avoids a database round trip on each
// of those.
const cacheById = new Map<number, CacheAt>();

async function resolveCache(
	db: Db,
	cacheId: number,
): Promise<CacheAt | undefined> {
	const cached = cacheById.get(cacheId);
	if (cached !== undefined) return cached;

	const row = await findCacheById(db, cacheId);
	if (!row) return undefined;

	cacheById.set(cacheId, row);
	return row;
}

/** The org whose caches a pusher's names refer to: its token's, or the default org's. */
function orgOfPusher(identity: AuthIdentity): string {
	return identity.kind === "jwt" ? (identity.claims.org ?? DEFAULT_ORG_ID) : DEFAULT_ORG_ID;
}

/** Why the caller may not use a loaded session, if they may not. */
async function sessionAccessError(
	config: WorkerConfig,
	session: UploadSession | undefined,
	identity: AuthIdentity,
): Promise<{ error: string; status: number } | undefined> {
	// Expiry is enforced at request time, not just via GC.
	if (!session || session.expiresAt <= new Date()) {
		return { error: "Not found", status: 404 };
	}
	const cache = await resolveCache(config.db, session.cacheId);
	if (!cache?.protocols.includes("nix")) return { error: "Not found", status: 404 };
	if (identity.kind === "jwt") {
		if (!hasCacheAccess(identity.claims, cache) || !isOrgsToken(identity.claims, cache.orgId)) {
			return { error: "Forbidden", status: 403 };
		}
	}
	return undefined;
}

/**
 * Load an upload session and verify the caller has access to its cache.
 * Bearer-token callers are trusted implicitly; JWT callers must hold
 * access to the cache the session belongs to.
 */
async function loadSessionWithAuthCheck(
	config: WorkerConfig,
	sessionId: string,
	identity: AuthIdentity,
): Promise<{ session: UploadSession; error?: never } | { session?: never; error: Response }> {
	const session = (await loadUploadSessions(config, [sessionId])).get(sessionId);
	const denied = await sessionAccessError(config, session, identity);
	if (denied || !session) {
		return { error: errorResponse(denied?.error ?? "Not found", denied?.status ?? 404) };
	}
	return { session };
}

async function loadUploadSessions(config: WorkerConfig, ids: readonly string[]): Promise<Map<string, UploadSession>> {
	const groups = new Map<string, string[]>();
	for (const id of ids) {
		const org = streamSessionOrg(id);
		if (!org) continue;
		groups.set(org, [...(groups.get(org) ?? []), id]);
	}
	const sessions: UploadSession[][] = await Promise.all([...groups].map(([org, ids]) =>
		config.uploadCoordinator.getByName(org, { locationHint: "weur" }).getStreams(ids)));
	// A missing SQLite session never falls back to independently writable SQL.
	return new Map(sessions.flat().map(s => [s.id, s]));
}

type HashedSession = UploadSession & { fileHash: string };

function hasFileHash(session: UploadSession): session is HashedSession {
	return session.fileHash !== null;
}

/** A narinfo line's value: printable ASCII without spaces, or nothing. */
const NarinfoWord = (field: string) =>
	v.optional(v.nullable(v.pipe(v.string(`${field} must be printable ASCII without spaces`), v.regex(/^[!-~]+$/, `${field} must be printable ASCII without spaces`))), null);

const STAGING_PREFIX = "staging/";

/** Whether a pusher may push to this cache of its org. */
function orgAllows(identity: AuthIdentity, cache: CacheAt): boolean {
	return identity.kind !== "jwt" || (isOrgsToken(identity.claims, cache.orgId) && hasCacheAccess(identity.claims, cache));
}

export async function handleUploadPart(
	request: Request,
	config: WorkerConfig,
	sessionId: string,
	partNumber: number,
	identity: AuthIdentity,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	return uploadStreamPart(request, config, result.session, partNumber);
}

/** The object's metadata key naming the session that uploaded it. */
const SESSION_METADATA = "session";

/**
 * Drops a cached 404 for a path just published, so it shows up at once
 * rather than after the negative TTL. The Cache API is per data center: this
 * clears the one handling the publish, where the pusher's own lookups land.
 */
async function forgetNarinfoMiss(origin: string, cachePath: string, storePathHash: string, privateGen: number | string | undefined): Promise<void> {
	const cache = await caches.open("snowstead-narinfo");
	await cache.delete(narinfoCacheKey(origin, cachePath, storePathHash, privateGen));
}

type PublishResult =
	| { readonly sessionId: string; readonly storePathHash: string; readonly published: true; readonly alreadyExisted?: true }
	| { readonly sessionId: string; readonly error: string; readonly status: number };

/**
 * Publishes completed sessions of one cache with a few statements for all
 * of them. Capacity admits verified NARs before exposing their narinfos.
 * The org lock covers publication and eviction; failed writes heal on retry.
 */
async function publishSessions(
	config: WorkerConfig,
	cacheId: number,
	sessions: readonly HashedSession[],
	origin: string,
): Promise<PublishResult[]> {
	// Fresh, not resolveCache's copy: narinfo goes to the cache's path now,
	// which an org's slug change moves (slug-move.ts).
	const cache = await findCacheById(config.db, cacheId);
	if (cache && !cache.protocols.includes("nix")) {
		return sessions.map((s) => ({ sessionId: s.id, error: "Not found", status: 404 }));
	}
	if (cache === undefined) {
		return sessions.map((s) => ({ sessionId: s.id, error: "Internal error", status: 500 }));
	}
	cacheById.set(cache.id, cache);
	const visibility = await privateCache(config, cache.path);
	const isPrivate = visibility.isPrivate;
	const privateGen = visibility.isPrivate ? visibility.gen : undefined;

	const existing = new Map<string, PublishedPath>();
	let existingBlobs: BlobObject[] = [];
	const blobs = await ensureBlobObjects(config.db, sessions.map((s) => ({
		fileHash: s.fileHash,
		fileSize: s.fileSize,
		compression: s.compression,
		r2Key: narKey(s.fileHash, s.compression, isPrivate),
	})));
	const blobFor = (fileHash: string, compression: string) =>
		blobs.find((b) => b.fileHash === fileHash && b.compression === compression);

	const results = new Map<string, PublishResult>();
	const rows: (Parameters<typeof createPublishedPaths>[1][number] & { readonly session: HashedSession })[] = [];
	for (const session of sessions) {
		const blob = blobFor(session.fileHash, session.compression);
		if (!blob) {
			results.set(session.id, { sessionId: session.id, error: "Internal error", status: 500 });
			continue;
		}
		rows.push({
			cacheId,
			storePathHash: session.storePathHash,
			storePath: session.storePath,
			narHash: session.narHash,
			narSize: session.narSize,
			blobObjectId: blob.id,
			referencesJson: session.referencesJson,
			deriver: session.deriver,
			system: session.system,
			signaturesJson: "[]",
			session,
		});
	}

	let inserted: Set<string>;
	try {
		inserted = new Set(await withOrgCapacity(config, cache.orgId,
			sessions.map(session => ({ cacheId, storePathHash: session.storePathHash })),
			async tx => {
				// Keep the deletion fence until the capacity transaction commits.
				await lockUploadSessions(tx);
				// Read under the org lock: a completed replay may have been evicted
				// since request admission and must insert its row again, not merely
				// rewrite an orphaned narinfo from a stale snapshot.
				for (const path of await findPublishedPaths(tx, cacheId, sessions.map(s => s.storePathHash))) existing.set(path.storePathHash, path);
				existingBlobs = await findBlobObjectsByIds(tx, [...existing.values()].map(p => p.blobObjectId));
				for (const session of sessions) if (existing.has(session.storePathHash)) {
					results.set(session.id, { sessionId: session.id, storePathHash: session.storePathHash, published: true, alreadyExisted: true });
				}
				// The blob sweep (gc.ts) deletes a NAR only once no live session names
				// it, so a live session's NAR is still there, and its path row keeps it
				// from now on. A session expiring by now may have lost its NAR, and its
				// blob row, to a sweep since it was verified: those are checked again,
				// here, where no sweep can run until the rows are in.
				const soon = new Date(Date.now() + EXPIRY_MARGIN_MS);
				const atRisk = rows.filter((r) => r.session.expiresAt <= soon);
				const gone = new Set<string>();
				const streams = rows.filter(r => r.session.partSize !== null);
				const currentStreams = new Map((await findUploadSessions(tx, streams.map(r => r.session.id))).map(s => [s.id, s]));
				for (const row of streams) {
					const current = currentStreams.get(row.session.id);
					if (!current || !["finalizing", "completed"].includes(current.status) || current.expiresAt <= new Date()) gone.add(row.session.id);
				}
				await Promise.all(atRisk.map(async (r) => {
					if (!(await bucketFor(config, isPrivate).head(narKey(r.session.fileHash, r.session.compression, isPrivate)))) gone.add(r.session.id);
				}));
				const kept = rows.filter((r) => !gone.has(r.session.id) && !existing.has(r.storePathHash));
				const current = await ensureBlobObjects(tx, kept.filter((r) => atRisk.includes(r)).map((r) => ({
					fileHash: r.session.fileHash,
					fileSize: r.session.fileSize,
					compression: r.session.compression,
					r2Key: narKey(r.session.fileHash, r.session.compression, isPrivate),
				})));
				for (const id of gone) {
					results.set(id, { sessionId: id, error: "Upload incomplete: the stored NAR is gone, push again", status: 400 });
				}
				return createPublishedPaths(tx, kept.map(({ session, ...row }) => ({
					...row,
					blobObjectId: current.find((b) => b.fileHash === session.fileHash && b.compression === session.compression)?.id ?? row.blobObjectId,
				})));
			}, { origin, afterAdmission: async () => {
				// Admit before exposing narinfo, holding the org lock through its
				// write so concurrent eviction cannot recreate a withdrawn path.
				// Retries repair failed external writes from the published row.
				await Promise.all(sessions.map(async session => {
					const result = results.get(session.id);
					if (result && "error" in result) return;
					const known = existing.get(session.storePathHash);
					const path = known ?? rows.find(row => row.session.id === session.id);
					const blob = known ? existingBlobs.find(blob => blob.id === known.blobObjectId) : blobFor(session.fileHash, session.compression);
					if (!path || !blob) return;
					try { await storeNarinfo(config, cache, path, blob, isPrivate); }
					catch (error) {
						console.error("Failed to store narinfo", { sessionId: session.id }, errorForLog(error));
						results.set(session.id, { sessionId: session.id, error: "Internal error", status: 500 });
					}
				}));
			} }));
	} catch (error) {
		if (!(error instanceof CapacityError)) throw error;
		return sessions.map(s => ({ sessionId: s.id, error: error.message, status: error.status }));
	}
	// Re-publishes also rewrite narinfo (for example after a key change),
	// and retries must invalidate even if a previous attempt inserted the row.
	const published = sessions.filter((s) => {
		const result = results.get(s.id);
		return result === undefined || "published" in result;
	}).map((s) => s.storePathHash);
	await Promise.all(published.map((hash) => forgetNarinfoMiss(origin, cache.path, hash, privateGen)));
	if (!isPrivate) await scheduleNarinfoPurge(config, cache.path, published);
	for (const session of sessions) {
		if (results.has(session.id)) continue;
		// A path that is not inserted was published by someone else meanwhile.
		results.set(session.id, inserted.has(session.storePathHash)
			? { sessionId: session.id, storePathHash: session.storePathHash, published: true }
			: { sessionId: session.id, storePathHash: session.storePathHash, published: true, alreadyExisted: true });
	}
	return sessions.map((s) => results.get(s.id) ?? { sessionId: s.id, error: "Internal error", status: 500 });
}

const PARTS = "parts must contain {partNumber (1–10000), etag} objects";
const UNIQUE_PARTS = "parts must have nonempty ETags and unique part numbers";

/** A multipart upload's parts, with ETags unquoted. */
const PartList = v.pipe(
	v.array(
		v.object({
			partNumber: v.pipe(v.number(PARTS), v.integer(PARTS), v.minValue(1, PARTS), v.maxValue(10_000, PARTS)),
			etag: v.pipe(v.string(PARTS), v.transform((etag) => etag.replace(/^"(.*)"$/, "$1"))),
		}, PARTS),
		"parts must be an array of at most 10000 parts",
	),
	v.maxLength(10_000, "parts must be an array of at most 10000 parts"),
	v.check((parts) => parts.every((p) => p.etag !== "") && new Set(parts.map((p) => p.partNumber)).size === parts.length, UNIQUE_PARTS),
);

type Part = v.InferOutput<typeof PartList>[number];

/** Keep the assembled proof at staging until GC so interrupted installs retry. */
async function assembleStaged(config: WorkerConfig, session: HashedSession, parts: readonly Part[]): Promise<string | undefined> {
	const key = session.r2UploadKey ?? "";
	if (session.r2UploadId) {
		try {
			await config.bucket.resumeMultipartUpload(key, session.r2UploadId).complete([...parts]);
		} catch (err) {
			// Probe only on recovery: a prior attempt or concurrent finalizer
			// may have completed this MPU before publication finished.
			if (!(await config.bucket.head(key))) return `Upload incomplete: ${messageOf(err)}`;
		}
	}
	return undefined;
}

const SESSION_TTL_SECONDS = 3600;
// How close to expiry a session must be for publishing to check its NAR is
// still there: clocks of the Worker and of the blob sweep can disagree a bit.
const EXPIRY_MARGIN_MS = 5 * 60 * 1000;
// Each path publishes with a handful of R2 and Cache API calls; 100 keeps a
// batch well inside a request's subrequest and Cache API limits.
const MAX_BATCH = 100;

const MAX_MISSING_PATHS_BATCH = 1000;

const MISSING_PATHS = "Missing required fields: cache, storePathHashes";

const MissingPathsQuery = v.object({
	cache: v.pipe(v.string(MISSING_PATHS), v.nonEmpty(MISSING_PATHS)),
	storePathHashes: v.pipe(
		v.array(v.string(), MISSING_PATHS),
		v.maxLength(MAX_MISSING_PATHS_BATCH, `storePathHashes exceeds maximum of ${MAX_MISSING_PATHS_BATCH}`),
	),
});

export async function handleGetMissingPaths(
	request: Request,
	config: WorkerConfig,
	identity: AuthIdentity,
): Promise<Response> {
	const body = await parseBody(request, MissingPathsQuery);
	if (body instanceof Response) return body;

	const cache = await findCache(config.db, orgOfPusher(identity), body.cache);
	if (!cache?.protocols.includes("nix")) {
		return errorResponse("Cache not found", 404);
	}

	if (identity.kind === "jwt" && (!hasCacheAccess(identity.claims, cache) || !orgAllows(identity, cache))) {
		return errorResponse("Forbidden", 403);
	}

	const existingHashes = await findPublishedHashes(config.db, cache.id, body.storePathHashes);
	// A push that still has these paths keeps them from retention.
	config.defer(touchPublishedPaths(config.db, cache.id, existingHashes, new Date()).catch((err) => {
		console.error("Failed to mark paths pushed", errorForLog(err));
	}));
	const existingSet = new Set(existingHashes);
	const absent = body.storePathHashes.filter((h) => !existingSet.has(h));
	// What an upstream serves is not missing: substituters have it already.
	// Answered from what the server has recorded, without asking an upstream:
	// the client checks the paths it doesn't know about itself, free of a
	// Worker's six connections at a time, and the server checks them after
	// the response, recording what it finds for every later push.
	const served = await knownUpstream(config, absent);
	const unchecked = config.upstreams.length > 0 ? absent.filter((h) => !served.has(h)) : [];
	if (unchecked.length > 0) {
		config.defer(checkUpstream(config, unchecked).catch((err) => console.error("Upstream check failed", errorForLog(err))));
	}

	return jsonResponse({
		// Still everything to push for clients that check nothing themselves.
		missing: absent.filter((h) => !served.has(h)),
		upstream: absent.filter((h) => served.has(h)),
		// Which of missing a client may look up in upstreams, and skip if found.
		unchecked,
		upstreams: config.upstreams,
	});
}

const MIB = 1024 ** 2;
const MAX_OBJECT_BYTES = 5 * 1024 ** 4;
const StreamSize = v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(MAX_OBJECT_BYTES));
const StreamPath = v.pipe(v.object({
	storePath: v.string(),
	storePathHash: StorePathHash,
	narHash: NarHash,
	narSize: StreamSize,
	compression: v.literal("zstd"),
	references: v.nullish(v.array(StorePathBasename), []),
	deriver: NarinfoWord("deriver"),
	inline: v.optional(v.boolean(), false),
}), v.check(({ storePath, storePathHash }) =>
	storePath.startsWith(`/nix/store/${storePathHash}-`) && v.is(StorePathBasename, storePath.slice(11)),
"storePath must be /nix/store/<storePathHash>-<name>"),
v.check(path => !path.inline || path.narSize <= MIB, "Inline NAR exceeds 1 MiB"));
const StreamBatch = v.object({
	paths: v.pipe(v.array(StreamPath), v.minLength(1), v.maxLength(MAX_BATCH)),
});
const StreamParts = v.object({ parts: v.pipe(v.array(v.object({
	partNumber: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(10_000)),
	size: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(1024 ** 3)),
})), v.minLength(1), v.maxLength(MAX_BATCH),
v.check((parts) => new Set(parts.map((p) => p.partNumber)).size === parts.length, "Duplicate part numbers")) });
const StreamPartsBatch = v.object({ uploads: v.pipe(v.array(v.object({
	sessionId: v.string(),
	// Validate each reservation independently, after authorization.
	parts: v.unknown(),
})), v.minLength(1), v.maxLength(MAX_BATCH),
v.check((uploads) => new Set(uploads.map(u => u.sessionId)).size === uploads.length, "Duplicate sessions")) });
const StreamFinalize = v.object({ uploads: v.pipe(v.array(v.object({
	sessionId: v.string(),
	narHash: NarHash,
	narSize: StreamSize,
	fileHash: FileHash,
	fileSize: StreamSize,
	parts: v.pipe(PartList, v.minLength(1)),
})), v.minLength(1), v.maxLength(MAX_BATCH),
v.check((uploads) => new Set(uploads.map((u) => u.sessionId)).size === uploads.length, "Duplicate sessions")) });

/** ZSTD_COMPRESSBOUND, rounded up to equal MiB parts within R2's limits. */
function streamPartSize(narSize: number): number {
	const bound = narSize + Math.floor(narSize / 256) + (narSize < 128 * 1024 ? Math.floor((128 * 1024 - narSize) / 2048) : 0);
	return Math.min(1024 ** 3, Math.max(8 * MIB, Math.ceil(bound / 10_000 / MIB) * MIB));
}

export async function handleCreateUploadStreams(
	request: Request, config: WorkerConfig, cacheName: string, identity: AuthIdentity,
): Promise<Response> {
	const cache = await findCache(config.db, orgOfPusher(identity), cacheName);
	if (!cache?.protocols.includes("nix")) return errorResponse("Cache not found", 404);
	if (!orgAllows(identity, cache)) return errorResponse("Forbidden", 403);
	const body = await parseBody(request, StreamBatch);
	if (body instanceof Response) return body;
	cacheById.set(cache.id, cache);
	if (await isPrivateCache(config, cache.path) && (await findOrg(config.db, cache.orgId))?.privateCaches === false) {
		return errorResponse(PRIVATE_CACHES_REFUSED, 403);
	}
	const rows: (UploadSession & { partSize: number; r2UploadKey: string; status: "streaming" })[] = [];
	let reservationStarted = false;
	try {
		const paths = body.paths.entries();
		const created = await Promise.allSettled(Array.from({ length: Math.min(4, body.paths.length) }, async () => {
			for (const [index, path] of paths) {
				const id = streamSessionId(cache.orgId);
				const r2UploadKey = `${STAGING_PREFIX}${id}`;
				const multipart = path.inline ? undefined : await config.bucket.createMultipartUpload(r2UploadKey, {
					customMetadata: { [SESSION_METADATA]: id },
				});
				rows[index] = {
					...path, id, cacheId: cache.id, fileHash: null, fileSize: 0,
					partSize: path.inline ? MIB : streamPartSize(path.narSize), referencesJson: JSON.stringify(path.references),
					system: null, status: "streaming" as const, r2UploadKey, r2UploadId: multipart?.uploadId ?? null,
					createdAt: new Date(),
					expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000),
				};
			}
		}));
		const failed = created.find(r => r.status === "rejected");
		if (failed?.status === "rejected") throw failed.reason;
		reservationStarted = true;
		const refused = await config.uploadCoordinator.getByName(cache.orgId, { locationHint: "weur" }).createStreams(cache.orgId, rows);
		if (!refused) return jsonResponse({ sessions: rows.map((r) => ({ sessionId: r.id, partSize: r.partSize, inline: r.r2UploadId === null })) }, 201);
		await Promise.allSettled(rows.filter(r => r.r2UploadId !== null).map((r) => config.bucket.resumeMultipartUpload(r.r2UploadKey, r.r2UploadId!).abort()));
		return refused;
	} catch (error) {
		// A failed reservation can have committed. Leave uncertain rows and MPUs
		// to GC rather than aborting a session the caller could still retry.
		if (!reservationStarted) {
			await Promise.allSettled(rows.filter(r => r.r2UploadId !== null).map((r) => config.bucket.resumeMultipartUpload(r.r2UploadKey, r.r2UploadId!).abort()));
		}
		console.error("Failed to create upload streams", errorForLog(error));
		return errorResponse("Internal error", 500);
	}
}

export async function handleReserveUploadParts(
	request: Request, config: WorkerConfig, sessionId: string, identity: AuthIdentity,
): Promise<Response> {
	const body = await parseBody(request, StreamParts);
	if (body instanceof Response) return body;
	const results = await reserveUploadParts(request, config, [{ sessionId, parts: body.parts }], identity);
	const result = results.get(sessionId)!;
	return result instanceof Response ? result : jsonResponse(result);
}

export async function handleReserveUploadPartsBatch(
	request: Request, config: WorkerConfig, identity: AuthIdentity,
): Promise<Response> {
	const body = await parseBody(request, StreamPartsBatch);
	if (body instanceof Response) return body;
	const reserved = await reserveUploadParts(request, config, body.uploads, identity);
	const results = await Promise.all(body.uploads.map(async ({ sessionId }) => {
		const result = reserved.get(sessionId)!;
		return result instanceof Response
			? { sessionId, error: (await result.json<{ error: string }>()).error, status: result.status }
			: { sessionId, ...result };
	}));
	return jsonResponse({ results });
}

type PartGrants = { parts: { partNumber: number; url: string; headers: Record<string, string> }[] };

async function reserveUploadParts(
	request: Request, config: WorkerConfig, inputs: readonly { sessionId: string; parts: unknown }[], identity: AuthIdentity,
): Promise<Map<string, PartGrants | Response>> {
	const results = new Map<string, PartGrants | Response>();
	const sessions = await loadUploadSessions(config, inputs.map(i => i.sessionId));
	const groups = new Map<string, { sessionId: string; parts: v.InferOutput<typeof StreamParts>["parts"] }[]>();
	// Finish all authorization checks before invoking any coordinator or signer.
	for (const input of inputs) {
		const session = sessions.get(input.sessionId);
		const denied = await sessionAccessError(config, session, identity);
		if (denied || !session) {
			results.set(input.sessionId, errorResponse(denied?.error ?? "Not found", denied?.status ?? 404));
			continue;
		}
		if (session.r2UploadId === null) {
			results.set(input.sessionId, errorResponse("Not a multipart upload", 409));
			continue;
		}
		const parsed = v.safeParse(StreamParts, { parts: input.parts });
		if (!parsed.success) {
			results.set(input.sessionId, errorResponse("Invalid part reservations", 400));
			continue;
		}
		const cache = await resolveCache(config.db, session.cacheId);
		if (!cache) {
			results.set(input.sessionId, errorResponse("Not found", 404));
			continue;
		}
		const group = groups.get(cache.orgId) ?? [];
		group.push({ sessionId: input.sessionId, parts: parsed.output.parts });
		groups.set(cache.orgId, group);
	}
	await Promise.all([...groups].map(async ([orgId, uploads]) => {
		try {
			const coordinator = config.uploadCoordinator.getByName(orgId, { locationHint: "weur" });
			const reserved = await coordinator.reserveStreamParts(uploads);
			for (const input of uploads) {
				if (!reserved.has(input.sessionId)) throw new Error("Missing reservation result");
				const refused = reserved.get(input.sessionId);
				if (refused) {
					results.set(input.sessionId, errorResponse(refused.error, refused.status));
				} else {
					results.set(input.sessionId, await partGrants(request, config, sessions.get(input.sessionId)!, input.parts));
				}
			}
		} catch (error) {
			console.error("Failed to reserve upload parts", errorForLog(error));
			for (const input of uploads) if (!results.has(input.sessionId)) results.set(input.sessionId, errorResponse("Internal error", 500));
		}
	}));
	return results;
}

async function partGrants(
	request: Request, config: WorkerConfig, session: UploadSession, reservations: readonly { partNumber: number; size: number }[],
): Promise<PartGrants> {
	const { r2Endpoint, r2AccessKeyId, r2SecretAccessKey } = config;
	const key = session.r2UploadKey!;
	const uploadId = session.r2UploadId!;
	const expiresIn = Math.max(1, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000));
	// The CLI sends only supplied headers on PUT. Return its credential only
	// for the same-origin authenticated proxy, never for an R2 presigned URL.
	const authorization = request.headers.get("authorization");
	const proxyHeaders: Record<string, string> = !r2Endpoint || !r2AccessKeyId || !r2SecretAccessKey
		? authorization ? { authorization } : {}
		: {};
	const parts = await Promise.all(reservations.map(async ({ partNumber, size }) => ({
		partNumber,
		url: r2Endpoint && r2AccessKeyId && r2SecretAccessKey
			? await createPresignedPartPut(r2Endpoint, r2AccessKeyId, r2SecretAccessKey, config.r2BucketName, key, uploadId, partNumber, expiresIn, size)
			: new URL(`/_api/v1/uploads/${encodeURIComponent(session.id)}/part/${partNumber}`, request.url).href,
		headers: { "content-length": String(size), ...proxyHeaders },
	})));
	return { parts };
}

/** The proxy has the same immutable byte grant as a presigned part URL. */
async function uploadStreamPart(request: Request, config: WorkerConfig, session: UploadSession, partNumber: number): Promise<Response> {
	if (request.method !== "PUT") return new Response("Method Not Allowed", { status: 405, headers: { allow: "PUT" } });
	if (session.status !== "streaming" || !session.r2UploadKey || !session.r2UploadId) return errorResponse("Conflict", 409);
	const org = streamSessionOrg(session.id);
	if (!org) return errorResponse("Not found", 404);
	const parts = await config.uploadCoordinator.getByName(org, { locationHint: "weur" }).getStreamParts(session.id);
	const reserved = parts.find((p) => p.partNumber === partNumber);
	if (!reserved || request.headers.get("content-length") !== String(reserved.size) || !request.body) {
		return errorResponse("Part must match its reserved content-length", 400);
	}
	const fixed = new FixedLengthStream(reserved.size);
	const piping = request.body.pipeTo(fixed.writable);
	// Attach a rejection handler immediately, even if R2 fails before reading.
	void piping.catch(() => {});
	try {
		const part = await config.bucket.resumeMultipartUpload(session.r2UploadKey, session.r2UploadId)
			.uploadPart(partNumber, fixed.readable);
		await piping;
		return jsonResponse({ partNumber, etag: part.etag }, 200, { etag: `"${part.etag}"` });
	} catch (error) {
		// Cancel a blocked upstream transfer if R2 rejects before consuming it.
		await fixed.readable.cancel().catch(() => {});
		throw error;
	}
}

export async function handleFinalizeUploadStreams(
	request: Request, config: WorkerConfig, identity: AuthIdentity, origin: string,
): Promise<Response> {
	const body = await parseBody(request, StreamFinalize);
	if (body instanceof Response) return body;
	const loaded = await loadUploadSessions(config, body.uploads.map(upload => upload.sessionId));
	return finalizeUploadStreams(config, identity, origin, body, loaded);
}

/** One bounded binary request replaces reserve, part PUT, and finalize for tiny NARs. */
export async function handleInlineUpload(
	request: Request, config: WorkerConfig, sessionId: string, identity: AuthIdentity,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	const session = result.session;
	if (session.r2UploadId !== null || session.partSize !== MIB || session.narSize > MIB) return errorResponse("Not an inline upload", 409);
	const fileHash = valueOf(FileHash, new URL(request.url).searchParams.get("fileHash"));
	if (!fileHash) return errorResponse("Invalid file hash", 400);
	const length = request.headers.get("content-length");
	if (length === null) return errorResponse("Content-Length required", 411);
	const size = Number(length);
	if (!Number.isSafeInteger(size) || size < 1) return errorResponse("Invalid Content-Length", 400);
	if (size > MIB) return errorResponse("Inline upload exceeds 1 MiB", 413);
	if (!request.body) return errorResponse("Upload body required", 400);
	// Do not trust Content-Length to bound a buffered read. Cancel immediately
	// on excess bytes, and never allocate more than the admitted object size.
	const bytes = new Uint8Array(size);
	let offset = 0;
	try {
		await request.body.pipeTo(new WritableStream<Uint8Array>({
			write(chunk) {
				if (offset + chunk.byteLength > size) throw new Error("File size mismatch");
				bytes.set(chunk, offset);
				offset += chunk.byteLength;
			},
		}));
	} catch { return errorResponse("File size mismatch", 400); }
	if (offset !== size) return errorResponse("File size mismatch", 400);
	const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(byte => byte.toString(16).padStart(2, "0")).join("");
	if (hash !== fileHash) return errorResponse("File hash mismatch", 400);
	const response = await finalizeUploadStreams(config, identity, new URL(request.url).origin, { uploads: [{
		sessionId, narHash: session.narHash, narSize: session.narSize, fileHash, fileSize: size,
		parts: [{ partNumber: 1, etag: fileHash }],
	}] }, new Map([[sessionId, session]]), bytes.buffer);
	const { results } = await response.json<{ results: PublishResult[] }>();
	return jsonResponse(results[0]);
}

async function finalizeUploadStreams(
	config: WorkerConfig, identity: AuthIdentity, origin: string,
	body: { uploads: StreamReceipt[] }, loaded: Map<string, UploadSession>, inlineBytes?: ArrayBuffer,
): Promise<Response> {
	const results = new Map<string, PublishResult | { sessionId: string; published: false; error: string; status: number }>();
	const usable: HashedSession[] = [];
	const fail = (sessionId: string, error: string, status: number) => results.set(sessionId, { sessionId, published: false, error, status });
	const authorized: typeof body.uploads = [];
	for (const upload of body.uploads) {
		const sessionId = upload.sessionId;
		try {
			const session = loaded.get(sessionId);
			const denied = await sessionAccessError(config, session, identity);
			if (denied || !session) {
				fail(sessionId, denied?.error ?? "Not found", denied?.status ?? 404);
				continue;
			}
			if (session.partSize === null || (session.r2UploadId === null) !== (inlineBytes !== undefined)) {
				fail(sessionId, "Conflict", 409);
				continue;
			}
			authorized.push(upload);
		} catch (error) {
			console.error("Failed to finalize upload stream", { sessionId }, errorForLog(error));
			fail(sessionId, "Internal error", 500);
		}
	}
	try {
		// Seal locally first. SQL imports exact immutable receipts once, before
		// the existing global installation/GC fence may see canonical bytes.
		const sealed = new Map<string, UploadSession | { error: string; status: number }>();
		const orgs = new Set(authorized.map(u => streamSessionOrg(u.sessionId)).filter(org => org !== undefined));
		for (const org of orgs) {
			const batch = authorized.filter(u => streamSessionOrg(u.sessionId) === org);
			const coordinator = config.uploadCoordinator.getByName(org, { locationHint: "weur" });
			const local = inlineBytes === undefined ? await coordinator.sealStreams(batch) : await coordinator.sealInlineStreams(batch);
			const ready: { session: UploadSession; parts: StreamPart[] }[] = [];
			for (const [id, result] of local) {
				if ("error" in result) sealed.set(id, result);
				else { ready.push(result); sealed.set(id, result.session); }
			}
			// SQL may already have committed publication before the DO saw its ack.
			for (const [id, session] of await bridgeUploadStreams(config.db, ready)) sealed.set(id, session);
		}
		await config.releaseDb();
		const pending: (HashedSession & { inlineBytes?: ArrayBuffer })[] = [];
		const uploads = authorized.values();
		await Promise.all(Array.from({ length: Math.min(4, authorized.length) }, async () => {
			for (const upload of uploads) {
				const session = sealed.get(upload.sessionId)!;
				if ("error" in session) {
					fail(upload.sessionId, session.error, session.status);
					continue;
				}
				if (!hasFileHash(session)) throw new Error("Sealed stream has no file hash");
				if (session.status === "completed") {
					usable.push(session);
					continue;
				}
				if (inlineBytes !== undefined) {
					pending.push({ ...session, inlineBytes });
					continue;
				}
				try {
					const error = await assembleStaged(config, session, upload.parts);
					if (error) fail(session.id, error, 400);
					else pending.push(session);
				} catch (error) {
					console.error("Failed to assemble upload stream", { sessionId: session.id }, errorForLog(error));
					fail(session.id, "Internal error", 500);
				}
			}
		}));
		const installed = await installStagedNars(config, pending);
		for (const session of pending) {
			const error = installed.get(session.id);
			if (error) fail(session.id, error, error === INSTALLATION_BUSY || error === INSTALLATION_INCOMPLETE ? 503 : 400);
			else usable.push(session);
		}
	} catch (error) {
		console.error("Failed to finalize upload streams", errorForLog(error));
		for (const upload of authorized) if (!results.has(upload.sessionId)) fail(upload.sessionId, "Internal error", 500);
	}
	const byCache = new Map<number, HashedSession[]>();
	for (const session of usable) byCache.set(session.cacheId, [...(byCache.get(session.cacheId) ?? []), session]);
	for (const [cacheId, sessions] of byCache) {
		try {
			// Publish together before releasing reservations, retaining the
			// batched protocol's database savings for small store paths.
			const published = await publishSessions(config, cacheId, sessions, origin);
			for (const result of published) results.set(result.sessionId, result);
			const publishedSessions = sessions.filter(s => {
				const result = results.get(s.id);
				return result && !("error" in result);
			});
			const successful = publishedSessions.filter(s => s.status !== "completed");
			const completed = new Set(await completeUploadSessions(config.db, successful));
			// Another retry may have completed the same sealed session meanwhile.
			const raced = successful.filter(s => !completed.has(s.id));
			const current = new Map((await findUploadSessions(config.db, raced.map(s => s.id))).map(s => [s.id, s]));
			for (const session of raced) if (current.get(session.id)?.status !== "completed") fail(session.id, "Conflict", 409);
			const org = sessions.map(s => streamSessionOrg(s.id)).find(org => org !== undefined);
			if (org) await config.uploadCoordinator.getByName(org, { locationHint: "weur" })
				.completeStreams(publishedSessions.filter(s => streamSessionOrg(s.id) === org && !("error" in results.get(s.id)!)).map(s => s.id));
		} catch (error) {
			console.error("Failed to publish upload streams", { cacheId }, errorForLog(error));
			for (const session of sessions) fail(session.id, "Internal error", 500);
		}
	}
	return jsonResponse({ results: body.uploads.map(u => results.get(u.sessionId)) });
}

export async function handleAbortUploadStream(
	config: WorkerConfig, sessionId: string, identity: AuthIdentity,
): Promise<Response> {
	const loaded = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (loaded.error) return loaded.error;
	if (loaded.session.partSize === null) return errorResponse("Conflict", 409);
	const org = streamSessionOrg(sessionId);
	if (!org) return errorResponse("Not found", 404);
	if (!await config.uploadCoordinator.getByName(org, { locationHint: "weur" }).abortStream(sessionId)) return errorResponse("Conflict", 409);
	const session = await abortUploadStream(config.db, sessionId);
	if (!session) return errorResponse("Conflict", 409);
	if (session.r2UploadKey && session.r2UploadId) {
		try { await config.bucket.resumeMultipartUpload(session.r2UploadKey, session.r2UploadId).abort(); }
		catch { /* Already aborted MPUs are absent; GC retries cleanup. */ }
	}
	if (session.r2UploadKey) await config.bucket.delete(session.r2UploadKey);
	return jsonResponse({ aborted: true });
}
