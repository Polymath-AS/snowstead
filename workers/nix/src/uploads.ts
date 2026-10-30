import * as v from "valibot";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import type { AuthIdentity } from "@snowstead/cache-core/auth";
import { hasCacheAccess, isOrgsToken } from "@snowstead/cache-core/jwt";
import {
	findCache,
	findCacheById,
	findUploadSession,
	findUploadSessions,
	transitionSessionStatus,
	transitionToMultipart,
	completeUploadSessions,
	upsertUploadPart,
	findUploadParts,
	ensureBlobObjects,
	findBlobObjectsByIds,
	createPublishedPaths,
	findPublishedPaths,
	findPublishedHashes,
	touchPublishedPaths,
	findOrg,
	withUploadSessionLock,
	sealUploadStream,
	abortUploadStream,
} from "@snowstead/cache-core/db/repository";
import { installStagedNar, INSTALLATION_BUSY, INSTALLATION_INCOMPLETE } from "@snowstead/cache-core/nar-install";
import type { UploadSession } from "@snowstead/cache-core/db/types";
import type { CacheAt, OrgUsage } from "@snowstead/cache-core/db/repository";
import { DEFAULT_ORG_ID } from "@snowstead/cache-core/db/schema";
import type { SessionResponse } from "@snowstead/cache-domain";
import { storeNarinfo, narinfoCacheKey } from "@snowstead/cache-core/narinfo";
import { scheduleNarinfoPurge } from "@snowstead/cache-core/cdn";
import { IMMUTABLE, bucketFor, bucketForKey, bucketNameForKey, narKey } from "@snowstead/cache-core/layout";
import { createPresignedPartPut, createPresignedPut } from "@snowstead/cache-core/presign";
import { PRIVATE_CACHES_REFUSED, isPrivateCache, privateCache } from "@snowstead/cache-core/visibility";
import { checkUpstream, knownUpstream } from "@snowstead/cache-core/upstream";
import { jsonResponse, errorResponse, messageOf } from "@snowstead/cache-core/responses";
import { Compression, FileHash, NarHash, StorePathBasename, StorePathHash, parseBody } from "@snowstead/cache-core/schemas";
import type { Db } from "@snowstead/cache-core/db/connection";
import { errorForLog } from "@snowstead/cache-core/logging";

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
	const session = await findUploadSession(config.db, sessionId);
	const denied = await sessionAccessError(config, session, identity);
	if (denied || !session) {
		return { error: errorResponse(denied?.error ?? "Not found", denied?.status ?? 404) };
	}
	return { session };
}

const MISSING = "Missing required fields";

type HashedSession = UploadSession & { fileHash: string };

function isLegacySession(session: UploadSession): session is HashedSession {
	return session.partSize === null && session.fileHash !== null;
}

function hasFileHash(session: UploadSession): session is HashedSession {
	return session.fileHash !== null;
}

/** A narinfo line's value: printable ASCII without spaces, or nothing. */
const NarinfoWord = (field: string) =>
	v.optional(v.nullable(v.pipe(v.string(`${field} must be printable ASCII without spaces`), v.regex(/^[!-~]+$/, `${field} must be printable ASCII without spaces`))), null);

const Size = (field: string) =>
	v.pipe(v.number("narSize and fileSize must be numbers"), v.finite(`${field} must be a positive number`), v.gtValue(0, `${field} must be a positive number`));

/** The session a client asks for. Each field becomes a narinfo line. */
const SessionParams = v.pipe(
	v.object({
		storePath: v.pipe(v.string(MISSING), v.nonEmpty(MISSING)),
		storePathHash: v.pipe(v.string(MISSING), v.nonEmpty(MISSING), StorePathHash),
		narHash: v.pipe(v.string(MISSING), v.nonEmpty(MISSING), NarHash),
		narSize: Size("narSize"),
		fileHash: v.pipe(v.string(MISSING), v.nonEmpty(MISSING), FileHash),
		fileSize: Size("fileSize"),
		compression: v.pipe(v.string(MISSING), v.nonEmpty(MISSING), Compression),
		references: v.nullish(v.array(StorePathBasename, "references must be an array"), []),
		deriver: NarinfoWord("deriver"),
		system: NarinfoWord("system"),
	}, MISSING),
	v.check(
		({ storePath, storePathHash }) => storePath.startsWith(`/nix/store/${storePathHash}-`) && v.is(StorePathBasename, storePath.slice(11)),
		"storePath must be /nix/store/<storePathHash>-<name>",
	),
);

type SessionParams = v.InferOutput<typeof SessionParams>;

/**
 * NARs are shared by every cache that has them, so a pusher may only add
 * one to its cache by showing it has the bytes: knowing a NAR's hash and
 * size, which its narinfo tells anyone who can read it, must not be enough
 * to claim another org's private NAR, nor to overwrite a shared one.
 *
 * Every new session uploads to its own staging key. The shared installer
 * verifies those bytes and serializes canonical writes, including large
 * multipart promotions. Only pre-existing sessions may still name a
 * canonical upload target; their completion path remains supported.
 */
const STAGING_PREFIX = "staging/";

function isStaged(session: Pick<UploadSession, "r2UploadKey">): boolean {
	return session.r2UploadKey?.startsWith(STAGING_PREFIX) ?? false;
}

function formatBytes(bytes: number): string {
	const units = ["bytes", "KB", "MB", "GB", "TB"];
	let value = bytes;
	let unit = 0;
	while (value >= 1000 && unit < units.length - 1) {
		value /= 1000;
		unit++;
	}
	return `${unit === 0 ? value : value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** Why a push was refused, in terms its pusher can act on. */
function storageFullResponse(usage: OrgUsage & { readonly limit: number; readonly requested: number }): Response {
	const inUse = usage.used + usage.pending;
	const left = Math.max(0, usage.limit - inUse);
	return errorResponse(
		`Not enough storage: this push needs ${formatBytes(usage.requested)}, and ${formatBytes(left)} of your ${formatBytes(usage.limit)} is left.`,
		507,
	);
}

/** Whether a pusher may push to this cache of its org. */
function orgAllows(identity: AuthIdentity, cache: CacheAt): boolean {
	return identity.kind !== "jwt" || (isOrgsToken(identity.claims, cache.orgId) && hasCacheAccess(identity.claims, cache));
}

/**
 * Records sessions for paths of one cache in one statement, and says where
 * each NAR goes; the cache's org must have room for all of them.
 */
async function createSessions(
	config: WorkerConfig,
	cache: CacheAt,
	items: readonly SessionParams[],
): Promise<SessionResponse[] | Response> {
	if (!cache.protocols.includes("nix")) return errorResponse("Cache not found", 404);
	// Seed the ID → cache map so session-scoped requests skip the database lookup.
	cacheById.set(cache.id, cache);
	// Visibility controls admission; every new upload stages in the private bucket.
	const isPrivate = await isPrivateCache(config, cache.path);
	if (isPrivate && (await findOrg(config.db, cache.orgId))?.privateCaches === false) {
		return errorResponse(PRIVATE_CACHES_REFUSED, 403);
	}
	const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
	const presigning = Boolean(config.r2AccessKeyId && config.r2SecretAccessKey && config.r2Endpoint);

	const rows = await Promise.all(items.map(async (p) => {
		const id = crypto.randomUUID();
		const inParts = presigning && p.fileSize > PRESIGNED_PARTS_MIN_BYTES && p.fileSize <= PRESIGNED_PUT_MAX_BYTES;
		const r2UploadKey = `${STAGING_PREFIX}${id}`;
		const multipart = inParts ? await config.bucket.createMultipartUpload(r2UploadKey, {
			customMetadata: { [SESSION_METADATA]: id },
		}) : undefined;
		return {
			id,
			cacheId: cache.id,
			storePathHash: p.storePathHash,
			storePath: p.storePath,
			narHash: p.narHash,
			narSize: p.narSize,
			fileHash: p.fileHash,
			fileSize: p.fileSize,
			compression: p.compression,
			referencesJson: JSON.stringify(p.references),
			deriver: p.deriver,
			system: p.system,
			status: multipart ? ("uploading" as const) : ("pending" as const),
			r2UploadKey,
			r2UploadId: multipart?.uploadId ?? null,
			expiresAt,
		};
	}));
	const refused = await config.uploadCoordinator.getByName(cache.orgId, { locationHint: "weur" })
		.reserveNix(cache.orgId, rows);
	if (refused) {
		await Promise.allSettled(rows.flatMap((r) =>
			r.r2UploadId ? [config.bucket.resumeMultipartUpload(r.r2UploadKey, r.r2UploadId).abort()] : [],
		));
		return refused instanceof Response ? refused : storageFullResponse(refused);
	}

	return Promise.all(rows.map(async (row): Promise<SessionResponse> => {
		const expiresAt = row.expiresAt.toISOString();
		if (!config.r2AccessKeyId || !config.r2SecretAccessKey || !config.r2Endpoint || row.fileSize > PRESIGNED_PUT_MAX_BYTES) {
			return { sessionId: row.id, r2Key: row.r2UploadKey, uploadMethod: "direct", expiresAt };
		}
		if (row.r2UploadId) {
			const { r2Endpoint, r2AccessKeyId, r2SecretAccessKey } = config;
			const count = Math.ceil(row.fileSize / PART_SIZE_BYTES);
			const parts = await Promise.all(Array.from({ length: count }, async (_, i) => ({
				partNumber: i + 1,
				url: await createPresignedPartPut(
					r2Endpoint,
					r2AccessKeyId,
					r2SecretAccessKey,
					config.r2BucketName,
					row.r2UploadKey,
					row.r2UploadId ?? "",
					i + 1,
					SESSION_TTL_SECONDS,
				),
			})));
			return { sessionId: row.id, r2Key: row.r2UploadKey, uploadMethod: "presigned-parts", partSize: PART_SIZE_BYTES, parts, expiresAt };
		}
		// One PUT; R2 checks the bytes against the file hash itself.
		const put = await createPresignedPut(
			config.r2Endpoint,
			config.r2AccessKeyId,
			config.r2SecretAccessKey,
			bucketNameForKey(config, row.r2UploadKey),
			row.r2UploadKey,
			row.fileHash,
			SESSION_TTL_SECONDS,
			{ [SESSION_METADATA]: row.id },
			!isStaged(row),
		);
		return {
			sessionId: row.id,
			r2Key: row.r2UploadKey,
			uploadMethod: "presigned",
			uploadUrl: put.url,
			uploadHeaders: put.headers,
			expiresAt,
		};
	}));
}

export async function handleCreateSession(
	request: Request,
	config: WorkerConfig,
	cacheName: string,
	identity: AuthIdentity,
): Promise<Response> {
	const cache = await findCache(config.db, orgOfPusher(identity), cacheName);
	if (!cache) {
		return errorResponse("Cache not found", 404);
	}
	if (!orgAllows(identity, cache)) {
		return errorResponse("Forbidden", 403);
	}

	const params = await parseBody(request, SessionParams);
	if (params instanceof Response) return params;

	const sessions = await createSessions(config, cache, [params]);
	if (sessions instanceof Response) return sessions;
	return jsonResponse(sessions[0], 201);
}

/**
 * Sessions for many paths in one request, in the order asked; a pusher
 * otherwise pays a round trip to the database per path.
 */
export async function handleCreateSessions(
	request: Request,
	config: WorkerConfig,
	cacheName: string,
	identity: AuthIdentity,
): Promise<Response> {
	const cache = await findCache(config.db, orgOfPusher(identity), cacheName);
	if (!cache) {
		return errorResponse("Cache not found", 404);
	}
	if (!orgAllows(identity, cache)) {
		return errorResponse("Forbidden", 403);
	}

	const body = await parseBody(request, SessionBatch);
	if (body instanceof Response) return body;

	const sessions = await createSessions(config, cache, body.paths);
	if (sessions instanceof Response) return sessions;
	return jsonResponse({ sessions }, 201);
}

export async function handleMultipart(
	config: WorkerConfig,
	sessionId: string,
	identity: AuthIdentity,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	const session = result.session;
	if (!isLegacySession(session)) return errorResponse("Conflict", 409);

	if (session.status !== "pending" && session.status !== "uploading") {
		return errorResponse("Conflict", 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Internal error", 500);
	}
	if (session.r2UploadId) {
		return jsonResponse({ uploadId: session.r2UploadId, r2Key: session.r2UploadKey });
	}

	// New grants always stage, even when upgrading an old canonical session.
	const key = `${STAGING_PREFIX}${session.id}`;
	const multipart = await bucketForKey(config, key).createMultipartUpload(key, {
		customMetadata: { [SESSION_METADATA]: session.id },
	});

	const transitioned = await transitionToMultipart(config.db, session, multipart.uploadId, key);
	if (!transitioned) {
		try { await multipart.abort(); } catch { /* best effort */ }
		const current = await loadSessionWithAuthCheck(config, sessionId, identity);
		if (current.error) return current.error;
		if (current.session.status === "uploading" && current.session.r2UploadId && current.session.r2UploadKey) {
			return jsonResponse({ uploadId: current.session.r2UploadId, r2Key: current.session.r2UploadKey });
		}
		return errorResponse("Conflict", 409);
	}

	return jsonResponse({
		uploadId: multipart.uploadId,
		r2Key: key,
	});
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
	const session = result.session;
	if (session.partSize !== null) {
		return uploadStreamPart(request, config, session, partNumber);
	}
	if (!isLegacySession(session)) return errorResponse("Conflict", 409);

	if (session.status !== "uploading") {
		return errorResponse("Conflict", 409);
	}

	if (!session.r2UploadKey || !session.r2UploadId) {
		return errorResponse("Bad request", 400);
	}

	if (!request.body) {
		return errorResponse("Request body is empty", 400);
	}

	const multipart = bucketForKey(config, session.r2UploadKey).resumeMultipartUpload(session.r2UploadKey, session.r2UploadId);
	const uploadedPart = await multipart.uploadPart(partNumber, request.body);

	await upsertUploadPart(config.db, {
		sessionId,
		partNumber,
		etag: uploadedPart.etag,
		size: 0,
	});

	return jsonResponse({ partNumber, etag: uploadedPart.etag });
}

export async function handleUploadBlob(
	request: Request,
	config: WorkerConfig,
	sessionId: string,
	identity: AuthIdentity,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	const session = result.session;
	if (!isLegacySession(session)) return errorResponse("Conflict", 409);

	if ((session.status !== "pending" && session.status !== "uploading") || session.r2UploadId) {
		return errorResponse("Conflict", 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Internal error", 500);
	}

	if (!request.body) {
		return errorResponse("Request body is empty", 400);
	}

	// A canonical retry is create-only too. The caller can complete its own
	// earlier successful upload, or retarget this reservation to multipart.
	if (session.status === "pending") {
		const transitioned = await transitionSessionStatus(config.db, sessionId, "pending", "uploading");
		if (!transitioned) {
			// Re-read to check if someone else moved it to uploading (retry-safe)
			const current = await findUploadSession(config.db, sessionId);
			if (!current || current.status !== "uploading" || current.r2UploadId || current.r2UploadKey !== session.r2UploadKey) {
				return errorResponse("Conflict", 409);
			}
		}
	}

	// R2 rejects a body whose SHA-256 is not the session's file hash, as it
	// does for presigned uploads.
	const uploaded = await bucketForKey(config, session.r2UploadKey).put(session.r2UploadKey, request.body, {
		sha256: session.fileHash,
		httpMetadata: { contentType: "application/x-nix-nar", cacheControl: IMMUTABLE },
		customMetadata: { [SESSION_METADATA]: session.id },
		...(!isStaged(session) ? { onlyIf: { etagDoesNotMatch: "*" } } : {}),
	});
	if (!uploaded) return errorResponse("Precondition failed", 412);

	return jsonResponse({ uploaded: true, r2Key: session.r2UploadKey });
}

/** The object's metadata key naming the session that uploaded it. */
const SESSION_METADATA = "session";

/** Whether an object's bytes have this SHA-256, read through the Worker. */
async function hashesTo(bucket: R2Bucket, key: string, sha256Hex: string): Promise<boolean> {
	const object = await bucket.get(key);
	if (!object) return false;
	const digest = new crypto.DigestStream("SHA-256");
	await object.body.pipeTo(digest);
	return hex(await digest.digest) === sha256Hex;
}

/** Why the object a session uploaded is not the one it named, if it is not. */
async function uploadError(config: WorkerConfig, session: HashedSession): Promise<string | undefined> {
	if (!session.r2UploadKey) {
		return "Internal error";
	}
	const bucket = bucketForKey(config, session.r2UploadKey);
	const head = await bucket.head(session.r2UploadKey);
	// Another pusher's upload of the same NAR proves nothing about this one.
	if (!head || head.customMetadata?.[SESSION_METADATA] !== session.id) {
		return "Upload incomplete";
	}
	if (head.size !== session.fileSize) {
		return "File size mismatch";
	}
	// R2 checked a single upload against this hash already; an assembled one
	// it can't, so that's hashed here, and goes if it's wrong.
	const stored = head.checksums.sha256;
	if (stored ? hex(stored) !== session.fileHash : !(await hashesTo(bucket, session.r2UploadKey, session.fileHash))) {
		if (!stored) await bucket.delete(session.r2UploadKey);
		return "File hash mismatch";
	}
	return undefined;
}

export async function handleComplete(
	request: Request,
	config: WorkerConfig,
	sessionId: string,
	identity: AuthIdentity,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	const session = result.session;
	if (!isLegacySession(session)) return errorResponse("Conflict", 409);

	const body = await parseBody(request, v.object({ parts: v.optional(PartList) }, OBJECT));
	if (body instanceof Response) return body;
	const parts = body.parts?.length ? body.parts : (await findUploadParts(config.db, sessionId)).filter((p): p is typeof p & { etag: string } => p.etag !== null);
	const invalid = await completionError(config, session, parts);
	if (invalid) return errorResponse(invalid.error, invalid.status);

	const completed = await completeUploadSessions(config.db, [session]);
	if (!completed.includes(sessionId)) {
		return errorResponse("Conflict", 409);
	}

	return jsonResponse({ status: "completed" });
}

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
 * of them. Each narinfo is stored before its row: it only describes a NAR
 * already uploaded and verified, so serving it before the row exists is
 * harmless, while a row without its narinfo would be a path nobody can see.
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

	const existing = new Map(
		(await findPublishedPaths(config.db, cacheId, sessions.map((s) => s.storePathHash))).map((p) => [p.storePathHash, p]),
	);
	const fresh = sessions.filter((s) => !existing.has(s.storePathHash));
	const blobs = await ensureBlobObjects(config.db, fresh.map((s) => ({
		fileHash: s.fileHash,
		fileSize: s.fileSize,
		compression: s.compression,
		r2Key: narKey(s.fileHash, s.compression, isPrivate),
	})));
	const existingBlobs = await findBlobObjectsByIds(config.db, [...existing.values()].map((p) => p.blobObjectId));
	const blobFor = (fileHash: string, compression: string) =>
		blobs.find((b) => b.fileHash === fileHash && b.compression === compression);

	const results = new Map<string, PublishResult>();
	const rows: (Parameters<typeof createPublishedPaths>[1][number] & { readonly session: HashedSession })[] = [];
	await Promise.all(sessions.map(async (session) => {
		const known = existing.get(session.storePathHash);
		try {
			if (known) {
				// Publishing again rewrites the narinfo, so a publish that failed
				// between storing it and recording the row heals on retry.
				const blob = existingBlobs.find((b) => b.id === known.blobObjectId);
				if (blob) await storeNarinfo(config, cache, known, blob, isPrivate);
				results.set(session.id, { sessionId: session.id, storePathHash: session.storePathHash, published: true, alreadyExisted: true });
				return;
			}
			const blob = blobFor(session.fileHash, session.compression);
			if (!blob) {
				results.set(session.id, { sessionId: session.id, error: "Internal error", status: 500 });
				return;
			}
			const path = {
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
			};
			await storeNarinfo(config, cache, path, blob, isPrivate);
			rows.push({ ...path, session });
		} catch (err) {
			console.error("Failed to publish", { sessionId: session.id }, errorForLog(err));
			results.set(session.id, { sessionId: session.id, error: "Internal error", status: 500 });
		}
	}));

	const inserted = new Set(await withUploadSessionLock(config.db, async (tx) => {
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
		const kept = rows.filter((r) => !gone.has(r.session.id));
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
	}));
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

export async function handlePublish(
	config: WorkerConfig,
	sessionId: string,
	identity: AuthIdentity,
	origin: string,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	const session = result.session;
	if (!isLegacySession(session)) return errorResponse("Conflict", 409);

	if (session.status !== "completed") {
		return errorResponse("Conflict", 409);
	}

	const [published] = await publishSessions(config, session.cacheId, [session], origin);
	if ("error" in published) {
		return errorResponse(published.error, published.status);
	}
	return jsonResponse({ published: true, storePathHash: published.storePathHash, alreadyExisted: published.alreadyExisted });
}

const OBJECT = "Expected an object";
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

/** Shared by single completion and batch commit; batch state writes stay batched. */
async function completionError(config: WorkerConfig, session: HashedSession, parts: readonly Part[]): Promise<{ error: string; status: number } | undefined> {
	// Presigned PUTs leave the session pending until verification.
	if (session.status !== "uploading" && !(session.status === "pending" && !session.r2UploadId)) {
		return { error: "Conflict", status: 409 };
	}
	if (!session.r2UploadKey) return { error: "Internal error", status: 500 };
	if (session.r2UploadId && parts.length === 0) return { error: "Conflict", status: 409 };
	if (session.r2UploadId && !isStaged(session)) {
		await bucketForKey(config, session.r2UploadKey).resumeMultipartUpload(session.r2UploadKey, session.r2UploadId).complete([...parts]);
	}
	const error = isStaged(session) ? await promoteStaged(config, session, parts) : await uploadError(config, session);
	return error ? { error, status: error === INSTALLATION_BUSY || error === INSTALLATION_INCOMPLETE ? 503 : error === "Internal error" ? 500 : 400 } : undefined;
}

/** Assemble once, then verify and install through the shared canonical gate.
 * Keep the session's proof at staging until GC so interrupted installs retry.
 */
async function promoteStaged(config: WorkerConfig, session: HashedSession, parts: readonly Part[]): Promise<string | undefined> {
	const key = session.r2UploadKey ?? "";
	if (session.r2UploadId && !(await config.bucket.head(key))) {
		try {
			await config.bucket.resumeMultipartUpload(key, session.r2UploadId).complete([...parts]);
		} catch (err) {
			// Another finalizer may have completed this MPU concurrently.
			if (!(await config.bucket.head(key))) return `Upload incomplete: ${messageOf(err)}`;
		}
	}
	return installStagedNar(config, session);
}

/**
 * Completes and publishes many uploaded sessions in one request: what
 * /complete then /publish do for each, with a few statements for all of
 * them. Staged sessions name their parts in `parts`; other multipart
 * sessions must be completed first. Results come in the order asked, each
 * a publish's response or an error with its status.
 */
export async function handleCommit(
	request: Request,
	config: WorkerConfig,
	identity: AuthIdentity,
	origin: string,
): Promise<Response> {
	const body = await parseBody(request, Commit);
	if (body instanceof Response) return body;
	const sessionIds = [...new Set(body.sessionIds)];
	const parts = new Map(Object.entries(body.parts));

	const results = new Map<string, PublishResult>();
	const fail = (sessionId: string, error: string, status: number) => results.set(sessionId, { sessionId, error, status });

	const loaded = new Map((await findUploadSessions(config.db, sessionIds)).map((s) => [s.id, s]));
	const usable: HashedSession[] = [];
	for (const sessionId of sessionIds) {
		const session = loaded.get(sessionId);
		const denied = await sessionAccessError(config, session, identity);
		if (denied || !session) {
			fail(sessionId, denied?.error ?? "Not found", denied?.status ?? 404);
		} else if (!isLegacySession(session)) {
			fail(sessionId, "Conflict", 409);
		} else if (session.status !== "completed" && session.r2UploadId && !isStaged(session)) {
			// Proxied canonical multipart uploads must use /complete first.
			fail(sessionId, "Conflict", 409);
		} else {
			usable.push(session);
		}
	}

	const uploaded = usable.filter((s) => s.status !== "completed");
	// Installers release the idle request connection across storage transfers.
	// Do not close a sibling's SQL transaction while another install runs.
	const invalid: Awaited<ReturnType<typeof completionError>>[] = [];
	for (const session of uploaded) invalid.push(await completionError(config, session, parts.get(session.id) ?? []));
	const verified = uploaded.filter((s, i) => {
		const error = invalid[i];
		if (error) fail(s.id, error.error, error.status);
		return !error;
	});
	const moved = new Set(await completeUploadSessions(config.db, verified));
	for (const s of verified) {
		if (!moved.has(s.id)) fail(s.id, "Conflict", 409);
	}

	const byCache = new Map<number, HashedSession[]>();
	for (const s of usable) {
		if (results.has(s.id)) continue;
		byCache.set(s.cacheId, [...(byCache.get(s.cacheId) ?? []), s]);
	}
	for (const [cacheId, sessions] of byCache) {
		for (const published of await publishSessions(config, cacheId, sessions, origin)) {
			results.set(published.sessionId, published);
		}
	}

	return jsonResponse({ results: sessionIds.map((id) => results.get(id)) });
}

// R2 takes single PUTs up to 5 GiB; larger NARs use multipart uploads.
const PRESIGNED_PUT_MAX_BYTES = 5 * 1024 ** 3 - (1 << 20);
// Above this a NAR uploads in presigned parts of PART_SIZE_BYTES; R2 wants
// every part but the last the same size, and at least 5 MiB.
const PRESIGNED_PARTS_MIN_BYTES = 64 * 1024 ** 2;
const PART_SIZE_BYTES = 32 * 1024 ** 2;
const SESSION_TTL_SECONDS = 3600;
// How close to expiry a session must be for publishing to check its NAR is
// still there: clocks of the Worker and of the blob sweep can disagree a bit.
const EXPIRY_MARGIN_MS = 5 * 60 * 1000;
// Each path publishes with a handful of R2 and Cache API calls; 100 keeps a
// batch well inside a request's subrequest and Cache API limits.
const MAX_BATCH = 100;

const PATHS = `paths must be an array of 1 to ${MAX_BATCH} sessions`;

const SessionBatch = v.object({
	paths: v.pipe(v.array(SessionParams, PATHS), v.minLength(1, PATHS), v.maxLength(MAX_BATCH, PATHS)),
});

const SESSION_IDS = `sessionIds must be an array of 1 to ${MAX_BATCH} session ids`;

const Commit = v.object({
	sessionIds: v.pipe(v.array(v.string(SESSION_IDS), SESSION_IDS), v.minLength(1, SESSION_IDS), v.maxLength(MAX_BATCH, SESSION_IDS)),
	parts: v.optional(v.record(v.string(), PartList, "parts must map session ids to their parts"), {}),
}, OBJECT);

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
}), v.check(({ storePath, storePathHash }) =>
	storePath.startsWith(`/nix/store/${storePathHash}-`) && v.is(StorePathBasename, storePath.slice(11)),
"storePath must be /nix/store/<storePathHash>-<name>"));
const StreamBatch = v.object({
	paths: v.pipe(v.array(StreamPath), v.minLength(1), v.maxLength(MAX_BATCH)),
});
const StreamParts = v.object({ parts: v.pipe(v.array(v.object({
	partNumber: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(10_000)),
	size: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(1024 ** 3)),
})), v.minLength(1), v.maxLength(MAX_BATCH),
v.check((parts) => new Set(parts.map((p) => p.partNumber)).size === parts.length, "Duplicate part numbers")) });
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
	const rows = [];
	let reservationStarted = false;
	try {
		for (const path of body.paths) {
			const id = crypto.randomUUID();
			const r2UploadKey = `${STAGING_PREFIX}${id}`;
			const multipart = await config.bucket.createMultipartUpload(r2UploadKey, {
				customMetadata: { [SESSION_METADATA]: id },
			});
			rows.push({
				...path, id, cacheId: cache.id, fileHash: null, fileSize: 0,
				partSize: streamPartSize(path.narSize), referencesJson: JSON.stringify(path.references),
				system: null, status: "streaming" as const, r2UploadKey, r2UploadId: multipart.uploadId,
				expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000),
			});
		}
		reservationStarted = true;
		const refused = await config.uploadCoordinator.getByName(cache.orgId, { locationHint: "weur" }).reserveNix(cache.orgId, rows);
		if (!refused) return jsonResponse({ sessions: rows.map((r) => ({ sessionId: r.id, partSize: r.partSize })) }, 201);
		await Promise.allSettled(rows.map((r) => config.bucket.resumeMultipartUpload(r.r2UploadKey, r.r2UploadId).abort()));
		return refused instanceof Response ? refused : storageFullResponse(refused);
	} catch (error) {
		// A failed reservation can have committed. Leave uncertain rows and MPUs
		// to GC rather than aborting a session the caller could still retry.
		if (!reservationStarted) {
			await Promise.allSettled(rows.map((r) => config.bucket.resumeMultipartUpload(r.r2UploadKey, r.r2UploadId).abort()));
		}
		console.error("Failed to create upload streams", errorForLog(error));
		return errorResponse("Internal error", 500);
	}
}

export async function handleReserveUploadParts(
	request: Request, config: WorkerConfig, sessionId: string, identity: AuthIdentity,
): Promise<Response> {
	const loaded = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (loaded.error) return loaded.error;
	const session = loaded.session;
	if (session.partSize === null || session.status !== "streaming" || !session.r2UploadKey || !session.r2UploadId) {
		return errorResponse("Conflict", 409);
	}
	const body = await parseBody(request, StreamParts);
	if (body instanceof Response) return body;
	const cache = await resolveCache(config.db, session.cacheId);
	if (!cache) return errorResponse("Not found", 404);
	const refused = await config.uploadCoordinator.getByName(cache.orgId, { locationHint: "weur" })
		.reserveNixParts(cache.orgId, sessionId, body.parts);
	if (refused) {
		if (refused instanceof Response) return refused;
		return "error" in refused ? errorResponse(refused.error, refused.status) : storageFullResponse(refused);
	}
	const { r2Endpoint, r2AccessKeyId, r2SecretAccessKey } = config;
	const key = session.r2UploadKey;
	const uploadId = session.r2UploadId;
	const expiresIn = Math.max(1, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000));
	// The CLI sends only supplied headers on PUT. Return its credential only
	// for the same-origin authenticated proxy, never for an R2 presigned URL.
	const authorization = request.headers.get("authorization");
	const proxyHeaders = !r2Endpoint || !r2AccessKeyId || !r2SecretAccessKey
		? authorization ? { authorization } : {}
		: {};
	const parts = await Promise.all(body.parts.map(async ({ partNumber, size }) => ({
		partNumber,
		url: r2Endpoint && r2AccessKeyId && r2SecretAccessKey
			? await createPresignedPartPut(r2Endpoint, r2AccessKeyId, r2SecretAccessKey, config.r2BucketName, key, uploadId, partNumber, expiresIn, size)
			: new URL(`/_api/v1/uploads/${encodeURIComponent(sessionId)}/part/${partNumber}`, request.url).href,
		headers: { "content-length": String(size), ...proxyHeaders },
	})));
	return jsonResponse({ parts });
}

/** The proxy has the same immutable byte grant as a presigned part URL. */
async function uploadStreamPart(request: Request, config: WorkerConfig, session: UploadSession, partNumber: number): Promise<Response> {
	if (request.method !== "PUT") return new Response("Method Not Allowed", { status: 405, headers: { allow: "PUT" } });
	if (session.status !== "streaming" || !session.r2UploadKey || !session.r2UploadId) return errorResponse("Conflict", 409);
	const reserved = (await findUploadParts(config.db, session.id)).find((p) => p.partNumber === partNumber);
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
	const results = new Map<string, PublishResult | { sessionId: string; published: false; error: string; status: number }>();
	const usable: HashedSession[] = [];
	const fail = (sessionId: string, error: string, status: number) => results.set(sessionId, { sessionId, published: false, error, status });
	for (const upload of body.uploads) {
		const sessionId = upload.sessionId;
		try {
			const session = await findUploadSession(config.db, sessionId);
			const denied = await sessionAccessError(config, session, identity);
			if (denied || !session) {
				fail(sessionId, denied?.error ?? "Not found", denied?.status ?? 404);
				continue;
			}
			if (session.partSize === null) {
				fail(sessionId, "Conflict", 409);
				continue;
			}
			const sealed = await sealUploadStream(config.db, sessionId, upload);
			if ("error" in sealed) {
				fail(sessionId, sealed.error, sealed.status);
				continue;
			}
			if (!hasFileHash(sealed)) throw new Error("Sealed stream has no file hash");
			if (sealed.status !== "completed") {
				const error = await promoteStaged(config, sealed, upload.parts);
				if (error) {
					fail(sessionId, error, error === INSTALLATION_BUSY || error === INSTALLATION_INCOMPLETE ? 503 : 400);
					continue;
				}
			}
			usable.push(sealed);
		} catch (error) {
			console.error("Failed to finalize upload stream", { sessionId }, errorForLog(error));
			fail(sessionId, "Internal error", 500);
		}
	}
	const byCache = new Map<number, HashedSession[]>();
	for (const session of usable) byCache.set(session.cacheId, [...(byCache.get(session.cacheId) ?? []), session]);
	for (const [cacheId, sessions] of byCache) {
		try {
			// Publish together before releasing reservations, retaining the
			// batched protocol's database savings for small store paths.
			const published = await publishSessions(config, cacheId, sessions, origin);
			for (const result of published) results.set(result.sessionId, result);
			const successful = sessions.filter(s => {
				const result = results.get(s.id);
				return result && !("error" in result) && s.status !== "completed";
			});
			const completed = new Set(await completeUploadSessions(config.db, successful));
			// Another retry may have completed the same sealed session meanwhile.
			const raced = successful.filter(s => !completed.has(s.id));
			const current = new Map((await findUploadSessions(config.db, raced.map(s => s.id))).map(s => [s.id, s]));
			for (const session of raced) if (current.get(session.id)?.status !== "completed") fail(session.id, "Conflict", 409);
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
	const session = await abortUploadStream(config.db, sessionId);
	if (!session) return errorResponse("Conflict", 409);
	if (session.r2UploadKey && session.r2UploadId) {
		try { await config.bucket.resumeMultipartUpload(session.r2UploadKey, session.r2UploadId).abort(); }
		catch { /* Already aborted MPUs are absent; GC retries cleanup. */ }
	}
	if (session.r2UploadKey) await config.bucket.delete(session.r2UploadKey);
	return jsonResponse({ aborted: true });
}

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
