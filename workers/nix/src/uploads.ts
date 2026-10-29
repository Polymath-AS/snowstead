import * as v from "valibot";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import type { AuthIdentity } from "@snowstead/cache-core/auth";
import { hasCacheAccess, isOrgsToken } from "@snowstead/cache-core/jwt";
import {
	findCache,
	findCacheById,
	createUploadSessionsWithinLimit,
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
} from "@snowstead/cache-core/db/repository";
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
 * - A NAR stored already uploads to a staging key of the session's own, and
 *   is checked against the file hash before the session completes.
 * - So do large NARs in parts, whose assembled object R2 can't check.
 * - Any other upload goes to the NAR's key, where R2 checks the hash on the
 *   way in, tagged with its session: a session completes only on its own
 *   upload, never on one another pusher made meanwhile.
 *
 * The exception is a NAR too large for one PUT (over 5 GiB) that isn't
 * stored yet: R2 can't move it into place, so it assembles at its own key
 * and is hashed in the Worker before it completes, and deleted if wrong.
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
	// Straight into the bucket the cache is served from.
	const isPrivate = await isPrivateCache(config, cache.path);
	if (isPrivate && (await findOrg(config.db, cache.orgId))?.privateCaches === false) {
		return errorResponse(PRIVATE_CACHES_REFUSED, 403);
	}
	const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
	const presigning = Boolean(config.r2AccessKeyId && config.r2SecretAccessKey && config.r2Endpoint);

	const rows = await Promise.all(items.map(async (p) => {
		const id = crypto.randomUUID();
		const inParts = presigning && p.fileSize > PRESIGNED_PARTS_MIN_BYTES && p.fileSize <= PRESIGNED_PUT_MAX_BYTES;
		const target = narKey(p.fileHash, p.compression, isPrivate);
		const stored = !inParts && (await bucketFor(config, isPrivate).head(target)) !== null;
		const r2UploadKey = inParts || stored ? `${STAGING_PREFIX}${id}` : target;
		const multipart = inParts ? await config.bucket.createMultipartUpload(r2UploadKey) : undefined;
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
	const refused = await createUploadSessionsWithinLimit(config.db, cache.orgId, rows);
	if (refused) {
		await Promise.allSettled(rows.flatMap((r) =>
			r.r2UploadId ? [config.bucket.resumeMultipartUpload(r.r2UploadKey, r.r2UploadId).abort()] : [],
		));
		return storageFullResponse(refused);
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

	if (session.status !== "pending" && session.status !== "uploading") {
		return errorResponse("Conflict", 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Internal error", 500);
	}
	if (session.r2UploadId) {
		return jsonResponse({ uploadId: session.r2UploadId, r2Key: session.r2UploadKey });
	}

	// Parts assemble at a staging key, unless the NAR is too large to move
	// into place from one; then at its own key, hashed when it completes.
	const key = isStaged(session) || session.fileSize <= PRESIGNED_PUT_MAX_BYTES ? `${STAGING_PREFIX}${session.id}` : session.r2UploadKey;
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
async function uploadError(config: WorkerConfig, session: UploadSession): Promise<string | undefined> {
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

	const body = await parseBody(request, v.object({ parts: v.optional(PartList) }, OBJECT));
	if (body instanceof Response) return body;
	const parts = body.parts?.length ? body.parts : await findUploadParts(config.db, sessionId);
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
	sessions: readonly UploadSession[],
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
	const rows: (Parameters<typeof createPublishedPaths>[1][number] & { readonly session: UploadSession })[] = [];
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
async function completionError(config: WorkerConfig, session: UploadSession, parts: readonly Part[]): Promise<{ error: string; status: number } | undefined> {
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
	return error ? { error, status: error === "Internal error" ? 500 : 400 } : undefined;
}

/**
 * Checks this session's own staged bytes, assembling parts first. A missing
 * NAR is installed with a checksum-checked, create-only PUT; a stored one
 * is verified and left alone. Replacing it would erase an outstanding
 * canonical uploader's session metadata, invalidating its proof before it
 * can complete. Checking for absence alone isn't enough: another client's
 * PUT can arrive between the check and promotion.
 * NARs too large for one PUT can only reuse an existing object. The staging
 * object goes either way; a completed session records its verified proof.
 */
async function promoteStaged(config: WorkerConfig, session: UploadSession, parts: readonly Part[]): Promise<string | undefined> {
	const key = session.r2UploadKey ?? "";
	const cache = await resolveCache(config.db, session.cacheId);
	if (cache === undefined) return "Internal error";
	if (session.r2UploadId) {
		try {
			await config.bucket.resumeMultipartUpload(key, session.r2UploadId).complete([...parts]);
		} catch (err) {
			return `Upload incomplete: ${messageOf(err)}`;
		}
	}
	try {
		const isPrivate = await isPrivateCache(config, cache.path);
		const target = narKey(session.fileHash, session.compression, isPrivate);
		const bucket = bucketFor(config, isPrivate);
		let stored = await bucket.head(target);
		if (!stored && session.fileSize <= PRESIGNED_PUT_MAX_BYTES) {
			const staged = await config.bucket.get(key);
			if (!staged) return "Upload incomplete";
			if (staged.size !== session.fileSize) {
				await staged.body.cancel();
				return "File size mismatch";
			}
			try {
				const installed = await bucket.put(target, staged.body, {
					sha256: session.fileHash,
					httpMetadata: { contentType: "application/x-nix-nar", cacheControl: IMMUTABLE },
					onlyIf: { etagDoesNotMatch: "*" },
				});
				if (installed) return undefined;
			} catch {
				return "File hash mismatch";
			}
			if (!staged.bodyUsed) await staged.body.cancel();
			stored = await bucket.head(target);
		}
		// A failed conditional PUT need not consume or checksum its body.
		// Never accept the canonical NAR as proof of this session's upload.
		const staged = await config.bucket.head(key);
		if (!staged) return "Upload incomplete";
		if (staged.size !== session.fileSize) return "File size mismatch";
		if (staged.checksums.sha256
			? hex(staged.checksums.sha256) !== session.fileHash
			: !(await hashesTo(config.bucket, key, session.fileHash))) return "File hash mismatch";
		if (!stored) return "Upload incomplete: the stored NAR is gone, push again";
		if (stored.size !== session.fileSize) return "File size mismatch";
		if (stored.checksums.sha256
			? hex(stored.checksums.sha256) !== session.fileHash
			: !(await hashesTo(bucket, target, session.fileHash))) return "File hash mismatch";
		return undefined;
	} finally {
		await config.bucket.delete(key);
	}
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
	const usable: UploadSession[] = [];
	for (const sessionId of sessionIds) {
		const session = loaded.get(sessionId);
		const denied = await sessionAccessError(config, session, identity);
		if (denied || !session) {
			fail(sessionId, denied?.error ?? "Not found", denied?.status ?? 404);
		} else if (session.status !== "completed" && session.r2UploadId && !isStaged(session)) {
			// Proxied canonical multipart uploads must use /complete first.
			fail(sessionId, "Conflict", 409);
		} else {
			usable.push(session);
		}
	}

	const uploaded = usable.filter((s) => s.status !== "completed");
	const invalid = await Promise.all(uploaded.map((s) => completionError(config, s, parts.get(s.id) ?? [])));
	const verified = uploaded.filter((s, i) => {
		const error = invalid[i];
		if (error) fail(s.id, error.error, error.status);
		return !error;
	});
	const moved = new Set(await completeUploadSessions(config.db, verified));
	for (const s of verified) {
		if (!moved.has(s.id)) fail(s.id, "Conflict", 409);
	}

	const byCache = new Map<number, UploadSession[]>();
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

// R2 takes single PUTs up to 5 GiB; larger NARs go through the Worker in
// parts. A staged upload is moved into place with one such PUT, so it has
// the same limit.
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

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
