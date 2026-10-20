import type { WorkerConfig } from "./config.js";
import type { AuthIdentity } from "./auth.js";
import { hasCacheAccess } from "./jwt.js";
import {
	findCacheByName,
	findCacheById,
	createUploadSessions,
	createUploadSessionsWithinLimit,
	findUploadSession,
	findUploadSessions,
	transitionSessionStatus,
	transitionToMultipart,
	completeUploadSessions,
	upsertUploadPart,
	upsertUploadParts,
	findUploadParts,
	ensureBlobObjects,
	findBlobObjectsByIds,
	createPublishedPaths,
	findPublishedPaths,
	findPublishedHashes,
} from "./db/repository.js";
import type { Cache, UploadSession } from "./db/types.js";
import type { OrgUsage } from "./db/repository.js";
import type { SessionResponse } from "@snowstead/cache-domain";
import { storeNarinfo, narinfoCacheKey } from "./narinfo.js";
import { IMMUTABLE, bucketFor, bucketForKey, bucketNameForKey, narKey } from "./layout.js";
import { createPresignedPartPut, createPresignedPut } from "./presign.js";
import { isPrivateCache } from "./visibility.js";
import { servedUpstream } from "./upstream.js";
import {
	parseFileHash,
	parseCompression,
	parseNarHash,
	parseStorePathBasename,
	parseStorePathHash,
} from "@snowstead/cache-domain";
import { jsonResponse, errorResponse, parseJsonBody } from "./responses.js";
import type { Db } from "./db/connection.js";

// Module-scope cache: cache ID → cache name. Cache rows are immutable today
// (no rename or delete endpoints), so entries never go stale. Avoids a database
// round trip on every session-scoped upload request made with a JWT.
const cacheIdToName = new Map<number, string>();

async function resolveCacheName(
	db: Db,
	cacheId: number,
): Promise<string | undefined> {
	const cached = cacheIdToName.get(cacheId);
	if (cached !== undefined) return cached;

	const row = await findCacheById(db, cacheId);
	if (!row) return undefined;

	cacheIdToName.set(cacheId, row.name);
	return row.name;
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
	if (identity.kind === "jwt") {
		const cacheName = await resolveCacheName(config.db, session.cacheId);
		if (cacheName === undefined || !hasCacheAccess(identity.claims, cacheName)) {
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

interface SessionParams {
	readonly storePath: string;
	readonly storePathHash: string;
	readonly narHash: string;
	readonly narSize: number;
	readonly fileHash: string;
	readonly fileSize: number;
	readonly compression: string;
	readonly references: readonly string[];
	readonly deriver: string | null;
	readonly system: string | null;
}

/** The session a client asks for, or why it cannot have it. */
function parseSessionParams(input: unknown): SessionParams | string {
	if (typeof input !== "object" || input === null) {
		return "Missing required fields";
	}
	const body = input as Record<string, unknown>;
	if (!body.storePath || !body.storePathHash || !body.narHash || !body.fileHash || !body.compression) {
		return "Missing required fields";
	}

	if (typeof body.narSize !== "number" || typeof body.fileSize !== "number") {
		return "narSize and fileSize must be numbers";
	}

	const storePathHash = parseStorePathHash(String(body.storePathHash));
	if (typeof storePathHash === "object") {
		return storePathHash.message;
	}

	if (!Number.isFinite(body.narSize) || body.narSize <= 0) {
		return "narSize must be a positive number";
	}
	if (!Number.isFinite(body.fileSize) || body.fileSize <= 0) {
		return "fileSize must be a positive number";
	}

	const fileHash = parseFileHash(String(body.fileHash));
	if (typeof fileHash === "object") {
		return fileHash.message;
	}

	const compression = parseCompression(String(body.compression));
	if (typeof compression === "object") {
		return compression.message;
	}

	// Stored canonical: the narinfo signature covers the nix32 form.
	const narHash = parseNarHash(String(body.narHash));
	if (typeof narHash === "object") {
		return narHash.message;
	}

	// Each of these becomes a narinfo line.
	const storePath = String(body.storePath);
	const storeBasename = storePath.startsWith("/nix/store/") ? storePath.slice(11) : "";
	if (
		typeof parseStorePathBasename(storeBasename) === "object" ||
		!storeBasename.startsWith(`${storePathHash}-`)
	) {
		return "storePath must be /nix/store/<storePathHash>-<name>";
	}
	for (const field of ["deriver", "system"] as const) {
		const value = body[field];
		if (value != null && (typeof value !== "string" || !/^[!-~]+$/.test(value))) {
			return `${field} must be printable ASCII without spaces`;
		}
	}

	const references = body.references ?? [];
	if (!Array.isArray(references)) {
		return "references must be an array";
	}
	for (const r of references) {
		const parsed = parseStorePathBasename(String(r));
		if (typeof parsed === "object") {
			return parsed.message;
		}
	}

	return {
		storePath,
		storePathHash,
		narHash,
		narSize: body.narSize,
		fileHash,
		fileSize: body.fileSize,
		compression,
		references: references.map(String),
		deriver: (body.deriver as string | undefined) ?? null,
		system: (body.system as string | undefined) ?? null,
	};
}

/**
 * Large NARs upload in parallel parts: one connection carries far less than
 * several. The parts go to a staging key of their own, never to the NAR's
 * shared key, until the assembled object has been checked against the file
 * hash.
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

/** Whether a token tied to an org may push to this cache. */
function orgAllows(identity: AuthIdentity, cache: Cache): boolean {
	return identity.kind !== "jwt" || identity.claims.org === undefined || identity.claims.org === cache.orgId;
}

/**
 * Records sessions for paths of one cache in one statement, and says where
 * each NAR goes; a cache's org must have room for all of them.
 */
async function createSessions(
	config: WorkerConfig,
	cache: Cache,
	items: readonly SessionParams[],
): Promise<SessionResponse[] | Response> {
	// Seed the ID → name cache so session-scoped requests skip the database lookup.
	cacheIdToName.set(cache.id, cache.name);
	// Straight into the bucket the cache is served from.
	const isPrivate = await isPrivateCache(config, cache.name);
	const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
	const presigning = Boolean(config.r2AccessKeyId && config.r2SecretAccessKey && config.r2Endpoint);

	const rows = await Promise.all(items.map(async (p) => {
		const id = crypto.randomUUID();
		const inParts = presigning && p.fileSize > PRESIGNED_PARTS_MIN_BYTES && p.fileSize <= PRESIGNED_PUT_MAX_BYTES;
		const r2UploadKey = inParts ? `${STAGING_PREFIX}${id}` : narKey(p.fileHash, p.compression, isPrivate);
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
	if (cache.orgId === null) {
		await createUploadSessions(config.db, rows);
	} else {
		const refused = await createUploadSessionsWithinLimit(config.db, cache.orgId, rows);
		if (refused) {
			await Promise.allSettled(rows.flatMap((r) =>
				r.r2UploadId ? [config.bucket.resumeMultipartUpload(r.r2UploadKey, r.r2UploadId).abort()] : [],
			));
			return storageFullResponse(refused);
		}
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
	const cache = await findCacheByName(config.db, cacheName);
	if (!cache) {
		return errorResponse("Cache not found", 404);
	}
	if (!orgAllows(identity, cache)) {
		return errorResponse("Forbidden", 403);
	}

	const body = await parseJsonBody<unknown>(request);
	if (body instanceof Response) return body;

	const params = parseSessionParams(body);
	if (typeof params === "string") {
		return errorResponse(params, 400);
	}

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
	const cache = await findCacheByName(config.db, cacheName);
	if (!cache) {
		return errorResponse("Cache not found", 404);
	}
	if (!orgAllows(identity, cache)) {
		return errorResponse("Forbidden", 403);
	}

	const body = await parseJsonBody<{ paths?: unknown }>(request);
	if (body instanceof Response) return body;

	if (!Array.isArray(body.paths) || body.paths.length === 0 || body.paths.length > MAX_BATCH) {
		return errorResponse(`paths must be an array of 1 to ${MAX_BATCH} sessions`, 400);
	}

	const items: SessionParams[] = [];
	for (const [i, item] of body.paths.entries()) {
		const params = parseSessionParams(item);
		if (typeof params === "string") {
			return errorResponse(`paths[${i}]: ${params}`, 400);
		}
		items.push(params);
	}

	const sessions = await createSessions(config, cache, items);
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

	if (session.status !== "pending") {
		return errorResponse("Conflict", 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Internal error", 500);
	}

	const multipart = await bucketForKey(config, session.r2UploadKey).createMultipartUpload(session.r2UploadKey);

	const transitioned = await transitionToMultipart(config.db, sessionId, multipart.uploadId);
	if (!transitioned) {
		try { await multipart.abort(); } catch { /* best effort */ }
		return errorResponse("Conflict", 409);
	}

	return jsonResponse({
		uploadId: multipart.uploadId,
		r2Key: session.r2UploadKey,
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

	if (session.status !== "pending" && session.status !== "uploading") {
		return errorResponse("Conflict", 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Internal error", 500);
	}

	if (!request.body) {
		return errorResponse("Request body is empty", 400);
	}

	// Blob upload is idempotent (PUT overwrites), so allow both pending and uploading states.
	// Attempt pending→uploading; if already uploading the transition fails but that is acceptable.
	if (session.status === "pending") {
		const transitioned = await transitionSessionStatus(config.db, sessionId, "pending", "uploading");
		if (!transitioned) {
			// Re-read to check if someone else moved it to uploading (retry-safe)
			const current = await findUploadSession(config.db, sessionId);
			if (!current || current.status !== "uploading") {
				return errorResponse("Conflict", 409);
			}
		}
	}

	// R2 rejects a body whose SHA-256 is not the session's file hash, as it
	// does for presigned uploads.
	await bucketForKey(config, session.r2UploadKey).put(session.r2UploadKey, request.body, {
		sha256: session.fileHash,
		httpMetadata: { contentType: "application/x-nix-nar", cacheControl: IMMUTABLE },
	});

	return jsonResponse({ uploaded: true, r2Key: session.r2UploadKey });
}

/** Why the object a session uploaded is not the one it named, if it is not. */
async function uploadError(config: WorkerConfig, session: UploadSession): Promise<string | undefined> {
	if (!session.r2UploadKey) {
		return "Internal error";
	}
	const head = await bucketForKey(config, session.r2UploadKey).head(session.r2UploadKey);
	if (!head) {
		return "Upload incomplete";
	}
	if (head.size !== session.fileSize) {
		return "File size mismatch";
	}
	// R2 checked a presigned upload against this hash already; check what it
	// recorded, wherever it recorded one.
	const stored = head.checksums.sha256;
	if (stored && hex(stored) !== session.fileHash) {
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

	// A presigned upload goes straight to R2, so its session is still pending.
	// Staged parts are checked and moved into place only by a commit.
	const presigned = session.status === "pending" && !session.r2UploadId;
	if ((session.status !== "uploading" && !presigned) || isStaged(session)) {
		return errorResponse("Conflict", 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Internal error", 500);
	}

	const body = await parseJsonBody<{
		parts?: Array<{ partNumber: number; etag: string; size: number }>;
	}>(request);
	if (body instanceof Response) return body;

	if (body.parts && body.parts.length > 0) {
		await upsertUploadParts(config.db, sessionId, body.parts);
	}

	if (session.r2UploadId) {
		const parts = await findUploadParts(config.db, sessionId);
		const multipart = bucketForKey(config, session.r2UploadKey).resumeMultipartUpload(session.r2UploadKey, session.r2UploadId);
		await multipart.complete(parts.map(p => ({ partNumber: p.partNumber, etag: p.etag })));
	}

	const invalid = await uploadError(config, session);
	if (invalid) {
		return errorResponse(invalid, invalid === "Internal error" ? 500 : 400);
	}

	const transitioned = await transitionSessionStatus(config.db, sessionId, presigned ? "pending" : "uploading", "completed");
	if (!transitioned) {
		return errorResponse("Conflict", 409);
	}

	return jsonResponse({ status: "completed" });
}

/**
 * Drops a cached 404 for a path just published, so it shows up at once
 * rather than after the negative TTL. The Cache API is per data center: this
 * clears the one handling the publish, where the pusher's own lookups land.
 */
async function forgetNarinfoMiss(origin: string, cacheName: string, storePathHash: string): Promise<void> {
	const cache = await caches.open("snowstead-narinfo");
	// Both keys: cheaper than looking up whether the cache is private.
	await Promise.all([
		cache.delete(narinfoCacheKey(origin, cacheName, storePathHash, false)),
		cache.delete(narinfoCacheKey(origin, cacheName, storePathHash, true)),
	]);
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
	const cacheName = await resolveCacheName(config.db, cacheId);
	if (cacheName === undefined) {
		return sessions.map((s) => ({ sessionId: s.id, error: "Internal error", status: 500 }));
	}
	const isPrivate = await isPrivateCache(config, cacheName);

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
	const rows: Parameters<typeof createPublishedPaths>[1][number][] = [];
	await Promise.all(sessions.map(async (session) => {
		const known = existing.get(session.storePathHash);
		try {
			if (known) {
				// Publishing again rewrites the narinfo, so a publish that failed
				// between storing it and recording the row heals on retry.
				const blob = existingBlobs.find((b) => b.id === known.blobObjectId);
				if (blob) await storeNarinfo(config, cacheName, known, blob, isPrivate);
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
			await storeNarinfo(config, cacheName, path, blob, isPrivate);
			rows.push(path);
		} catch (err) {
			console.error("Failed to publish", { sessionId: session.id }, err);
			results.set(session.id, { sessionId: session.id, error: "Internal error", status: 500 });
		}
	}));

	const inserted = new Set(await createPublishedPaths(config.db, rows));
	await Promise.all([...inserted].map((hash) => forgetNarinfoMiss(origin, cacheName, hash)));
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

type Part = { readonly partNumber: number; readonly etag: string };

function parseParts(value: unknown): Map<string, Part[]> | string {
	const parts = new Map<string, Part[]>();
	if (value === undefined) return parts;
	if (typeof value !== "object" || value === null) return "parts must map session ids to their parts";
	for (const [sessionId, list] of Object.entries(value)) {
		if (
			!Array.isArray(list) ||
			!list.every((p: { partNumber?: unknown; etag?: unknown }) => Number.isInteger(p?.partNumber) && typeof p?.etag === "string")
		) {
			return `parts of ${sessionId} must be {partNumber, etag} objects`;
		}
		// S3 quotes ETags; the binding takes them bare.
		parts.set(sessionId, list.map((p: Part) => ({ partNumber: p.partNumber, etag: p.etag.replace(/^"(.*)"$/, "$1") })));
	}
	return parts;
}

/**
 * Assembles a staged upload's parts, checks the object against the file
 * hash and moves it to the NAR's key: R2 refuses a put whose body does not
 * hash to it. The staging object goes either way.
 */
async function promoteStaged(config: WorkerConfig, session: UploadSession, parts: readonly Part[]): Promise<string | undefined> {
	const key = session.r2UploadKey ?? "";
	const cacheName = await resolveCacheName(config.db, session.cacheId);
	if (!session.r2UploadId || cacheName === undefined) return "Internal error";
	try {
		await config.bucket.resumeMultipartUpload(key, session.r2UploadId).complete([...parts]);
	} catch (err) {
		return `Upload incomplete: ${err instanceof Error ? err.message : String(err)}`;
	}
	try {
		const staged = await config.bucket.get(key);
		if (!staged) return "Upload incomplete";
		if (staged.size !== session.fileSize) {
			await staged.body.cancel();
			return "File size mismatch";
		}
		const isPrivate = await isPrivateCache(config, cacheName);
		const target = narKey(session.fileHash, session.compression, isPrivate);
		const bucket = bucketFor(config, isPrivate);
		if (await bucket.head(target)) {
			await staged.body.cancel();
			return undefined;
		}
		try {
			await bucket.put(target, staged.body, {
				sha256: session.fileHash,
				httpMetadata: { contentType: "application/x-nix-nar", cacheControl: IMMUTABLE },
			});
		} catch {
			return "File hash mismatch";
		}
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
	const body = await parseJsonBody<{ sessionIds?: unknown; parts?: unknown }>(request);
	if (body instanceof Response) return body;

	const ids = body.sessionIds;
	if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_BATCH || !ids.every((id) => typeof id === "string")) {
		return errorResponse(`sessionIds must be an array of 1 to ${MAX_BATCH} session ids`, 400);
	}
	const sessionIds = [...new Set(ids as string[])];
	const parts = parseParts(body.parts);
	if (typeof parts === "string") {
		return errorResponse(parts, 400);
	}

	const results = new Map<string, PublishResult>();
	const fail = (sessionId: string, error: string, status: number) => results.set(sessionId, { sessionId, error, status });

	const loaded = new Map((await findUploadSessions(config.db, sessionIds)).map((s) => [s.id, s]));
	const usable: UploadSession[] = [];
	for (const sessionId of sessionIds) {
		const session = loaded.get(sessionId);
		const denied = await sessionAccessError(config, session, identity);
		if (denied || !session) {
			fail(sessionId, denied?.error ?? "Not found", denied?.status ?? 404);
		} else if (
			session.status === "completed" ||
			((session.status === "pending" || session.status === "uploading") && !session.r2UploadId) ||
			(session.status === "uploading" && isStaged(session) && parts.has(sessionId))
		) {
			usable.push(session);
		} else {
			fail(sessionId, "Conflict", 409);
		}
	}

	const uploaded = usable.filter((s) => s.status !== "completed");
	const invalid = await Promise.all(uploaded.map((s) =>
		isStaged(s) ? promoteStaged(config, s, parts.get(s.id) ?? []) : uploadError(config, s),
	));
	const verified = uploaded.filter((s, i) => {
		const error = invalid[i];
		if (error) fail(s.id, error, error === "Internal error" ? 500 : 400);
		return !error;
	});
	const moved = new Set(await completeUploadSessions(config.db, verified.map((s) => s.id)));
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
// Each path publishes with a handful of R2 and Cache API calls; 100 keeps a
// batch well inside a request's subrequest and Cache API limits.
const MAX_BATCH = 100;

const MAX_MISSING_PATHS_BATCH = 1000;

export async function handleGetMissingPaths(
	request: Request,
	config: WorkerConfig,
	identity: AuthIdentity,
): Promise<Response> {
	const body = await parseJsonBody<{
		cache: string;
		storePathHashes: string[];
	}>(request);
	if (body instanceof Response) return body;

	if (!body.cache || !Array.isArray(body.storePathHashes)) {
		return errorResponse("Missing required fields: cache, storePathHashes", 400);
	}

	if (body.storePathHashes.length > MAX_MISSING_PATHS_BATCH) {
		return errorResponse(`storePathHashes exceeds maximum of ${MAX_MISSING_PATHS_BATCH}`, 400);
	}

	const cache = await findCacheByName(config.db, body.cache);
	if (!cache) {
		return errorResponse("Cache not found", 404);
	}

	if (identity.kind === "jwt" && !hasCacheAccess(identity.claims, body.cache)) {
		return errorResponse("Forbidden", 403);
	}

	const existingHashes = await findPublishedHashes(config.db, cache.id, body.storePathHashes);
	const existingSet = new Set(existingHashes);
	const absent = body.storePathHashes.filter((h) => !existingSet.has(h));
	// What an upstream serves is not missing: substituters have it already.
	const served = await servedUpstream(config, absent);

	return jsonResponse({
		missing: absent.filter((h) => !served.has(h)),
		upstream: absent.filter((h) => served.has(h)),
	});
}

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
