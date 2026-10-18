import type { WorkerConfig } from "./config.js";
import type { AuthIdentity } from "./auth.js";
import { hasCacheAccess } from "./jwt.js";
import {
	findCacheByName,
	findCacheById,
	createUploadSessions,
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
import { storeNarinfo, narinfoCacheKey } from "./narinfo.js";
import { IMMUTABLE, bucketForKey, bucketNameForKey, narKey } from "./layout.js";
import { createPresignedPut } from "./presign.js";
import { isPrivateCache } from "./visibility.js";
import {
	parseFileHash,
	parseCompression,
	parseNarHash,
	parseStorePathBasename,
	parseStorePathHash,
} from "@helios/cache-domain";
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

interface CreatedSession {
	readonly sessionId: string;
	readonly r2Key: string;
	/** "presigned": PUT the NAR to uploadUrl with uploadHeaders; "direct": through the API. */
	readonly uploadMethod: "presigned" | "direct";
	readonly uploadUrl?: string;
	readonly uploadHeaders?: Record<string, string>;
	readonly expiresAt: Date;
}

/** Records sessions for paths of one cache in one statement, and says where each NAR goes. */
async function createSessions(
	config: WorkerConfig,
	cache: Cache,
	items: readonly SessionParams[],
): Promise<CreatedSession[]> {
	// Seed the ID → name cache so session-scoped requests skip the database lookup.
	cacheIdToName.set(cache.id, cache.name);
	// Straight into the bucket the cache is served from.
	const isPrivate = await isPrivateCache(config, cache.name);
	const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);

	const rows = items.map((p) => ({
		id: crypto.randomUUID(),
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
		r2UploadKey: narKey(p.fileHash, p.compression, isPrivate),
		r2UploadId: null,
		expiresAt,
	}));
	await createUploadSessions(config.db, rows);

	return Promise.all(rows.map(async (row): Promise<CreatedSession> => {
		// Straight to R2 when presigning is configured and one PUT can carry it;
		// R2 then checks the bytes against the file hash itself.
		if (config.r2AccessKeyId && config.r2SecretAccessKey && config.r2Endpoint && row.fileSize <= PRESIGNED_PUT_MAX_BYTES) {
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
		}
		return { sessionId: row.id, r2Key: row.r2UploadKey, uploadMethod: "direct", expiresAt };
	}));
}

export async function handleCreateSession(
	request: Request,
	config: WorkerConfig,
	cacheName: string,
): Promise<Response> {
	const cache = await findCacheByName(config.db, cacheName);
	if (!cache) {
		return errorResponse("Cache not found", 404);
	}

	const body = await parseJsonBody<unknown>(request);
	if (body instanceof Response) return body;

	const params = parseSessionParams(body);
	if (typeof params === "string") {
		return errorResponse(params, 400);
	}

	const [session] = await createSessions(config, cache, [params]);
	return jsonResponse(session, 201);
}

/**
 * Sessions for many paths in one request, in the order asked; a pusher
 * otherwise pays a round trip to the database per path.
 */
export async function handleCreateSessions(
	request: Request,
	config: WorkerConfig,
	cacheName: string,
): Promise<Response> {
	const cache = await findCacheByName(config.db, cacheName);
	if (!cache) {
		return errorResponse("Cache not found", 404);
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

	return jsonResponse({ sessions: await createSessions(config, cache, items) }, 201);
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
	const presigned = session.status === "pending" && !session.r2UploadId;
	if (session.status !== "uploading" && !presigned) {
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
	const cache = await caches.open("helios-narinfo");
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
	const fresh = sessions.filter((s) => !existing.has(s.storePathHash) && s.r2UploadKey);
	const blobs = await ensureBlobObjects(config.db, fresh.map((s) => ({
		fileHash: s.fileHash,
		fileSize: s.fileSize,
		compression: s.compression,
		r2Key: s.r2UploadKey ?? "",
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
			console.error("Failed to publish", { sessionId: session.id, error: err instanceof Error ? err.message : String(err) });
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

/**
 * Completes and publishes many uploaded sessions in one request: what
 * /complete then /publish do for each, with a few statements for all of
 * them. Multipart sessions must be completed first. Results come in the
 * order asked, each a publish's response or an error with its status.
 */
export async function handleCommit(
	request: Request,
	config: WorkerConfig,
	identity: AuthIdentity,
	origin: string,
): Promise<Response> {
	const body = await parseJsonBody<{ sessionIds?: unknown }>(request);
	if (body instanceof Response) return body;

	const ids = body.sessionIds;
	if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_BATCH || !ids.every((id) => typeof id === "string")) {
		return errorResponse(`sessionIds must be an array of 1 to ${MAX_BATCH} session ids`, 400);
	}
	const sessionIds = [...new Set(ids as string[])];

	const results = new Map<string, PublishResult>();
	const fail = (sessionId: string, error: string, status: number) => results.set(sessionId, { sessionId, error, status });

	const loaded = new Map((await findUploadSessions(config.db, sessionIds)).map((s) => [s.id, s]));
	const usable: UploadSession[] = [];
	for (const sessionId of sessionIds) {
		const session = loaded.get(sessionId);
		const denied = await sessionAccessError(config, session, identity);
		if (denied || !session) {
			fail(sessionId, denied?.error ?? "Not found", denied?.status ?? 404);
		} else if (session.status === "completed" || ((session.status === "pending" || session.status === "uploading") && !session.r2UploadId)) {
			usable.push(session);
		} else {
			fail(sessionId, "Conflict", 409);
		}
	}

	const uploaded = usable.filter((s) => s.status !== "completed");
	const invalid = await Promise.all(uploaded.map((s) => uploadError(config, s)));
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

// R2 takes single PUTs up to 5 GiB; larger NARs go through the Worker in parts.
const PRESIGNED_PUT_MAX_BYTES = 5 * 1024 ** 3 - (1 << 20);
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
	const missing = body.storePathHashes.filter((h) => !existingSet.has(h));

	return jsonResponse({ missing });
}

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
