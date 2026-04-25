import type { WorkerConfig } from "./config.js";
import type { AuthIdentity } from "./auth.js";
import { hasCacheAccess } from "./jwt.js";
import {
	findCacheByName,
	findCacheById,
	createUploadSession,
	findUploadSession,
	transitionSessionStatus,
	transitionToMultipart,
	upsertUploadPart,
	findUploadParts,
	createBlobObject,
	findBlobObject,
	createPublishedPath,
	findPublishedPath,
	findPublishedHashes,
} from "./db/repository.js";
import type { UploadSession } from "./db/types.js";
import { buildR2ObjectKey, parseFileHash, parseCompression, parseStorePathHash } from "@helios/cache-domain";
import { jsonResponse, errorResponse, parseJsonBody } from "./responses.js";

// ── Session Auth Helper ──

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
	if (!session) {
		return { error: errorResponse("Not found", 404) };
	}

	// Enforce session expiry at request time, not just via GC
	if (session.expiresAt <= new Date().toISOString()) {
		return { error: errorResponse("Not found", 404) };
	}

	if (identity.kind === "jwt") {
		const cache = await findCacheById(config.db, session.cacheId);
		if (!cache || !hasCacheAccess(identity.claims, cache.name)) {
			return { error: errorResponse("Forbidden", 403) };
		}
	}

	return { session };
}

// ── Create Upload Session ──

export async function handleCreateSession(
	request: Request,
	config: WorkerConfig,
	cacheName: string,
): Promise<Response> {
	const cache = await findCacheByName(config.db, cacheName);
	if (!cache) {
		return errorResponse("Cache not found", 404);
	}

	const body = await parseJsonBody<{
		storePath: string;
		storePathHash: string;
		narHash: string;
		narSize: number;
		fileHash: string;
		fileSize: number;
		compression: string;
		references?: string[];
		deriver?: string;
		system?: string;
	}>(request);
	if (body instanceof Response) return body;

	if (!body.storePath || !body.storePathHash || !body.narHash || !body.fileHash || !body.compression) {
		return errorResponse("Missing required fields", 400);
	}

	if (typeof body.narSize !== "number" || typeof body.fileSize !== "number") {
		return errorResponse("narSize and fileSize must be numbers", 400);
	}

	const parsedHash = parseStorePathHash(body.storePathHash);
	if (typeof parsedHash === "object") {
		return errorResponse(parsedHash.message, 400);
	}

	if (!Number.isFinite(body.narSize) || body.narSize <= 0) {
		return errorResponse("narSize must be a positive number", 400);
	}
	if (!Number.isFinite(body.fileSize) || body.fileSize <= 0) {
		return errorResponse("fileSize must be a positive number", 400);
	}

	const fileHash = parseFileHash(body.fileHash);
	if (typeof fileHash === "object") {
		return errorResponse(fileHash.message, 400);
	}

	const compression = parseCompression(body.compression);
	if (typeof compression === "object") {
		return errorResponse(compression.message, 400);
	}

	const r2Key = buildR2ObjectKey(fileHash, compression);
	const sessionId = crypto.randomUUID();
	const expiresAt = new Date(Date.now() + 3600_000).toISOString();

	const session = await createUploadSession(config.db, {
		id: sessionId,
		cacheId: cache.id,
		storePathHash: body.storePathHash,
		storePath: body.storePath,
		narHash: body.narHash,
		narSize: body.narSize,
		fileHash: body.fileHash,
		fileSize: body.fileSize,
		compression: body.compression,
		referencesJson: JSON.stringify(body.references ?? []),
		deriver: body.deriver ?? null,
		system: body.system ?? null,
		r2UploadKey: r2Key,
		r2UploadId: null,
		expiresAt,
	});

	return jsonResponse({
		sessionId: session.id,
		r2Key,
		uploadMethod: "direct",
		expiresAt,
	}, 201);
}

// ── Initiate Multipart Upload ──

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

	const multipart = await config.bucket.createMultipartUpload(session.r2UploadKey);

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

// ── Upload Part (Multipart) ──

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

	const multipart = config.bucket.resumeMultipartUpload(session.r2UploadKey, session.r2UploadId);
	const uploadedPart = await multipart.uploadPart(partNumber, request.body);

	await upsertUploadPart(config.db, {
		sessionId,
		partNumber,
		etag: uploadedPart.etag,
		size: 0,
	});

	return jsonResponse({ partNumber, etag: uploadedPart.etag });
}

// ── Upload Blob ──

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

	await config.bucket.put(session.r2UploadKey, request.body, {
		httpMetadata: { contentType: "application/x-nix-nar" },
	});

	return jsonResponse({ uploaded: true, r2Key: session.r2UploadKey });
}

// ── Complete Upload ──

export async function handleComplete(
	request: Request,
	config: WorkerConfig,
	sessionId: string,
	identity: AuthIdentity,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	const session = result.session;

	if (session.status !== "uploading") {
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
		for (const part of body.parts) {
			await upsertUploadPart(config.db, {
				sessionId,
				partNumber: part.partNumber,
				etag: part.etag,
				size: part.size,
			});
		}
	}

	if (session.r2UploadId) {
		const parts = await findUploadParts(config.db, sessionId);
		const multipart = config.bucket.resumeMultipartUpload(session.r2UploadKey, session.r2UploadId);
		await multipart.complete(parts.map(p => ({ partNumber: p.partNumber, etag: p.etag })));
	}

	const head = await config.bucket.head(session.r2UploadKey);
	if (!head) {
		return errorResponse("Upload incomplete", 400);
	}

	if (head.size !== session.fileSize) {
		return errorResponse("File size mismatch", 400);
	}

	const transitioned = await transitionSessionStatus(config.db, sessionId, "uploading", "completed");
	if (!transitioned) {
		return errorResponse("Conflict", 409);
	}

	return jsonResponse({ status: "completed" });
}

// ── Publish Path ──

export async function handlePublish(
	config: WorkerConfig,
	sessionId: string,
	identity: AuthIdentity,
): Promise<Response> {
	const result = await loadSessionWithAuthCheck(config, sessionId, identity);
	if (result.error) return result.error;
	const session = result.session;

	if (session.status !== "completed") {
		return errorResponse("Conflict", 409);
	}

	const existing = await findPublishedPath(config.db, session.cacheId, session.storePathHash);
	if (existing) {
		return jsonResponse({ published: true, storePathHash: session.storePathHash, alreadyExisted: true });
	}

	let blob = await findBlobObject(config.db, session.fileHash, session.compression);
	if (!blob) {
		if (!session.r2UploadKey) {
			return errorResponse("Internal error", 500);
		}
		try {
			blob = await createBlobObject(config.db, {
				fileHash: session.fileHash,
				fileSize: session.fileSize,
				compression: session.compression,
				r2Key: session.r2UploadKey,
			});
		} catch {
			blob = await findBlobObject(config.db, session.fileHash, session.compression);
			if (!blob) {
				return errorResponse("Internal error", 500);
			}
		}
	}

	try {
		await createPublishedPath(config.db, {
			cacheId: session.cacheId,
			storePathHash: session.storePathHash,
			storePath: session.storePath,
			narHash: session.narHash,
			narSize: session.narSize,
			blobObjectId: blob.id,
			referencesJson: session.referencesJson,
			deriver: session.deriver,
			system: session.system,
			signaturesJson: "[]",
		});
	} catch {
		const raced = await findPublishedPath(config.db, session.cacheId, session.storePathHash);
		if (raced) {
			return jsonResponse({ published: true, storePathHash: session.storePathHash, alreadyExisted: true });
		}
		return errorResponse("Internal error", 500);
	}

	return jsonResponse({ published: true, storePathHash: session.storePathHash });
}

// ── Get Missing Paths ──

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
