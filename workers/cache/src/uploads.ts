import type { WorkerConfig } from "./config.js";
import {
	findCacheByName,
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
import { buildR2ObjectKey, parseFileHash, parseCompression, parseStorePathHash } from "@odin/cache-domain";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}

function errorResponse(message: string, status: number): Response {
	return jsonResponse({ error: message }, status);
}

async function parseJsonBody<T>(request: Request): Promise<T | Response> {
	try {
		return await request.json<T>();
	} catch {
		return errorResponse("Invalid JSON in request body", 400);
	}
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
): Promise<Response> {
	const session = await findUploadSession(config.db, sessionId);
	if (!session) {
		return errorResponse("Session not found", 404);
	}

	if (session.status !== "pending") {
		return errorResponse(`Session is in '${session.status}' state, expected 'pending'`, 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Session has no R2 upload key", 500);
	}

	const multipart = await config.bucket.createMultipartUpload(session.r2UploadKey);

	const transitioned = await transitionToMultipart(config.db, sessionId, multipart.uploadId);
	if (!transitioned) {
		try { await multipart.abort(); } catch { /* best effort */ }
		return errorResponse("Session state changed concurrently, expected 'pending'", 409);
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
): Promise<Response> {
	const session = await findUploadSession(config.db, sessionId);
	if (!session) {
		return errorResponse("Session not found", 404);
	}

	if (session.status !== "uploading") {
		return errorResponse(`Session is in '${session.status}' state, expected 'uploading'`, 409);
	}

	if (!session.r2UploadKey || !session.r2UploadId) {
		return errorResponse("Session has no active multipart upload", 400);
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
): Promise<Response> {
	const session = await findUploadSession(config.db, sessionId);
	if (!session) {
		return errorResponse("Session not found", 404);
	}

	if (session.status !== "pending" && session.status !== "uploading") {
		return errorResponse(`Session is in '${session.status}' state, expected 'pending' or 'uploading'`, 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Session has no R2 upload key", 500);
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
				return errorResponse("Session state changed concurrently", 409);
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
): Promise<Response> {
	const session = await findUploadSession(config.db, sessionId);
	if (!session) {
		return errorResponse("Session not found", 404);
	}

	if (session.status !== "uploading") {
		return errorResponse(`Session is in '${session.status}' state, expected 'uploading'`, 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Session has no R2 upload key", 500);
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
		return errorResponse("Object not found in R2, upload may not be complete", 400);
	}

	if (head.size !== session.fileSize) {
		return errorResponse(
			`File size mismatch: expected ${session.fileSize}, got ${head.size}`,
			400,
		);
	}

	const transitioned = await transitionSessionStatus(config.db, sessionId, "uploading", "completed");
	if (!transitioned) {
		return errorResponse("Session state changed concurrently", 409);
	}

	return jsonResponse({ status: "completed" });
}

// ── Publish Path ──

export async function handlePublish(
	config: WorkerConfig,
	sessionId: string,
): Promise<Response> {
	const session = await findUploadSession(config.db, sessionId);
	if (!session) {
		return errorResponse("Session not found", 404);
	}

	if (session.status !== "completed") {
		return errorResponse(`Session must be completed before publishing, current status: '${session.status}'`, 409);
	}

	const existing = await findPublishedPath(config.db, session.cacheId, session.storePathHash);
	if (existing) {
		return jsonResponse({ published: true, storePathHash: session.storePathHash, alreadyExisted: true });
	}

	let blob = await findBlobObject(config.db, session.fileHash, session.compression);
	if (!blob) {
		if (!session.r2UploadKey) {
			return errorResponse("Session has no R2 upload key", 500);
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
				return errorResponse("Failed to create or find blob object", 500);
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
		return errorResponse("Failed to publish path", 500);
	}

	return jsonResponse({ published: true, storePathHash: session.storePathHash });
}

// ── Get Missing Paths ──

const MAX_MISSING_PATHS_BATCH = 1000;

export async function handleGetMissingPaths(
	request: Request,
	config: WorkerConfig,
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

	const existingHashes = await findPublishedHashes(config.db, cache.id, body.storePathHashes);
	const existingSet = new Set(existingHashes);
	const missing = body.storePathHashes.filter((h) => !existingSet.has(h));

	return jsonResponse({ missing });
}
