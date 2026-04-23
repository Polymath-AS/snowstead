import type { WorkerConfig } from "./config.js";
import {
	findCacheByName,
	createUploadSession,
	findUploadSession,
	updateUploadSessionStatus,
	createUploadPart,
	createBlobObject,
	findBlobObject,
	createPublishedPath,
	findPublishedPath,
	findPublishedHashes,
} from "./db/repository.js";
import { buildR2ObjectKey, parseFileHash, parseCompression } from "@odin/cache-domain";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}

function errorResponse(message: string, status: number): Response {
	return jsonResponse({ error: message }, status);
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

	const body = await request.json<{
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
	}>();

	if (!body.storePath || !body.storePathHash || !body.narHash || !body.fileHash || !body.compression) {
		return errorResponse("Missing required fields", 400);
	}

	if (typeof body.narSize !== "number" || typeof body.fileSize !== "number") {
		return errorResponse("narSize and fileSize must be numbers", 400);
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

	await updateUploadSessionStatus(config.db, sessionId, "uploading");

	return jsonResponse({
		uploadId: multipart.uploadId,
		r2Key: session.r2UploadKey,
	});
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

	await config.bucket.put(session.r2UploadKey, request.body, {
		httpMetadata: { contentType: "application/x-nix-nar" },
	});

	await updateUploadSessionStatus(config.db, sessionId, "uploading");

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

	if (session.status !== "pending" && session.status !== "uploading") {
		return errorResponse(`Session is in '${session.status}' state`, 409);
	}

	if (!session.r2UploadKey) {
		return errorResponse("Session has no R2 upload key", 500);
	}

	const body = await request.json<{
		parts?: Array<{ partNumber: number; etag: string; size: number }>;
	}>();

	if (body.parts && body.parts.length > 0) {
		for (const part of body.parts) {
			await createUploadPart(config.db, {
				sessionId,
				partNumber: part.partNumber,
				etag: part.etag,
				size: part.size,
			});
		}
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

	await updateUploadSessionStatus(config.db, sessionId, "completed");

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

export async function handleGetMissingPaths(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	const body = await request.json<{
		cache: string;
		storePathHashes: string[];
	}>();

	if (!body.cache || !Array.isArray(body.storePathHashes)) {
		return errorResponse("Missing required fields: cache, storePathHashes", 400);
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
