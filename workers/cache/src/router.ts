import type { WorkerConfig } from "./config.js";
import { findCacheByName, findPublishedPath, findBlobObject, findBlobObjectById } from "./db/repository.js";
import { renderNarinfo } from "./narinfo.js";
import { verifyAuth } from "./auth.js";
import { computeFingerprint, signNarinfo } from "./signing.js";
import { parseCacheName, parseStorePathHash, parseFileHash, parseCompression } from "@odin/cache-domain";
import {
	handleCreateSession,
	handleMultipart,
	handleUploadPart,
	handleUploadBlob,
	handleComplete,
	handlePublish,
	handleGetMissingPaths,
} from "./uploads.js";
import { createPresignedUrl } from "./presign.js";

export async function handleRequest(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const method = request.method;

	if (url.pathname === "/") {
		return json({ service: "odin-cache", status: "ok" });
	}

	if (url.pathname === "/healthz") {
		return handleHealthz(config);
	}

	// Write API routes (POST and PUT)
	if (url.pathname.startsWith("/_api/v1/")) {
		if (method !== "POST" && method !== "PUT") {
			return new Response("Method Not Allowed", {
				status: 405,
				headers: { allow: "POST, PUT" },
			});
		}
		return handleWriteApi(request, config, url.pathname);
	}

	// Read paths (GET/HEAD only)
	if (method !== "GET" && method !== "HEAD") {
		return new Response("Method Not Allowed", {
			status: 405,
			headers: { allow: "GET, HEAD" },
		});
	}

	const segments = url.pathname.split("/").filter(Boolean);
	if (segments.length < 2) {
		return new Response("Not Found", { status: 404 });
	}

	const cacheName = parseCacheName(segments[0]);
	if (typeof cacheName === "object") {
		return new Response("Not Found", { status: 404 });
	}

	const cache = await findCacheByName(config.db, cacheName);
	if (!cache) {
		return new Response("Not Found", { status: 404 });
	}

	if (segments[1] === "nix-cache-info") {
		return handleNixCacheInfo();
	}

	if (segments[1].endsWith(".narinfo")) {
		const hashStr = segments[1].slice(0, -".narinfo".length);
		return handleNarinfo(config, cache.id, hashStr, method);
	}

	if (segments[1] === "nar" && segments.length === 4 && segments[3].endsWith(".nar")) {
		return handleNarDownload(config, segments[2], segments[3].slice(0, -".nar".length));
	}

	return new Response("Not Found", { status: 404 });
}

function json(body: Record<string, string | boolean | number>, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}

async function handleHealthz(config: WorkerConfig): Promise<Response> {
	try {
		await findCacheByName(config.db, "__healthz_probe__");
		return json({ ok: true, service: "odin-cache" });
	} catch {
		return json({ ok: false, service: "odin-cache" }, 503);
	}
}

function handleNixCacheInfo(): Response {
	const body = [
		"StoreDir: /nix/store",
		"WantMassQuery: 1",
		"Priority: 40",
	].join("\n") + "\n";

	return new Response(body, {
		headers: { "content-type": "text/x-nix-cache-info" },
	});
}

async function handleNarinfo(
	config: WorkerConfig,
	cacheId: number,
	hashStr: string,
	method: string,
): Promise<Response> {
	const storePathHash = parseStorePathHash(hashStr);
	if (typeof storePathHash === "object") {
		return new Response("Not Found", { status: 404 });
	}

	const path = await findPublishedPath(config.db, cacheId, storePathHash);
	if (!path) {
		return new Response("Not Found", { status: 404 });
	}

	const blob = await findBlobObjectById(config.db, path.blobObjectId);
	if (!blob) {
		return new Response("Not Found", { status: 404 });
	}

	const fingerprint = computeFingerprint(path);
	const sig = await signNarinfo(fingerprint, config.signingKeyName, config.signingPrivateKey);
	const signatures = sig ? [sig] : [];
	const body = renderNarinfo(path, blob, signatures);

	if (method === "HEAD") {
		return new Response(null, {
			status: 200,
			headers: {
				"content-type": "text/x-nix-narinfo",
				"content-length": String(new TextEncoder().encode(body).byteLength),
			},
		});
	}

	return new Response(body, {
		headers: { "content-type": "text/x-nix-narinfo" },
	});
}

async function handleNarDownload(
	config: WorkerConfig,
	rawFileHash: string,
	rawCompression: string,
): Promise<Response> {
	const fileHash = parseFileHash(rawFileHash);
	if (typeof fileHash === "object") {
		return new Response("Not Found", { status: 404 });
	}

	const compression = parseCompression(rawCompression);
	if (typeof compression === "object") {
		return new Response("Not Found", { status: 404 });
	}

	const blob = await findBlobObject(config.db, fileHash, compression);
	if (!blob) {
		return new Response("Not Found", { status: 404 });
	}

	if (config.r2AccessKeyId && config.r2SecretAccessKey && config.r2Endpoint) {
		const url = await createPresignedUrl(
			config.r2Endpoint,
			config.r2AccessKeyId,
			config.r2SecretAccessKey,
			"odin-cache",
			blob.r2Key,
			3600,
		);
		return new Response(null, {
			status: 302,
			headers: {
				location: url,
				"cache-control": "public, max-age=3600",
			},
		});
	}

	const object = await config.bucket.get(blob.r2Key);
	if (!object) {
		return new Response("Not Found", { status: 404 });
	}

	return new Response(object.body, {
		headers: {
			"content-type": "application/x-nix-nar",
			"content-length": String(blob.fileSize),
			"cache-control": "public, max-age=31536000, immutable",
		},
	});
}

async function handleWriteApi(
	request: Request,
	config: WorkerConfig,
	pathname: string,
): Promise<Response> {
	const authError = verifyAuth(request, config);
	if (authError) {
		return authError;
	}

	if (pathname === "/_api/v1/get-missing-paths") {
		return handleGetMissingPaths(request, config);
	}

	const sessionCreate = pathname.match(/^\/_api\/v1\/caches\/([^/]+)\/upload-sessions$/);
	if (sessionCreate) {
		return handleCreateSession(request, config, sessionCreate[1]);
	}

	const multipart = pathname.match(/^\/_api\/v1\/uploads\/([^/]+)\/multipart$/);
	if (multipart) {
		return handleMultipart(config, multipart[1]);
	}

	const partUpload = pathname.match(/^\/_api\/v1\/uploads\/([^/]+)\/part\/(\d+)$/);
	if (partUpload) {
		return handleUploadPart(request, config, partUpload[1], parseInt(partUpload[2], 10));
	}

	const blob = pathname.match(/^\/_api\/v1\/uploads\/([^/]+)\/blob$/);
	if (blob) {
		return handleUploadBlob(request, config, blob[1]);
	}

	const complete = pathname.match(/^\/_api\/v1\/uploads\/([^/]+)\/complete$/);
	if (complete) {
		return handleComplete(request, config, complete[1]);
	}

	const publish = pathname.match(/^\/_api\/v1\/uploads\/([^/]+)\/publish$/);
	if (publish) {
		return handlePublish(config, publish[1]);
	}

	return new Response("Not Found", { status: 404 });
}
