import type { WorkerConfig } from "./config.js";
import { findCacheByName, findPublishedPathWithBlob, createAuditLog } from "./db/repository.js";
import { renderNarinfo } from "./narinfo.js";
import { authenticateWrite, authenticateAdmin, actorId } from "./auth.js";
import type { AuthIdentity } from "./auth.js";
import { hasPermission, hasCacheAccess } from "./jwt.js";
import { errorResponse } from "./responses.js";
import { computeFingerprint, signNarinfo } from "./signing.js";
import { parseCacheName, parseStorePathHash, parseFileHash, parseCompression } from "@helios/cache-domain";
import type { CacheName } from "@helios/cache-domain";
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
import { handleCreateToken, handleListTokens, handleRevokeToken } from "./admin.js";

// Pre-compiled route patterns. Compiled once per isolate, not per request.
const RE_SESSION_CREATE = /^\/_api\/v1\/caches\/([^/]+)\/upload-sessions$/;
const RE_MULTIPART = /^\/_api\/v1\/uploads\/([^/]+)\/multipart$/;
const RE_PART_UPLOAD = /^\/_api\/v1\/uploads\/([^/]+)\/part\/(\d+)$/;
const RE_BLOB = /^\/_api\/v1\/uploads\/([^/]+)\/blob$/;
const RE_COMPLETE = /^\/_api\/v1\/uploads\/([^/]+)\/complete$/;
const RE_PUBLISH = /^\/_api\/v1\/uploads\/([^/]+)\/publish$/;
const RE_REVOKE = /^\/_api\/v1\/admin\/tokens\/([^/]+)\/revoke$/;

// Module-scope cache: cache name → D1 cache ID.
// Workers are short-lived isolates reused across requests on the same edge node,
// so this avoids a ~20ms D1 round trip on every narinfo warm hit.
const cacheNameToId = new Map<CacheName, number>();

async function resolveCacheId(
	db: WorkerConfig["db"],
	name: CacheName,
): Promise<number | undefined> {
	const cached = cacheNameToId.get(name);
	if (cached !== undefined) return cached;

	const row = await findCacheByName(db, name);
	if (!row) return undefined;

	cacheNameToId.set(name, row.id);
	return row.id;
}

export async function handleRequest(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const method = request.method;

	if (url.pathname === "/") {
		return json({ service: "helios-cache", status: "ok" });
	}

	if (url.pathname === "/healthz") {
		return handleHealthz(config);
	}

	// Admin API routes
	if (url.pathname.startsWith("/_api/v1/admin/")) {
		return handleAdminApi(request, config, url.pathname);
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

	// nix-cache-info is static — skip D1 lookup for the cache
	if (segments[1] === "nix-cache-info") {
		return NIX_CACHE_INFO_RESPONSE();
	}

	// NAR downloads are content-addressed — skip cache name D1 lookup
	if (segments[1] === "nar" && segments.length === 4 && segments[3].endsWith(".nar")) {
		return handleNarDownload(config, segments[2], segments[3].slice(0, -".nar".length), request, method);
	}

	const cacheName = parseCacheName(segments[0]);
	if (typeof cacheName === "object") {
		return new Response("Not Found", { status: 404 });
	}

	const cacheId = await resolveCacheId(config.db, cacheName);
	if (cacheId === undefined) {
		return new Response("Not Found", { status: 404 });
	}

	if (segments[1].endsWith(".narinfo")) {
		const hashStr = segments[1].slice(0, -".narinfo".length);
		return handleNarinfo(config, cacheId, hashStr, method, request);
	}

	return new Response("Not Found", { status: 404 });
}

function json(body: Record<string, string | boolean | number>, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}

function writeAuditLog(
	config: WorkerConfig,
	identity: AuthIdentity,
	action: string,
	cacheName: string | null,
	status: number,
	detail: string,
	ip: string | null,
): void {
	if (!config.ctx) return;
	config.ctx.waitUntil(
		createAuditLog(config.db, {
			actor: actorId(identity),
			action,
			cacheName,
			detail,
			ip,
			status,
		}).catch((err) => {
			console.error("Failed to write audit log", { error: err instanceof Error ? err.message : String(err) });
		}),
	);
}

async function handleHealthz(config: WorkerConfig): Promise<Response> {
	try {
		await findCacheByName(config.db, "__healthz_probe__");
		return json({ ok: true, service: "helios-cache" });
	} catch {
		return json({ ok: false, service: "helios-cache" }, 503);
	}
}

// Reused across requests — avoids per-request allocation
const textEncoder = new TextEncoder();

// Pre-computed static nix-cache-info body — avoids per-request string allocation
const NIX_CACHE_INFO_BODY = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n";

function NIX_CACHE_INFO_RESPONSE(): Response {
	return new Response(NIX_CACHE_INFO_BODY, {
		headers: { "content-type": "text/x-nix-cache-info" },
	});
}

async function handleNarinfo(
	config: WorkerConfig,
	cacheId: number,
	hashStr: string,
	method: string,
	request: Request,
): Promise<Response> {
	const storePathHash = parseStorePathHash(hashStr);
	if (typeof storePathHash === "object") {
		return new Response("Not Found", { status: 404 });
	}

	// Normalize to GET for shared cache (HEAD and GET share the same cache entry)
	const cacheKey = new Request(request.url, { method: "GET" });
	const cache = await caches.open("helios-narinfo");
	const cached = await cache.match(cacheKey);
	if (cached) {
		if (method === "HEAD") {
			return new Response(null, { status: 200, headers: cached.headers });
		}
		return cached;
	}

	// Single joined query: published_paths + blob_objects
	const result = await findPublishedPathWithBlob(config.db, cacheId, storePathHash);
	if (!result) {
		return new Response("Not Found", { status: 404 });
	}

	const refs: string[] = JSON.parse(result.path.referencesJson);
	const storedSigs: string[] = JSON.parse(result.path.signaturesJson);
	const fingerprint = computeFingerprint(result.path, refs);
	const sig = await signNarinfo(fingerprint, config.signingKeyName, config.signingPrivateKey);
	const signatures = sig ? [sig] : [];
	const body = renderNarinfo(result.path, result.blob, refs, storedSigs, signatures);

	const response = new Response(body, {
		headers: {
			"content-type": "text/x-nix-narinfo",
			"content-length": String(textEncoder.encode(body).byteLength),
			"cache-control": "public, max-age=31536000, immutable",
		},
	});

	// Cache at edge (non-blocking)
	if (config.ctx) {
		config.ctx.waitUntil(cache.put(cacheKey, response.clone()));
	}

	if (method === "HEAD") {
		return new Response(null, {
			status: 200,
			headers: response.headers,
		});
	}

	return response;
}

async function handleNarDownload(
	config: WorkerConfig,
	rawFileHash: string,
	rawCompression: string,
	request: Request,
	method: string,
): Promise<Response> {
	const fileHash = parseFileHash(rawFileHash);
	if (typeof fileHash === "object") {
		return new Response("Not Found", { status: 404 });
	}

	const compression = parseCompression(rawCompression);
	if (typeof compression === "object") {
		return new Response("Not Found", { status: 404 });
	}

	// NAR keys are content-addressed, so we can skip the D1 lookup
	// and go straight to R2 using the key derived from the URL
	const r2Key = `nars/sha256/${fileHash}/${compression}.nar`;

	// Presigned R2 redirect (bypasses Worker entirely)
	if (config.r2AccessKeyId && config.r2SecretAccessKey && config.r2Endpoint) {
		const url = await createPresignedUrl(
			config.r2Endpoint,
			config.r2AccessKeyId,
			config.r2SecretAccessKey,
			config.r2BucketName,
			r2Key,
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

	// Edge cache check (use a GET key for shared cache)
	const cacheUrl = new URL(request.url);
	const cacheRequest = new Request(cacheUrl, { method: "GET" });
	const cache = await caches.open("helios-nar");
	const cached = await cache.match(cacheRequest);
	if (cached) {
		if (method === "HEAD") {
			return new Response(null, { status: 200, headers: cached.headers });
		}
		return cached;
	}

	if (method === "HEAD") {
		const head = await config.bucket.head(r2Key);
		if (!head) {
			return new Response("Not Found", { status: 404 });
		}
		return new Response(null, {
			status: 200,
			headers: {
				"content-type": "application/x-nix-nar",
				"content-length": String(head.size),
				"cache-control": "public, max-age=31536000, immutable",
			},
		});
	}

	const object = await config.bucket.get(r2Key);
	if (!object) {
		return new Response("Not Found", { status: 404 });
	}

	const response = new Response(object.body, {
		headers: {
			"content-type": "application/x-nix-nar",
			"content-length": String(object.size),
			"cache-control": "public, max-age=31536000, immutable",
		},
	});

	// Store in CF edge cache (non-blocking)
	if (config.ctx) {
		config.ctx.waitUntil(cache.put(cacheRequest, response.clone()));
	}

	return response;
}

async function handleAdminApi(
	request: Request,
	config: WorkerConfig,
	pathname: string,
): Promise<Response> {
	const authResult = await authenticateAdmin(request, config);
	if (authResult.kind === "error") {
		return authResult.response;
	}

	const ip = request.headers.get("cf-connecting-ip");

	if (pathname === "/_api/v1/admin/tokens" && request.method === "POST") {
		const response = await handleCreateToken(request, config);
		writeAuditLog(config, authResult.identity, "token.create", null, response.status, "{}", ip);
		return response;
	}

	if (pathname === "/_api/v1/admin/tokens" && request.method === "GET") {
		const response = await handleListTokens(config);
		writeAuditLog(config, authResult.identity, "token.list", null, response.status, "{}", ip);
		return response;
	}

	const revokeMatch = pathname.match(RE_REVOKE);
	if (revokeMatch && request.method === "POST") {
		const response = await handleRevokeToken(request, config, revokeMatch[1]);
		writeAuditLog(config, authResult.identity, "token.revoke", null, response.status, JSON.stringify({ jti: revokeMatch[1] }), ip);
		return response;
	}

	return new Response("Not Found", { status: 404 });
}

async function handleWriteApi(
	request: Request,
	config: WorkerConfig,
	pathname: string,
): Promise<Response> {
	const authResult = await authenticateWrite(request, config);
	if (authResult.kind === "error") {
		return authResult.response;
	}

	const identity = authResult.identity;
	const ip = request.headers.get("cf-connecting-ip");

	// Check push permission for JWT tokens
	if (identity.kind === "jwt" && !hasPermission(identity.claims, "push")) {
		const response = errorResponse("Forbidden", 403);
		writeAuditLog(config, identity, "push", null, 403, '{"reason":"missing push permission"}', ip);
		return response;
	}

	if (pathname === "/_api/v1/get-missing-paths") {
		const response = await handleGetMissingPaths(request, config, identity);
		writeAuditLog(config, identity, "push", null, response.status, '{"endpoint":"get-missing-paths"}', ip);
		return response;
	}

	const sessionCreate = pathname.match(RE_SESSION_CREATE);
	if (sessionCreate) {
		const cacheName = sessionCreate[1];
		if (identity.kind === "jwt" && !hasCacheAccess(identity.claims, cacheName)) {
			const response = errorResponse("Forbidden", 403);
			writeAuditLog(config, identity, "push", cacheName, 403, '{"reason":"cache access denied"}', ip);
			return response;
		}
		const response = await handleCreateSession(request, config, cacheName);
		writeAuditLog(config, identity, "push", cacheName, response.status, '{"endpoint":"create-session"}', ip);
		return response;
	}

	// Session-scoped upload routes — all share the same audit pattern
	const uploadRoutes: ReadonlyArray<{
		readonly pattern: RegExp;
		readonly endpoint: string;
		readonly handle: (match: RegExpMatchArray) => Promise<Response>;
	}> = [
		{
			pattern: RE_MULTIPART,
			endpoint: "multipart",
			handle: (m) => handleMultipart(config, m[1], identity),
		},
		{
			pattern: RE_PART_UPLOAD,
			endpoint: "upload-part",
			handle: (m) => handleUploadPart(request, config, m[1], parseInt(m[2], 10), identity),
		},
		{
			pattern: RE_BLOB,
			endpoint: "upload-blob",
			handle: (m) => handleUploadBlob(request, config, m[1], identity),
		},
		{
			pattern: RE_COMPLETE,
			endpoint: "complete",
			handle: (m) => handleComplete(request, config, m[1], identity),
		},
		{
			pattern: RE_PUBLISH,
			endpoint: "publish",
			handle: (m) => handlePublish(config, m[1], identity),
		},
	];

	for (const route of uploadRoutes) {
		const match = pathname.match(route.pattern);
		if (match) {
			const response = await route.handle(match);
			writeAuditLog(config, identity, "push", null, response.status, `{"endpoint":"${route.endpoint}"}`, ip);
			return response;
		}
	}

	return new Response("Not Found", { status: 404 });
}
