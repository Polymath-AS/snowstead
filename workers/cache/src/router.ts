import type { WorkerConfig } from "./config.js";
import { findCacheByName, createAuditLog } from "./db/repository.js";
import { narinfoCacheKey } from "./narinfo.js";
import { bucketFor, narKey, narinfoKey } from "./layout.js";
import { authenticateWrite, authenticateAdmin, authorizeRead, actorId } from "./auth.js";
import { isPrivateCache } from "./visibility.js";
import type { AuthIdentity } from "./auth.js";
import { hasPermission, hasCacheAccess } from "./jwt.js";
import { errorResponse } from "./responses.js";
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
import { handleCreateToken, handleListTokens, handleRevokeToken, handleCreateCache, handleListCaches, handleBackfillNarinfo, handleSyncAuth } from "./admin.js";

// Pre-compiled route patterns. Compiled once per isolate, not per request.
const RE_SESSION_CREATE = /^\/_api\/v1\/caches\/([^/]+)\/upload-sessions$/;
const RE_MULTIPART = /^\/_api\/v1\/uploads\/([^/]+)\/multipart$/;
const RE_PART_UPLOAD = /^\/_api\/v1\/uploads\/([^/]+)\/part\/(\d+)$/;
const RE_BLOB = /^\/_api\/v1\/uploads\/([^/]+)\/blob$/;
const RE_COMPLETE = /^\/_api\/v1\/uploads\/([^/]+)\/complete$/;
const RE_PUBLISH = /^\/_api\/v1\/uploads\/([^/]+)\/publish$/;
const RE_REVOKE = /^\/_api\/v1\/admin\/tokens\/([^/]+)\/revoke$/;

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
	// On cache.polmath.no the Worker serves private caches under /private/;
	// elsewhere (workers.dev) it serves every cache at the root.
	if (segments[0] === "private") segments.shift();

	// Public narinfo points at ../nar/..., shared by every public cache.
	if (segments[0] === "nar" && segments.length === 3 && segments[2].endsWith(".nar")) {
		return handleNarDownload(config, segments[1], segments[2].slice(0, -".nar".length), request, method, false);
	}

	if (segments.length < 2) {
		return new Response("Not Found", { status: 404 });
	}

	const cacheName = parseCacheName(segments[0]);
	if (typeof cacheName === "object") {
		return new Response("Not Found", { status: 404 });
	}

	// Before any cache lookup, so a response one caller was allowed to see
	// is never served to another.
	const isPrivate = await isPrivateCache(config, cacheName);
	if (isPrivate) {
		const denied = await authorizeRead(request, config, cacheName);
		if (denied) return denied;
	}

	if (segments[1] === "nix-cache-info" && segments.length === 2) {
		const response = NIX_CACHE_INFO_RESPONSE();
		if (isPrivate) response.headers.set("cache-control", "private, no-cache");
		return response;
	}

	if (segments[1] === "nar" && segments.length === 4 && segments[3].endsWith(".nar")) {
		return handleNarDownload(config, segments[2], segments[3].slice(0, -".nar".length), request, method, isPrivate);
	}

	if (segments[1].endsWith(".narinfo") && segments.length === 2) {
		const hashStr = segments[1].slice(0, -".narinfo".length);
		return handleNarinfo(config, cacheName, hashStr, method, request, isPrivate);
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
	config.defer(
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

// Nix mass-queries every substituter for every store path in a build, so most
// narinfo lookups are misses. Cache 404s briefly at the edge to keep that
// negative-lookup storm off the database. Short TTL so newly published paths appear quickly.
const NARINFO_NEGATIVE_TTL_SECONDS = 60;

/**
 * What a client may cache: private caches' responses only by the client
 * itself. The copy kept in the Cache API stays cacheable, since cache.put
 * refuses responses that say otherwise; it is only ever served through this
 * Worker, after authorization.
 */
function forClient(response: Response, isPrivate: boolean, method: string): Response {
	const headers = new Headers(response.headers);
	if (isPrivate) headers.set("cache-control", "private, no-cache");
	return new Response(method === "HEAD" ? null : response.body, { status: response.status, headers });
}

async function handleNarinfo(
	config: WorkerConfig,
	cacheName: CacheName,
	hashStr: string,
	method: string,
	request: Request,
	isPrivate: boolean,
): Promise<Response> {
	const storePathHash = parseStorePathHash(hashStr);
	if (typeof storePathHash === "object") {
		return new Response("Not Found", { status: 404 });
	}

	// HEAD and GET share the entry.
	const cacheKey = narinfoCacheKey(new URL(request.url).origin, cacheName, storePathHash, isPrivate);
	const cache = await caches.open("helios-narinfo");
	const cached = await cache.match(cacheKey);
	if (cached) {
		return forClient(cached, isPrivate, method);
	}

	// The narinfo was rendered and signed at publish. An unknown cache and an
	// unpublished path are both a missing object: a (negatively cached) 404.
	const object = await bucketFor(config, isPrivate).get(narinfoKey(cacheName, storePathHash, isPrivate));
	if (!object) {
		const notFound = () =>
			new Response("Not Found", { status: 404, headers: { "cache-control": `public, max-age=${NARINFO_NEGATIVE_TTL_SECONDS}` } });
		if (config.ctx) {
			// A fresh Response rather than clone(): a tee'd body whose sibling is
			// never consumed can stall cache.put.
			config.ctx.waitUntil(cache.put(cacheKey, notFound()));
		}
		return forClient(notFound(), isPrivate, method);
	}

	const body = await object.text();
	const response = new Response(body, {
		headers: {
			"content-type": "text/x-nix-narinfo",
			"content-length": String(textEncoder.encode(body).byteLength),
			"cache-control": "public, max-age=31536000, immutable",
		},
	});
	if (config.ctx) {
		config.ctx.waitUntil(cache.put(cacheKey, response.clone()));
	}
	return forClient(response, isPrivate, method);
}

async function handleNarDownload(
	config: WorkerConfig,
	rawFileHash: string,
	rawCompression: string,
	request: Request,
	method: string,
	isPrivate: boolean,
): Promise<Response> {
	const fileHash = parseFileHash(rawFileHash);
	if (typeof fileHash === "object") {
		return new Response("Not Found", { status: 404 });
	}

	const compression = parseCompression(rawCompression);
	if (typeof compression === "object") {
		return new Response("Not Found", { status: 404 });
	}

	// NAR keys are content-addressed, so the key comes from the URL alone.
	const r2Key = narKey(fileHash, compression, isPrivate);
	const bucket = bucketFor(config, isPrivate);

	// Presigned R2 redirect (bypasses the Worker entirely); the credentials
	// are for the private bucket, and public NARs have cache.polmath.no.
	if (isPrivate && config.r2AccessKeyId && config.r2SecretAccessKey && config.r2Endpoint) {
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
				// The URL is a credential for an hour; a private cache's must not be shared.
				"cache-control": isPrivate ? "private, max-age=3600" : "public, max-age=3600",
			},
		});
	}

	// HEAD and GET share the entry; private caches' entries live under a host
	// of their own, as narinfo's do.
	const cacheUrl = new URL(request.url);
	const cacheRequest = new Request(isPrivate ? `https://private.helios-cache.internal${cacheUrl.pathname}` : cacheUrl, { method: "GET" });
	const cache = await caches.open("helios-nar");
	const cached = await cache.match(cacheRequest);
	if (cached) {
		return forClient(cached, isPrivate, method);
	}

	if (method === "HEAD") {
		const head = await bucket.head(r2Key);
		if (!head) {
			return new Response("Not Found", { status: 404 });
		}
		return forClient(
			new Response(null, {
				status: 200,
				headers: {
					"content-type": "application/x-nix-nar",
					"content-length": String(head.size),
					"cache-control": "public, max-age=31536000, immutable",
				},
			}),
			isPrivate,
			method,
		);
	}

	const object = await bucket.get(r2Key);
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

	return forClient(response, isPrivate, method);
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

	if (pathname === "/_api/v1/admin/caches" && request.method === "POST") {
		const response = await handleCreateCache(request, config);
		writeAuditLog(config, authResult.identity, "cache.create", null, response.status, "{}", ip);
		return response;
	}

	if (pathname === "/_api/v1/admin/caches" && request.method === "GET") {
		return handleListCaches(config);
	}

	if (pathname === "/_api/v1/admin/auth/sync" && request.method === "POST") {
		const response = await handleSyncAuth(config);
		writeAuditLog(config, authResult.identity, "auth.sync", null, response.status, "{}", ip);
		return response;
	}

	if (pathname === "/_api/v1/admin/narinfo/backfill" && request.method === "POST") {
		const response = await handleBackfillNarinfo(request, config);
		writeAuditLog(config, authResult.identity, "narinfo.backfill", null, response.status, "{}", ip);
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
			handle: (m) => handlePublish(config, m[1], identity, new URL(request.url).origin),
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
