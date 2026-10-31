import type { WorkerConfig } from "@snowstead/cache-core/config";
import { cacheHasNar, findCacheByPath, findPublishedPathWithBlob, recordBandwidth } from "@snowstead/cache-core/db/repository";
import type { CacheAt } from "@snowstead/cache-core/db/repository";
import { signingKeyFor } from "@snowstead/cache-core/cache-keys";
import { OrgSlug, cachePath, splitReadPath, DEFAULT_ORG_SLUG } from "@snowstead/cache-core/cache-path";
import { writeAuditLog } from "@snowstead/cache-core/audit";
import { overLimit } from "@snowstead/cache-core/rate-limit";
import { errorForLog } from "@snowstead/cache-core/logging";
import { narinfoCacheKey, privateCacheBase, signedNarinfo } from "@snowstead/cache-core/narinfo";
import { bucketFor, narKey, narinfoKey, NARINFO_CACHE_CONTROL } from "@snowstead/cache-core/layout";
import { actorId, authenticateWrite, authorizeRead } from "@snowstead/cache-core/auth";
import { privateCache } from "@snowstead/cache-core/visibility";
import type { AuthIdentity } from "@snowstead/cache-core/auth";
import { hasPermission } from "@snowstead/cache-core/jwt";
import { errorResponse } from "@snowstead/cache-core/responses";
import { CacheName, Compression, FileHash, StorePathHash, valueOf } from "@snowstead/cache-core/schemas";
import { recordNixAccess } from "@snowstead/cache-core/capacity";
import {
	handleUploadPart,
	handleGetMissingPaths,
	handleCreateUploadStreams,
	handleReserveUploadParts,
	handleReserveUploadPartsBatch,
	handleFinalizeUploadStreams,
	handleInlineUpload,
	handleInlineUploadBatch,
	handleAbortUploadStream,
} from "./uploads.js";

// Pre-compiled route patterns. Compiled once per isolate, not per request.
const RE_STREAM_BATCH = /^\/_api\/v1\/caches\/([^/]+)\/upload-streams\/batch$/;
const RE_STREAM_PARTS = /^\/_api\/v1\/uploads\/([^/]+)\/parts$/;
const RE_STREAM_ABORT = /^\/_api\/v1\/uploads\/([^/]+)\/abort$/;
const RE_INLINE_UPLOAD = /^\/_api\/v1\/uploads\/([^/]+)\/inline$/;
const RE_PART_UPLOAD = /^\/_api\/v1\/uploads\/([^/]+)\/part\/(\d+)$/;

export async function handleRequest(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	const url = new URL(request.url);
	const method = request.method;

	if (url.pathname.startsWith("/_api/v1/orgs/") || url.pathname.startsWith("/_api/v1/admin/")) {
		return new Response("Not Found", { status: 404 });
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
	// On cache.snowstead.com the Worker serves private caches under /private/;
	// elsewhere (workers.dev) it serves every cache at the root.
	if (segments[0] === "private") segments.shift();

	// Public narinfo points at ../nar/..., shared by every public cache.
	if (segments[0] === "nar" && segments.length === 3 && segments[2].endsWith(".nar")) {
		return handleNarDownload(config, segments[1], segments[2].slice(0, -".nar".length), request, method);
	}

	// /<cache>/... is a default-org cache, /<slug>/<cache>/... another org's.
	const at = splitReadPath(segments);
	const cacheName = valueOf(CacheName, at?.cache);
	const slug = at?.slug === DEFAULT_ORG_SLUG ? at.slug : valueOf(OrgSlug, at?.slug);
	if (at === undefined || cacheName === undefined || slug === undefined) {
		return new Response("Not Found", { status: 404 });
	}
	const path = cachePath(slug, cacheName);
	const rest = at.rest;

	// Before any cache lookup, so a response one caller was allowed to see
	// is never served to another.
	const visibility = await privateCache(config, path);
	const isPrivate = visibility.isPrivate;
	if (isPrivate) {
		const denied = await authorizeRead(request, config, path, cacheName);
		if (denied) return denied;
		// By where the reads come from: the pull token itself stays in authorizeRead.
		const limited = await overLimit(config, "read", `${path}:${request.headers.get("cf-connecting-ip") ?? "unknown"}`);
		if (limited) return limited;
	}

	// Product admission precedes every cached response. Authenticate old
	// private slug markers first so those addresses never become public.
	const cache = await findCacheByPath(config.db, slug, cacheName);
	if (!cache?.protocols.includes("nix")) {
		return new Response("Not Found", { status: 404, headers: { "cache-control": "no-store" } });
	}
	// A stale public KV marker must never authorize a CDN handoff once the
	// authoritative cache row is private. The caller can retry after KV catches up.
	if (!isPrivate && !cache.isPublic && request.headers.get("x-snowstead-cdn-read") === "1") {
		return new Response("Not Found", { status: 404, headers: { "cache-control": "no-store" } });
	}

	if (rest[0] === "nix-cache-info" && rest.length === 1) {
		const handoff = !isPrivate && publicCdnRead(request);
		if (handoff) return handoff;
		const response = NIX_CACHE_INFO_RESPONSE();
		if (isPrivate) response.headers.set("cache-control", "private, no-cache");
		return response;
	}

	const scope = visibility.isPrivate ? { path, gen: visibility.gen, id: visibility.id, org: visibility.org, slug, name: cacheName } : undefined;
	if (rest[0] === "nar" && rest.length === 3 && rest[2].endsWith(".nar")) {
		// A scoped public URL must not expose another cache's shared blob.
		// Check before the NAR cache lookup, including for HEAD guards used by
		// hosted gateways before their native CDN fetch.
		if (!isPrivate) {
			if (!cache.isPublic || !(await cacheHasNar(config.db, cache.id, rest[1], rest[2].slice(0, -".nar".length)))) {
				return new Response("Not Found", { status: 404, headers: { "cache-control": "no-store" } });
			}
		}
		return handleNarDownload(config, rest[1], rest[2].slice(0, -".nar".length), request, method, scope);
	}

	if (rest[0]?.endsWith(".narinfo") && rest.length === 1) {
		const hashStr = rest[0].slice(0, -".narinfo".length);
		const response = await handleNarinfo(config, cache, hashStr, method, request, scope?.gen);
		if (response.status === 200 || response.status === 204) recordNixAccess(config, cache.id, hashStr);
		return response;
	}

	return new Response("Not Found", { status: 404 });
}

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

/** Admission-only opt-in for hosted gateways. Never a cacheable authorization. */
function publicCdnRead(request: Request): Response | undefined {
	if (request.headers.get("x-snowstead-cdn-read") !== "1") return undefined;
	return new Response(null, { status: 204, headers: { "x-snowstead-cdn-read": "1", "cache-control": "no-store" } });
}

/**
 * What a client may cache: private caches' responses only by the client
 * itself. The copy kept in the Cache API stays cacheable, since cache.put
 * refuses responses that say otherwise; it is only ever served through this
 * Worker, after authorization.
 */
function forClient(response: Response, isPrivate: boolean, method: string): Response {
	// A public GET's response needs nothing changed; copying it anyway was a
	// twentieth of a cache read's CPU.
	if (!isPrivate && method !== "HEAD") return response;
	const headers = new Headers(response.headers);
	if (isPrivate) headers.set("cache-control", "private, no-cache");
	return new Response(method === "HEAD" ? null : response.body, { status: response.status, headers });
}

/** Apply validators to the stored representation, also on Cache API hits. */
function narinfoForClient(response: Response, isPrivate: boolean, request: Request): Response {
	if (response.ok) {
		const etag = response.headers.get("etag");
		const modified = Date.parse(response.headers.get("last-modified") ?? "");
		const matches = (value: string, weak: boolean) => value.split(",").some((tag) => {
			const candidate = tag.trim();
			return candidate === "*" || (etag !== null && (weak ? candidate.replace(/^W\//, "") === etag.replace(/^W\//, "") : candidate === etag));
		});
		const match = request.headers.get("if-match");
		const none = request.headers.get("if-none-match");
		const unmodified = Date.parse(request.headers.get("if-unmodified-since") ?? "");
		const since = Date.parse(request.headers.get("if-modified-since") ?? "");
		const failed = match !== null ? !matches(match, false) : modified > unmodified;
		const unchanged = none !== null ? matches(none, true) : modified <= since;
		if (failed || unchanged) {
			void response.body?.cancel();
			const headers = new Headers(response.headers);
			headers.delete("content-length");
			return forClient(new Response(null, { status: failed ? 412 : 304, headers }), isPrivate, request.method);
		}
	}
	return forClient(response, isPrivate, request.method);
}

async function handleNarinfo(
	config: WorkerConfig,
	cacheAt: CacheAt,
	hashStr: string,
	method: string,
	request: Request,
	privateGen: number | string | undefined,
): Promise<Response> {
	const isPrivate = privateGen !== undefined;
	const cachePath = cacheAt.path;
	const storePathHash = valueOf(StorePathHash, hashStr);
	if (storePathHash === undefined) {
		return new Response("Not Found", { status: 404 });
	}
	// Public metadata is scoped by its R2 key. Product admission has already
	// passed; let the CDN resolve existence, validators, and negative entries.
	const handoff = !isPrivate && publicCdnRead(request);
	if (handoff) return handoff;

	// HEAD and GET share the entry.
	const cacheKey = narinfoCacheKey(new URL(request.url).origin, cachePath, storePathHash, privateGen);
	const cache = await caches.open("snowstead-narinfo");
	const cached = await cache.match(cacheKey);
	if (cached) {
		return narinfoForClient(cached, isPrivate, request);
	}

	let response: Response | undefined;
	if (isPrivate) {
		// Publication is the SQL commit, not a second R2 metadata write. Old
		// stored private narinfo is deliberately ignored, including orphans.
		const published = await findPublishedPathWithBlob(config.db, cacheAt.id, storePathHash);
		if (published) {
			const body = await signedNarinfo(await signingKeyFor(config, cacheAt), published.path, published.blob, true, cachePath);
			const bytes = new TextEncoder().encode(body);
			const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
			const etag = [...digest].map(byte => byte.toString(16).padStart(2, "0")).join("");
			response = new Response(body, { headers: {
				"content-type": "text/x-nix-narinfo", "content-length": String(bytes.length),
				"cache-control": NARINFO_CACHE_CONTROL, "etag": `"${etag}"`,
				// No Last-Modified: a signing-key change can alter this representation
				// without changing the published path's creation timestamp.
			} });
		}
	} else {
		const key = narinfoKey(cachePath, storePathHash, false);
		// Public HEAD still reads only R2 metadata and never populates a GET
		// cache entry with an empty body.
		const object = await (method === "HEAD" ? config.publicBucket.head(key) : config.publicBucket.get(key));
		if (object) response = new Response(method === "HEAD" ? null : (object as R2ObjectBody).body, {
			headers: {
				"content-type": "text/x-nix-narinfo", "content-length": String(object.size),
				"cache-control": NARINFO_CACHE_CONTROL, "etag": object.httpEtag,
				"last-modified": object.uploaded.toUTCString(),
			},
		});
	}
	if (!response) {
		const notFound = () =>
			new Response("Not Found", { status: 404, headers: { "cache-control": `public, max-age=${NARINFO_NEGATIVE_TTL_SECONDS}` } });
		if (config.ctx) {
			// A fresh Response rather than clone(): a tee'd body whose sibling is
			// never consumed can stall cache.put.
			config.ctx.waitUntil(cache.put(cacheKey, notFound()));
		}
		return forClient(notFound(), isPrivate, method);
	}

	if (config.ctx && (isPrivate || method !== "HEAD")) {
		config.ctx.waitUntil(cache.put(cacheKey, response.clone()));
	}
	return narinfoForClient(response, isPrivate, request);
}

/** The private cache a NAR is asked for through, past authorization. */
interface PrivateScope {
	readonly path: string;
	readonly gen: number | string;
	readonly id?: number;
	readonly org: string | null | undefined;
	readonly slug: string;
	readonly name: string;
}

// Larger NARs are streamed without a cached copy: caching one splits its
// stream, and a copy that falls behind the client is buffered in the
// Worker's memory.
const CACHED_NAR_MAX_BYTES = 100 * 1024 ** 2;

async function handleNarDownload(
	config: WorkerConfig,
	rawFileHash: string,
	rawCompression: string,
	request: Request,
	method: string,
	scope?: PrivateScope,
): Promise<Response> {
	const fileHash = valueOf(FileHash, rawFileHash);
	const compression = valueOf(Compression, rawCompression);
	if (fileHash === undefined || compression === undefined) {
		return new Response("Not Found", { status: 404 });
	}

	const isPrivate = scope !== undefined;
	// Scoped public requests arrive only after the fresh DB membership check.
	const handoff = !isPrivate && publicCdnRead(request);
	if (handoff) return handoff;
	// NAR keys are content-addressed, so the key comes from the URL alone.
	const r2Key = narKey(fileHash, compression, isPrivate);
	const bucket = bucketFor(config, isPrivate);

	// HEAD and GET share the entry. A private cache's entry is its own, at its
	// generation, and stored only once the check below has passed for it.
	const url = new URL(request.url);
	const cacheKey = scope
		? `${privateCacheBase(scope.path, scope.gen)}/nar/${fileHash}/${compression}.nar`
		: `${url.origin}${url.pathname}`;
	const cache = await caches.open("snowstead-nar");
	const cached = await cache.match(cacheKey);
	if (cached) {
		if (scope && method === "GET") meter(config, scope, Number(cached.headers.get("content-length") ?? 0));
		return forClient(cached, isPrivate, method);
	}

	// Private NARs are stored once by their hash for every private cache, so
	// a cache serves one only when one of its paths uses it: otherwise a
	// token for one cache could read another's NARs by their hashes.
	if (scope && !(await privateCacheHasNar(config, scope, fileHash, compression))) {
		return new Response("Not Found", { status: 404, headers: { "cache-control": "private, no-cache" } });
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

	// Private NARs too: through the Worker, which checked the caller, rather
	// than by a presigned R2 URL, which anyone holding it could use.
	const response = new Response(object.body, {
		headers: {
			"content-type": "application/x-nix-nar",
			"content-length": String(object.size),
			// Even if a generation write fails, a cached membership check must
			// not let a deleted private NAR stay accessible for a year.
			"cache-control": isPrivate ? NARINFO_CACHE_CONTROL : "public, max-age=31536000, immutable",
		},
	});
	if (config.ctx && object.size <= CACHED_NAR_MAX_BYTES) {
		config.ctx.waitUntil(cache.put(cacheKey, response.clone()).catch(() => {}));
	}
	if (scope) meter(config, scope, object.size);
	return forClient(response, isPrivate, method);
}

/** Counts a private NAR's bytes toward its org's bandwidth, after the response. */
function meter(config: WorkerConfig, scope: PrivateScope, bytes: number): void {
	config.defer((async () => {
		const org = scope.org ?? (await findCacheByPath(config.db, scope.slug, scope.name))?.orgId;
		if (org !== undefined) await recordBandwidth(config.db, org, bytes, new Date());
	})().catch((err) => console.error("Recording bandwidth failed", errorForLog(err))));
}

async function privateCacheHasNar(config: WorkerConfig, scope: PrivateScope, fileHash: string, compression: string): Promise<boolean> {
	const id = scope.id ?? (await findCacheByPath(config.db, scope.slug, scope.name))?.id;
	return id !== undefined && (await cacheHasNar(config.db, id, fileHash, compression));
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
	const limited = await overLimit(config, "push", actorId(identity));
	if (limited) return limited;
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

	const streamBatch = pathname.match(RE_STREAM_BATCH);
	if (streamBatch) {
		if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { allow: "POST" } });
		const response = await handleCreateUploadStreams(request, config, streamBatch[1], identity);
		writeAuditLog(config, identity, "push", streamBatch[1], response.status, '{"endpoint":"create-upload-streams"}', ip);
		return response;
	}
	if (pathname === "/_api/v1/uploads/parts") {
		if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { allow: "POST" } });
		const response = await handleReserveUploadPartsBatch(request, config, identity);
		writeAuditLog(config, identity, "push", null, response.status, '{"endpoint":"reserve-upload-parts-batch"}', ip);
		return response;
	}
	if (pathname === "/_api/v1/uploads/finalize") {
		if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { allow: "POST" } });
		const response = await handleFinalizeUploadStreams(request, config, identity, new URL(request.url).origin);
		writeAuditLog(config, identity, "push", null, response.status, '{"endpoint":"finalize-upload-streams"}', ip);
		return response;
	}
	if (pathname === "/_api/v1/uploads/inline/batch") {
		if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { allow: "POST" } });
		const response = await handleInlineUploadBatch(request, config, identity);
		writeAuditLog(config, identity, "push", null, response.status, '{"endpoint":"inline-upload-batch"}', ip);
		return response;
	}

	// Session-scoped upload routes — all share the same audit pattern
	const uploadRoutes: ReadonlyArray<{
		readonly pattern: RegExp;
		readonly endpoint: string;
		readonly method?: string;
		readonly handle: (match: RegExpMatchArray, config: WorkerConfig) => Promise<Response>;
	}> = [
		{
			pattern: RE_INLINE_UPLOAD,
			endpoint: "inline-upload",
			method: "POST",
			handle: (m, c) => handleInlineUpload(request, c, m[1], identity),
		},
		{
			pattern: RE_STREAM_PARTS,
			endpoint: "reserve-upload-parts",
			method: "POST",
			handle: (m, c) => handleReserveUploadParts(request, c, m[1], identity),
		},
		{
			pattern: RE_STREAM_ABORT,
			endpoint: "abort-upload-stream",
			method: "POST",
			handle: (m, c) => handleAbortUploadStream(c, m[1], identity),
		},
		{
			pattern: RE_PART_UPLOAD,
			endpoint: "upload-part",
			handle: (m, c) => handleUploadPart(request, c, m[1], parseInt(m[2], 10), identity),
		},
	];

	for (const route of uploadRoutes) {
		const match = pathname.match(route.pattern);
		if (match) {
			if (route.method && request.method !== route.method) {
				return new Response("Method Not Allowed", { status: 405, headers: { allow: route.method } });
			}
			// No transaction around the transfer: publishing fences itself
			// against the blob sweep, briefly (uploads.ts).
			const response = await route.handle(match, config);
			writeAuditLog(config, identity, "push", null, response.status, `{"endpoint":"${route.endpoint}"}`, ip);
			return response;
		}
	}

	return new Response("Not Found", { status: 404 });
}
