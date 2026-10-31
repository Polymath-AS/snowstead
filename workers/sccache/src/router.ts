import type { WorkerConfig } from "@snowstead/cache-core/config";
import { authenticateWrite, actorId } from "@snowstead/cache-core/auth";
import { hasCacheAccess, hasPermission, isOrgsToken } from "@snowstead/cache-core/jwt";
import { errorResponse } from "@snowstead/cache-core/responses";
import { overLimit } from "@snowstead/cache-core/rate-limit";
import { findSccacheTarget, SCCACHE_MAX_BYTES } from "@snowstead/cache-core/sccache";
import { recordSccacheAccess } from "@snowstead/cache-core/capacity";
import { consumeBody, uploadArchive } from "./upload.js";

/** sccache's WebDAV subset, not a general-purpose WebDAV filesystem. */
export async function handleRequest(request: Request, config: WorkerConfig): Promise<Response> {
	const url = new URL(request.url);
	// OpenDAL appends '/' even when the configured endpoint already ends in it.
	const match = /^\/_api\/v1\/sccache\/([a-z0-9-]+)\/([a-z0-9-]+)\/+(.*)$/.exec(url.pathname);
	if (!match) return errorResponse("Not Found", 404);
	const path = match[3];
	const action = /^([a-f0-9])\/([a-f0-9])\/([a-f0-9])\/([a-f0-9]{64})$/.exec(path);
	const directory = /^(?:[a-f0-9]\/){0,3}$/.test(path);
	const probe = path === ".sccache_check";
	if (!probe && !directory && (!action || action[4].slice(0, 3) !== action.slice(1, 4).join(""))) return errorResponse("Not Found", 404);
	const write = request.method === "PUT" || request.method === "MKCOL";
	if (!["GET", "HEAD", "PUT", "PROPFIND", "MKCOL"].includes(request.method)) return errorResponse("Method Not Allowed", 405, { allow: "GET, HEAD, PUT, PROPFIND, MKCOL" });
	const target = await findSccacheTarget(config.db, match[1], match[2], action?.[4] ?? "");
	if (!target || !target.cache.protocols.includes("sccache")) return errorResponse("Not Found", 404);
	const { cache, entry } = target;
	if (write || !cache.isPublic) {
		const auth = await authenticateWrite(request, config);
		if (auth.kind === "error") return auth.response;
		const identity = auth.identity;
		if (identity.kind !== "jwt" || !hasPermission(identity.claims, write ? "sccache:write" : "sccache:read")
			|| !isOrgsToken(identity.claims, cache.orgId) || !hasCacheAccess(identity.claims, cache)) return errorResponse("Forbidden", 403);
		const limited = await overLimit(config, write ? "push" : "read", actorId(identity));
		if (limited) return limited;
	}
	// Virtual directories avoid R2 marker writes and same-prefix contention.
	if (directory) {
		await config.releaseDb();
		if (request.method === "MKCOL") return new Response(null, { status: 201 });
		if (request.method === "PROPFIND") return new Response(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>${url.pathname}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getlastmodified>${cache.createdAt.toUTCString()}</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, { status: 207, headers: { "content-type": "application/xml", "cache-control": "no-store" } });
		return errorResponse("Method Not Allowed", 405);
	}
	if (request.method === "PUT") {
		const length = request.headers.get("content-length") ?? "";
		if (!/^\d+$/.test(length)) return errorResponse("Content-Length required", 411);
		const size = Number(length);
		if (!Number.isSafeInteger(size) || size > (probe ? 1024 : SCCACHE_MAX_BYTES)) return errorResponse("Artifact is too large", 413);
		if (probe) {
			await config.releaseDb();
			try { await consumeBody(request, size); } catch { return errorResponse("Content length mismatch", 400); }
			return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
		}
		return uploadArchive(request, config, cache, action![4], size);
	}
	if (!["GET", "HEAD"].includes(request.method)) return errorResponse("Method Not Allowed", 405);
	if (!entry || entry.expiresAt.getTime() <= Date.now()) return errorResponse("Not Found", 404);
	const head = request.method === "HEAD";
	const key = new Request(`${url.origin}/_snowstead_sccache_cdn/${entry.r2Key}`);
	const edge = await caches.open("snowstead-sccache");
	const hit = await edge.match(key);
	if (hit) {
		if (head) await hit.body?.cancel();
		recordSccacheAccess(config, entry.id);
		await config.releaseDb();
		return returned(hit, head, "HIT");
	}
	const result = head ? null : await config.bucket.get(entry.r2Key);
	const object = head ? await config.bucket.head(entry.r2Key) : result;
	if (!object) return errorResponse("Not Found", 404);
	const ttl = Math.min(3600, Math.floor((entry.expiresAt.getTime() - Date.now()) / 1000));
	if (ttl < 0) { await result?.body.cancel(); return errorResponse("Not Found", 404); }
	const response = new Response(result?.body ?? null, { headers: { "content-type": "application/octet-stream",
		"content-length": String(object.size), etag: object.httpEtag, "cache-control": `public, max-age=${ttl}` } });
	// Limit the tee backlog when the client and edge cache consume at different speeds.
	if (!head && ttl > 0 && object.size <= 8 * 1024 * 1024 && config.ctx) config.ctx.waitUntil(edge.put(key, response.clone()));
	recordSccacheAccess(config, entry.id);
	await config.releaseDb();
	return returned(response, head, "MISS");
}

function returned(response: Response, head: boolean, source: string): Response {
	const headers = new Headers(response.headers);
	headers.set("cache-control", "no-store");
	headers.set("cloudflare-cdn-cache-control", "no-store");
	headers.set("x-snowstead-cache", source);
	return new Response(head ? null : response.body, { headers });
}
