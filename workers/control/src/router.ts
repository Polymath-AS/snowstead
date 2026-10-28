import type { WorkerConfig } from "@snowstead/cache-core/config";
import { findOrg, globalOverview, listOrgs } from "@snowstead/cache-core/db/repository";
import { writeAuditLog } from "@snowstead/cache-core/audit";
import { actorId, authenticateAdmin } from "@snowstead/cache-core/auth";
import { errorResponse, jsonResponse } from "@snowstead/cache-core/responses";
import { handleOrgApi } from "./org-api.js";
import { handleCreateToken, handleListTokens, handleRevokeToken, handleCreateCache, handleListCaches, handleGetCache, handleBackfillNarinfo, handleSyncAuth, handleDeletePaths, handlePurgeCache, handleDeleteCache } from "./admin.js";

const RE_REVOKE = /^\/_api\/v1\/admin\/tokens\/([^/]+)\/revoke$/;
const RE_ADMIN_CACHE = /^\/_api\/v1\/admin\/caches\/([^/]+)$/;
const RE_ADMIN_CACHE_PATHS_DELETE = /^\/_api\/v1\/admin\/caches\/([^/]+)\/paths\/delete$/;
const RE_ADMIN_CACHE_PURGE = /^\/_api\/v1\/admin\/caches\/([^/]+)\/purge$/;
const RE_ADMIN_CACHE_DELETE = /^\/_api\/v1\/admin\/caches\/([^/]+)\/delete$/;

export async function handleRequest(request: Request, config: WorkerConfig): Promise<Response> {
	const url = new URL(request.url);
	if (url.pathname === "/") return jsonResponse({ service: "snowstead", status: "ok" });
	if (url.pathname === "/healthz") {
		try {
			await findOrg(config.db, "__healthz_probe__");
			return jsonResponse({ ok: true, service: "snowstead" });
		} catch {
			return jsonResponse({ ok: false, service: "snowstead" }, 503);
		}
	}
	if (url.pathname.startsWith("/_api/v1/orgs/")) return handleOrgApi(request, config, url);
	if (url.pathname.startsWith("/_api/v1/admin/")) return handleAdminApi(request, config, url.pathname);
	return new Response("Not Found", { status: 404 });
}

async function handleAdminApi(request: Request, config: WorkerConfig, pathname: string): Promise<Response> {
	const authResult = await authenticateAdmin(request, config);
	if (authResult.kind === "error") return authResult.response;

	if (pathname === "/_api/v1/admin/orgs" && request.method === "GET") {
		const { search, searchParams } = new URL(request.url);
		if (search.length > 8192) return errorResponse("Organization filter is too long", 414);
		// No query means operator inventory. Any supplied query must explicitly
		// name 1–50 IDs: typos or empty filters must never broaden into inventory.
		// URL.search loses a bare ?, and searchParams drops empty & components.
		const ids = request.url.includes("?") ? searchParams.getAll("id") : undefined;
		if (ids !== undefined && (ids.length === 0 || ids.length > 50
			|| search.slice(1).split("&").includes("")
			|| [...searchParams.keys()].some(key => key !== "id")
			|| ids.some(id => !/^[A-Za-z0-9_-]{1,128}$/.test(id)))) {
			return errorResponse("Use 1 to 50 id parameters, each containing 1 to 128 letters, numbers, underscores, or dashes", 400);
		}
		return jsonResponse({ orgs: await listOrgs(config.db, ids) });
	}
	if (pathname === "/_api/v1/admin/overview" && request.method === "GET") {
		return jsonResponse(await globalOverview(config.db, new Date()));
	}
	const ip = request.headers.get("cf-connecting-ip");
	if (pathname === "/_api/v1/admin/tokens" && request.method === "POST") {
		const response = await handleCreateToken(request, config, actorId(authResult.identity));
		writeAuditLog(config, authResult.identity, "token.create", null, response.status, "{}", ip);
		return response;
	}
	if (pathname === "/_api/v1/admin/tokens" && request.method === "GET") {
		const response = await handleListTokens(config, new URL(request.url));
		writeAuditLog(config, authResult.identity, "token.list", null, response.status, "{}", ip);
		return response;
	}
	if (pathname === "/_api/v1/admin/caches" && request.method === "POST") {
		const response = await handleCreateCache(request, config);
		writeAuditLog(config, authResult.identity, "cache.create", null, response.status, "{}", ip);
		return response;
	}
	if (pathname === "/_api/v1/admin/caches" && request.method === "GET") {
		return handleListCaches(config, new URL(request.url));
	}
	const cacheMatch = pathname.match(RE_ADMIN_CACHE);
	if (cacheMatch && request.method === "GET") return handleGetCache(config, decodeURIComponent(cacheMatch[1]));
	const purgeMatch = pathname.match(RE_ADMIN_CACHE_PURGE);
	if (purgeMatch && request.method === "POST") {
		const name = decodeURIComponent(purgeMatch[1]);
		const response = await handlePurgeCache(request, config, name);
		writeAuditLog(config, authResult.identity, "cache.purge", name, response.status, "{}", ip);
		return response;
	}
	const deleteCacheMatch = pathname.match(RE_ADMIN_CACHE_DELETE);
	if (deleteCacheMatch && request.method === "POST") {
		const name = decodeURIComponent(deleteCacheMatch[1]);
		const response = await handleDeleteCache(config, name, new URL(request.url).origin);
		const detail = response.ok ? JSON.stringify({ paths: (await response.clone().json<{ paths: number }>()).paths }) : "{}";
		writeAuditLog(config, authResult.identity, "cache.delete", name, response.status, detail, ip);
		return response;
	}
	const deleteMatch = pathname.match(RE_ADMIN_CACHE_PATHS_DELETE);
	if (deleteMatch && request.method === "POST") {
		const name = decodeURIComponent(deleteMatch[1]);
		const response = await handleDeletePaths(request, config, name, new URL(request.url).origin);
		const detail = response.ok ? JSON.stringify({ deleted: (await response.clone().json<{ deleted: string[] }>()).deleted }) : "{}";
		writeAuditLog(config, authResult.identity, "paths.delete", name, response.status, detail, ip);
		return response;
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
		const response = await handleRevokeToken(request, config, revokeMatch[1], actorId(authResult.identity));
		writeAuditLog(config, authResult.identity, "token.revoke", null, response.status, JSON.stringify({ jti: revokeMatch[1] }), ip);
		return response;
	}
	return new Response("Not Found", { status: 404 });
}
