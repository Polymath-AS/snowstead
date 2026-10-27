import * as v from "valibot";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import { actorId, authenticateOrg, generateOrgApiKey } from "@snowstead/cache-core/auth";
import { handleSigningApi } from "./signing-api.js";
import { handleGoManagement } from "@snowstead/cache-core/go-cache";
import { writeAuditLog } from "@snowstead/cache-core/audit";
import { MoveCursor, moveSlugPage } from "./slug-move.js";
import { overLimit } from "@snowstead/cache-core/rate-limit";
import { createOrgApiKey, findOrg, listAuditLogs, listOrgApiKeys, revokeOrgApiKey } from "@snowstead/cache-core/db/repository";
import {
	handleGetOrg,
	handlePutOrg,
	handleCreateCache,
	handleListCaches,
	handleGetCache,
	handleDeletePaths,
	handlePurgeCache,
	handleListPaths,
	handleDeleteCache,
	handleCreateToken,
	handleListTokens,
	handleRevokeToken,
} from "./admin.js";
import { jsonResponse, errorResponse } from "@snowstead/cache-core/responses";
import { OrgId, parseBody, valueOf } from "@snowstead/cache-core/schemas";

/**
 * One org's API, under /_api/v1/orgs/:org: its storage, caches, tokens, and
 * API keys. The operator's ADMIN_SECRET reaches every org; an org's API key
 * reaches only its own, and this is where that's enforced, so nothing of
 * another org can be read or changed through it. Setting the storage limit
 * and making API keys are the operator's: a key can't raise its own limit or
 * mint keys that outlive its revocation.
 *
 *   GET  /                           storage limit and usage
 *   PUT  /                           { slug?, storageLimit?, privateCaches?, customSigningKeys? } (operator)
 *   POST /move                       { cursor }: move a page of objects after a slug change
 *   GET  /keys                       the org's API keys, without secrets
 *   POST /keys                       { name }: a new key, shown once (operator)
 *   POST /keys/:id/revoke
 *   GET  /caches   POST /caches      as the admin API, within the org
 *   GET  /caches/:name
 *   GET  /caches/:name/paths?q=&before=&limit=   its paths, searched by name
 *   POST /caches/:name/paths/delete
 *   POST /caches/:name/delete        the cache, its paths, and its name
 *   POST /caches/:name/purge
 *   GET  /tokens   POST /tokens
 *   POST /tokens/:jti/revoke
 *   GET  /audit?before=&limit=       what happened in the org, newest first
 */
export async function handleOrgApi(request: Request, config: WorkerConfig, url: URL): Promise<Response> {
	const [rawOrg = "", ...rest] = url.pathname.slice("/_api/v1/orgs/".length).split("/");
	const org = valueOf(OrgId, decodeURIComponent(rawOrg));
	if (org === undefined) {
		return errorResponse("Not Found", 404);
	}

	const auth = await authenticateOrg(request, config, org);
	if (auth.kind === "error") {
		return auth.response;
	}
	const identity = auth.identity;
	const isOperator = identity.kind === "admin";
	// The operator itself goes unlimited; acting for a dashboard user, it counts as them.
	if (identity.kind !== "admin" || identity.onBehalfOf !== undefined) {
		const limited = await overLimit(config, "api", actorId(identity));
		if (limited) return limited;
	}
	const ip = request.headers.get("cf-connecting-ip");
	const audit = (action: string, response: Response, cache: string | null = null, detail: object = {}) => {
		writeAuditLog(config, identity, action, cache, response.status, JSON.stringify(detail), ip, org);
		return response;
	};
	const method = request.method;
	const route = rest.join("/");
	const value = (i: number) => decodeURIComponent(rest[i] ?? "");

	// Only the operator's PUT can come before the org exists.
	if (!(method === "PUT" && route === "") && !(await findOrg(config.db, org))) {
		return errorResponse(`no org ${org}`, 404);
	}

	if (route === "" && method === "GET") return handleGetOrg(config, org);
	if (route === "" && method === "PUT") {
		if (!isOperator) return errorResponse("Forbidden", 403);
		const old = await findOrg(config.db, org);
		const response = await handlePutOrg(request, config, org);
		const current = response.ok ? await findOrg(config.db, org) : undefined;
		return audit("org.put", response, null, {
			old: old ? { slug: old.slug, storageLimit: old.storageLimit, privateCaches: old.privateCaches, customSigningKeys: old.customSigningKeys } : null,
			new: current ? { slug: current.slug, storageLimit: current.storageLimit, privateCaches: current.privateCaches, customSigningKeys: current.customSigningKeys } : null,
		});
	}
	if (route === "move" && method === "POST") return handleMoveSlug(request, config, org);

	if (route === "keys" && method === "GET") return handleListKeys(config, org);
	if (route === "keys" && method === "POST") {
		if (!isOperator) return errorResponse("Forbidden", 403);
		const response = await handleCreateKey(request, config, org);
		const made = await answered<{ id: string; name: string }>(response);
		return audit("key.create", response, null, { key: made.id, name: made.name });
	}
	if (rest.length === 3 && rest[0] === "keys" && rest[2] === "revoke" && method === "POST") {
		return audit("key.revoke", await handleRevokeKey(config, org, value(1)), null, { key: value(1) });
	}

	if (route === "caches" && method === "GET") return handleListCaches(config, url, org);
	if (rest[0] === "caches" && rest[2] === "go") {
		if (rest.length === 3 && method === "GET") return handleGoManagement(config, org, value(1), false);
		if (rest.length === 4 && rest[3] === "reset" && method === "POST") {
			return audit("go.reset", await handleGoManagement(config, org, value(1), true), value(1));
		}
	}
	if (rest[0] === "caches" && rest[2] === "signing-keys" && (
		(rest.length === 3 && (method === "GET" || method === "POST")) ||
		(rest.length === 5 && rest[4] === "activate" && method === "POST")
	)) {
		const response = await handleSigningApi(request, config, org, value(1), rest.length === 5 ? value(3) : undefined);
		if (method === "GET") return response;
		const key = await answered<{ id: string; publicKey: string }>(response);
		return audit(rest.length === 5 ? "signing-key.activate" : "signing-key.stage", response, value(1), { key: key.id, publicKey: key.publicKey });
	}
	if (route === "caches" && method === "POST") {
		// The same request creates a cache or sets an existing one's settings,
		// so the entry keeps the settings it left, not only that it ran.
		const response = await handleCreateCache(request, config, org);
		const cache = await answered<{ name: string; private: boolean; retentionDays: number | null }>(response);
		return audit("cache.create", response, cache.name ?? null, { private: cache.private, retentionDays: cache.retentionDays });
	}
	if (rest.length === 2 && rest[0] === "caches" && method === "GET") return handleGetCache(config, value(1), org);
	if (rest.length === 3 && rest[0] === "caches" && rest[2] === "purge" && method === "POST") {
		return audit("cache.purge", await handlePurgeCache(request, config, value(1), org), value(1));
	}
	if (rest.length === 3 && rest[0] === "caches" && rest[2] === "paths" && method === "GET") return handleListPaths(config, value(1), url, org);
	if (rest.length === 3 && rest[0] === "caches" && rest[2] === "delete" && method === "POST") {
		const response = await handleDeleteCache(config, value(1), url.origin, org);
		const paths = response.ok ? (await response.clone().json<{ paths: number }>()).paths : undefined;
		return audit("cache.delete", response, value(1), { paths });
	}
	if (rest.length === 4 && rest[0] === "caches" && rest[2] === "paths" && rest[3] === "delete" && method === "POST") {
		const response = await handleDeletePaths(request, config, value(1), url.origin, org);
		const deleted = response.ok ? (await response.clone().json<{ deleted: string[] }>()).deleted : [];
		return audit("paths.delete", response, value(1), { deleted });
	}

	if (route === "tokens" && method === "GET") return handleListTokens(config, url, org);
	if (route === "tokens" && method === "POST") {
		const response = await handleCreateToken(request, config, actorId(identity), org);
		const token = await answered<{ jti: string; subject: string }>(response);
		return audit("token.create", response, null, { jti: token.jti, subject: token.subject });
	}
	if (rest.length === 3 && rest[0] === "tokens" && rest[2] === "revoke" && method === "POST") {
		return audit("token.revoke", await handleRevokeToken(request, config, value(1), actorId(identity), org), null, { jti: value(1) });
	}

	if (route === "audit" && method === "GET") return handleListAudit(config, org, url);

	return errorResponse("Not Found", 404);
}

/**
 * What a successful response said, for its audit entry, so the log can name
 * what was made; a refusal names nothing. The token's secret is in its
 * response too, so callers pick the fields to keep.
 */
async function answered<T>(response: Response): Promise<Partial<T>> {
	return response.ok ? response.clone().json<T>() : {};
}

const DEFAULT_AUDIT_PAGE = 50;
const MAX_AUDIT_PAGE = 200;

/**
 * A page of the org's audit log, newest first. `next` is the `before` for
 * the page after, null at the end. Actors are API keys (key:<id>), token
 * ids, "admin" for the operator, or user:<email> for the operator acting
 * for a dashboard user (x-snowstead-actor).
 */
async function handleListAudit(config: WorkerConfig, org: string, url: URL): Promise<Response> {
	const limit = Number(url.searchParams.get("limit") ?? DEFAULT_AUDIT_PAGE);
	const rawBefore = url.searchParams.get("before");
	const before = rawBefore === null ? undefined : Number(rawBefore);
	if (!Number.isInteger(limit) || limit < 1 || limit > MAX_AUDIT_PAGE) {
		return errorResponse(`limit must be between 1 and ${MAX_AUDIT_PAGE}`, 400);
	}
	if (before !== undefined && (!Number.isSafeInteger(before) || before < 1)) {
		return errorResponse("before must be an entry id", 400);
	}

	const rows = await listAuditLogs(config.db, org, limit, before);
	const last = rows.at(-1);
	return jsonResponse({
		entries: rows.map((r) => ({
			id: r.id,
			at: r.timestamp,
			actor: r.actor,
			action: r.action,
			cache: r.cacheName,
			status: r.status,
			detail: JSON.parse(r.detail) as unknown,
			ip: r.ip,
		})),
		next: rows.length === limit && last ? last.id : null,
	});
}

const MAX_KEY_NAME_LENGTH = 64;

const KEY_NAME = `name must be 1 to ${MAX_KEY_NAME_LENGTH} characters`;

const NewKey = v.object({
	name: v.pipe(v.string(KEY_NAME), v.trim(), v.nonEmpty(KEY_NAME), v.maxLength(MAX_KEY_NAME_LENGTH, KEY_NAME)),
});

async function handleCreateKey(request: Request, config: WorkerConfig, org: string): Promise<Response> {
	const body = await parseBody(request, NewKey);
	if (body instanceof Response) return body;
	const name = body.name;

	const { id, key, secretHash } = await generateOrgApiKey();
	const row = await createOrgApiKey(config.db, { id, orgId: org, name, secretHash });
	return jsonResponse({ id, name, key, createdAt: row.createdAt }, 201);
}

async function handleListKeys(config: WorkerConfig, org: string): Promise<Response> {
	const keys = await listOrgApiKeys(config.db, org);
	return jsonResponse({
		keys: keys.map((k) => ({ id: k.id, name: k.name, createdAt: k.createdAt, revokedAt: k.revokedAt })),
	});
}

/** Revoking a revoked key is done, not an error; another org's key is missing. */
async function handleRevokeKey(config: WorkerConfig, org: string, id: string): Promise<Response> {
	if (!(await revokeOrgApiKey(config.db, org, id))) {
		return errorResponse(`no key ${id}`, 404);
	}
	return jsonResponse({ revoked: true, id });
}

/**
 * Moves a page of the org's objects to its new slug (slug-move.ts). Call
 * with each answer's `next` until it says done.
 */
async function handleMoveSlug(request: Request, config: WorkerConfig, org: string): Promise<Response> {
	const body = await parseBody(request, v.object({ cursor: MoveCursor }));
	if (body instanceof Response) return body;
	return jsonResponse(await moveSlugPage(config, org, body.cursor, new URL(request.url).origin));
}
