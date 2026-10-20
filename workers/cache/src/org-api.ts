import type { WorkerConfig } from "./config.js";
import { authenticateOrg, generateOrgApiKey } from "./auth.js";
import { writeAuditLog } from "./audit.js";
import { createOrgApiKey, findOrg, listOrgApiKeys, revokeOrgApiKey } from "./db/repository.js";
import {
	parseOrgId,
	handleGetOrg,
	handlePutOrg,
	handleCreateCache,
	handleListCaches,
	handleGetCache,
	handleDeletePaths,
	handleCreateToken,
	handleListTokens,
	handleRevokeToken,
} from "./admin.js";
import { jsonResponse, errorResponse, parseJsonBody } from "./responses.js";

/**
 * One org's API, under /_api/v1/orgs/:org: its storage, caches, tokens, and
 * API keys. The operator's ADMIN_SECRET reaches every org; an org's API key
 * reaches only its own, and this is where that's enforced, so nothing of
 * another org can be read or changed through it. Setting the storage limit
 * and making API keys are the operator's: a key can't raise its own limit or
 * mint keys that outlive its revocation.
 *
 *   GET  /                           storage limit and usage
 *   PUT  /                           { storageLimit } (operator)
 *   GET  /keys                       the org's API keys, without secrets
 *   POST /keys                       { name }: a new key, shown once (operator)
 *   POST /keys/:id/revoke
 *   GET  /caches   POST /caches      as the admin API, within the org
 *   GET  /caches/:name
 *   POST /caches/:name/paths/delete
 *   GET  /tokens   POST /tokens
 *   POST /tokens/:jti/revoke
 */
export async function handleOrgApi(request: Request, config: WorkerConfig, url: URL): Promise<Response> {
	const [rawOrg = "", ...rest] = url.pathname.slice("/_api/v1/orgs/".length).split("/");
	const org = parseOrgId(decodeURIComponent(rawOrg));
	if (org === undefined) {
		return errorResponse("Not Found", 404);
	}

	const auth = await authenticateOrg(request, config, org);
	if (auth.kind === "error") {
		return auth.response;
	}
	const identity = auth.identity;
	const isOperator = identity.kind === "admin";
	const ip = request.headers.get("cf-connecting-ip");
	const audit = (action: string, response: Response, cache: string | null = null, detail: object = {}) => {
		writeAuditLog(config, identity, action, cache, response.status, JSON.stringify({ org, ...detail }), ip);
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
		return audit("org.put", await handlePutOrg(request, config, org));
	}

	if (route === "keys" && method === "GET") return handleListKeys(config, org);
	if (route === "keys" && method === "POST") {
		if (!isOperator) return errorResponse("Forbidden", 403);
		return audit("key.create", await handleCreateKey(request, config, org));
	}
	if (rest.length === 3 && rest[0] === "keys" && rest[2] === "revoke" && method === "POST") {
		return audit("key.revoke", await handleRevokeKey(config, org, value(1)), null, { key: value(1) });
	}

	if (route === "caches" && method === "GET") return handleListCaches(config, url, org);
	if (route === "caches" && method === "POST") return audit("cache.create", await handleCreateCache(request, config, org));
	if (rest.length === 2 && rest[0] === "caches" && method === "GET") return handleGetCache(config, value(1), org);
	if (rest.length === 4 && rest[0] === "caches" && rest[2] === "paths" && rest[3] === "delete" && method === "POST") {
		const response = await handleDeletePaths(request, config, value(1), url.origin, org);
		const deleted = response.ok ? (await response.clone().json<{ deleted: string[] }>()).deleted : [];
		return audit("paths.delete", response, value(1), { deleted });
	}

	if (route === "tokens" && method === "GET") return handleListTokens(config, url, org);
	if (route === "tokens" && method === "POST") return audit("token.create", await handleCreateToken(request, config, org));
	if (rest.length === 3 && rest[0] === "tokens" && rest[2] === "revoke" && method === "POST") {
		return audit("token.revoke", await handleRevokeToken(request, config, value(1), org), null, { jti: value(1) });
	}

	return errorResponse("Not Found", 404);
}

const MAX_KEY_NAME_LENGTH = 64;

async function handleCreateKey(request: Request, config: WorkerConfig, org: string): Promise<Response> {
	const body = await parseJsonBody<{ name?: unknown }>(request);
	if (body instanceof Response) return body;

	const name = typeof body.name === "string" ? body.name.trim() : "";
	if (name.length === 0 || name.length > MAX_KEY_NAME_LENGTH) {
		return errorResponse(`name must be 1 to ${MAX_KEY_NAME_LENGTH} characters`, 400);
	}

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

