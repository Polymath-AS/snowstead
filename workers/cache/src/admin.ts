import type { WorkerConfig } from "./config.js";
import { signJwt, isTokenPermission, MAX_CACHES_PER_TOKEN, MAX_PERMS_PER_TOKEN, TOKEN_ISSUER, TOKEN_AUDIENCE } from "./jwt.js";
import type { TokenClaims } from "./jwt.js";
import type { TokenPermission } from "./db/types.js";
import {
	createApiToken,
	listApiTokens,
	revokeApiToken,
} from "./db/repository.js";
import { jsonResponse, errorResponse, parseJsonBody } from "./responses.js";

const MAX_TOKEN_LIFETIME_DAYS = 365;
const DEFAULT_TOKEN_LIFETIME_DAYS = 90;
const MAX_SUBJECT_LENGTH = 256;
const MAX_REASON_LENGTH = 512;

// ── Create Token ──

export async function handleCreateToken(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	if (!config.jwtSecret) {
		return errorResponse("Service unavailable", 503);
	}

	const body = await parseJsonBody<{
		subject: string;
		caches: string[];
		perms: string[];
		expiresInDays?: number;
	}>(request);
	if (body instanceof Response) return body;

	if (!body.subject || typeof body.subject !== "string") {
		return errorResponse("subject must be a non-empty string", 400);
	}

	if (body.subject.length > MAX_SUBJECT_LENGTH) {
		return errorResponse("subject exceeds maximum length", 400);
	}

	if (!Array.isArray(body.caches) || body.caches.length === 0) {
		return errorResponse("caches must be a non-empty array of cache names", 400);
	}
	if (body.caches.length > MAX_CACHES_PER_TOKEN) {
		return errorResponse(`caches exceeds maximum of ${MAX_CACHES_PER_TOKEN}`, 400);
	}
	for (const c of body.caches) {
		if (typeof c !== "string" || c.length === 0) {
			return errorResponse("each cache entry must be a non-empty string", 400);
		}
	}

	if (!Array.isArray(body.perms) || body.perms.length === 0) {
		return errorResponse("perms must be a non-empty array", 400);
	}
	if (body.perms.length > MAX_PERMS_PER_TOKEN) {
		return errorResponse(`perms exceeds maximum of ${MAX_PERMS_PER_TOKEN}`, 400);
	}
	const validatedPerms: TokenPermission[] = [];
	for (const p of body.perms) {
		if (typeof p !== "string" || !isTokenPermission(p)) {
			return errorResponse(`invalid permission: ${String(p)}, expected "pull" or "push"`, 400);
		}
		validatedPerms.push(p);
	}

	const expiresInDays = body.expiresInDays ?? DEFAULT_TOKEN_LIFETIME_DAYS;
	if (!Number.isFinite(expiresInDays) || !Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > MAX_TOKEN_LIFETIME_DAYS) {
		return errorResponse(`expiresInDays must be between 1 and ${MAX_TOKEN_LIFETIME_DAYS}`, 400);
	}

	const dedupedCaches = [...new Set(body.caches)];
	const dedupedPerms = [...new Set(validatedPerms)];

	const now = Date.now() / 1000;
	const jti = crypto.randomUUID();
	const exp = now + expiresInDays * 86400;

	const claims: TokenClaims = {
		jti,
		sub: body.subject,
		iss: TOKEN_ISSUER,
		aud: TOKEN_AUDIENCE,
		caches: dedupedCaches,
		perms: dedupedPerms,
		iat: Math.floor(now),
		exp: Math.floor(exp),
	};

	const token = await signJwt(claims, config.jwtSecret);

	const expiresAt = new Date(exp * 1000).toISOString();

	await createApiToken(config.db, {
		jti,
		subject: body.subject,
		cachesJson: JSON.stringify(dedupedCaches),
		permsJson: JSON.stringify(dedupedPerms),
		expiresAt,
		createdBy: "admin",
	});

	return jsonResponse({
		token,
		jti,
		subject: body.subject,
		caches: dedupedCaches,
		perms: dedupedPerms,
		expiresAt,
	}, 201);
}

// ── List Tokens ──

export async function handleListTokens(
	config: WorkerConfig,
): Promise<Response> {
	const tokens = await listApiTokens(config.db);
	const result = tokens.map((t) => ({
		jti: t.jti,
		subject: t.subject,
		caches: JSON.parse(t.cachesJson),
		perms: JSON.parse(t.permsJson),
		createdAt: t.createdAt,
		expiresAt: t.expiresAt,
		createdBy: t.createdBy,
		revokedAt: t.revokedAt,
		revokedBy: t.revokedBy,
		revocationReason: t.revocationReason,
	}));
	return jsonResponse({ tokens: result });
}

// ── Revoke Token ──

export async function handleRevokeToken(
	request: Request,
	config: WorkerConfig,
	jti: string,
): Promise<Response> {
	const body = await parseJsonBody<{
		reason: string;
	}>(request);
	if (body instanceof Response) return body;

	if (!body.reason || typeof body.reason !== "string") {
		return errorResponse("reason must be a non-empty string", 400);
	}

	if (body.reason.length > MAX_REASON_LENGTH) {
		return errorResponse("reason exceeds maximum length", 400);
	}

	const revoked = await revokeApiToken(config.db, jti, "admin", body.reason);
	if (!revoked) {
		return errorResponse("Token not found or already revoked", 404);
	}

	return jsonResponse({ revoked: true, jti });
}
