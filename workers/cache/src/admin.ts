import type { WorkerConfig } from "./config.js";
import { signJwt, isTokenPermission, MAX_CACHES_PER_TOKEN, MAX_PERMS_PER_TOKEN, TOKEN_ISSUER, TOKEN_AUDIENCE } from "./jwt.js";
import type { TokenClaims } from "./jwt.js";
import type { TokenPermission } from "./db/types.js";
import {
	createApiToken,
	listApiTokens,
	revokeApiToken,
	findApiToken,
	listRevokedTokens,
	ensureCache,
	listCaches,
	setCachePublic,
	findCacheByName,
	cacheHasPaths,
	listPublishedPathsAfter,
} from "./db/repository.js";
import { storeNarinfo } from "./narinfo.js";
import { setPrivateMarker, isPrivateCache } from "./visibility.js";
import { recordRevocation } from "./revocations.js";
import { RESERVED_CACHE_NAMES, setPublicCacheInfo } from "./layout.js";
import { parseCacheName } from "@helios/cache-domain";
import { jsonResponse, errorResponse, parseJsonBody } from "./responses.js";

const MAX_TOKEN_LIFETIME_DAYS = 365;
const DEFAULT_TOKEN_LIFETIME_DAYS = 90;
const MAX_SUBJECT_LENGTH = 256;
const MAX_REASON_LENGTH = 512;

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

	const expiresAt = new Date(exp * 1000);

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

	const token = await findApiToken(config.db, jti);
	if (!token || token.revokedAt) {
		return errorResponse("Token not found or already revoked", 404);
	}
	// KV first: requests check revocation there, and a failure after it still
	// leaves the token refused, while the reverse would leave it working with
	// the database saying otherwise.
	await recordRevocation(config, jti, token.expiresAt);
	await revokeApiToken(config.db, jti, "admin", body.reason);

	return jsonResponse({ revoked: true, jti });
}

/**
 * Creates a cache, or sets an existing one's visibility when `private` is
 * given. Idempotent, so setup can declare its caches on every run.
 */
export async function handleCreateCache(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	const body = await parseJsonBody<{ name: string; private?: boolean }>(request);
	if (body instanceof Response) return body;

	const name = parseCacheName(String(body.name ?? ""));
	if (typeof name === "object") {
		return errorResponse(name.message, 400);
	}
	if (RESERVED_CACHE_NAMES.has(name)) {
		return errorResponse(`${name} is reserved`, 400);
	}
	if (body.private !== undefined && typeof body.private !== "boolean") {
		return errorResponse("private must be a boolean", 400);
	}

	const existing = await findCacheByName(config.db, name);
	const changing = existing !== undefined && body.private !== undefined && existing.isPublic === body.private;
	// A published path's objects live in its visibility's bucket; moving them
	// is not supported yet, so only an empty cache can change.
	if (changing && existing && (await cacheHasPaths(config.db, existing.id))) {
		return errorResponse("only a cache without published paths can change visibility", 409);
	}

	// The marker before the database when turning private, after it when
	// turning public: a failure in between leaves the cache private.
	if (body.private === true) {
		await setPrivateMarker(config, name, true);
		await setPublicCacheInfo(config, name, false);
	}
	const { cache, created } = await ensureCache(config.db, name, body.private !== true);
	let isPublic = cache.isPublic;
	const changed = !created && changing;
	if (changed) {
		isPublic = !body.private;
		await setCachePublic(config.db, name, isPublic);
	}
	if (isPublic) {
		await setPrivateMarker(config, name, false);
		await setPublicCacheInfo(config, name, true);
	}

	return jsonResponse({ name: cache.name, private: !isPublic, createdAt: cache.createdAt, created, changed }, created ? 201 : 200);
}

export async function handleListCaches(
	config: WorkerConfig,
): Promise<Response> {
	const caches = await listCaches(config.db);
	return jsonResponse({ caches: caches.map((c) => ({ name: c.name, private: !c.isPublic, createdAt: c.createdAt })) });
}

const MAX_BACKFILL_BATCH = 1000;
const BACKFILL_CONCURRENCY = 4;

/**
 * Renders and stores the narinfo of published paths after `after` (an id),
 * for paths published before narinfo was stored at publish, or after the
 * signing key changes. Call with each response's `next` until it is null.
 */
export async function handleBackfillNarinfo(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	const body = await parseJsonBody<{ after?: number; limit?: number }>(request);
	if (body instanceof Response) return body;

	const after = body.after ?? 0;
	const limit = body.limit ?? 500;
	if (!Number.isInteger(after) || after < 0) {
		return errorResponse("after must be a non-negative integer", 400);
	}
	if (!Number.isInteger(limit) || limit < 1 || limit > MAX_BACKFILL_BATCH) {
		return errorResponse(`limit must be between 1 and ${MAX_BACKFILL_BATCH}`, 400);
	}

	const rows = await listPublishedPathsAfter(config.db, after, limit);
	const caches = [...new Set(rows.map((r) => r.cacheName))];
	const visibility = new Map(await Promise.all(caches.map(async (c) => [c, await isPrivateCache(config, c)] as const)));
	await Promise.all(caches.filter((c) => !visibility.get(c)).map((c) => setPublicCacheInfo(config, c, true)));
	// A path whose NAR is missing is skipped: a narinfo pointing at nothing
	// would be worse than none.
	// A few at a time: copying a NAR holds two R2 streams open, and a Worker
	// may only keep a handful of connections open at once.
	const results: PromiseSettledResult<void>[] = [];
	for (let i = 0; i < rows.length; i += BACKFILL_CONCURRENCY) {
		const batch = rows.slice(i, i + BACKFILL_CONCURRENCY);
		results.push(
			...(await Promise.allSettled(
				batch.map((r) => storeNarinfo(config, r.cacheName, r.path, r.blob, visibility.get(r.cacheName) ?? true)),
			)),
		);
	}
	const skipped = rows.filter((_, i) => results[i].status === "rejected").map((r) => `${r.cacheName}/${r.path.storePathHash}`);
	const last = rows.at(-1);
	return jsonResponse({
		written: rows.length - skipped.length,
		skipped,
		next: rows.length === limit && last ? last.path.id : null,
	});
}

/** Writes the database's revocations of unexpired tokens to KV, for tokens revoked before KV held them. */
export async function handleSyncRevocations(config: WorkerConfig): Promise<Response> {
	const revoked = await listRevokedTokens(config.db, new Date());
	for (const token of revoked) {
		await recordRevocation(config, token.jti, token.expiresAt);
	}
	return jsonResponse({ synced: revoked.length });
}
