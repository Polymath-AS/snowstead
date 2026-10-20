import type { WorkerConfig } from "./config.js";
import { signJwt, isTokenPermission, MAX_CACHES_PER_TOKEN, MAX_PERMS_PER_TOKEN, TOKEN_ISSUER, TOKEN_AUDIENCE } from "./jwt.js";
import type { TokenClaims } from "./jwt.js";
import type { TokenPermission } from "./db/types.js";
import type { CacheStats, PathSelection } from "./db/repository.js";
import { signingPublicKey } from "./signing.js";
import { newCacheKey } from "./cache-keys.js";
import { deleteCachePaths } from "./path-deletion.js";
import { DEFAULT_ORG_ID } from "./db/schema.js";
import { cachePath, parseOrgSlug } from "./cache-path.js";
import {
	createApiToken,
	listApiTokens,
	revokeApiToken,
	findApiToken,
	listRevokedTokens,
	ensureCache,
	listCaches,
	listCacheStats,
	listRecentPaths,
	setCachePublic,
	setCacheRetention,
	findCache,
	findOrgBySlug,
	orgHasPaths,
	setCacheSigningKey,
	cacheHasPaths,
	listPublishedPathsAfter,
	findOrg,
	putOrg,
	orgUsage,
} from "./db/repository.js";
import { storeNarinfo } from "./narinfo.js";
import { setPrivate, isPrivateCache } from "./visibility.js";
import { recordRevocation } from "./revocations.js";
import { RESERVED_CACHE_NAMES, setPublicCacheInfo } from "./layout.js";
import { parseCacheName, parseStorePathHash } from "@snowstead/cache-domain";
import { jsonResponse, errorResponse, parseJsonBody } from "./responses.js";

const MAX_TOKEN_LIFETIME_DAYS = 365;
const DEFAULT_TOKEN_LIFETIME_DAYS = 90;
const MAX_SUBJECT_LENGTH = 256;
const MAX_REASON_LENGTH = 512;

// Handlers that take `scope` serve both the admin API, where it's undefined
// and they act on the default org (a self-hosted install's), and one org's
// API, where it's that org. Cache names are an org's own, so a cache of
// another org is never in reach.

/** An org id as the service running Snowstead names it, such as a WorkOS organization id. */
export function parseOrgId(value: unknown): string | undefined {
	return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : undefined;
}

export async function handleCreateToken(
	request: Request,
	config: WorkerConfig,
	scope?: string,
): Promise<Response> {
	if (!config.jwtSecret) {
		return errorResponse("Service unavailable", 503);
	}

	const body = await parseJsonBody<{
		subject: string;
		caches: string[];
		perms: string[];
		expiresInDays?: number;
		org?: string;
	}>(request);
	if (body instanceof Response) return body;

	const org = scope ?? (body.org === undefined ? undefined : parseOrgId(body.org));
	if (scope === undefined && body.org !== undefined && org === undefined) {
		return errorResponse("org must be an org id", 400);
	}

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

	// A token is one org's, and names that org's caches; * is all of them,
	// since it can reach no other org's.
	const tokenOrg = org ?? DEFAULT_ORG_ID;
	for (const name of dedupedCaches) {
		if (name !== "*" && !(await findCache(config.db, tokenOrg, name))) {
			return errorResponse(`${name} is not a cache of ${tokenOrg}`, 400);
		}
	}

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
		...(tokenOrg === undefined ? {} : { org: tokenOrg }),
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
		orgId: tokenOrg ?? null,
	});

	return jsonResponse({
		token,
		jti,
		subject: body.subject,
		caches: dedupedCaches,
		perms: dedupedPerms,
		org: tokenOrg ?? null,
		expiresAt,
	}, 201);
}

/** All tokens, or one org's with `?org=`. */
export async function handleListTokens(
	config: WorkerConfig,
	url: URL,
	scope?: string,
): Promise<Response> {
	const filter = scope ?? orgFilter(url);
	if (filter instanceof Response) return filter;
	const tokens = await listApiTokens(config.db, filter);
	const result = tokens.map((t) => ({
		jti: t.jti,
		subject: t.subject,
		caches: JSON.parse(t.cachesJson),
		perms: JSON.parse(t.permsJson),
		org: t.orgId,
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
	scope?: string,
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
	if (!token || token.revokedAt || (scope !== undefined && token.orgId !== scope)) {
		return errorResponse("Token not found or already revoked", 404);
	}
	// KV first: requests check revocation there, and a failure after it still
	// leaves the token refused, while the reverse would leave it working with
	// the database saying otherwise.
	await recordRevocation(config, jti, token.expiresAt);
	await revokeApiToken(config.db, jti, "admin", body.reason);

	return jsonResponse({ revoked: true, jti });
}

const MAX_RETENTION_DAYS = 3650;

/**
 * Creates a cache, or sets an existing one's visibility when `private` is
 * given and its retention when `retentionDays` is: days a path stays after
 * its last push, or null to keep paths until they're deleted. Idempotent,
 * so setup can declare its caches on every run.
 */
export async function handleCreateCache(
	request: Request,
	config: WorkerConfig,
	scope?: string,
): Promise<Response> {
	const body = await parseJsonBody<{ name: string; private?: boolean; org?: string; retentionDays?: unknown }>(request);
	if (body instanceof Response) return body;

	const retention = body.retentionDays;
	if (retention !== undefined && retention !== null
		&& !(typeof retention === "number" && Number.isInteger(retention) && retention >= 1 && retention <= MAX_RETENTION_DAYS)) {
		return errorResponse(`retentionDays must be a whole number of days from 1 to ${MAX_RETENTION_DAYS}, or null`, 400);
	}

	const org = scope ?? (body.org === undefined ? DEFAULT_ORG_ID : parseOrgId(body.org));
	if (org === undefined) {
		return errorResponse("org must be an org id", 400);
	}
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

	const orgRow = await findOrg(config.db, org);
	if (!orgRow) {
		return errorResponse(`no org ${org}`, 404);
	}
	const existing = await findCache(config.db, org, name);
	const path = cachePath(orgRow.slug, name);
	const changing = existing !== undefined && body.private !== undefined && existing.isPublic === body.private;
	// A published path's objects live in its visibility's bucket; moving them
	// is not supported yet, so only an empty cache can change.
	if (changing && existing && (await cacheHasPaths(config.db, existing.id))) {
		return errorResponse("only a cache without published paths can change visibility", 409);
	}

	// The marker before the database when turning private, after it when
	// turning public: a failure in between leaves the cache private.
	if (body.private === true) {
		await setPrivate(config, path, true, org);
		await setPublicCacheInfo(config, path, false);
	}
	const { cache, created } = await ensureCache(config.db, name, body.private !== true, org);
	if (created) {
		const key = await newCacheKey(config, cache);
		if (key) await setCacheSigningKey(config.db, cache.id, key);
	}
	let isPublic = cache.isPublic;
	const changed = !created && changing;
	if (changed) {
		isPublic = !body.private;
		await setCachePublic(config.db, cache.id, isPublic);
	}
	if (isPublic) {
		await setPrivate(config, path, false, org);
		await setPublicCacheInfo(config, path, true);
	}

	let retentionDays = cache.retentionDays;
	if (retention !== undefined && retention !== retentionDays) {
		retentionDays = retention;
		await setCacheRetention(config.db, cache.id, retentionDays);
	}

	return jsonResponse({ name: cache.name, path, private: !isPublic, retentionDays, createdAt: cache.createdAt, created, changed }, created ? 201 : 200);
}

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const RECENT_PATHS = 10;

function cacheSummary(stats: CacheStats) {
	return {
		name: stats.cache.name,
		path: stats.cache.path,
		private: !stats.cache.isPublic,
		org: stats.cache.orgId,
		retentionDays: stats.cache.retentionDays,
		createdAt: stats.cache.createdAt,
		paths: stats.paths,
		size: stats.size,
		addedLastWeek: stats.addedSince,
		lastAddedAt: stats.lastAddedAt,
	};
}

/** The `?org=` a listing is narrowed to, if any. */
function orgFilter(url: URL): string | undefined | Response {
	const raw = url.searchParams.get("org");
	if (raw === null) return undefined;
	return parseOrgId(raw) ?? errorResponse("org must be an org id", 400);
}

/** All caches, or one org's with `?org=`. */
export async function handleListCaches(
	config: WorkerConfig,
	url: URL,
	scope?: string,
): Promise<Response> {
	const filter = scope ?? orgFilter(url);
	if (filter instanceof Response) return filter;
	const stats = await listCacheStats(config.db, new Date(Date.now() - WEEK_MS), { orgId: filter });
	return jsonResponse({ caches: stats.map(cacheSummary) });
}

/** One cache's numbers, its newest paths, and the public key to trust it with. */
export async function handleGetCache(
	config: WorkerConfig,
	rawName: string,
	scope?: string,
): Promise<Response> {
	const name = parseCacheName(rawName);
	if (typeof name === "object") {
		return errorResponse(name.message, 400);
	}

	const [stats] = await listCacheStats(config.db, new Date(Date.now() - WEEK_MS), { name, orgId: scope ?? DEFAULT_ORG_ID });
	if (stats === undefined) {
		return errorResponse(`no cache named ${name}`, 404);
	}

	const recent = await listRecentPaths(config.db, stats.cache.id, RECENT_PATHS);
	return jsonResponse({
		...cacheSummary(stats),
		publicKey: stats.cache.signingPublicKey ?? (await signingPublicKey(config.signingKeyName, config.signingPrivateKey)),
		recentPaths: recent.map((p) => ({ storePath: p.storePath, size: p.fileSize, addedAt: p.createdAt })),
	});
}

async function orgResponse(config: WorkerConfig, id: string, status = 200): Promise<Response> {
	const org = await findOrg(config.db, id);
	if (!org) {
		return errorResponse(`no org ${id}`, 404);
	}
	const usage = await orgUsage(config.db, id, new Date());
	return jsonResponse({ id: org.id, slug: org.slug, storageLimit: org.storageLimit, used: usage.used, pending: usage.pending }, status);
}

/** An org's storage limit and what its caches hold. */
export async function handleGetOrg(config: WorkerConfig, rawId: string): Promise<Response> {
	const id = parseOrgId(rawId);
	if (id === undefined) {
		return errorResponse("org must be an org id", 400);
	}
	return orgResponse(config, id);
}

/**
 * Creates an org or sets its storage limit, in bytes or null for none, and
 * its slug, which its caches are served under (cache-path.ts). A lower limit
 * than its caches hold refuses new pushes until they fit again. Creating an
 * org needs a slug. Changing one moves every cache's URL, and public caches
 * are stored at theirs, so it's refused once the org has published paths.
 */
export async function handlePutOrg(request: Request, config: WorkerConfig, rawId: string): Promise<Response> {
	const id = parseOrgId(rawId);
	if (id === undefined) {
		return errorResponse("org must be an org id", 400);
	}
	const body = await parseJsonBody<{ storageLimit?: unknown; slug?: unknown }>(request);
	if (body instanceof Response) return body;
	const limit = body.storageLimit;
	if (limit !== null && !(typeof limit === "number" && Number.isSafeInteger(limit) && limit >= 0)) {
		return errorResponse("storageLimit must be a whole number of bytes, or null", 400);
	}

	const existing = await findOrg(config.db, id);
	let slug = existing?.slug;
	if (body.slug !== undefined && body.slug !== slug) {
		const parsed = id === DEFAULT_ORG_ID ? { message: "the default org's slug can't change" } : parseOrgSlug(body.slug);
		if (typeof parsed === "object") {
			return errorResponse(parsed.message, 400);
		}
		const holder = await findOrgBySlug(config.db, parsed);
		if (holder && holder.id !== id) {
			return errorResponse(`${parsed} is taken`, 409);
		}
		if (existing && (await orgHasPaths(config.db, id))) {
			return errorResponse("an org's slug can't change once its caches have paths", 409);
		}
		slug = parsed;
	}
	if (slug === undefined) {
		return errorResponse("slug is needed to create an org", 400);
	}
	await putOrg(config.db, id, limit, slug);
	return orgResponse(config, id);
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
	const caches = [...new Set(rows.map((r) => r.cache.path))];
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
				batch.map((r) => storeNarinfo(config, r.cache, r.path, r.blob, visibility.get(r.cache.path) ?? true)),
			)),
		);
	}
	const skipped = rows.filter((_, i) => results[i].status === "rejected").map((r) => `${r.cache.path}/${r.path.storePathHash}`);
	const last = rows.at(-1);
	return jsonResponse({
		written: rows.length - skipped.length,
		skipped,
		next: rows.length === limit && last ? last.path.id : null,
	});
}

/**
 * Writes the database's authorization state to KV, where requests read it:
 * which caches are private, and revocations of unexpired tokens. For state
 * from before KV held it; changes made through the API write both.
 */
export async function handleSyncAuth(config: WorkerConfig): Promise<Response> {
	const caches = await listCaches(config.db);
	for (const cache of caches) {
		await setPrivate(config, cache.path, !cache.isPublic, cache.orgId);
	}
	const revoked = await listRevokedTokens(config.db, new Date());
	for (const token of revoked) {
		await recordRevocation(config, token.jti, token.expiresAt);
	}
	return jsonResponse({ caches: caches.length, private: caches.filter((c) => !c.isPublic).length, revocations: revoked.length });
}

const MAX_DELETE_BATCH = 500;

/**
 * Deletes published paths from a cache, which frees their bytes from its
 * org's usage at once. The body names the paths, `{ storePathHashes }` with
 * 1 to 500 hashes, or asks for every path published before a time,
 * `{ before: "<ISO 8601>" }`, deleted oldest first 500 at a time. Answers
 * `{ deleted, notFound, more }`: the hashes deleted, the hashes named that
 * the cache did not have (so a repeat is not an error), and whether paths
 * before the time are left for another call. The NARs stay for GC, which
 * deletes one once no cache's path points at it.
 */
export async function handleDeletePaths(
	request: Request,
	config: WorkerConfig,
	rawName: string,
	origin: string,
	scope?: string,
): Promise<Response> {
	const name = parseCacheName(rawName);
	if (typeof name === "object") {
		return errorResponse(name.message, 400);
	}
	const body = await parseJsonBody<{ storePathHashes?: unknown; before?: unknown }>(request);
	if (body instanceof Response) return body;

	if ((body.storePathHashes === undefined) === (body.before === undefined)) {
		return errorResponse("give one of storePathHashes or before", 400);
	}
	let which: PathSelection;
	let named: string[] = [];
	if (body.storePathHashes !== undefined) {
		const hashes = body.storePathHashes;
		if (!Array.isArray(hashes) || hashes.length === 0 || hashes.length > MAX_DELETE_BATCH) {
			return errorResponse(`storePathHashes must be an array of 1 to ${MAX_DELETE_BATCH} hashes`, 400);
		}
		for (const raw of hashes) {
			const hash = parseStorePathHash(String(raw));
			if (typeof hash === "object") {
				return errorResponse(`${String(raw)}: ${hash.message}`, 400);
			}
			named.push(hash);
		}
		named = [...new Set(named)];
		which = { storePathHashes: named };
	} else {
		const before = typeof body.before === "string" ? new Date(body.before) : undefined;
		if (before === undefined || Number.isNaN(before.getTime())) {
			return errorResponse("before must be an ISO 8601 time", 400);
		}
		which = { before, limit: MAX_DELETE_BATCH };
	}

	const cache = await findCache(config.db, scope ?? DEFAULT_ORG_ID, name);
	if (!cache) {
		return errorResponse(`no cache named ${name}`, 404);
	}
	const deleted = await deleteCachePaths(config, cache, which, origin);

	const gone = new Set(deleted);
	return jsonResponse({
		deleted: "before" in which ? deleted : named.filter((h) => gone.has(h)),
		notFound: named.filter((h) => !gone.has(h)),
		more: "before" in which && deleted.length === which.limit,
	});
}
