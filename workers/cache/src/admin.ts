import type { WorkerConfig } from "./config.js";
import { cacheIdEntry, isCachePattern, signJwt, Permission, MAX_CACHES_PER_TOKEN, MAX_PERMS_PER_TOKEN, TOKEN_ISSUER, TOKEN_AUDIENCE } from "./jwt.js";
import type { TokenClaims } from "./jwt.js";
import type { CacheAt, CacheStats, PathSelection } from "./db/repository.js";
import { signingPublicKey } from "./signing.js";
import { newCacheKey } from "./cache-keys.js";
import { deleteCachePaths } from "./path-deletion.js";
import { purgeCache, purgeNarinfo, scheduleNarinfoPurge } from "./cdn.js";
import { DEFAULT_ORG_ID } from "./db/schema.js";
import { OrgSlug, cachePath } from "./cache-path.js";
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
	searchPublishedPaths,
	deleteEmptyCache,
	setCachePublic,
	setCacheRetention,
	findCache,
	findOrgHoldingSlug,
	startSlugMove,
	setCacheSigningKey,
	cacheHasPaths,
	listPublishedPathsAfter,
	findOrg,
	putOrg,
	orgUsage,
	bandwidthThisMonth,
} from "./db/repository.js";
import { storeNarinfo } from "./narinfo.js";
import { readyNewPath } from "./slug-move.js";
import { PRIVATE_CACHES_REFUSED, setPrivate, isPrivateCache } from "./visibility.js";
import { recordRevocation } from "./revocations.js";
import { RESERVED_CACHE_NAMES, bucketForKey, setPublicCacheInfo } from "./layout.js";
import * as v from "valibot";
import { CacheName, OrgId, StorePathHash, parseBody, parsed } from "./schemas.js";
import { jsonResponse, errorResponse } from "./responses.js";

/** A cache name pattern: cache name characters, and * for any run of them. */
const CACHE_PATTERN_RE = /^[a-z0-9*-]{1,64}$/;

const MAX_TOKEN_LIFETIME_DAYS = 365;
const DEFAULT_TOKEN_LIFETIME_DAYS = 90;
const MAX_SUBJECT_LENGTH = 256;
const MAX_REASON_LENGTH = 512;

// Handlers that take `scope` serve both the admin API, where it's undefined
// and they act on the default org (a self-hosted install's), and one org's
// API, where it's that org. Cache names are an org's own, so a cache of
// another org is never in reach.

const SUBJECT = "subject must be a non-empty string";
const CACHE_ENTRY = "each cache entry must be a non-empty string";
const EXPIRES = `expiresInDays must be between 1 and ${MAX_TOKEN_LIFETIME_DAYS}`;

const NewToken = v.object({
	org: v.optional(OrgId),
	subject: v.pipe(v.string(SUBJECT), v.nonEmpty(SUBJECT), v.maxLength(MAX_SUBJECT_LENGTH, "subject exceeds maximum length")),
	caches: v.pipe(
		v.array(v.pipe(v.string(CACHE_ENTRY), v.nonEmpty(CACHE_ENTRY)), "caches must be a non-empty array of cache names"),
		v.nonEmpty("caches must be a non-empty array of cache names"),
		v.maxLength(MAX_CACHES_PER_TOKEN, `caches exceeds maximum of ${MAX_CACHES_PER_TOKEN}`),
	),
	perms: v.pipe(
		v.array(Permission, "perms must be a non-empty array"),
		v.nonEmpty("perms must be a non-empty array"),
		v.maxLength(MAX_PERMS_PER_TOKEN, `perms exceeds maximum of ${MAX_PERMS_PER_TOKEN}`),
	),
	expiresInDays: v.optional(
		v.nullable(v.pipe(v.number(EXPIRES), v.integer(EXPIRES), v.minValue(1, EXPIRES), v.maxValue(MAX_TOKEN_LIFETIME_DAYS, EXPIRES))),
		DEFAULT_TOKEN_LIFETIME_DAYS,
	),
});

export async function handleCreateToken(
	request: Request,
	config: WorkerConfig,
	actor: string,
	scope?: string,
): Promise<Response> {
	if (!config.jwtSecret) {
		return errorResponse("Service unavailable", 503);
	}

	const body = await parseBody(request, NewToken);
	if (body instanceof Response) return body;

	const org = scope ?? body.org;
	const expiresInDays = body.expiresInDays;
	const dedupedCaches = [...new Set(body.caches)];
	const dedupedPerms = [...new Set(body.perms)];

	// A token is one org's, and reaches only that org's caches: named ones
	// by id, so a rename keeps the token working, and patterns by name, so
	// ci-* takes in caches made later; * is all of them.
	const tokenOrg = org ?? DEFAULT_ORG_ID;
	const entries: string[] = [];
	for (const entry of dedupedCaches) {
		if (isCachePattern(entry)) {
			if (!CACHE_PATTERN_RE.test(entry)) {
				return errorResponse(`${entry} must be cache name characters and *`, 400);
			}
			entries.push(entry);
			continue;
		}
		const cache = await findCache(config.db, tokenOrg, entry);
		if (!cache) {
			return errorResponse(`${entry} is not a cache of ${tokenOrg}`, 400);
		}
		entries.push(cacheIdEntry(cache.id));
	}

	const now = Date.now() / 1000;
	const jti = crypto.randomUUID();
	const exp = expiresInDays === null ? null : now + expiresInDays * 86400;

	const claims: TokenClaims = {
		jti,
		sub: body.subject,
		iss: TOKEN_ISSUER,
		aud: TOKEN_AUDIENCE,
		caches: entries,
		perms: dedupedPerms,
		...(tokenOrg === undefined ? {} : { org: tokenOrg }),
		iat: Math.floor(now),
		...(exp === null ? {} : { exp: Math.floor(exp) }),
	};

	const token = await signJwt(claims, config.jwtSecret);

	const expiresAt = exp === null ? null : new Date(exp * 1000);

	await createApiToken(config.db, {
		jti,
		subject: body.subject,
		caches: entries,
		permsJson: JSON.stringify(dedupedPerms),
		expiresAt,
		createdBy: actor,
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
	const [tokens, caches] = await Promise.all([listApiTokens(config.db, filter), listCaches(config.db, filter)]);
	// Shown by name: a token names caches by id, which nobody reads.
	const names = new Map(caches.map((c) => [cacheIdEntry(c.id), c.name]));
	const result = tokens.map((t) => ({
		jti: t.jti,
		subject: t.subject,
		caches: t.caches.map((entry) => names.get(entry) ?? entry),
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

const REASON = "reason must be a non-empty string";

const Revocation = v.object({
	reason: v.pipe(v.string(REASON), v.nonEmpty(REASON), v.maxLength(MAX_REASON_LENGTH, "reason exceeds maximum length")),
});

export async function handleRevokeToken(
	request: Request,
	config: WorkerConfig,
	jti: string,
	actor: string,
	scope?: string,
): Promise<Response> {
	const body = await parseBody(request, Revocation);
	if (body instanceof Response) return body;

	const token = await findApiToken(config.db, jti);
	if (!token || token.revokedAt || (scope !== undefined && token.orgId !== scope)) {
		return errorResponse("Token not found or already revoked", 404);
	}
	// KV first: requests check revocation there, and a failure after it still
	// leaves the token refused, while the reverse would leave it working with
	// the database saying otherwise.
	await recordRevocation(config, jti, token.expiresAt);
	await revokeApiToken(config.db, jti, actor, body.reason);

	return jsonResponse({ revoked: true, jti });
}

const MAX_RETENTION_DAYS = 3650;

const RETENTION = `retentionDays must be a whole number of days from 1 to ${MAX_RETENTION_DAYS}, or null`;

const CacheSettings = v.object({
	retentionDays: v.optional(
		v.nullable(v.pipe(v.number(RETENTION), v.integer(RETENTION), v.minValue(1, RETENTION), v.maxValue(MAX_RETENTION_DAYS, RETENTION))),
	),
	org: v.optional(OrgId, DEFAULT_ORG_ID),
	name: v.pipe(
		CacheName,
		v.check((name) => !RESERVED_CACHE_NAMES.has(name), (issue) => `${String(issue.input)} is reserved`),
	),
	private: v.optional(v.boolean("private must be a boolean")),
});

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
	const body = await parseBody(request, CacheSettings);
	if (body instanceof Response) return body;

	const retention = body.retentionDays;
	const org = scope ?? body.org;
	const name = body.name;

	const orgRow = await findOrg(config.db, org);
	if (!orgRow) {
		return errorResponse(`no org ${org}`, 404);
	}
	const existing = await findCache(config.db, org, name);
	if (!existing && config.requireCacheSigningKeys && !await config.signingMasterKey()) {
		return errorResponse("cache signing requires SIGNING_MASTER_KEY", 503);
	}
	// An org without private-cache permission keeps existing ones private, but makes no more.
	if (body.private === true && !orgRow.privateCaches && (existing === undefined || existing.isPublic)) {
		return errorResponse(PRIVATE_CACHES_REFUSED, 403);
	}
	const path = cachePath(orgRow.slug, name);
	const changing = existing !== undefined && body.private !== undefined && existing.isPublic === body.private;
	// A published path's objects live in its visibility's bucket; moving them
	// is not supported yet, so only an empty cache can change.
	if (changing && existing && (await cacheHasPaths(config.db, existing.id))) {
		return errorResponse("only a cache without published paths can change visibility", 409);
	}

	// The marker before the database when turning private, after it when
	// turning public: a failure in between leaves the cache private.
	if (body.private === true && existing) {
		await setPrivate(config, path, true, { org, id: existing.id });
		await setPublicCacheInfo(config, path, false);
	}
	const { cache, created } = await config.db.transaction(async tx => {
		const result = await ensureCache(tx, name, body.private !== true, org);
		if (result.created) {
			const key = await newCacheKey(config, result.cache);
			if (key) await setCacheSigningKey(tx, result.cache.id, key);
		}
		return result;
	});
	if (created) {
		if (!cache.isPublic) await setPrivate(config, path, true, { org, id: cache.id });
	}
	let isPublic = cache.isPublic;
	const changed = !created && changing;
	if (changed) {
		isPublic = !body.private;
		await setCachePublic(config.db, cache.id, isPublic);
	}
	if (isPublic) {
		await setPrivate(config, path, false, { org, id: cache.id });
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
	return parsed(OrgId, raw);
}

/** A cache of the org in `scope` (the default org's without one), or a 404 naming it. */
async function cacheNamed(config: WorkerConfig, name: string, scope: string | undefined): Promise<CacheAt | Response> {
	return (await findCache(config.db, scope ?? DEFAULT_ORG_ID, name)) ?? errorResponse(`no cache named ${name}`, 404);
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
	const name = parsed(CacheName, rawName);
	if (name instanceof Response) return name;

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
	const now = new Date();
	const [usage, served] = await Promise.all([orgUsage(config.db, id, now), bandwidthThisMonth(config.db, id, now)]);
	return jsonResponse({
		id: org.id,
		slug: org.slug,
		movingFrom: org.movingFrom,
		storageLimit: org.storageLimit,
		privateCaches: org.privateCaches,
		customSigningKeys: org.customSigningKeys,
		used: usage.used,
		pending: usage.pending,
		servedThisMonth: served,
	}, status);
}

/** An org's storage limit and what its caches hold. */
export async function handleGetOrg(config: WorkerConfig, rawId: string): Promise<Response> {
	const id = parsed(OrgId, rawId);
	if (id instanceof Response) return id;
	return orgResponse(config, id);
}

const OrgTerms = v.strictObject({
	// Parsed only when it changes, below.
	slug: v.optional(v.unknown()),
	storageLimit: v.optional(v.nullable(v.pipe(v.number(), v.safeInteger(), v.minValue(0)))),
	privateCaches: v.optional(v.boolean()),
	customSigningKeys: v.optional(v.boolean()),
});

const OrgSlugConflict = v.object({ cause: v.object({ code: v.literal("23505"), constraint: v.literal("orgs_slug_unique") }) });

/**
 * Creates an org or updates its limits and slug (cache-path.ts). A lower limit
 * than its caches hold refuses new pushes until they fit again. Creating an
 * org needs a slug. Changing one moves every cache's URL, and caches are
 * stored at theirs: the new paths are readied here, and POST /move then
 * moves the objects (slug-move.ts). The old slug stays the org's until then.
 */
export async function handlePutOrg(request: Request, config: WorkerConfig, rawId: string): Promise<Response> {
	const id = parsed(OrgId, rawId);
	if (id instanceof Response) return id;
	const body = await parseBody(request, OrgTerms);
	if (body instanceof Response) return body;

	const existing = await findOrg(config.db, id);
	let slug = existing?.slug;
	if (body.slug !== undefined && body.slug !== slug) {
		if (id === DEFAULT_ORG_ID) {
			return errorResponse("the default org's slug can't change", 400);
		}
		const wanted = parsed(OrgSlug, body.slug);
		if (wanted instanceof Response) return wanted;
		const holder = await findOrgHoldingSlug(config.db, wanted);
		if (holder && holder.id !== id) {
			return errorResponse(`${wanted} is taken`, 409);
		}
		if (existing?.movingFrom) {
			return errorResponse("the last slug change is still moving the org's caches; finish it with POST /move first", 409);
		}
		slug = wanted;
	}
	if (slug === undefined) {
		return errorResponse("slug is needed to create an org", 400);
	}
	try {
		if (existing && slug !== existing.slug) {
			const orgCaches = await listCaches(config.db, id);
			if (orgCaches.length > 0) {
				const to = slug;
				await Promise.all(orgCaches.map((c) => readyNewPath(config, c, cachePath(to, c.name))));
				await startSlugMove(config.db, id, slug, existing.slug);
			}
		}
		const { storageLimit, privateCaches, customSigningKeys } = body;
		if (!(await putOrg(config.db, id, slug, { storageLimit, privateCaches, customSigningKeys }))) return errorResponse(`${slug} is taken`, 409);
	} catch (err) {
		// The preflight slug lookup is advisory; Postgres decides concurrent claims.
		if (v.is(OrgSlugConflict, err)) return errorResponse(`${slug} is taken`, 409);
		throw err;
	}
	return orgResponse(config, id);
}

const MAX_BACKFILL_BATCH = 1000;
const BACKFILL_CONCURRENCY = 4;

const AFTER = "after must be a non-negative integer";
const BACKFILL_LIMIT = `limit must be between 1 and ${MAX_BACKFILL_BATCH}`;

const BackfillPage = v.object({
	after: v.optional(v.pipe(v.number(AFTER), v.integer(AFTER), v.minValue(0, AFTER)), 0),
	limit: v.optional(v.pipe(v.number(BACKFILL_LIMIT), v.integer(BACKFILL_LIMIT), v.minValue(1, BACKFILL_LIMIT), v.maxValue(MAX_BACKFILL_BATCH, BACKFILL_LIMIT)), 500),
});

/**
 * Renders and stores the narinfo of published paths after `after` (an id),
 * for paths published before narinfo was stored at publish, or after the
 * signing key changes. Call with each response's `next` until it is null.
 */
export async function handleBackfillNarinfo(
	request: Request,
	config: WorkerConfig,
): Promise<Response> {
	const body = await parseBody(request, BackfillPage);
	if (body instanceof Response) return body;
	const { after, limit } = body;

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
	for (const cache of caches) {
		if (visibility.get(cache)) continue;
		const hashes = rows.filter((r, i) => r.cache.path === cache && results[i].status === "fulfilled").map((r) => r.path.storePathHash);
		await scheduleNarinfoPurge(config, cache, hashes);
	}
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
		await setPrivate(config, cache.path, !cache.isPublic, { org: cache.orgId, id: cache.id });
	}
	const revoked = await listRevokedTokens(config.db, new Date());
	for (const token of revoked) {
		await recordRevocation(config, token.jti, token.expiresAt);
	}
	return jsonResponse({ caches: caches.length, private: caches.filter((c) => !c.isPublic).length, revocations: revoked.length });
}

const MAX_DELETE_BATCH = 500;

const HASHES = `storePathHashes must be an array of 1 to ${MAX_DELETE_BATCH} hashes`;

const Hashes = v.pipe(v.array(StorePathHash, HASHES), v.minLength(1, HASHES), v.maxLength(MAX_DELETE_BATCH, HASHES));

const ISO_TIME = "before must be an ISO 8601 time";

const PathsToDelete = v.pipe(
	v.object({
		storePathHashes: v.optional(Hashes),
		before: v.optional(v.pipe(v.string(ISO_TIME), v.transform((at) => new Date(at)), v.check((at) => !Number.isNaN(at.getTime()), ISO_TIME))),
	}),
	v.check((body) => (body.storePathHashes === undefined) !== (body.before === undefined), "give one of storePathHashes or before"),
);

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
	const name = parsed(CacheName, rawName);
	if (name instanceof Response) return name;
	const body = await parseBody(request, PathsToDelete);
	if (body instanceof Response) return body;

	const named = [...new Set(body.storePathHashes)];
	const which: PathSelection = body.before ? { before: body.before, limit: MAX_DELETE_BATCH } : { storePathHashes: named };

	const cache = await cacheNamed(config, name, scope);
	if (cache instanceof Response) return cache;
	const deleted = await deleteCachePaths(config, cache, which, origin);

	const gone = new Set(deleted);
	return jsonResponse({
		deleted: "before" in which ? deleted : named.filter((h) => gone.has(h)),
		notFound: named.filter((h) => !gone.has(h)),
		more: "before" in which && deleted.length === which.limit,
	});
}

const PathsToPurge = v.strictObject({ storePathHashes: v.optional(Hashes) }, "expected {} or { storePathHashes }");

/**
 * Purges what the CDN holds for a public cache: the narinfo of the paths
 * named, or everything under the cache. Publishing and deleting purge on
 * their own; this is for when the CDN holds something it should not.
 */
export async function handlePurgeCache(
	request: Request,
	config: WorkerConfig,
	rawName: string,
	scope?: string,
): Promise<Response> {
	const name = parsed(CacheName, rawName);
	if (name instanceof Response) return name;
	if (!config.cdn) {
		return errorResponse("no CDN is configured to purge", 400);
	}
	const body = await parseBody(request, PathsToPurge);
	if (body instanceof Response) return body;
	const hashes = body.storePathHashes;

	const cache = await cacheNamed(config, name, scope);
	if (cache instanceof Response) return cache;
	if (!cache.isPublic) {
		return errorResponse("private caches are not on the CDN", 400);
	}
	try {
		await (hashes ? purgeNarinfo(config, cache.path, hashes) : purgeCache(config, cache.path));
	} catch (err) {
		console.error("CDN purge failed", err);
		return errorResponse("the CDN refused the purge; try again shortly", 502);
	}
	// Cloudflare acknowledged the purge, not a verified eviction in every
	// location. Do not claim that the assets have already disappeared.
	return jsonResponse({ accepted: true, paths: hashes ? [...new Set(hashes)] : "all" });
}


const DEFAULT_PATH_PAGE = 50;
const MAX_PATH_PAGE = 200;

/**
 * A cache's paths, newest first, narrowed by `q` to the ones whose name
 * contains it (a hash or package name; a full store path works too).
 * `next` is the `before` for the page after, null at the end.
 */
export async function handleListPaths(config: WorkerConfig, rawName: string, url: URL, scope?: string): Promise<Response> {
	const name = parsed(CacheName, rawName);
	if (name instanceof Response) return name;
	const query = (url.searchParams.get("q") ?? "").trim().replace(/^\/nix\/store\//, "");
	const limit = Number(url.searchParams.get("limit") ?? DEFAULT_PATH_PAGE);
	const rawBefore = url.searchParams.get("before");
	const before = rawBefore === null ? undefined : Number(rawBefore);
	if (query.length > 200) {
		return errorResponse("q must be at most 200 characters", 400);
	}
	if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PATH_PAGE) {
		return errorResponse(`limit must be between 1 and ${MAX_PATH_PAGE}`, 400);
	}
	if (before !== undefined && (!Number.isSafeInteger(before) || before < 1)) {
		return errorResponse("before must be a path id", 400);
	}

	const cache = await cacheNamed(config, name, scope);
	if (cache instanceof Response) return cache;
	const rows = await searchPublishedPaths(config.db, cache.id, query, limit, before);
	const last = rows.at(-1);
	return jsonResponse({
		paths: rows.map((p) => ({
			storePath: p.storePath,
			storePathHash: p.storePathHash,
			size: p.fileSize,
			narSize: p.narSize,
			addedAt: p.createdAt,
			lastPushedAt: p.lastPushedAt,
		})),
		next: rows.length === limit && last ? last.id : null,
	});
}

// Paths published while a cache is being deleted send it round again.
const DELETE_CACHE_ATTEMPTS = 3;

/**
 * Deletes a cache: its paths (as deleting paths does, a batch at a time),
 * its nix-cache-info and private marker, what the CDN holds under it, and
 * then the cache itself, so its name is free again. NARs stay for GC, which
 * deletes each once no cache's path points at it. Tokens keep working for
 * their other caches.
 */
export async function handleDeleteCache(config: WorkerConfig, rawName: string, origin: string, scope?: string): Promise<Response> {
	const name = parsed(CacheName, rawName);
	if (name instanceof Response) return name;
	const cache = await cacheNamed(config, name, scope);
	if (cache instanceof Response) return cache;

	let paths = 0;
	for (let attempt = 1; ; attempt++) {
		for (;;) {
			const deleted = await deleteCachePaths(config, cache, { before: new Date(Date.now() + 60_000), limit: MAX_DELETE_BATCH }, origin);
			paths += deleted.length;
			if (deleted.length < MAX_DELETE_BATCH) break;
		}
		const { deleted, staged } = await deleteEmptyCache(config.db, cache.id);
		if (deleted) {
			await Promise.all(staged.map((key) => bucketForKey(config, key).delete(key).catch(() => undefined)));
			break;
		}
		if (attempt === DELETE_CACHE_ATTEMPTS) {
			return errorResponse("pushes kept publishing to this cache while it was deleted; try again", 409);
		}
	}

	await setPublicCacheInfo(config, cache.path, false);
	await setPrivate(config, cache.path, false, { org: cache.orgId, id: cache.id });
	if (cache.isPublic) {
		const purged = purgeCache(config, cache.path).catch((err: unknown) => console.error("CDN purge of a deleted cache failed", err));
		if (config.ctx) config.ctx.waitUntil(purged);
		else await purged;
	}
	return jsonResponse({ deleted: true, name, paths });
}
