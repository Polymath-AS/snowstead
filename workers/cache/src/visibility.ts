import * as v from "valibot";
import type { WorkerConfig } from "./config.js";

/**
 * Whether the cache at a path (cache-path.ts) is private, answered without
 * the database: a private
 * cache has an entry in KV, and no entry means public, as every cache was
 * before private caches existed. The database's is_public is the source of
 * truth; the entry is written before it when a cache turns private and
 * removed after it when it turns public, so a failure in between leaves the
 * cache private, never exposed.
 *
 * The entry also names the cache's org, so reads can check a token is the
 * org's without the database, and carries the cache's generation: the
 * Cache API keys of its narinfo and NARs include it, and deleting paths
 * moves it on, so copies cached anywhere stop being served (the Cache API
 * can only be cleared in the data center a request runs in). Entries from before orgs say "1", which
 * names none; POST /_api/v1/admin/auth/sync rewrites them.
 *
 * KV reads and isolate memos use a 30-second TTL, but KV is eventually
 * consistent: propagation can take 60 seconds or more. This is not a
 * bounded global invalidation or immediate revocation guarantee.
 */
const KV_CACHE_TTL_SECONDS = 30;
const MEMO_MAX_ENTRIES = 10_000;
/**
 * A private cache's org: an id, null for none, or undefined for an entry
 * that predates orgs; and its id, for tokens that name it by id, unless the
 * entry predates that.
 */
export type PrivateCache =
	| { readonly isPrivate: false }
	| { readonly isPrivate: true; readonly org: string | null | undefined; readonly id?: number; readonly gen: number | string };

const visibility = new Map<string, PrivateCache & { readonly until: number }>();

const LEGACY_ENTRY = "1";

/** A private cache's entry; a field it lacks or garbles falls back on its own. */
const Entry = v.object({
	org: v.fallback(v.nullable(v.string()), null),
	id: v.fallback(v.optional(v.number()), undefined),
	gen: v.fallback(v.union([v.number(), v.string()]), 0),
});

function parseEntry(value: string | null): PrivateCache {
	if (value === null) return { isPrivate: false };
	if (value === LEGACY_ENTRY) return { isPrivate: true, org: undefined, gen: 0 };
	try {
		return { isPrivate: true, ...v.parse(Entry, JSON.parse(value)) };
	} catch {
		// Unreadable is still private: only the org check is lost.
		return { isPrivate: true, org: undefined, gen: 0 };
	}
}

function privateKey(cachePath: string): string {
	return `private/${cachePath}`;
}

export async function privateCache(config: WorkerConfig, cachePath: string): Promise<PrivateCache> {
	const now = Date.now();
	const known = visibility.get(cachePath);
	if (known && known.until > now) {
		return known;
	}
	const entry = parseEntry(await config.authKv.get(privateKey(cachePath), { cacheTtl: KV_CACHE_TTL_SECONDS }));
	if (visibility.size >= MEMO_MAX_ENTRIES) {
		visibility.clear();
	}
	visibility.set(cachePath, { ...entry, until: now + KV_CACHE_TTL_SECONDS * 1000 });
	return entry;
}

export async function isPrivateCache(config: WorkerConfig, cachePath: string): Promise<boolean> {
	return (await privateCache(config, cachePath)).isPrivate;
}

/** Writes or removes the entry; call before (private) or after (public) the database. */
export async function setPrivate(
	config: WorkerConfig,
	cachePath: string,
	isPrivate: boolean,
	cache: { readonly org: string | null; readonly id: number },
): Promise<void> {
	if (isPrivate) {
		// A generation of its own, so copies cached before it was last private
		// (and its paths deleted while public) are never served again.
		const entry = { ...cache, gen: crypto.randomUUID() };
		await config.authKv.put(privateKey(cachePath), JSON.stringify(entry));
		visibility.set(cachePath, { isPrivate: true, ...entry, until: Date.now() + KV_CACHE_TTL_SECONDS * 1000 });
	} else {
		await config.authKv.delete(privateKey(cachePath));
		visibility.set(cachePath, { isPrivate: false, until: Date.now() + KV_CACHE_TTL_SECONDS * 1000 });
	}
}

// KV takes one write a second to a key; deletions in quick succession,
// as retention makes, wait their turn.
const KV_WRITE_RETRIES = 5;

/**
 * A fresh epoch after deletion, without reading/modifying a potentially
 * stale KV value. Concurrent deletions must never reuse a generation.
 * Remote readers pick it up eventually, not within a guaranteed deadline.
 */
export async function nextGeneration(config: WorkerConfig, cache: { readonly path: string; readonly id: number; readonly orgId: string }): Promise<void> {
	const key = privateKey(cache.path);
	const entry = { org: cache.orgId, id: cache.id, gen: crypto.randomUUID() };
	for (let attempt = 1; ; attempt++) {
		try {
			await config.authKv.put(key, JSON.stringify(entry));
			break;
		} catch (err) {
			if (attempt === KV_WRITE_RETRIES) throw err;
			await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
		}
	}
	visibility.set(cache.path, { isPrivate: true, ...entry, until: Date.now() + KV_CACHE_TTL_SECONDS * 1000 });
}

/** Why a push to, or a new, private cache is refused without org permission. */
export const PRIVATE_CACHES_REFUSED =
	"this org does not allow private caches: its private caches keep serving their paths, but take no pushes, and no new ones can be made";
