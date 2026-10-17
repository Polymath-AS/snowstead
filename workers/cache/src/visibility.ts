import type { WorkerConfig } from "./config.js";

/**
 * Whether a cache is private, answered without the database: a private
 * cache has an entry in KV, and no entry means public, as every cache was
 * before private caches existed. The database's is_public is the source of
 * truth; the entry is written before it when a cache turns private and
 * removed after it when it turns public, so a failure in between leaves the
 * cache private, never exposed.
 *
 * KV reads are cached at the edge for KV_CACHE_TTL_SECONDS, misses too,
 * and isolates remember answers for as long: a change reaches every
 * location within that time.
 */
const KV_CACHE_TTL_SECONDS = 30;
const MEMO_MAX_ENTRIES = 10_000;
const visibility = new Map<string, { readonly isPrivate: boolean; readonly until: number }>();

function privateKey(cacheName: string): string {
	return `private/${cacheName}`;
}

export async function isPrivateCache(config: WorkerConfig, cacheName: string): Promise<boolean> {
	const now = Date.now();
	const known = visibility.get(cacheName);
	if (known && known.until > now) {
		return known.isPrivate;
	}
	const isPrivate = (await config.authKv.get(privateKey(cacheName), { cacheTtl: KV_CACHE_TTL_SECONDS })) !== null;
	if (visibility.size >= MEMO_MAX_ENTRIES) {
		visibility.clear();
	}
	visibility.set(cacheName, { isPrivate, until: now + KV_CACHE_TTL_SECONDS * 1000 });
	return isPrivate;
}

/** Writes or removes the entry; call before (private) or after (public) the database. */
export async function setPrivate(config: WorkerConfig, cacheName: string, isPrivate: boolean): Promise<void> {
	if (isPrivate) {
		await config.authKv.put(privateKey(cacheName), "1");
	} else {
		await config.authKv.delete(privateKey(cacheName));
	}
	visibility.delete(cacheName);
}
