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
 * org's without the database. Entries from before orgs say "1", which
 * names none; POST /_api/v1/admin/auth/sync rewrites them.
 *
 * KV reads are cached at the edge for KV_CACHE_TTL_SECONDS, misses too,
 * and isolates remember answers for as long: a change reaches every
 * location within that time.
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
	| { readonly isPrivate: true; readonly org: string | null | undefined; readonly id?: number };

const visibility = new Map<string, PrivateCache & { readonly until: number }>();

const LEGACY_ENTRY = "1";

function parseEntry(value: string | null): PrivateCache {
	if (value === null) return { isPrivate: false };
	if (value === LEGACY_ENTRY) return { isPrivate: true, org: undefined };
	try {
		const { org, id } = JSON.parse(value) as { org?: unknown; id?: unknown };
		return {
			isPrivate: true,
			org: typeof org === "string" ? org : null,
			...(typeof id === "number" ? { id } : {}),
		};
	} catch {
		// Unreadable is still private: only the org check is lost.
		return { isPrivate: true, org: undefined };
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
		await config.authKv.put(privateKey(cachePath), JSON.stringify(cache));
	} else {
		await config.authKv.delete(privateKey(cachePath));
	}
	visibility.delete(cachePath);
}
