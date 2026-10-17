import type { WorkerConfig } from "./config.js";

/**
 * Whether a cache is private, answered without the database: a private
 * cache has a marker object in the bucket, and no marker means public, as
 * every cache was before private caches existed. The database's is_public
 * is the source of truth; the marker is written before it when a cache
 * turns private and removed after it when it turns public, so a failure in
 * between leaves the cache private, never exposed.
 */
export function privateMarkerKey(cacheName: string): string {
	return `caches/private/${cacheName}`;
}

// Isolates are reused across requests, so a lookup per cache per isolate
// usually suffices. A visibility change reaches other isolates within this.
const VISIBILITY_TTL_MS = 30_000;
const VISIBILITY_MEMO_MAX_ENTRIES = 10_000;
const visibility = new Map<string, { readonly isPrivate: boolean; readonly until: number }>();

export async function isPrivateCache(config: WorkerConfig, cacheName: string): Promise<boolean> {
	const now = Date.now();
	const known = visibility.get(cacheName);
	if (known && known.until > now) {
		return known.isPrivate;
	}
	const isPrivate = (await config.bucket.head(privateMarkerKey(cacheName))) !== null;
	if (visibility.size >= VISIBILITY_MEMO_MAX_ENTRIES) {
		visibility.clear();
	}
	visibility.set(cacheName, { isPrivate, until: now + VISIBILITY_TTL_MS });
	return isPrivate;
}

/** Writes or removes the marker; call before (private) or after (public) the database. */
export async function setPrivateMarker(config: WorkerConfig, cacheName: string, isPrivate: boolean): Promise<void> {
	if (isPrivate) {
		await config.bucket.put(privateMarkerKey(cacheName), "");
	} else {
		await config.bucket.delete(privateMarkerKey(cacheName));
	}
	visibility.delete(cacheName);
}
