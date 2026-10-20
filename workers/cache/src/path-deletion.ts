import type { WorkerConfig } from "./config.js";
import type { CacheAt, PathSelection } from "./db/repository.js";
import { deletePublishedPaths } from "./db/repository.js";
import { bucketFor, narinfoKey } from "./layout.js";
import { narinfoCacheKey } from "./narinfo.js";
import { inBackground, purgeNarinfo } from "./cdn.js";
import { isPrivateCache } from "./visibility.js";

/**
 * Deletes paths from a cache, which frees their bytes from its org's usage
 * at once, and returns the hashes deleted. The NARs stay for GC, which
 * deletes one once no cache's path points at it.
 *
 * The narinfo goes while the rows are deleted but not committed: if that
 * fails, the rows stay and a retry finishes, whereas a narinfo outliving its
 * row would point at a NAR that GC is free to delete. Named hashes lose
 * their narinfo even without a row, as a publish that stored one but failed
 * to record its row would leave.
 */
export async function deleteCachePaths(
	config: WorkerConfig,
	cache: Pick<CacheAt, "id" | "path">,
	which: PathSelection,
	origin?: string,
): Promise<string[]> {
	const isPrivate = await isPrivateCache(config, cache.path);
	const bucket = bucketFor(config, isPrivate);
	const named = "storePathHashes" in which ? which.storePathHashes : [];

	const deleted = await deletePublishedPaths(config.db, cache.id, which, async (hashes) => {
		const keys = [...new Set([...named, ...hashes])].map((h) => narinfoKey(cache.path, h, isPrivate));
		if (keys.length > 0) await bucket.delete(keys);
	});

	// The Cache API is per data center: this clears the one handling the
	// request, when there is one. Elsewhere a narinfo already served stays
	// cached until evicted.
	if (origin !== undefined) {
		const narinfos = await caches.open("snowstead-narinfo");
		await Promise.allSettled(deleted.map((h) => narinfos.delete(narinfoCacheKey(origin, cache.path, h, isPrivate))));
	}
	// A public narinfo served before stays cached by the CDN for a year: the
	// path would stay downloadable after its NAR is gone.
	if (!isPrivate) await inBackground(config, purgeNarinfo(config, cache.path, [...new Set([...named, ...deleted])]));
	return deleted;
}
