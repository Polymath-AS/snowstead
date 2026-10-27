import type { WorkerConfig } from "./config.js";
import type { CacheAt, PathSelection } from "./db/repository.js";
import { deletePublishedPaths } from "./db/repository.js";
import { bucketFor, narinfoKey } from "./layout.js";
import { narinfoCacheKey } from "./narinfo.js";
import { scheduleNarinfoPurge } from "./cdn.js";
import { nextGeneration } from "./visibility.js";

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
	cache: Pick<CacheAt, "id" | "path" | "orgId" | "isPublic">,
	which: PathSelection,
	origin?: string,
): Promise<string[]> {
	const isPrivate = !cache.isPublic;
	const bucket = bucketFor(config, isPrivate);
	const named = "storePathHashes" in which ? which.storePathHashes : [];

	const deleted = await deletePublishedPaths(config.db, cache.id, which, async (hashes) => {
		const keys = [...new Set([...named, ...hashes])].map((h) => narinfoKey(cache.path, h, isPrivate));
		if (keys.length > 0) await bucket.delete(keys);
	});

	if (isPrivate) {
		// The Cache API can only be cleared where a request runs: moving the
		// generation on retires the cache's copies everywhere instead.
		if (deleted.length > 0 || named.length > 0) await nextGeneration(config, cache);
	} else if (origin !== undefined) {
		// The Worker's own copies of public narinfo (served on workers.dev),
		// in the one data center it can clear.
		const narinfos = await caches.open("snowstead-narinfo");
		await Promise.all([...new Set([...named, ...deleted])].map((h) => narinfos.delete(narinfoCacheKey(origin, cache.path, h))));
	}
	if (!isPrivate) await scheduleNarinfoPurge(config, cache.path, [...named, ...deleted]);
	return deleted;
}
