import type { WorkerConfig } from "./config.js";
import { and, eq, inArray, lt } from "drizzle-orm";
import type { CacheAt, PathSelection } from "./db/repository.js";
import { deletePublishedPaths, findCacheById } from "./db/repository.js";
import { publishedPaths } from "./db/schema.js";
import { readPublicationCache, withdrawPublications } from "./publications.js";
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
	const lifecycle = await readPublicationCache(config, cache.id);
	if (lifecycle) {
		const current = await findCacheById(config.db, cache.id);
		if (!current) return [];
		const named = "storePathHashes" in which ? which.storePathHashes : undefined;
		const column = "lastPushedBefore" in which ? publishedPaths.lastPushedAt : publishedPaths.createdAt;
		const before = "lastPushedBefore" in which ? which.lastPushedBefore : "before" in which ? which.before : undefined;
		const selection = config.db.select({ hash: publishedPaths.storePathHash }).from(publishedPaths)
			.where(and(eq(publishedPaths.cacheId, cache.id), named ? inArray(publishedPaths.storePathHash, [...named]) : lt(column, before!)))
			.orderBy(column, publishedPaths.id);
		const rows = await ("limit" in which ? selection.limit(which.limit) : selection);
		const result = await withdrawPublications(config, current, named ?? rows.map((row) => row.hash));
		if (result.pending.length) throw new Error("Path withdrawal is pending; retry the same selection");
		return rows.map((row) => row.hash);
	}
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
