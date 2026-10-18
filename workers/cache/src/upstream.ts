import type { WorkerConfig } from "./config.js";
import { findUpstreamHashes, recordUpstreamPaths } from "./db/repository.js";

// An upstream that does not answer in time does not hold up a push: its
// paths are pushed instead.
const UPSTREAM_TIMEOUT_MS = 5000;

/**
 * The hashes among `storePathHashes` that an upstream cache already serves,
 * so a push can leave them out: whoever substitutes from a cache has its
 * upstreams too. Answers found are remembered; paths not found are asked
 * about again on the next push, as an upstream may have built them since.
 */
export async function servedUpstream(
	config: WorkerConfig,
	storePathHashes: readonly string[],
	fetcher: typeof fetch = fetch,
): Promise<Set<string>> {
	const { upstreams } = config;
	const served = new Set(await findUpstreamHashes(config.db, storePathHashes, upstreams));
	const unknown = storePathHashes.filter((h) => !served.has(h));
	if (unknown.length === 0 || upstreams.length === 0) return served;

	const found: { storePathHash: string; upstream: string }[] = [];
	await Promise.all(unknown.map(async (storePathHash) => {
		for (const upstream of upstreams) {
			if (await hasNarinfo(fetcher, upstream, storePathHash)) {
				found.push({ storePathHash, upstream });
				served.add(storePathHash);
				return;
			}
		}
	}));
	await recordUpstreamPaths(config.db, found);
	return served;
}

async function hasNarinfo(fetcher: typeof fetch, upstream: string, storePathHash: string): Promise<boolean> {
	try {
		const res = await fetcher(`${upstream}/${storePathHash}.narinfo`, {
			method: "HEAD",
			signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
		});
		return res.ok;
	} catch {
		return false;
	}
}
