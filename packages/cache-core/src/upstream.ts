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
	const served = await knownUpstream(config, storePathHashes);
	const unknown = storePathHashes.filter((h) => !served.has(h));
	for (const h of await checkUpstream(config, unknown, fetcher)) served.add(h);
	return served;
}

/** The hashes among `storePathHashes` recorded as served upstream, without asking one. */
export async function knownUpstream(config: WorkerConfig, storePathHashes: readonly string[]): Promise<Set<string>> {
	return new Set(await findUpstreamHashes(config.db, storePathHashes, config.upstreams));
}

/**
 * Asks the upstreams about `storePathHashes`, records those one serves, and
 * returns them. Only the server's own answers are recorded: a client's
 * claim that a path is upstream could make every other pusher skip it.
 */
export async function checkUpstream(
	config: WorkerConfig,
	storePathHashes: readonly string[],
	fetcher: typeof fetch = fetch,
): Promise<string[]> {
	const { upstreams } = config;
	if (storePathHashes.length === 0 || upstreams.length === 0) return [];
	const found: { storePathHash: string; upstream: string }[] = [];
	await Promise.all(storePathHashes.map(async (storePathHash) => {
		for (const upstream of upstreams) {
			if (await hasNarinfo(fetcher, upstream, storePathHash)) {
				found.push({ storePathHash, upstream });
				return;
			}
		}
	}));
	await recordUpstreamPaths(config.db, found);
	return found.map((f) => f.storePathHash);
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
