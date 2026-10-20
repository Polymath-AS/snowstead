import { limiter } from "./batch.js";

// The client has no limit on connections a Worker would have, and narinfo
// lookups are small: this many at once finishes a closure in about a second.
const CONCURRENCY = 64;
const TIMEOUT_MS = 5000;

/**
 * The hashes some upstream serves, looked up by the client itself. A path
 * whose lookup fails is not counted as served, so it is pushed.
 */
export async function servedUpstream(
  storePathHashes: readonly string[],
  upstreams: readonly string[],
  fetcher: typeof fetch = fetch,
): Promise<Set<string>> {
  const slot = limiter(CONCURRENCY);
  const served = new Set<string>();
  await Promise.all(storePathHashes.map((hash) => slot(async () => {
    for (const upstream of upstreams) {
      if (await hasNarinfo(fetcher, upstream, hash)) {
        served.add(hash);
        return;
      }
    }
  })));
  return served;
}

async function hasNarinfo(fetcher: typeof fetch, upstream: string, hash: string): Promise<boolean> {
  try {
    const res = await fetcher(`${upstream.replace(/\/$/, "")}/${hash}.narinfo`, {
      method: "HEAD",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return res.ok;
  } catch {
    return false;
  }
}
