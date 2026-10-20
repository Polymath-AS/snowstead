import type { WorkerConfig } from "./config.js";
import { narinfoKey } from "./layout.js";

/**
 * The CDN in front of the public bucket caches narinfo it served: hits for
 * a year, misses briefly (the zone's Cache Rule). A path published or
 * deleted is purged by URL, so it shows or goes at once rather than when
 * the cached answer expires. Purges by URL are cheap on every plan: 800
 * URLs a second, 100 a request. A whole cache is purged by prefix, which
 * plans allow only a few times a minute.
 *
 * Without a zone and token configured (self-hosted, local) nothing is
 * purged, and cached answers expire on their own.
 */
const URLS_PER_PURGE = 100;

export interface CdnConfig {
	readonly zoneId: string;
	readonly token: string;
	/** Where the public bucket is served, such as https://cache.snowstead.com. */
	readonly origin: string;
}

export async function purgeNarinfo(
	config: WorkerConfig,
	cachePath: string,
	storePathHashes: readonly string[],
	fetcher: typeof fetch = fetch,
): Promise<void> {
	const { cdn } = config;
	if (!cdn || storePathHashes.length === 0) return;
	const urls = storePathHashes.map((h) => `${cdn.origin}/${narinfoKey(cachePath, h, false)}`);
	const purges: Promise<void>[] = [];
	for (let i = 0; i < urls.length; i += URLS_PER_PURGE) {
		purges.push(purge(cdn, { files: urls.slice(i, i + URLS_PER_PURGE) }, fetcher));
	}
	await Promise.all(purges);
}

/** Purges everything the CDN holds for a cache. */
export async function purgeCache(config: WorkerConfig, cachePath: string, fetcher: typeof fetch = fetch): Promise<void> {
	const { cdn } = config;
	if (!cdn) return;
	await purge(cdn, { prefixes: [`${new URL(cdn.origin).host}/${cachePath}/`] }, fetcher);
}

async function purge(cdn: CdnConfig, body: object, fetcher: typeof fetch): Promise<void> {
	const res = await fetcher(`https://api.cloudflare.com/client/v4/zones/${cdn.zoneId}/purge_cache`, {
		method: "POST",
		headers: { authorization: `Bearer ${cdn.token}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
	if (!res.ok) {
		throw new Error(`CDN purge failed (${res.status}): ${await res.text()}`);
	}
}

/**
 * Runs a purge after the response when there is a request to outlive, and
 * reports a failure rather than failing the caller: what was purged expires
 * from the CDN on its own anyway.
 */
export function inBackground(config: WorkerConfig, purge: Promise<void>): Promise<void> {
	const reported = purge.catch((err: unknown) => console.error("CDN purge failed", err));
	if (config.ctx) {
		config.ctx.waitUntil(reported);
		return Promise.resolve();
	}
	return reported;
}
