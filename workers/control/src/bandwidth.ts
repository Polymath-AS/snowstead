import type { AnalyticsConfig, WorkerConfig } from "@snowstead/cache-core/config";
import { cachePath, splitReadPath } from "@snowstead/cache-core/cache-path";
import { PRODUCTS, listOrgs, publicCachesByPath, publicNarCaches, setBandwidth } from "@snowstead/cache-core/db/repository";
import { errorForLog } from "@snowstead/cache-core/logging";
import type { CacheBandwidth, Product, PublicCache } from "@snowstead/cache-core/db/repository";

/**
 * Bandwidth is an estimate, imported every 6 hours from Cloudflare's
 * analytics rather than counted per request in Postgres:
 *
 * - Bytes the Workers serve (private NARs, Go and sccache artifacts) are
 *   written per download to the Analytics Engine dataset (cache-core
 *   bandwidth.ts) and summed here by cache, product and day.
 * - Public caches are served by R2 and the CDN without the Workers, so
 *   their bytes come from the zone's HTTP analytics for the public host,
 *   summed by path. A narinfo or nix-cache-info path names its cache.
 *   Public NARs are shared at /nar/, so a NAR's bytes are split evenly
 *   among the public caches that hold it now; bytes for paths no cache
 *   claims (API calls, deleted caches and NARs, probes) aren't counted.
 *
 * Both sources sample, and both keep at least 31 days. Each import replaces
 * yesterday's and today's counts (UTC), so a day settles at the first run
 * after it ends, and a run that fails is made up by the next.
 */
const API = "https://api.cloudflare.com/client/v4";
const PAGE = 10_000;
const NAR_BATCH = 1_000;

const ZONE_QUERY = `query PublicBandwidth($zoneTag: string!, $host: string!, $date: Date!, $after: string!) {
	viewer {
		zones(filter: { zoneTag: $zoneTag }) {
			httpRequestsAdaptiveGroups(
				limit: ${PAGE}
				filter: { date: $date, clientRequestHTTPHost: $host, clientRequestPath_gt: $after }
				orderBy: [clientRequestPath_ASC]
			) {
				sum { edgeResponseBytes }
				dimensions { clientRequestPath }
			}
		}
	}
}`;

interface Group {
	readonly sum: { readonly edgeResponseBytes: number };
	readonly dimensions: { readonly clientRequestPath: string };
}

/** Bytes the CDN served for each path of the public host on a UTC day. */
async function bytesByPath(analytics: AnalyticsConfig, zone: { zoneId: string; host: string }, date: string, fetcher: typeof fetch): Promise<Map<string, number>> {
	const paths = new Map<string, number>();
	for (let after = ""; ;) {
		const response = await fetcher(`${API}/graphql`, {
			method: "POST",
			headers: { authorization: `Bearer ${analytics.token}`, "content-type": "application/json" },
			body: JSON.stringify({ query: ZONE_QUERY, variables: { zoneTag: zone.zoneId, host: zone.host, date, after } }),
		});
		const result = await response.json<{ data?: { viewer: { zones: { httpRequestsAdaptiveGroups: Group[] }[] } }; errors?: { message: string }[] | null }>().catch(() => null);
		if (!response.ok || !result?.data || (result.errors?.length ?? 0) > 0) {
			throw new Error(`Cloudflare zone analytics query failed (${response.status}): ${result?.errors?.map((e) => e.message).join("; ") ?? "no data"}`);
		}
		const groups = result.data.viewer.zones[0]?.httpRequestsAdaptiveGroups ?? [];
		for (const g of groups) paths.set(g.dimensions.clientRequestPath, g.sum.edgeResponseBytes);
		if (groups.length < PAGE) return paths;
		after = groups[groups.length - 1].dimensions.clientRequestPath;
	}
}

/** The public bytes each cache served on a UTC day, and the bytes no cache claims. */
async function publicBandwidth(config: WorkerConfig, analytics: AnalyticsConfig, zone: { zoneId: string; host: string }, date: string, fetcher: typeof fetch) {
	const paths = await bytesByPath(analytics, zone, date, fetcher);
	const cacheByPath = await publicCachesByPath(config.db);
	const byCache = new Map<number, CacheBandwidth>();
	const add = (cache: PublicCache, bytes: number) => byCache.set(cache.id, { orgId: cache.orgId, cacheId: cache.id, product: "nix", bytes: (byCache.get(cache.id)?.bytes ?? 0) + bytes });
	const narBytes = new Map<string, number>();
	let unclaimed = 0;
	for (const [path, bytes] of paths) {
		const segments = path.split("/").filter(Boolean);
		if (segments.length === 3 && segments[0] === "nar" && segments[2].endsWith(".nar")) {
			const nar = `${segments[1]}/${segments[2].slice(0, -".nar".length)}`;
			narBytes.set(nar, (narBytes.get(nar) ?? 0) + bytes);
			continue;
		}
		const read = splitReadPath(segments);
		const cache = read && cacheByPath.get(cachePath(read.slug, read.cache));
		if (cache === undefined) unclaimed += bytes;
		else add(cache, bytes);
	}
	const nars = [...narBytes.keys()];
	for (let i = 0; i < nars.length; i += NAR_BATCH) {
		const holders = await publicNarCaches(config.db, nars.slice(i, i + NAR_BATCH));
		for (const nar of nars.slice(i, i + NAR_BATCH)) {
			const caches = holders.get(nar) ?? [];
			const bytes = narBytes.get(nar)!;
			if (caches.length === 0) unclaimed += bytes;
			for (const cache of caches) add(cache, bytes / caches.length);
		}
	}
	return { rows: [...byCache.values()], unclaimed };
}

/** The bytes the Workers served on a UTC day, by cache and product, from the Analytics Engine dataset. */
async function workerBandwidth(analytics: AnalyticsConfig, date: string, fetcher: typeof fetch): Promise<CacheBandwidth[]> {
	if (!/^[a-z0-9_]+$/.test(analytics.dataset)) throw new Error(`Invalid bandwidth dataset name ${analytics.dataset}`);
	if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`Invalid day ${date}`);
	const next = new Date(Date.parse(`${date}T00:00:00Z`) + 86_400_000).toISOString().slice(0, 10);
	// _sample_interval scales each sampled row back to what it stands for.
	const query = `SELECT index1 AS cache, blob1 AS org, blob2 AS product, SUM(_sample_interval * double1) AS bytes
		FROM ${analytics.dataset}
		WHERE timestamp >= toDateTime('${date} 00:00:00') AND timestamp < toDateTime('${next} 00:00:00')
		GROUP BY cache, org, product
		FORMAT JSON`;
	const response = await fetcher(`${API}/accounts/${analytics.accountId}/analytics_engine/sql`, {
		method: "POST",
		headers: { authorization: `Bearer ${analytics.token}` },
		body: query,
	});
	if (!response.ok) throw new Error(`Analytics Engine query failed (${response.status}): ${(await response.text()).slice(0, 500)}`);
	const { data } = await response.json<{ data: { cache: string; org: string; product: string; bytes: number | string }[] }>();
	return data.flatMap(({ cache, org, product, bytes }) => {
		const cacheId = Number(cache);
		// Rows this importer can't place are ignored, not stored.
		if (!Number.isSafeInteger(cacheId) || cacheId <= 0 || !PRODUCTS.includes(product as Product)) return [];
		return [{ orgId: org, cacheId, product: product as Product, bytes: Number(bytes) }];
	});
}

/**
 * Re-imports yesterday and today (UTC), each source on its own, so one that
 * fails (say, a token missing a permission) still lets the other through;
 * its failure is returned for the caller to log. Undefined when analytics
 * aren't configured.
 */
export async function importBandwidth(config: WorkerConfig, now: Date, fetcher: typeof fetch = fetch) {
	const analytics = config.analytics;
	if (!analytics) return undefined;
	const days = [new Date(now.getTime() - 86_400_000), now].map((d) => d.toISOString().slice(0, 10));
	const imported: Record<string, { workerRows?: number; publicRows?: number; unclaimedPublicBytes?: number }> = {};
	const errors: { source: string; day: string; error: unknown }[] = [];
	const attempt = async (source: string, day: string, work: () => Promise<void>) => {
		try {
			await work();
		} catch (err) {
			errors.push({ source, day, error: errorForLog(err) });
		}
	};
	for (const day of days) {
		imported[day] = {};
		await attempt("workers", day, async () => {
			const orgs = new Set((await listOrgs(config.db)).map((o) => o.id));
			// An org deleted since it was served can no longer hold counts.
			const rows = (await workerBandwidth(analytics, day, fetcher)).filter((r) => orgs.has(r.orgId));
			await setBandwidth(config.db, day, "bytes", rows, now);
			imported[day].workerRows = rows.length;
		});
		const zone = analytics.publicZone;
		if (zone) await attempt("public", day, async () => {
			const { rows, unclaimed } = await publicBandwidth(config, analytics, zone, day, fetcher);
			await setBandwidth(config.db, day, "publicBytes", rows, now);
			imported[day].publicRows = rows.length;
			imported[day].unclaimedPublicBytes = Math.round(unclaimed);
		});
	}
	return { imported, errors };
}
