import type { WorkerConfig } from "./config.js";
import type { Product } from "./db/repository.js";

/**
 * Records bytes a Worker served from a cache as one Analytics Engine data
 * point, without waiting and without the database. Control's cron sums
 * them by cache, product and day into bandwidth_daily. Field order is the
 * schema that query reads: index1 the cache, blob1 its org, blob2 the
 * product, double1 the bytes.
 */
export function recordBandwidth(config: WorkerConfig, cache: { readonly id: number; readonly orgId: string }, product: Product, bytes: number): void {
	config.bandwidth?.writeDataPoint({ indexes: [String(cache.id)], blobs: [cache.orgId, product], doubles: [bytes] });
}
