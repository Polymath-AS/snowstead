import type { WorkerConfig } from "./config.js";
import { narinfoKey } from "./layout.js";

/**
 * Public reads stay on the CDN. Purges accelerate visibility of mutations;
 * narinfo's short TTL is the fallback if the purge service is unavailable.
 * Automatic purges are recorded in the private bucket before dispatch, so
 * an exhausted retry or a terminated waitUntil can be retried by the cron.
 *
 * Without a zone and token configured (self-hosted, local) nothing is
 * purged, and cached answers expire on their own.
 */
const URLS_PER_PURGE = 100;
const PURGE_ATTEMPTS = 3;
const PURGE_TIMEOUT_MS = 5000;
const MAX_RETRY_WAIT_MS = 2000;
const PURGE_PREFIX = "cdn-purges/";
const RETRY_BATCH = 100;
// The Free plan allows 800 URLs/s per account. Serialize and pace batches
// here; concurrent isolates still share the account's limit, so handle 429.
const BATCH_INTERVAL_MS = 125;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface CdnConfig {
	readonly zoneId: string;
	readonly token: string;
	/** Where the public bucket is served, such as https://cache.snowstead.com. */
	readonly origin: string;
}

class PurgeError extends Error {
	constructor(status: number, readonly retryAt?: number) {
		super(`CDN purge failed (${status})`);
	}
}

export async function purgeNarinfo(
	config: WorkerConfig,
	cachePath: string,
	storePathHashes: readonly string[],
	fetcher: typeof fetch = fetch,
): Promise<void> {
	const { cdn } = config;
	if (!cdn || storePathHashes.length === 0) return;
	const urls = [...new Set(storePathHashes)].map((h) => `${cdn.origin}/${narinfoKey(cachePath, h, false)}`);
	for (let i = 0; i < urls.length; i += URLS_PER_PURGE) {
		if (i > 0) await sleep(BATCH_INTERVAL_MS);
		await purge(cdn, { files: urls.slice(i, i + URLS_PER_PURGE) }, fetcher);
	}
}

/** Purges everything the CDN holds for a cache. */
export async function purgeCache(config: WorkerConfig, cachePath: string, fetcher: typeof fetch = fetch): Promise<void> {
	const { cdn } = config;
	if (!cdn) return;
	await purge(cdn, { prefixes: [`${new URL(cdn.origin).host}/${cachePath}/`] }, fetcher);
}

async function purge(cdn: CdnConfig, body: object, fetcher: typeof fetch): Promise<void> {
	for (let attempt = 0; attempt < PURGE_ATTEMPTS; attempt++) {
		let response: Response;
		try {
			response = await fetcher(`https://api.cloudflare.com/client/v4/zones/${cdn.zoneId}/purge_cache`, {
				method: "POST",
				headers: { authorization: `Bearer ${cdn.token}`, "content-type": "application/json" },
				body: JSON.stringify(body),
				signal: AbortSignal.timeout(PURGE_TIMEOUT_MS),
			});
		} catch {
			if (attempt === PURGE_ATTEMPTS - 1) throw new Error("CDN purge request failed");
			await sleep(1000 * (attempt + 1));
			continue;
		}
		// Consume the body before retrying: an unread body holds a connection.
		const result = await response.json<{ success?: boolean }>().catch(() => null);
		if (response.ok && result?.success === true) return;
		const retryAfter = response.headers.get("retry-after");
		const seconds = retryAfter === null ? NaN : Number(retryAfter);
		const delay = retryAfter === null ? 1000 * (attempt + 1)
			: Number.isFinite(seconds) ? Math.max(0, seconds * 1000)
				: Math.max(0, Date.parse(retryAfter) - Date.now());
		const retryable = response.status === 429 || response.status >= 500;
		const error = new PurgeError(response.status, retryable && Number.isFinite(delay) ? Date.now() + delay : undefined);
		if (attempt === PURGE_ATTEMPTS - 1 || (response.status !== 429 && response.status < 500)) throw error;
		// Don't retry earlier than requested. Longer waits belong to the
		// durable backlog, not a request's limited waitUntil lifetime.
		if (!Number.isFinite(delay) || delay > MAX_RETRY_WAIT_MS) throw error;
		await sleep(delay);
	}
}

/**
 * One durable record per mutation batch, not per path. Keep it until every
 * URL was accepted: replaying a successful URL purge is harmless. Secrets
 * and origins are never stored; retries use the deployment's configuration.
 */
export async function scheduleNarinfoPurge(config: WorkerConfig, cachePath: string, hashes: readonly string[], fetcher: typeof fetch = fetch): Promise<void> {
	if (!config.cdn || hashes.length === 0) return;
	const key = `${PURGE_PREFIX}${String(Date.now()).padStart(16, "0")}-${crypto.randomUUID()}`;
	const job = { cachePath, hashes: [...new Set(hashes)] };
	await config.bucket.put(key, JSON.stringify(job));
	const reported = finishPurge(config, key, job, fetcher).catch((err: unknown) => console.error("CDN purge queued for retry", { key }, err));
	if (config.ctx) {
		config.ctx.waitUntil(reported);
	} else {
		await reported;
	}
}

async function finishPurge(config: WorkerConfig, key: string, job: { cachePath: string; hashes: string[]; retryAt?: number }, fetcher: typeof fetch): Promise<void> {
	try {
		await purgeNarinfo(config, job.cachePath, job.hashes, fetcher);
		await config.bucket.delete(key);
	} catch (err) {
		if (err instanceof PurgeError && err.retryAt !== undefined) {
			await config.bucket.put(key, JSON.stringify({ ...job, retryAt: err.retryAt }));
		}
		throw err;
	}
}

/** A bounded sweep; failures leave the current and remaining jobs intact. */
export async function retryCdnPurges(config: WorkerConfig, fetcher: typeof fetch = fetch): Promise<number> {
	if (!config.cdn) return 0;
	const pending = await config.bucket.list({ prefix: PURGE_PREFIX, limit: RETRY_BATCH });
	let completed = 0;
	for (const entry of pending.objects) {
		const object = await config.bucket.get(entry.key);
		if (!object) continue;
		const job = await object.json<{ cachePath: string; hashes: string[]; retryAt?: number }>();
		if (job.retryAt !== undefined && job.retryAt > Date.now()) continue;
		await finishPurge(config, entry.key, job, fetcher);
		completed++;
		await sleep(BATCH_INTERVAL_MS);
	}
	return completed;
}
