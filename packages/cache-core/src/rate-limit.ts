import type { WorkerConfig } from "./config.js";
import { errorResponse } from "./responses.js";

/**
 * Per-caller request limits, through Workers rate limiting (wrangler.jsonc):
 * pushes, the org API, and private reads each count a caller's requests a
 * minute, keyed by who they are, never by their secret. They're generous:
 * there to stop a runaway loop or a leaked token hammering the service, not
 * to meter real use. The operator itself is never limited. Without the
 * bindings (self-hosted elsewhere, older config), nothing is.
 *
 * The limiter is approximate and local to a data center, which is fine for
 * this; bandwidth is counted exactly, in bandwidth_daily.
 */

export type LimitKind = "push" | "api" | "read";

export interface RateLimiters {
	readonly push?: RateLimit;
	readonly api?: RateLimit;
	readonly read?: RateLimit;
}

const RETRY_AFTER_SECONDS = 60;

/** A 429 if `caller` has used up its minute of `kind` requests, else undefined. */
export async function overLimit(config: WorkerConfig, kind: LimitKind, caller: string): Promise<Response | undefined> {
	const limiter = config.rateLimiters[kind];
	if (!limiter) return undefined;
	const { success } = await limiter.limit({ key: caller });
	if (success) return undefined;
	return errorResponse(`Too many requests: slow down, and retry in ${RETRY_AFTER_SECONDS} seconds`, 429, { "retry-after": String(RETRY_AFTER_SECONDS) });
}
