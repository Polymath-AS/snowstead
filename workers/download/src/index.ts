import { handleDownload } from "@snowstead/cache-core/download";
import type { ReadBucket } from "@snowstead/cache-core/read-storage";

/** Separate deployment: deliberately excludes all control-service bindings. */
export interface DownloadEnv {
	AUTHORITY: Pick<ReadBucket, "get">;
	PRIVATE_BYTES: ReadBucket;
	PUBLIC_BYTES: ReadBucket;
	JWT_SECRET: string;
	OWNER_HOST_SUFFIX: string;
	CANONICAL_HOST: string;
	BYTES?: Fetcher;
	NATIVE_MAX_BYTES?: string;
	BYTE_NAMESPACE: string;
}

export default {
	async fetch(request: Request, env: DownloadEnv): Promise<Response> {
		const url = new URL(request.url);
		if (url.hostname !== env.CANONICAL_HOST) {
			const suffix = env.OWNER_HOST_SUFFIX;
			const owner = suffix.startsWith(".") && url.hostname.endsWith(suffix) ? url.hostname.slice(0, -suffix.length) : "";
			if (!/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/.test(owner)) {
				return new Response("Not Found", { status: 404, headers: { "cache-control": "no-store", "cloudflare-cdn-cache-control": "no-store" } });
			}
			url.pathname = `/${owner}${url.pathname}`;
		}
		const maxBytes = Number(env.NATIVE_MAX_BYTES ?? "0");
		// No guessed interpretation of the platform's advertised MB ceiling.
		// Configure a positive, staging-verified exact byte limit to opt in.
		const native = env.BYTES && Number.isSafeInteger(maxBytes) && maxBytes > 0
			? { service: env.BYTES, maxBytes, namespace: env.BYTE_NAMESPACE } : undefined;
		return handleDownload(new Request(url, request), {
			authority: env.AUTHORITY, publicBucket: env.PUBLIC_BYTES,
			privateBucket: env.PRIVATE_BYTES, jwtSecret: env.JWT_SECRET, native,
		});
	},
};
