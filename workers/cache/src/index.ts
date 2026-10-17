import { resolveConfig } from "./config.js";
import type { WorkerConfig } from "./config.js";
import { handleRequest } from "./router.js";
import { runGarbageCollection } from "./gc.js";
import { logRequest } from "./logging.js";

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const start = Date.now();
		let config: WorkerConfig | undefined;
		try {
			config = resolveConfig(env, ctx);
			const url = new URL(request.url);
			const response = await handleRequest(request, config);
			// Narinfo 404s are most of what Nix sends, not errors; logging each
			// cost a quarter of a miss's CPU. Workers records every request anyway.
			const expectedMiss = response.status === 404 && url.pathname.endsWith(".narinfo");
			if ((response.status >= 400 && !expectedMiss) || url.pathname.startsWith("/_api/")) {
				logRequest(request, response, start);
			}
			return response;
		} catch (err) {
			console.error("Unhandled error", { error: err instanceof Error ? err.message : String(err) });
			const response = new Response(JSON.stringify({ error: "Internal server error" }), {
				status: 500,
				headers: { "content-type": "application/json" },
			});
			logRequest(request, response, start);
			return response;
		} finally {
			// After the response: deferred writes finish, then the pool ends.
			if (config) ctx.waitUntil(config.close());
		}
	},

	async scheduled(event, env, ctx): Promise<void> {
		const config = resolveConfig(env);
		try {
			const result = await runGarbageCollection(config);
			const counts = {
				expiredSessions: result.expiredSessions,
				deletedBlobs: result.deletedBlobs,
				expiredTokens: result.expiredTokens,
				expiredAuditLogs: result.expiredAuditLogs,
			};
			if (result.errors.length > 0) {
				console.error("GC completed with errors", { ...counts, errors: result.errors });
			} else {
				console.log("GC completed", counts);
			}
		} finally {
			ctx.waitUntil(config.close());
		}
	},
} satisfies ExportedHandler<Env>;
