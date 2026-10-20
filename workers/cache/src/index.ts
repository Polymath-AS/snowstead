import { tracing } from "cloudflare:workers";
import { resolveConfig } from "./config.js";
import type { WorkerConfig } from "./config.js";
import { handleRequest } from "./router.js";
import { runGarbageCollection } from "./gc.js";
import { logRequest } from "./logging.js";
import { routeOf } from "./route.js";

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const start = Date.now();
		const url = new URL(request.url);
		const route = routeOf(request.method, url.pathname);
		// On the runtime's span for the request, which carries its CPU and wall
		// time: traces then group those by route.
		tracing.getActiveSpan()?.setAttribute("snowstead.route", route);
		let config: WorkerConfig | undefined;
		try {
			config = resolveConfig(env, ctx);
			const response = await handleRequest(request, config);
			// Narinfo 404s are most of what Nix sends, not errors; logging each
			// cost a quarter of a miss's CPU. Workers records every request anyway.
			const expectedMiss = response.status === 404 && url.pathname.endsWith(".narinfo");
			if ((response.status >= 400 && !expectedMiss) || url.pathname.startsWith("/_api/")) {
				logRequest(request, response, start, route);
			}
			return response;
		} catch (err) {
			console.error("Unhandled error", err);
			const response = new Response(JSON.stringify({ error: "Internal server error" }), {
				status: 500,
				headers: { "content-type": "application/json" },
			});
			logRequest(request, response, start, route);
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
				expiredPaths: result.expiredPaths,
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
