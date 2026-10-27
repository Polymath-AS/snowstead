import { tracing } from "cloudflare:workers";
import { DrizzleQueryError } from "drizzle-orm";
import { resolveConfig } from "./config.js";
import type { WorkerConfig } from "./config.js";
import { handleRequest } from "./router.js";
import { runGarbageCollection } from "./gc.js";
import { errorForLog, logRequest } from "./logging.js";
import { routeOf } from "./route.js";
import { retryCdnPurges } from "./cdn.js";
import { errorResponse } from "./responses.js";

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const start = Date.now();
		const url = new URL(request.url);
		const route = () => routeOf(request.method, url.pathname);
		// On the runtime's span for the request, which carries its CPU and wall
		// time: traces then group those by route. Worked out only for traced
		// requests: on every request it was a twentieth of a cache read's CPU.
		const span = tracing.getActiveSpan();
		if (span?.isTraced) span.setAttribute("snowstead.route", route());
		let config: WorkerConfig | undefined;
		try {
			config = resolveConfig(env, ctx);
			const response = await handleRequest(request, config);
			// Narinfo 404s are most of what Nix sends, not errors; logging each
			// cost a quarter of a miss's CPU. Workers records every request anyway.
			const expectedMiss = response.status === 404 && url.pathname.endsWith(".narinfo");
			if ((response.status >= 400 && !expectedMiss) || url.pathname.startsWith("/_api/")) {
				logRequest(request, response, start, route());
			}
			return response;
		} catch (err) {
			console.error("Unhandled error", errorForLog(err));
			const response = errorResponse("Internal server error", 500);
			logRequest(request, response, start, route());
			return response;
		} finally {
			// After the response: deferred writes finish, then the connection ends.
			const closing = config?.close();
			if (closing) ctx.waitUntil(closing);
		}
	},

	async scheduled(event, env, ctx): Promise<void> {
		const config = resolveConfig(env);
		try {
			if (event.cron === "*/5 * * * *") {
				try {
					console.log("CDN purge retry completed", { completed: await retryCdnPurges(config) });
				} catch (err) {
					console.error("CDN purge backlog remains", err);
				}
				return;
			}
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
		} catch (err) {
			if (!(err instanceof DrizzleQueryError)) throw err;
			console.error("Scheduled database work failed", errorForLog(err));
			// Preserve the failed invocation without letting the runtime log parameters.
			throw new Error("Scheduled database work failed");
		} finally {
			const closing = config.close();
			if (closing) ctx.waitUntil(closing);
		}
	},
} satisfies ExportedHandler<Env>;
