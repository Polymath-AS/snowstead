import { serve } from "@snowstead/cache-core/http";
import { resolveConfig } from "@snowstead/cache-core/config";
import { handleRequest } from "./router.js";
import { runGarbageCollection } from "./gc.js";
import { retryCdnPurges } from "@snowstead/cache-core/cdn";
import { DrizzleQueryError } from "drizzle-orm";
import { errorForLog } from "@snowstead/cache-core/logging";

export default {
	fetch(request, env, ctx): Promise<Response> {
		return serve(request, env, ctx, handleRequest);
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
			throw new Error("Scheduled database work failed");
		} finally {
			const closing = config.close();
			if (closing) ctx.waitUntil(closing);
		}
	},
} satisfies ExportedHandler<Env>;
