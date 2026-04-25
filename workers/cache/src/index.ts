import { resolveConfig } from "./config.js";
import { handleRequest } from "./router.js";
import { runGarbageCollection } from "./gc.js";
import { logRequest } from "./logging.js";

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const start = Date.now();
		try {
			const config = { ...resolveConfig(env), ctx };
			const url = new URL(request.url);
			const response = await handleRequest(request, config);
			if (response.status >= 400 || url.pathname.startsWith("/_api/")) {
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
		}
	},

	async scheduled(event, env, ctx): Promise<void> {
		const config = resolveConfig(env);
		const result = await runGarbageCollection(config);

		if (result.errors.length > 0) {
			console.error("GC completed with errors", {
				expiredSessions: result.expiredSessions,
				deletedBlobs: result.deletedBlobs,
				expiredTokens: result.expiredTokens,
				expiredAuditLogs: result.expiredAuditLogs,
				errors: result.errors,
				});
				} else {
				console.log("GC completed", {
				expiredSessions: result.expiredSessions,
				deletedBlobs: result.deletedBlobs,
				expiredTokens: result.expiredTokens,
				expiredAuditLogs: result.expiredAuditLogs,
			});
		}
	},
} satisfies ExportedHandler<Env>;
