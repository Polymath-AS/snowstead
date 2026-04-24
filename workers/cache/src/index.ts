import { resolveConfig } from "./config.js";
import { handleRequest } from "./router.js";
import { runGarbageCollection } from "./gc.js";
import { logRequest } from "./logging.js";

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const start = Date.now();
		const config = { ...resolveConfig(env), ctx };
		const response = await handleRequest(request, config);
		logRequest(request, response, start);
		return response;
	},

	async scheduled(event, env, ctx): Promise<void> {
		const config = resolveConfig(env);
		const result = await runGarbageCollection(config);

		if (result.errors.length > 0) {
			console.error("GC completed with errors", {
				expiredSessions: result.expiredSessions,
				deletedBlobs: result.deletedBlobs,
				errors: result.errors,
			});
		} else {
			console.log("GC completed", {
				expiredSessions: result.expiredSessions,
				deletedBlobs: result.deletedBlobs,
			});
		}
	},
} satisfies ExportedHandler<Env>;
