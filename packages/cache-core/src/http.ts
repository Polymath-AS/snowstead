import { tracing } from "cloudflare:workers";
import { resolveConfig } from "./config.js";
import type { WorkerConfig } from "./config.js";
import { errorForLog, logRequest } from "./logging.js";
import { routeOf } from "./route.js";
import { errorResponse } from "./responses.js";

/** Shared request tracing and request-local connection lifetime, not routing. */
export async function serve(
	request: Request,
	env: Env,
	ctx: ExecutionContext,
	handle: (request: Request, config: WorkerConfig) => Promise<Response>,
): Promise<Response> {
	const start = Date.now();
	const url = new URL(request.url);
	const route = () => routeOf(request.method, url.pathname);
	const span = tracing.getActiveSpan();
	if (span?.isTraced) span.setAttribute("snowstead.route", route());
	let config: WorkerConfig | undefined;
	try {
		config = resolveConfig(env, ctx);
		const response = await handle(request, config);
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
		const closing = config?.close();
		if (closing) ctx.waitUntil(closing);
	}
}
