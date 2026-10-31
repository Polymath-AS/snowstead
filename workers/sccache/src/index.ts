import { RpcTarget } from "cloudflare:workers";
import { serve } from "@snowstead/cache-core/http";
import { errorResponse } from "@snowstead/cache-core/responses";
import { handleRequest } from "./router.js";

class AdmittedRequest extends RpcTarget {
	constructor(private readonly operation: () => Promise<void>) { super(); }
	run() { return this.operation(); }
}

export default {
	fetch(request, env, ctx): Promise<Response> {
		return serve(request, env, ctx, async (request, config) => {
			const org = /^\/_api\/v1\/sccache\/([a-z0-9-]+)\//.exec(new URL(request.url).pathname)?.[1];
			if (!org) return errorResponse("Not Found", 404);
			let response: Response | undefined;
			const operation = new AdmittedRequest(async () => {
				try { response = await handleRequest(request, config); }
				finally { await config.releaseDb(); }
			});
			const write = request.method === "PUT" || request.method === "MKCOL";
			// Queue before even the authorization/metadata query. No payload or
			// Response crosses RPC, and a slot ends only after SQL has closed.
			const admitted = await config.uploadCoordinator.getByName(`sccache:${org}`, { locationHint: "weur" })
				.admitSccache(write ? "write" : "read", operation);
			return admitted ? response! : errorResponse("Compiler cache queue is busy; retry", 429, { "retry-after": "1" });
		});
	},
} satisfies ExportedHandler<Env>;
