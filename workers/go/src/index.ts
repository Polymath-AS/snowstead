import { serve } from "@snowstead/cache-core/http";
import { handleRequest } from "./router.js";

export default {
	fetch(request, env, ctx): Promise<Response> {
		return serve(request, env, ctx, handleRequest);
	},
} satisfies ExportedHandler<Env>;
