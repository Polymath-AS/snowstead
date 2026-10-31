export default {
	fetch(request, env): Promise<Response> {
		const path = new URL(request.url).pathname;
		if (path.startsWith("/_api/v1/sccache/")) return env.SCCACHE.fetch(request);
		if (path.startsWith("/_api/v1/go/")) return env.GO.fetch(request);
		const control = path === "/" || path === "/healthz"
			|| path.startsWith("/_api/v1/orgs/") || path.startsWith("/_api/v1/admin/");
		return (control ? env.CONTROL : env.NIX).fetch(request);
	},
} satisfies ExportedHandler<GatewayEnv>;
