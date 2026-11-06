export default {
	fetch(request, env): Promise<Response> {
		const url = new URL(request.url);
		if ("API_ORIGIN" in env) {
			const origin = new URL(env.API_ORIGIN);
			url.protocol = origin.protocol;
			url.host = origin.host;
			const forwarded = new Request(url, request);
			forwarded.headers.set("Host", origin.host);
			return fetch(forwarded, { redirect: "manual" });
		}
		const path = url.pathname;
		if (path.startsWith("/_api/v1/sccache/")) return env.SCCACHE.fetch(request);
		if (path.startsWith("/_api/v1/go/")) return env.GO.fetch(request);
		const control = path === "/" || path === "/healthz"
			|| path.startsWith("/_api/v1/orgs/") || path.startsWith("/_api/v1/admin/");
		return (control ? env.CONTROL : env.NIX).fetch(request);
	},
} satisfies ExportedHandler<Cloudflare.ProductionEnv | Cloudflare.StagingEnv>;
