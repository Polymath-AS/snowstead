export default {
	fetch(request: Request, env: GatewayEnv): Promise<Response> {
		if (!env.API_ORIGIN) return Promise.resolve(new Response("API origin is not configured", { status: 503 }));
		const url = new URL(request.url);
		const origin = new URL(env.API_ORIGIN);
		url.protocol = origin.protocol;
		url.host = origin.host;
		const forwarded = new Request(url, request);
		forwarded.headers.set("Host", origin.host);
		return fetch(forwarded, { redirect: "manual" });
	},
};
