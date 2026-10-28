import { PUBLICATION_KEY, type ReadBucket } from "@snowstead/cache-core/read-storage";

interface ByteEnv {
	PRIVATE_BYTES: ReadBucket;
	PUBLIC_BYTES: ReadBucket;
	BYTE_NAMESPACE: string;
}

// Only structured immutable publication keys. Even a privileged binding
// caller cannot use this service to read authority or staging prefixes.

/** No public ingress: this entrypoint is reachable through bindings only. */
export default {
	async fetch(request: Request, env: ByteEnv): Promise<Response> {
		const url = new URL(request.url);
		const prefix = `/${env.BYTE_NAMESPACE}`;
		const match = url.pathname.startsWith(`${prefix}/`) ? /^\/(public|private)\/(.+)$/.exec(url.pathname.slice(prefix.length)) : null;
		const refuse = (status: number) => new Response(null, { status, headers: { "cache-control": "no-store" } });
		if (request.method !== "GET" || url.search || !match || !PUBLICATION_KEY.test(match[2])) return refuse(404);
		const bucket = match[1] === "private" ? env.PRIVATE_BYTES : env.PUBLIC_BYTES;
		const object = await bucket.get(match[2]);
		if (!object) return refuse(503);
		return new Response(object.body, { headers: {
			"content-type": match[2].endsWith("/narinfo") ? "text/x-nix-narinfo" : "application/x-nix-nar",
			"content-length": String(object.size),
			"cache-control": "public, max-age=31536000, immutable",
		} });
	},
};
