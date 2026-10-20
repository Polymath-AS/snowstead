import { env } from "cloudflare:test";
import { describe, it, expect, afterAll } from "vitest";
import { resolveConfig } from "../src/config.js";
import { purgeCache, purgeNarinfo } from "../src/cdn.js";

const base = resolveConfig(env);
afterAll(() => base.close());
const config = { ...base, cdn: { zoneId: "zone1", token: "tok", origin: "https://cache.example.com" } };

/** A stand-in for Cloudflare's purge API, recording what it is asked. */
function api(status = 200) {
	const calls: { url: string; auth: string | null; body: { files?: string[]; prefixes?: string[] } }[] = [];
	const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
		calls.push({ url: String(input), auth: new Headers(init?.headers).get("authorization"), body: JSON.parse(String(init?.body)) });
		return new Response("{}", { status });
	}) as typeof fetch;
	return { calls, fetcher };
}

describe("CDN purges", () => {
	it("purge each path's public narinfo URL, 100 to a request", async () => {
		const hashes = Array.from({ length: 150 }, (_, i) => String(i).padStart(32, "a"));
		const { calls, fetcher } = api();
		await purgeNarinfo(config, "acme/main", hashes, fetcher);
		expect(calls.map((c) => c.body.files?.length)).toEqual([100, 50]);
		expect(calls[0].url).toBe("https://api.cloudflare.com/client/v4/zones/zone1/purge_cache");
		expect(calls[0].auth).toBe("Bearer tok");
		expect(calls[0].body.files?.[0]).toBe(`https://cache.example.com/acme/main/${hashes[0]}.narinfo`);
	});

	it("purge a whole cache by its prefix", async () => {
		const { calls, fetcher } = api();
		await purgeCache(config, "acme/main", fetcher);
		expect(calls[0].body).toEqual({ prefixes: ["cache.example.com/acme/main/"] });
	});

	it("say when Cloudflare refuses", async () => {
		const { fetcher } = api(429);
		await expect(purgeNarinfo(config, "main", ["a".repeat(32)], fetcher)).rejects.toThrow("429");
	});

	it("do nothing without a CDN configured", async () => {
		const { calls, fetcher } = api();
		await purgeNarinfo({ ...base, cdn: undefined }, "main", ["a".repeat(32)], fetcher);
		await purgeCache({ ...base, cdn: undefined }, "main", fetcher);
		expect(calls).toEqual([]);
	});
});
