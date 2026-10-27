import { env } from "cloudflare:test";
import { describe, it, expect, afterAll } from "vitest";
import { resolveConfig } from "../src/config.js";
import { checkUpstream, knownUpstream, servedUpstream } from "../src/upstream.js";

const base = resolveConfig(env);
afterAll(() => base.close());
const config = Object.assign(Object.create(base) as typeof base, { upstreams: ["https://up.example", "https://up2.example"] });

const hash = (c: string) => c.repeat(32);

/** A stand-in upstream serving `served` (URLs), recording what it is asked. */
function upstream(served: Set<string>) {
	const asked: string[] = [];
	const fetcher = (async (input: RequestInfo | URL) => {
		const url = String(input);
		asked.push(url);
		if (url.includes("down")) throw new Error("unreachable");
		return new Response(null, { status: served.has(url) ? 200 : 404 });
	}) as typeof fetch;
	return { asked, fetcher };
}

describe("upstream caches", () => {
	it("finds paths any upstream serves, and remembers them", async () => {
		const [a, b, c] = [hash("a"), hash("b"), hash("c")];
		const first = upstream(new Set([`https://up.example/${a}.narinfo`, `https://up2.example/${b}.narinfo`]));
		expect(await servedUpstream(config, [a, b, c], first.fetcher)).toEqual(new Set([a, b]));

		const second = upstream(new Set());
		expect(await servedUpstream(config, [a, b, c], second.fetcher)).toEqual(new Set([a, b]));
		// Only the path not found is asked about again.
		expect(second.asked).toEqual([`https://up.example/${c}.narinfo`, `https://up2.example/${c}.narinfo`]);
	});

	it("treats an unreachable upstream as not serving the path", async () => {
		const down = Object.assign(Object.create(base) as typeof base, { upstreams: ["https://down.example"] });
		const { fetcher } = upstream(new Set());
		expect(await servedUpstream(down, [hash("d")], fetcher)).toEqual(new Set());
	});

	it("only counts remembered paths of upstreams still configured", async () => {
		const other = Object.assign(Object.create(base) as typeof base, { upstreams: ["https://elsewhere.example"] });
		const { asked, fetcher } = upstream(new Set());
		expect(await servedUpstream(other, [hash("a")], fetcher)).toEqual(new Set());
		expect(asked).toEqual([`https://elsewhere.example/${hash("a")}.narinfo`]);
	});

	it("asks nothing without upstreams", async () => {
		const { asked, fetcher } = upstream(new Set());
		expect(await servedUpstream(base, [hash("e")], fetcher)).toEqual(new Set());
		expect(asked).toEqual([]);
	});
});

describe("checking upstreams apart from a push", () => {
	it("records only what the server itself found", async () => {
		const [f, g] = [hash("f"), hash("g")];
		const { fetcher } = upstream(new Set([`https://up.example/${f}.narinfo`]));
		expect(await checkUpstream(config, [f, g], fetcher)).toEqual([f]);
		expect(await knownUpstream(config, [f, g])).toEqual(new Set([f]));
	});

	it("knows without asking", async () => {
		const { asked, fetcher } = upstream(new Set());
		await knownUpstream(config, [hash("h")]);
		await checkUpstream({ ...config, upstreams: [] }, [hash("h")], fetcher);
		expect(asked).toEqual([]);
	});
});
