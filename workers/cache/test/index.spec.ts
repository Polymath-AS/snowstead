import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src";

describe("cache worker", () => {
	it("serves service info on /", async () => {
		const request = new Request<unknown, IncomingRequestCfProperties>(
			"http://example.com/"
		);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);

		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			service: "helios-cache",
			status: "ok",
		});
	});

	it("serves a health check on /healthz", async () => {
		const request = new Request("http://example.com/healthz");
		const response = await SELF.fetch(request);

		expect(response.status).toBe(200);
		const body = await response.json<{ ok: boolean; service: string }>();
		expect(body.service).toBe("helios-cache");
		expect(body.ok).toBe(true);
	});

	it("rejects unsupported methods on cache paths", async () => {
		const request = new Request("http://example.com/mycache/test.narinfo", { method: "POST" });
		const response = await SELF.fetch(request);

		expect(response.status).toBe(405);
		expect(response.headers.get("allow")).toBe("GET, HEAD");
	});

	it("returns 404 for unknown paths", async () => {
		const request = new Request("http://example.com/nonexistent");
		const response = await SELF.fetch(request);

		expect(response.status).toBe(404);
	});
});
