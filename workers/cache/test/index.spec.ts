import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import worker from "../src";

describe("cache worker", () => {
	it("logs database failure codes without leaking connection values or query parameters", async () => {
		const connection = new URL(env.HYPERDRIVE.connectionString);
		const missingDatabase = `missing_${crypto.randomUUID().replaceAll("-", "")}`;
		connection.pathname = `/${missingDatabase}`;
		const ctx = createExecutionContext();
		const errors = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			const response = await worker.fetch(new Request("http://example.com/_api/v1/admin/orgs", {
				headers: { authorization: "Bearer test-admin-secret" },
			}), { ...env, HYPERDRIVE: { ...env.HYPERDRIVE, connectionString: connection.toString() } }, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(500);
			expect(await response.json()).toEqual({ error: "Internal server error" });
			const output = JSON.stringify(errors.mock.calls);
			expect(output).toContain("3D000");
			expect(output).toContain("DatabaseError");
			for (const value of [missingDatabase, connection.toString(), "params:", "Failed query:"]) {
				expect(output).not.toContain(value);
			}
		} finally {
			errors.mockRestore();
		}
	});

	it("serves service info on /", async () => {
		const request = new Request<unknown, IncomingRequestCfProperties>(
			"http://example.com/"
		);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);

		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			service: "snowstead",
			status: "ok",
		});
	});

	it("serves a health check on /healthz", async () => {
		const request = new Request("http://example.com/healthz");
		const response = await SELF.fetch(request);

		expect(response.status).toBe(200);
		const body = await response.json<{ ok: boolean; service: string }>();
		expect(body.service).toBe("snowstead");
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
