import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

function admin(path: string, init: RequestInit = {}, secret = "test-admin-secret"): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/admin${path}`, {
		...init,
		headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
	});
}

describe("admin caches", () => {
	it("requires the admin secret", async () => {
		const res = await admin("/caches", { method: "POST", body: JSON.stringify({ name: "nope" }) }, "test-auth-token");
		expect(res.status).toBe(403);
	});

	it("creates a cache once and lists it", async () => {
		const name = `admin-${crypto.randomUUID().slice(0, 8)}`;
		const first = await admin("/caches", { method: "POST", body: JSON.stringify({ name }) });
		expect(first.status).toBe(201);
		expect(await first.json()).toMatchObject({ name, created: true });

		// Declaring it again is not an error.
		const again = await admin("/caches", { method: "POST", body: JSON.stringify({ name }) });
		expect(again.status).toBe(200);
		expect(await again.json()).toMatchObject({ name, created: false });

		const list = await admin("/caches");
		const { caches } = await list.json<{ caches: { name: string }[] }>();
		expect(caches.map((c) => c.name)).toContain(name);

		// Usable straight away by the read path.
		const info = await SELF.fetch(`http://example.com/${name}/nix-cache-info`);
		expect(info.status).toBe(200);
	});

	it.each([
		{ label: "uppercase", name: "Main" },
		{ label: "a slash", name: "a/b" },
		{ label: "an empty name", name: "" },
	])("rejects $label", async ({ name }) => {
		const res = await admin("/caches", { method: "POST", body: JSON.stringify({ name }) });
		expect(res.status).toBe(400);
	});
});
