import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createCache, createBlobObject, createPublishedPath } from "../src/db/repository.js";

const db = testDb();

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

describe("admin narinfo backfill", () => {
	it("stores the narinfo of paths published straight to the database", async () => {
		const cache = await createCache(db, `backfill-${crypto.randomUUID().slice(0, 8)}`);
		const blob = await createBlobObject(db, {
			fileHash: crypto.randomUUID().replaceAll("-", "").padEnd(64, "0"),
			fileSize: 10,
			compression: "zstd",
			r2Key: `nars/${crypto.randomUUID()}`,
		});
		const hash = "1".repeat(32);
		await createPublishedPath(db, {
			cacheId: cache.id,
			storePathHash: hash,
			storePath: `/nix/store/${hash}-backfilled`,
			narHash: `sha256:${"1".repeat(52)}`,
			narSize: 20,
			blobObjectId: blob.id,
			referencesJson: "[]",
			deriver: null,
			system: null,
			signaturesJson: "[]",
		});

		let after = 0;
		for (;;) {
			const res = await admin("/narinfo/backfill", { method: "POST", body: JSON.stringify({ after, limit: 2 }) });
			expect(res.status).toBe(200);
			const { next } = await res.json<{ written: number; next: number | null }>();
			if (next === null) break;
			after = next;
		}

		const narinfo = await SELF.fetch(`http://example.com/${cache.name}/${hash}.narinfo`);
		expect(narinfo.status).toBe(200);
		expect(await narinfo.text()).toContain(`StorePath: /nix/store/${hash}-backfilled`);
	});

	it("rejects an out-of-range limit", async () => {
		const res = await admin("/narinfo/backfill", { method: "POST", body: JSON.stringify({ limit: 5000 }) });
		expect(res.status).toBe(400);
	});
});
