import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createBlobObject, createPublishedPath, findCache } from "../src/db/repository.js";
import { runGarbageCollection } from "../../../workers/control/src/gc.js";
import { resolveConfig } from "../src/config.js";

const db = testDb();
const config = resolveConfig(env);
const unique = (prefix: string) => `${prefix}-${crypto.randomUUID().slice(0, 8)}`;

function orgApi(path: string, method = "GET", body?: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/orgs/default${path}`, {
		method,
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

/** A path published straight to the database, last pushed `daysAgo`, with its narinfo stored. */
async function pathPushed(cacheName: string, hash: string, daysAgo: number): Promise<void> {
	const cache = await findCache(db, "default", cacheName);
	if (!cache) throw new Error(`no cache ${cacheName}`);
	const blob = await createBlobObject(db, {
		fileHash: crypto.randomUUID().replaceAll("-", "").padEnd(64, "0"),
		fileSize: 10,
		compression: "zstd",
		r2Key: `nars/${crypto.randomUUID()}`,
	});
	await env.CACHE_BUCKET.put(blob.r2Key, new Uint8Array(10));
	const path = await createPublishedPath(db, {
		cacheId: cache.id,
		storePathHash: hash,
		storePath: `/nix/store/${hash}-kept`,
		narHash: `sha256:${"1".repeat(52)}`,
		narSize: 20,
		blobObjectId: blob.id,
		referencesJson: "[]",
		deriver: null,
		system: null,
		signaturesJson: "[]",
	});
	await db.execute(`update published_paths set last_pushed_at = now() - interval '${daysAgo} days' where id = ${path.id}`);
	await SELF.fetch("http://example.com/_api/v1/admin/narinfo/backfill", {
		method: "POST",
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: JSON.stringify({ after: path.id - 1, limit: 1 }),
	});
}

async function narinfoStatus(cache: string, hash: string): Promise<number> {
	return (await SELF.fetch(`http://example.com/${cache}/${hash}.narinfo`)).status;
}

async function lookup(cache: string, hashes: string[]): Promise<void> {
	const res = await SELF.fetch("http://example.com/_api/v1/get-missing-paths", {
		method: "POST",
		headers: { authorization: "Bearer test-auth-token", "content-type": "application/json" },
		body: JSON.stringify({ cache, storePathHashes: hashes }),
	});
	expect(res.status).toBe(200);
}

describe("retention", () => {
	it("is set per cache, and can be turned off", async () => {
		const name = unique("ret");
		expect(await (await orgApi("/caches", "POST", { name, retentionDays: 30, protocols: ["nix"] })).json()).toMatchObject({ retentionDays: 30 });
		expect(await (await orgApi(`/caches/${name}`)).json()).toMatchObject({ retentionDays: 30 });
		expect(await (await orgApi("/caches", "POST", { name, retentionDays: null })).json()).toMatchObject({ retentionDays: null });
	});

	it.each([0, 1.5, 4000, "30"])("refuses %s days", async (retentionDays) => {
		expect((await orgApi("/caches", "POST", { name: unique("ret"), retentionDays, protocols: ["nix"] })).status).toBe(400);
	});

	it("deletes paths last pushed longer ago than it, and keeps the rest", async () => {
		const name = unique("ret");
		await orgApi("/caches", "POST", { name, retentionDays: 7, protocols: ["nix"] });
		const [old, recent] = ["6".repeat(32), "7".repeat(32)];
		await pathPushed(name, old, 10);
		await pathPushed(name, recent, 2);

		const result = await runGarbageCollection(config);
		expect(result.errors).toEqual([]);
		expect(await narinfoStatus(name, old)).toBe(404);
		expect(await narinfoStatus(name, recent)).toBe(200);
		expect(await (await orgApi(`/caches/${name}`)).json()).toMatchObject({ paths: 1 });
	});

	it("keeps an old path a push still has", async () => {
		const name = unique("ret");
		await orgApi("/caches", "POST", { name, retentionDays: 7, protocols: ["nix"] });
		const hash = "8".repeat(32);
		await pathPushed(name, hash, 10);

		await lookup(name, [hash]);
		// The mark is written after the response.
		for (let i = 0; i < 50; i++) {
			const [row] = (await db.execute(`select last_pushed_at > now() - interval '1 day' as fresh from published_paths p join caches c on c.id = p.cache_id where c.name = '${name}'`)).rows as { fresh: boolean }[];
			if (row?.fresh) break;
			await new Promise((resolve) => setTimeout(resolve, 20));
		}
		await runGarbageCollection(config);
		expect(await narinfoStatus(name, hash)).toBe(200);
	});

	it("leaves a cache without it alone", async () => {
		const name = unique("ret");
		await orgApi("/caches", "POST", { name, protocols: ["nix"] });
		const hash = "9".repeat(32);
		await pathPushed(name, hash, 400);

		await runGarbageCollection(config);
		expect(await narinfoStatus(name, hash)).toBe(200);
	});

	it("is how long after the last push, not the first", async () => {
		const name = unique("ret");
		await orgApi("/caches", "POST", { name, retentionDays: 7, protocols: ["nix"] });
		const hash = "a".repeat(32);
		await pathPushed(name, hash, 3);
		await db.execute(`update published_paths p set created_at = now() - interval '90 days' from caches c where c.id = p.cache_id and c.name = '${name}'`);

		await runGarbageCollection(config);
		expect(await narinfoStatus(name, hash)).toBe(200);
	});
});
