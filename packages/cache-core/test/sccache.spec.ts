import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { and, eq, inArray } from "drizzle-orm";
import { testDb } from "./db.js";
import { caches, sccacheEntries } from "../src/db/schema.js";
import { findCache, orgUsage } from "../src/db/repository.js";
import { resolveConfig } from "../src/config.js";
import { sweepSccacheEntries } from "../src/sccache.js";
import { handleRequest } from "../../../workers/sccache/src/router.js";

const db = testDb();
const key = "abc" + "d".repeat(61);
const path = (key: string) => `${key[0]}/${key[1]}/${key[2]}/${key}`;
function api(org: string, suffix: string, method = "GET", body?: unknown) {
	return SELF.fetch(`http://example.com/_api/v1/orgs/${org}${suffix}`, { method,
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body) });
}
async function setup(privateCache = false) {
	const org = `sc-${crypto.randomUUID().slice(0, 8)}`;
	expect((await api(org, "", "PUT", { slug: org })).status).toBe(200);
	expect((await api(org, "/caches", "POST", { name: "main", private: privateCache, protocols: ["sccache", "go"] })).status).toBe(201);
	return org;
}
async function token(org: string, perms = ["sccache:read", "sccache:write"], caches = ["main"]) {
	const result = await api(org, "/tokens", "POST", { subject: "test", caches, perms });
	expect(result.status).toBe(201);
	return (await result.json<{ token: string }>()).token;
}
function transfer(org: string, credential?: string, body?: string, suffix = path(key), method = body === undefined ? "GET" : "PUT") {
	return SELF.fetch(`http://example.com/_api/v1/sccache/${org}/main/${suffix}`, { method,
		headers: credential ? { authorization: `Bearer ${credential}` } : {}, body });
}

describe("sccache WebDAV backend", () => {
	it("supports capability probes and virtual directories without storing markers", async () => {
		const org = await setup(true);
		const writer = await token(org);
		expect((await transfer(org, writer, undefined, ".sccache_check")).status).toBe(404);
		expect((await transfer(org, writer, "Hello, World!", ".sccache_check")).status).toBe(204);
		for (const directory of ["", "a/", "a/b/", "a/b/c/"]) {
			expect((await transfer(org, writer, undefined, directory, "MKCOL")).status).toBe(201);
			const response = await transfer(org, writer, undefined, directory, "PROPFIND");
			expect(response.status).toBe(207);
			expect(await response.text()).toContain("<d:collection/>");
		}
		expect(await (await api(org, "/caches/main/sccache")).json()).toMatchObject({ entries: 0, size: 0 });
		expect((await transfer(org, writer, "bad", "a/b/c/" + "f".repeat(64))).status).toBe(404);
		expect((await transfer(org, writer, undefined, path(key), "DELETE")).status).toBe(405);
	});

	it("authenticates private misses and warm hits and isolates permissions and tenants", async () => {
		const org = await setup(true);
		const other = await setup();
		const writer = await token(org);
		for (const credential of [undefined, await token(other), await token(org, ["pull", "push", "go:read", "go:write"])]) {
			expect((await transfer(org, credential)).status).toBe(credential ? 403 : 401);
		}
		expect((await transfer(org, writer, "archive")).status).toBe(201);
		expect(await (await transfer(org, writer)).text()).toBe("archive");
		expect((await transfer(org)).status).toBe(401);
		expect((await transfer(org, await token(org, ["sccache:write"]))).status).toBe(403);
		expect((await transfer(org, await token(org, ["sccache:read"]), "bad")).status).toBe(403);
		expect((await transfer(other)).status).toBe(404);
		const head = await transfer(org, writer, undefined, path(key), "HEAD");
		expect(head.status).toBe(200);
		expect(head.headers.get("content-length")).toBe("7");
		expect(head.headers.get("cache-control")).toBe("no-store");
		expect(await head.text()).toBe("");
		expect((await api(org, "/caches", "POST", { name: "main", private: false })).status).toBe(409);
		await api(org, "", "PUT", { privateCaches: false });
		expect((await transfer(org, writer, "archive")).status).toBe(403);
		expect(await (await transfer(org, writer)).text()).toBe("archive");
	});

	it("publishes exactly one immutable archive under concurrent duplicate writes", async () => {
		const org = await setup();
		await api(org, "", "PUT", { storageLimit: 5 });
		const writer = await token(org);
		const bodies = ["first", "other", "third", "forth"];
		const responses = await Promise.all(bodies.map(body => transfer(org, writer, body)));
		expect(responses.filter(r => r.status === 201)).toHaveLength(1);
		expect(responses.filter(r => r.status === 204)).toHaveLength(3);
		expect(await (await transfer(org)).text()).toBe(bodies[responses.findIndex(r => r.status === 201)]);
		expect((await transfer(org, writer, "a different size")).status).toBe(204);
		expect(await (await api(org, "")).json()).toMatchObject({ used: 5, pending: 0 });
		expect((await transfer(org, writer, "oversized", path("f".repeat(64)))).status).toBe(413);
		expect((await transfer(org, writer, "more", path("f".repeat(64)))).status).toBe(201);
		expect((await transfer(org)).status).toBe(404);
		expect(await (await api(org, "")).json()).toMatchObject({ used: 4, pending: 0 });
	});

	it("shares retained capacity with simultaneous Go uploads", async () => {
		const org = await setup();
		await api(org, "", "PUT", { storageLimit: 9 });
		const writer = await token(org, ["sccache:write", "go:write"]);
		const output = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("golang")))].map(b => b.toString(16).padStart(2, "0")).join("");
		const results = await Promise.all([
			transfer(org, writer, "compiler"),
			SELF.fetch(`http://example.com/_api/v1/go/${org}/main/v1/actions/${key}`, {
				method: "PUT", headers: { authorization: `Bearer ${writer}`, "x-snowstead-output-id": output }, body: "golang",
			}),
		]);
		expect(results.map(r => r.status)).toEqual([201, 201]);
		const compiler = await transfer(org);
		expect(await (await api(org, "")).json()).toMatchObject({ used: compiler.ok ? 8 : 6, pending: 0 });
		expect((await SELF.fetch(`http://example.com/_api/v1/go/${org}/main/v1/actions/${key}`)).status).toBe(compiler.ok ? 404 : 200);
	});

	it("counts multiple compiler entries and Go usage once at the quota boundary", async () => {
		const org = await setup();
		await api(org, "", "PUT", { storageLimit: 16 });
		const writer = await token(org, ["sccache:write", "go:write"]);
		for (const [index, body] of ["abc", "hello"].entries()) {
			expect((await transfer(org, writer, body, path(String(index).repeat(64)))).status).toBe(201);
		}
		const output = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("seven!!")))].map(b => b.toString(16).padStart(2, "0")).join("");
		expect((await SELF.fetch(`http://example.com/_api/v1/go/${org}/main/v1/actions/${key}`, {
			method: "PUT", headers: { authorization: `Bearer ${writer}`, "x-snowstead-output-id": output }, body: "seven!!",
		})).status).toBe(201);
		expect(await (await api(org, "")).json()).toMatchObject({ used: 15, pending: 0 });
		expect((await transfer(org, writer, "x", path("2".repeat(64)))).status).toBe(201);
		expect(await (await api(org, "")).json()).toMatchObject({ used: 16, pending: 0 });
		const cache = (await findCache(db, org, "main"))!;
		await db.update(sccacheEntries).set({ uploadedAt: new Date(0) })
			.where(and(eq(sccacheEntries.cacheId, cache.id), eq(sccacheEntries.action, "0".repeat(64))));
		expect((await transfer(org, writer, "y", path("3".repeat(64)))).status).toBe(201);
		expect((await transfer(org, undefined, undefined, path("0".repeat(64)))).status).toBe(404);
		expect(await (await api(org, "")).json()).toMatchObject({ used: 14, pending: 0 });
	});

	it("refreshes compiler LRU on successful reads including warm HEAD without extending retention", async () => {
		const org = await setup();
		await api(org, "", "PUT", { storageLimit: 8 });
		const writer = await token(org);
		await transfer(org, writer, "aaaa");
		await transfer(org, writer, "bbbb", path("b".repeat(64)));
		const cache = (await findCache(db, org, "main"))!;
		await db.update(sccacheEntries).set({ uploadedAt: new Date(0), lastAccessedAt: null }).where(eq(sccacheEntries.cacheId, cache.id));
		const [before] = await db.select().from(sccacheEntries).where(and(eq(sccacheEntries.cacheId, cache.id), eq(sccacheEntries.action, key)));
		expect(await (await transfer(org)).text()).toBe("aaaa");
		await db.update(sccacheEntries).set({ lastAccessedAt: new Date(0) }).where(eq(sccacheEntries.id, before.id));
		const head = await transfer(org, undefined, undefined, path(key), "HEAD");
		expect(head.status).toBe(200);
		expect(head.headers.get("x-snowstead-cache")).toBe("HIT");
		const [after] = await db.select().from(sccacheEntries).where(eq(sccacheEntries.id, before.id));
		expect(after.lastAccessedAt!.getTime()).toBeGreaterThan(0);
		expect(after.expiresAt).toEqual(before.expiresAt);
		expect((await transfer(org, writer, "cccc", path("c".repeat(64)))).status).toBe(201);
		expect((await transfer(org, undefined, undefined, path("b".repeat(64)))).status).toBe(404);
		expect(await (await transfer(org)).text()).toBe("aaaa");
	});

	it("retries busy capacity without replacing stored bytes, even after a malformed duplicate", async () => {
		const org = await setup();
		await api(org, "", "PUT", { storageLimit: 4 });
		const writer = await token(org);
		expect((await transfer(org, writer, "cold")).status).toBe(201);
		const cache = (await findCache(db, org, "main"))!;
		await db.transaction(async tx => {
			await tx.select().from(sccacheEntries).where(eq(sccacheEntries.cacheId, cache.id)).for("update");
			const response = await transfer(org, writer, "keep", path("f".repeat(64)));
			expect(response.status).toBe(503);
			expect(response.headers.get("retry-after")).toBe("1");
			expect((await transfer(org, undefined, undefined, path("f".repeat(64)))).status).toBe(404);
			expect(await (await api(org, "")).json()).toMatchObject({ used: 4, pending: 4 });
			const config = resolveConfig(env);
			try {
				const malformed = await handleRequest(new Request(`http://example.com/_api/v1/sccache/${org}/main/${path("f".repeat(64))}`, {
					method: "PUT", headers: { authorization: `Bearer ${writer}`, "content-length": "4" }, body: new Blob(["bad"]).stream(),
				}), config);
				expect(malformed.status).toBe(400);
			} finally { await config.close(); }
		});
		expect((await transfer(org, writer, "lose", path("f".repeat(64)))).status).toBe(204);
		expect(await (await transfer(org, undefined, undefined, path("f".repeat(64)))).text()).toBe("keep");
		expect((await transfer(org)).status).toBe(404);
		expect(await (await api(org, "")).json()).toMatchObject({ used: 4, pending: 0 });
	});

	it("bounds staging count and bytes separately from retained content", async () => {
		const org = await setup();
		await api(org, "", "PUT", { storageLimit: 4 });
		const writer = await token(org);
		const cache = (await findCache(db, org, "main"))!;
		const rows = Array.from({ length: 256 }, (_, i) => ({ id: crypto.randomUUID(), cacheId: cache.id,
			generation: cache.sccacheGeneration, action: String(i), r2Key: crypto.randomUUID(), size: 0,
			expiresAt: new Date(Date.now() + 3600_000) }));
		await db.insert(sccacheEntries).values(rows);
		expect((await transfer(org, writer, "data")).status).toBe(503);
		await db.delete(sccacheEntries).where(eq(sccacheEntries.id, rows[0].id));
		await db.update(sccacheEntries).set({ size: 1 }).where(eq(sccacheEntries.id, rows[1].id));
		expect((await transfer(org, writer, "data")).status).toBe(503);
		await db.update(sccacheEntries).set({ size: 0 }).where(eq(sccacheEntries.id, rows[1].id));
		expect((await transfer(org, writer, "data")).status).toBe(201);
		expect(await (await transfer(org)).text()).toBe("data");
	});

	it.each([2, 6, 64 * 1024 * 1024 + 1])("rejects a four-byte upload declared as %s without publishing", async length => {
		const org = await setup();
		const writer = await token(org);
		const config = resolveConfig(env);
		try {
			const response = await handleRequest(new Request(`http://example.com/_api/v1/sccache/${org}/main/${path(key)}`, {
				method: "PUT", headers: { authorization: `Bearer ${writer}`, "content-length": String(length) }, body: new Blob(["data"]).stream(),
			}), config);
			expect(response.status).toBe(length > 64 * 1024 * 1024 ? 413 : 400);
		} finally { await config.close(); }
		expect((await transfer(org)).status).toBe(404);
		expect((await transfer(org, writer, "good")).status).toBe(201);
	});

	it("keeps quota exact across expiry boundaries, publication, detachment, rollback and deletion", async () => {
		const org = await setup();
		const cache = (await findCache(db, org, "main"))!;
		const now = new Date("2026-11-01T12:00:30.000Z");
		const rows = [
			{ size: 2, offset: -1 }, { size: 3, offset: 0 },
			{ size: 5, offset: 1 }, { size: 7, offset: 29_999 },
			{ size: 11, offset: 30_000 }, { size: 13, offset: 30_001 },
			{ size: 17, offset: 90_000, pending: true }, { size: 31, offset: 2, pending: true },
			{ size: 19, offset: 90_000, generation: "obsolete" },
		].map(row => ({ id: crypto.randomUUID(), cacheId: cache.id, generation: row.generation ?? cache.sccacheGeneration,
			action: crypto.randomUUID(), r2Key: crypto.randomUUID(), size: row.size,
			uploadedAt: row.pending ? null : now, expiresAt: new Date(now.getTime() + row.offset) }));
		await db.insert(sccacheEntries).values(rows);
		expect(await orgUsage(db, org, now)).toEqual({ used: 36, pending: 48 });
		// Advancing time alone must expire quota, without any GC or data writes.
		expect(await orgUsage(db, org, new Date(now.getTime() + 30_000))).toEqual({ used: 13, pending: 17 });
		await db.update(sccacheEntries).set({ uploadedAt: now }).where(eq(sccacheEntries.id, rows[7].id));
		expect(await orgUsage(db, org, now)).toEqual({ used: 67, pending: 17 });
		await db.update(sccacheEntries).set({ expiresAt: new Date(now.getTime() - 1) }).where(eq(sccacheEntries.id, rows[7].id));
		await db.update(sccacheEntries).set({ cacheId: null }).where(eq(sccacheEntries.id, rows[5].id));
		expect(await orgUsage(db, org, now)).toEqual({ used: 23, pending: 17 });
		await expect(db.transaction(async tx => {
			await tx.delete(sccacheEntries).where(eq(sccacheEntries.cacheId, cache.id));
			throw new Error("rollback quota change");
		})).rejects.toThrow("rollback quota change");
		expect(await orgUsage(db, org, now)).toEqual({ used: 23, pending: 17 });
		await db.delete(sccacheEntries).where(eq(sccacheEntries.id, rows[2].id));
		expect(await orgUsage(db, org, now)).toEqual({ used: 18, pending: 17 });
		await api(org, "/caches/main/delete", "POST");
		expect(await orgUsage(db, org, now)).toEqual({ used: 0, pending: 0 });
	});

	it("allows a distinct artifact to finish while another body is stalled", async () => {
		const org = await setup();
		const writer = await token(org);
		const release = Promise.withResolvers<void>();
		let started = false;
		let finished = false;
		const body = new ReadableStream<Uint8Array>({ async pull(controller) {
			started = true;
			await release.promise;
			controller.enqueue(new TextEncoder().encode("slow"));
			controller.close();
		} }, { highWaterMark: 0 });
		const config = resolveConfig(env);
		const first = handleRequest(new Request(`http://example.com/_api/v1/sccache/${org}/main/${path(key)}`, {
			method: "PUT", headers: { authorization: `Bearer ${writer}`, "content-length": "4" }, body,
		}), config).then(r => { finished = true; return r; });
		let second: Promise<Response> | undefined;
		try {
			await expect.poll(() => started).toBe(true);
			let completed = false;
			second = transfer(org, writer, "fast", path("f".repeat(64))).then(r => { completed = true; return r; });
			await expect.poll(() => completed).toBe(true);
			expect((await second).status).toBe(201);
			expect(finished).toBe(false);
		} finally {
			release.resolve();
			await Promise.allSettled([first, second]);
			await config.close();
		}
		expect((await first).status).toBe(201);
	});

	it("bounds stalled uploads before SQL, keeps reads and other orgs usable, and recovers", async () => {
		const org = await setup();
		const writer = await token(org);
		const other = await setup();
		const otherWriter = await token(other);
		expect((await transfer(org, writer, "cached")).status).toBe(201);
		const streams = Array.from({ length: 8 }, () => new FixedLengthStream(4));
		const writers = streams.map(stream => stream.writable.getWriter());
		const uploads = streams.map((stream, i) => SELF.fetch(`http://example.com/_api/v1/sccache/${org}/main/${path(i.toString(16).padStart(64, "0"))}`, {
			method: "PUT", headers: { authorization: `Bearer ${writer}`, "content-length": "4" }, body: stream.readable,
		}));
		try {
			await Promise.all(writers.map(writer => writer.write(new TextEncoder().encode("s"))));
			await expect.poll(async () => (await (await api(org, "")).json<{ pending: number }>()).pending).toBe(32);
			expect(await (await transfer(org)).text()).toBe("cached");
			expect((await transfer(other, otherWriter, "independent")).status).toBe(201);
			const refused = await transfer(org, writer, "fast", path("f".repeat(64)));
			expect(refused.status).toBe(429);
			expect(refused.headers.get("retry-after")).toBe("1");
			expect((await transfer(org, undefined, undefined, path("f".repeat(64)))).status).toBe(404);
			expect(await (await api(org, "")).json()).toMatchObject({ pending: 32 });
		} finally {
			await Promise.all(writers.map(async writer => { await writer.write(new TextEncoder().encode("low")); await writer.close(); }));
			await Promise.allSettled(uploads);
		}
		expect((await Promise.all(uploads)).map(response => response.status)).toEqual(Array(8).fill(201));
		expect((await transfer(org, writer, "fast", path("f".repeat(64)))).status).toBe(201);
	});

	it("shares the sweep budget across garbage categories and skips locked entries", async () => {
		const org = await setup();
		const cache = (await findCache(db, org, "main"))!;
		await db.update(caches).set({ sccacheGeneration: "m" }).where(eq(caches.id, cache.id));
		const config = resolveConfig(env);
		try {
			// Drain garbage left by earlier lifecycle tests before measuring the batch.
			while (await sweepSccacheEntries(config)) { /* bounded by the fixture */ }
			const now = Date.now();
			const rows = Array.from({ length: 541 }, (_, i) => ({
				id: crypto.randomUUID(), cacheId: i >= 160 && i < 320 ? null : cache.id,
				generation: i >= 320 && i < 430 ? "a" : i >= 430 && i < 540 ? "z" : "m",
				action: crypto.randomUUID(), r2Key: crypto.randomUUID(), size: 0,
				uploadedAt: new Date(now), expiresAt: new Date(now + (i < 160 ? -1000 : 3600_000)),
			}));
			await db.insert(sccacheEntries).values(rows);
			const locked = [rows[0], rows[160], rows[320], rows[430]];
			await config.bucket.put(rows[0].r2Key, "locked");
			await config.bucket.put(rows[540].r2Key, "live");
			await db.transaction(async tx => {
				await tx.select().from(sccacheEntries).where(inArray(sccacheEntries.id, locked.map(row => row.id))).for("update");
				expect(await sweepSccacheEntries(config)).toBe(500);
				expect(await sweepSccacheEntries(config)).toBe(36);
				expect(await sweepSccacheEntries(config)).toBe(0);
				expect(await config.bucket.head(rows[0].r2Key)).not.toBeNull();
			});
			expect(await sweepSccacheEntries(config)).toBe(4);
			expect(await sweepSccacheEntries(config)).toBe(0);
			expect(await db.select({ id: sccacheEntries.id }).from(sccacheEntries)
				.where(inArray(sccacheEntries.id, rows.map(row => row.id)))).toEqual([{ id: rows[540].id }]);
			expect(await config.bucket.head(rows[0].r2Key)).toBeNull();
			expect(await config.bucket.head(rows[540].r2Key)).not.toBeNull();
		} finally { await config.close(); }
	});

	it("expires warm entries, resets independently, and sweeps orphaned objects", async () => {
		const org = await setup();
		const writer = await token(org);
		await transfer(org, writer, "old");
		await (await transfer(org)).text();
		const cache = (await findCache(db, org, "main"))!;
		const [old] = await db.select().from(sccacheEntries).where(eq(sccacheEntries.cacheId, cache.id));
		await db.update(sccacheEntries).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(sccacheEntries.id, old.id));
		expect((await transfer(org)).status).toBe(404);
		expect((await transfer(org, writer, "new")).status).toBe(201);
		await api(org, "/caches/main/go/reset", "POST");
		expect(await (await transfer(org)).text()).toBe("new");
		expect((await api(org, "/caches/main/sccache/reset", "POST")).status).toBe(200);
		expect((await transfer(org)).status).toBe(404);
		expect((await transfer(org, writer, "fresh")).status).toBe(201);
		const config = resolveConfig(env);
		try { expect(await sweepSccacheEntries(config)).toBeGreaterThan(0); } finally { await config.close(); }
		expect(await env.CACHE_BUCKET.head(old.r2Key)).toBeNull();
		expect(await (await transfer(org)).text()).toBe("fresh");
		await api(org, "/caches/main/delete", "POST");
		await api(org, "/caches", "POST", { name: "main", protocols: ["sccache"] });
		expect((await transfer(org)).status).toBe(404);
		expect((await transfer(org, writer, "stale token")).status).toBe(403);
	});
});
