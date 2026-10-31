import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { and, eq, sql } from "drizzle-orm";
import { testDb } from "./db.js";
import { apiTokens, caches, evictionLogs, goEntries, pinRevisions, pins, publishedPaths, sccacheEntries, uploadSessions } from "../src/db/schema.js";
import { createBlobObject, createPublishedPath, findCache, findPublishedPath, findUploadSession } from "../src/db/repository.js";
import { resolveConfig } from "../src/config.js";
import { authenticateWrite } from "../src/auth.js";
import { deleteCachePaths } from "../src/path-deletion.js";
import { evictCache } from "../src/cache-eviction.js";
import { sweepGoEntries } from "../src/go-cache.js";
import { publishSccacheUpload, reserveSccacheUpload, sweepSccacheEntries } from "../src/sccache.js";
import { runGarbageCollection } from "../../../workers/control/src/gc.js";

const db = testDb();
function api(org: string, path: string, method = "GET", body?: unknown, credential = "test-admin-secret") {
	return SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, { method,
		headers: { authorization: `Bearer ${credential}`, "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body) });
}
async function setup(privateCache = false) {
	const org = `policy-${crypto.randomUUID().slice(0, 8)}`;
	expect((await api(org, "", "PUT", { slug: org })).status).toBe(200);
	expect((await api(org, "/caches", "POST", { name: "main", private: privateCache, protocols: ["nix", "go", "sccache"] })).status).toBe(201);
	const { key } = await (await api(org, "/keys", "POST", { name: "manager" })).json<{ key: string }>();
	const { token, jti } = await (await api(org, "/tokens", "POST", { subject: "ci", caches: ["main"], perms: ["push", "pull", "go:read", "go:write", "sccache:read", "sccache:write"] })).json<{ token: string; jti: string }>();
	return { org, key, token, jti, cache: (await findCache(db, org, "main"))! };
}
type Target = Awaited<ReturnType<typeof setup>>;
async function nix(t: Target, char: string, references: string[] = []) {
	const hash = char.repeat(32), storePath = `/nix/store/${hash}-fixture`;
	const blob = await createBlobObject(db, { fileHash: crypto.randomUUID(), fileSize: 4, compression: "zstd", r2Key: `policy/${crypto.randomUUID()}` });
	const row = await createPublishedPath(db, { cacheId: t.cache.id, storePathHash: hash, storePath, narHash: `sha256:${"1".repeat(52)}`,
		narSize: 20, blobObjectId: blob.id, referencesJson: JSON.stringify(references), signaturesJson: "[]", deriver: null, system: null });
	await db.update(publishedPaths).set({ lastPushedAt: new Date(0) }).where(eq(publishedPaths.id, row.id));
	await env.PUBLIC_BUCKET.put(`${t.org}/main/${hash}.narinfo`, "narinfo");
	return { hash, storePath };
}
async function action(t: Target, product: "go" | "sccache", char: string, body?: string) {
	const key = char.repeat(64);
	const suffix = product === "go" ? `v1/actions/${key}` : `${char}/${char}/${char}/${key}`;
	const output = body === undefined ? "" : [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)))].map(b => b.toString(16).padStart(2, "0")).join("");
	return SELF.fetch(`http://example.com/_api/v1/${product}/${t.org}/main/${suffix}`, { method: body === undefined ? "GET" : "PUT", body,
		headers: { authorization: `Bearer ${t.token}`, ...(body === undefined ? {} : { "content-length": String(body.length), "x-snowstead-output-id": output }) } });
}
const pin = (t: Target, storePath: string, keep: unknown = "forever", credential = t.key) => api(t.org, "/caches/main/pins", "POST", { name: "release", storePath, keep }, credential);
type Pin = { name: string; keep: unknown; currentRevision: number; history: { revision: number; storePath: string; pinned: boolean }[] };
type Entry = { product: string; cache: string; key: string; size: number; reason?: string; id?: number };
type Info = { next: { items: Entry[]; cursor: string | null; bytesToFree: number }; recent: { items: Entry[]; cursor: string | null } };
const info = async (t: Target, query = "") => (await api(t.org, `/eviction${query}`, "GET", undefined, t.key)).json<Info>();

describe("control-plane cache policies", () => {
	it("records authenticated use for all products after the response, coalesces writes, and scopes token detail", async () => {
		const t = await setup(true), other = await setup();
		const detail = async () => (await api(t.org, `/tokens/${t.jti}`, "GET", undefined, t.key)).json<{ token: { lastUsedAt: string | null } }>();
		expect((await detail()).token.lastUsedAt).toBeNull();
		const config = resolveConfig(env);
		expect((await authenticateWrite(new Request("https://example.com", { headers: { authorization: `Bearer ${t.token}` } }), config)).kind).toBe("ok");
		expect((await detail()).token.lastUsedAt).toBeNull();
		await config.releaseDb();
		expect((await detail()).token.lastUsedAt).toBeNull();
		await config.close();
		const first = (await detail()).token.lastUsedAt!;
		expect(Number.isFinite(Date.parse(first))).toBe(true);
		for (const product of ["go", "sccache"] as const) {
			expect((await action(t, product, "a")).status).toBe(404);
			await db.update(apiTokens).set({ lastUsedAt: new Date(0) }).where(eq(apiTokens.jti, t.jti));
			expect((await action(t, product, "a")).status).toBe(404);
			await expect.poll(async () => (await detail()).token.lastUsedAt).not.toBe(new Date(0).toISOString());
		}
		await db.update(apiTokens).set({ lastUsedAt: new Date(0) }).where(eq(apiTokens.jti, t.jti));
		const read = () => SELF.fetch(`http://example.com/${t.org}/main/${"1".repeat(32)}.narinfo`, { headers: { authorization: `Basic ${btoa(`ci:${t.token}`)}` } });
		expect((await read()).status).toBe(404);
		await expect.poll(async () => (await detail()).token.lastUsedAt).not.toBe(new Date(0).toISOString());
		const before = (await detail()).token.lastUsedAt;
		await read();
		const again = resolveConfig(env);
		await authenticateWrite(new Request("https://example.com", { headers: { authorization: `Bearer ${t.token}` } }), again);
		await again.close();
		expect((await detail()).token.lastUsedAt).toBe(before);
		const list = await (await api(t.org, "/tokens")).json<{ tokens: { jti: string; lastUsedAt: string }[] }>();
		expect(list.tokens.find(row => row.jti === t.jti)?.lastUsedAt).toBe(before);
		expect((await api(other.org, `/tokens/${t.jti}`, "GET", undefined, other.key)).status).toBe(404);
		expect((await api(t.org, `/tokens/${t.jti}`, "GET", undefined, other.key)).status).toBe(403);
	});

	it("protects cyclic closures from capacity and retention, rejects missing dependencies, and audits push-token writes", async () => {
		const t = await setup(), other = await setup();
		const root = await nix(t, "1", [`${"2".repeat(32)}-fixture`]);
		const dependency = await nix(t, "2", [root.storePath.slice(11)]);
		await nix(other, "3");
		const missing = await nix(t, "4", [`${"3".repeat(32)}-fixture`]);
		expect((await pin(t, missing.storePath)).status).toBe(409);
		expect((await pin(t, root.storePath, "forever", other.token)).status).toBe(403);
		expect((await pin(t, root.storePath, "forever", t.token)).status).toBe(201);
		expect((await pin(t, root.storePath, "forever", t.token)).status).toBe(200);
		expect((await api(t.org, "/caches/main/pins", "GET", undefined, t.token)).status).toBe(403);
		const listed = await (await api(t.org, "/caches/main/pins", "GET", undefined, t.key)).json<{ pins: Pin[] }>();
		expect(listed.pins[0]).toMatchObject({ currentRevision: 1, history: [{ revision: 1, pinned: true }] });
		expect((await info(t)).next.items.map(row => row.key)).toEqual([missing.storePath]);
		const config = resolveConfig(env);
		try {
			expect(await deleteCachePaths(config, t.cache, { lastPushedBefore: new Date(), limit: 1 })).toEqual([missing.hash]);
			expect(await deleteCachePaths(config, t.cache, { storePathHashes: [dependency.hash] })).toEqual([]);
			expect(await env.PUBLIC_BUCKET.head(`${t.org}/main/${dependency.hash}.narinfo`)).not.toBeNull();
		} finally { await config.close(); }
		await api(t.org, "", "PUT", { storageLimit: 8 });
		expect((await action(t, "sccache", "a", "data")).status).toBe(503);
		expect(await findPublishedPath(db, t.cache.id, root.hash)).toBeDefined();
		expect((await api(t.org, "/caches/main/pins/release", "DELETE", undefined, t.token)).status).toBe(200);
		expect((await action(t, "sccache", "a", "data")).status).toBe(204);
		await expect.poll(async () => (await (await api(t.org, "/audit")).json<{ entries: { action: string }[] }>()).entries.filter(e => e.action.startsWith("pin.")).map(e => e.action).sort()).toEqual(["pin.create", "pin.delete", "pin.update"]);
	});

	it("keeps the requested revisions or superseded days, and refuses to resurrect deleted revisions", async () => {
		const t = await setup();
		const paths = await Promise.all(["1", "2", "3"].map(char => nix(t, char)));
		for (const path of paths) expect((await pin(t, path.storePath, { revisions: 2 })).ok).toBe(true);
		const result = await (await api(t.org, "/caches/main/pins")).json<{ pins: Pin[] }>();
		expect(result.pins[0].history.map(r => [r.revision, r.pinned])).toEqual([[3, true], [2, true], [1, false]]);
		expect((await pin(t, paths[2].storePath, { days: 2 })).status).toBe(200);
		const [row] = await db.select().from(pins).where(eq(pins.cacheId, t.cache.id));
		await db.update(pinRevisions).set({ supersededAt: new Date(Date.now() - 3 * 86400_000) }).where(and(eq(pinRevisions.pinId, row.id), eq(pinRevisions.revision, 1)));
		expect((await info(t)).next.items.map(e => e.key)).toEqual([paths[0].storePath]);
		const config = resolveConfig(env);
		try { expect(await deleteCachePaths(config, t.cache, { lastPushedBefore: new Date(), limit: 500 })).toEqual([paths[0].hash]); }
		finally { await config.close(); }
		expect((await pin(t, paths[2].storePath, "forever")).status).toBe(409);
		expect((await (await api(t.org, "/caches/main/pins")).json<{ pins: Pin[] }>()).pins[0].keep).toEqual({ days: 2 });
		for (const keep of [{ days: 0 }, { revisions: 1.5 }, { days: 1, revisions: 2 }, "bad"]) expect((await pin(t, paths[2].storePath, keep)).status).toBe(400);
	});

	it("pages mixed-product LRU and history, logs all removal reasons once, and isolates tenants", async () => {
		const t = await setup(), other = await setup();
		await nix(t, "1");
		for (const product of ["go", "sccache"] as const) expect((await action(t, product, "a", "data")).status).toBe(201);
		await nix(other, "2");
		const first = await info(t, "?limit=1");
		expect(first.next.items[0].product).toBe("nix");
		const second = await info(t, `?limit=1&nextCursor=${encodeURIComponent(first.next.cursor!)}`);
		const third = await info(t, `?limit=1&nextCursor=${encodeURIComponent(second.next.cursor!)}`);
		expect([first, second, third].flatMap(p => p.next.items.map(e => e.product))).toEqual(["nix", "go", "sccache"]);
		expect(third.next.cursor).toBeNull();
		expect((await api(other.org, `/eviction?nextCursor=${encodeURIComponent(first.next.cursor!)}`)).status).toBe(400);
		expect((await api(t.org, "/eviction", "GET", undefined, other.key)).status).toBe(403);
		await api(t.org, "", "PUT", { storageLimit: 8 });
		expect((await info(t)).next.bytesToFree).toBe(4);
		expect((await action(t, "sccache", "b", "data")).status).toBe(201);
		expect((await info(t)).recent.items.map(e => [e.product, e.reason])).toEqual([["go", "capacity"], ["nix", "capacity"]]);
		expect((await api(t.org, "/caches/main/sccache/reset", "POST")).status).toBe(200);
		const config = resolveConfig(env);
		try { await sweepGoEntries(config); await sweepSccacheEntries(config); } finally { await config.close(); }
		expect((await info(t)).recent.items).toHaveLength(4);
		expect((await info(t)).recent.items.filter(e => e.reason === "clear")).toHaveLength(2);
		expect((await action(t, "go", "c", "data")).status).toBe(201);
		await db.update(goEntries).set({ expiresAt: new Date(0) }).where(eq(goEntries.cacheId, t.cache.id));
		const gc = resolveConfig(env);
		try { await sweepGoEntries(gc); } finally { await gc.close(); }
		expect((await info(t)).recent.items[0]).toMatchObject({ product: "go", reason: "retention" });
		const page = await info(t, "?limit=2");
		const nextPage = await info(t, `?limit=2&recentCursor=${page.recent.cursor}`);
		expect(new Set([...page.recent.items, ...nextPage.recent.items].map(e => e.id)).size).toBe(4);
		expect((await info(other)).recent.items).toEqual([]);
		await db.update(evictionLogs).set({ evictedAt: new Date(0) }).where(eq(evictionLogs.orgId, t.org));
		const sweep = resolveConfig(env);
		try { expect((await runGarbageCollection(sweep)).errors).toEqual([]); } finally { await sweep.close(); }
		expect(await db.select().from(evictionLogs).where(eq(evictionLogs.orgId, t.org))).toEqual([]);
	});

	it("evicts every product and pins, preserves cache identity and credentials, and is safe to retry", async () => {
		const t = await setup(), other = await setup();
		const root = await nix(t, "1");
		await pin(t, root.storePath);
		await nix(other, "1");
		for (const product of ["go", "sccache"] as const) expect((await action(t, product, "a", "data")).status).toBe(201);
		expect((await api(t.org, "/caches/main/evict", "POST", undefined, other.key)).status).toBe(403);
		expect((await api(t.org, "/caches/main/evict", "POST", undefined, t.token)).status).toBe(403);
		const config = resolveConfig(env);
		try {
			const failing = { ...config, bucket: new Proxy(config.bucket, { get(target, property) { if (property === "delete") return async () => { throw new Error("R2 unavailable"); }; const value = Reflect.get(target, property); return typeof value === "function" ? value.bind(target) : value; } }) };
			await expect(evictCache(failing, t.cache, "http://example.com")).rejects.toThrow("R2 unavailable");
			expect(await findPublishedPath(db, t.cache.id, root.hash)).toBeDefined();
			expect((await info(t)).recent.items).toEqual([]);
		} finally { await config.close(); }
		const evicted = await api(t.org, "/caches/main/evict", "POST", undefined, t.key);
		expect(await evicted.json()).toEqual({ evicted: true, name: "main", removed: { nix: 1, go: 1, sccache: 1 }, pinsDeleted: 1 });
		expect((await findCache(db, t.org, "main"))?.id).toBe(t.cache.id);
		expect((await info(t)).recent.items.map(e => e.reason)).toEqual(["evict", "evict", "evict"]);
		expect(await (await api(t.org, "/caches/main/pins")).json()).toEqual({ pins: [] });
		expect(await findPublishedPath(db, other.cache.id, root.hash)).toBeDefined();
		expect(await (await api(t.org, "/caches/main/evict", "POST", undefined, t.key)).json()).toMatchObject({ removed: { nix: 0, go: 0, sccache: 0 }, pinsDeleted: 0 });
		expect((await action(t, "sccache", "a", "new!")).status).toBe(201);
		expect((await api(t.org, "/caches/main/delete", "POST")).status).toBe(200);
		expect((await info(t)).recent.items[0]).toMatchObject({ product: "sccache", reason: "clear" });
		expect((await info(t)).recent.items).toHaveLength(4);
		await expect.poll(async () => (await (await api(t.org, "/audit")).json<{ entries: { action: string }[] }>()).entries.some(e => e.action === "cache.evict")).toBe(true);
	});

	it("serializes pinning with uploads and eviction and rejects pre-eviction upload publication", async () => {
		const t = await setup();
		const root = await nix(t, "1");
		let pending: Promise<Response> | undefined;
		try {
			await db.transaction(async tx => {
				await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + t.org},0))`);
				pending = pin(t, root.storePath);
				await expect.poll(async () => Number((await tx.execute(sql`select count(*) as n from pg_locks where locktype='advisory' and not granted`)).rows[0].n)).toBeGreaterThan(0);
			});
			expect((await pending!).status).toBe(201);
		} finally { await pending; }
		const config = resolveConfig(env);
		try {
			const reservation = await reserveSccacheUpload(config.db, t.cache, "a".repeat(64), 4);
			if (reservation instanceof Response) throw new Error("reservation failed");
			await config.bucket.put(reservation.r2Key, "data");
			const id = crypto.randomUUID();
			await db.insert(uploadSessions).values({ id, cacheId: t.cache.id, storePathHash: "2".repeat(32), storePath: `/nix/store/${"2".repeat(32)}-fixture`, narHash: "sha256:fixture", narSize: 4, fileSize: 4, compression: "zstd", status: "finalizing", expiresAt: new Date(Date.now() + 3600_000) });
			let eviction: Promise<Response> | undefined;
			try {
				// Hold exactly the cache/entry locks of an in-flight transfer.
				await db.transaction(async tx => {
					await tx.select().from(caches).where(eq(caches.id, t.cache.id)).for("share");
					await tx.select().from(sccacheEntries).where(eq(sccacheEntries.id, reservation.id)).for("update");
					eviction = api(t.org, "/caches/main/evict", "POST");
					await expect.poll(async () => Number((await tx.execute(sql`select count(*) as n from pg_locks
						where locktype='transactionid' and not granted`)).rows[0].n)).toBeGreaterThan(0);
				});
				expect((await eviction!).status).toBe(200);
			} finally { await eviction; }
			await expect(publishSccacheUpload(config, t.cache, reservation.id, new Date(), "http://example.com")).rejects.toThrow();
			expect((await findUploadSession(db, id))?.status).toBe("aborted");
			expect(await db.select().from(sccacheEntries).where(eq(sccacheEntries.cacheId, t.cache.id))).toEqual([]);
			expect((await info(t)).next.items).toEqual([]);
			expect((await pin(t, root.storePath)).status).toBe(409);
		} finally { await config.close(); }
	});

	it.each(["go", "sccache"] as const)("logs %s reset exactly once when retention sweeps before its commit", async product => {
		const t = await setup();
		expect((await action(t, product, "a", "data")).status).toBe(201);
		const table = product === "go" ? goEntries : sccacheEntries;
		await db.update(table).set({ expiresAt: new Date(0) }).where(eq(table.cacheId, t.cache.id));
		const config = resolveConfig(env);
		try {
			await db.transaction(async tx => {
				await tx.update(caches).set(product === "go" ? { goGeneration: crypto.randomUUID() } : { sccacheGeneration: crypto.randomUUID() }).where(eq(caches.id, t.cache.id));
				await (product === "go" ? sweepGoEntries(config) : sweepSccacheEntries(config));
			});
			await (product === "go" ? sweepGoEntries(config) : sweepSccacheEntries(config));
			expect((await info(t)).recent.items).toHaveLength(1);
			expect((await info(t)).recent.items[0]).toMatchObject({ product, reason: "clear" });
		} finally { await config.close(); }
	});
});
