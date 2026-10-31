import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { and, eq, inArray, sql } from "drizzle-orm";
import { testDb } from "./db.js";
import { goEntries, publishedPaths, uploadSessions } from "../src/db/schema.js";
import { createBlobObject, createPublishedPath, findCache, findPublishedPath, withUploadSessionLock } from "../src/db/repository.js";
import { resolveConfig } from "../src/config.js";
import { CapacityError, recordNixAccess, withOrgCapacity } from "../src/capacity.js";

const db = testDb();
function api(org: string, path: string, method = "GET", body?: unknown) {
	return SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, { method,
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body) });
}
async function setup(limit: number | null = 8, privateCache = false) {
	const org = `capacity-${crypto.randomUUID().slice(0, 8)}`;
	expect((await api(org, "", "PUT", { slug: org, storageLimit: limit })).status).toBe(200);
	expect((await api(org, "/caches", "POST", { name: "main", private: privateCache, protocols: ["nix", "go"] })).status).toBe(201);
	const response = await api(org, "/tokens", "POST", { subject: "capacity", caches: ["*"], perms: ["go:write", "go:read", "pull"] });
	expect(response.status).toBe(201);
	return { org, token: (await response.json<{ token: string }>()).token, cache: (await findCache(db, org, "main"))! };
}
type Target = Awaited<ReturnType<typeof setup>>;
async function go(target: Target, action: string, body?: string, method = body === undefined ? "GET" : "PUT", authenticated = true) {
	const output = body === undefined ? "" : [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)))].map(b => b.toString(16).padStart(2, "0")).join("");
	return SELF.fetch(`http://example.com/_api/v1/go/${target.org}/${target.cache.name}/v1/actions/${action.repeat(64)}`, {
		method, body, headers: { ...(authenticated ? { authorization: `Bearer ${target.token}` } : {}),
			...(body === undefined ? {} : { "content-length": String(body.length), "x-snowstead-output-id": output }) } });
}
async function nix(target: Target, character = "1", size = 4, blob?: Awaited<ReturnType<typeof createBlobObject>>) {
	const hash = character.repeat(32);
	const object = blob ?? await createBlobObject(db, { fileHash: crypto.randomUUID(), fileSize: size, compression: "zstd", r2Key: `capacity/${crypto.randomUUID()}` });
	await env.PUBLIC_BUCKET.put(object.r2Key, "physical bytes");
	const row = await createPublishedPath(db, { cacheId: target.cache.id, storePathHash: hash, storePath: `/nix/store/${hash}-fixture`,
		narHash: `sha256:${"1".repeat(52)}`, narSize: 999, blobObjectId: object.id,
		referencesJson: "[]", signaturesJson: "[]", deriver: null, system: null });
	await db.update(publishedPaths).set({ lastPushedAt: new Date(0) }).where(eq(publishedPaths.id, row.id));
	await env.PUBLIC_BUCKET.put(`${target.org}/main/${hash}.narinfo`, "narinfo fixture");
	return { hash, object, row };
}

describe("org retained capacity", () => {
	it("evicts the cold Go action across caches, using observed successful GET and HEAD including CDN hits", async () => {
		const target = await setup();
		expect((await api(target.org, "/caches", "POST", { name: "other", protocols: ["go"] })).status).toBe(201);
		const other = { ...target, cache: (await findCache(db, target.org, "other"))! };
		expect((await go(target, "a", "aaaa")).status).toBe(201);
		expect((await go(other, "b", "bbbb")).status).toBe(201);
		await db.update(goEntries).set({ uploadedAt: new Date(0), lastAccessedAt: null }).where(inArray(goEntries.cacheId, [target.cache.id, other.cache.id]));
		await (await go(target, "a")).text();
		await expect.poll(async () => (await db.select().from(goEntries).where(and(eq(goEntries.cacheId, target.cache.id), eq(goEntries.action, "a".repeat(64)))))[0].lastAccessedAt).not.toBeNull();
		await db.update(goEntries).set({ lastAccessedAt: new Date(0) }).where(eq(goEntries.cacheId, target.cache.id));
		const head = await go(target, "a", undefined, "HEAD");
		expect(head.status).toBe(200);
		expect(head.headers.get("x-snowstead-cache")).toBe("HIT");
		await expect.poll(async () => (await db.select().from(goEntries).where(eq(goEntries.cacheId, target.cache.id)))[0].lastAccessedAt!.getTime()).toBeGreaterThan(0);
		expect((await go(target, "c", "cccc")).status).toBe(201);
		expect((await go(other, "b")).status).toBe(404);
		expect((await go(target, "a")).status).toBe(200);
		expect((await go(target, "c")).status).toBe(200);
		expect(await (await api(target.org, "")).json()).toMatchObject({ used: 8 });
	});

	it("does not flush retained objects for an oversized upload and does not double-charge duplicate publication", async () => {
		const target = await setup(4);
		expect((await go(target, "a", "aaaa")).status).toBe(201);
		expect((await go(target, "a", "aaaa")).status).toBe(204);
		expect((await go(target, "b", "large")).status).toBe(413);
		expect(await (await go(target, "a")).text()).toBe("aaaa");
		expect(await (await api(target.org, "")).json()).toMatchObject({ used: 4, pending: 0 });
	});

	it("shares Nix and Go capacity but preserves another org and shared physical NAR bytes", async () => {
		const target = await setup(4);
		const other = await setup(4);
		const cold = await nix(target);
		await nix(other, "1", 4, cold.object);
		expect((await go(target, "a", "aaaa")).status).toBe(201);
		expect(await findPublishedPath(db, target.cache.id, cold.hash)).toBeUndefined();
		expect(await findPublishedPath(db, other.cache.id, cold.hash)).toBeDefined();
		expect(await env.PUBLIC_BUCKET.head(cold.object.r2Key)).not.toBeNull();
		expect(await env.PUBLIC_BUCKET.head(`${target.org}/main/${cold.hash}.narinfo`)).toBeNull();
		expect(await env.PUBLIC_BUCKET.head(`${other.org}/main/${cold.hash}.narinfo`)).not.toBeNull();
		expect(await (await api(other.org, "")).json()).toMatchObject({ used: 4 });
	});

	it("lets a Nix publication evict Nix and Go under the session lock and coalesces observed Nix access", async () => {
		const target = await setup(8);
		const cold = await nix(target);
		expect((await go(target, "a", "aaaa")).status).toBe(201);
		const config = resolveConfig(env);
		try {
			const blob = await createBlobObject(db, { fileHash: crypto.randomUUID(), fileSize: 8, compression: "zstd", r2Key: crypto.randomUUID() });
			const hash = "2".repeat(32);
			await withOrgCapacity(config, target.org, [{ cacheId: target.cache.id, storePathHash: hash }], tx => withUploadSessionLock(tx, locked => createPublishedPath(locked, {
				cacheId: target.cache.id, storePathHash: hash, storePath: `/nix/store/${hash}-new`, narHash: "sha256:fixture", narSize: 999,
				blobObjectId: blob.id, referencesJson: "[]", signaturesJson: "[]", deriver: null, system: null })));
			expect((await go(target, "a")).status).toBe(404);
			expect(await findPublishedPath(db, target.cache.id, cold.hash)).toBeUndefined();
			expect(await env.PUBLIC_BUCKET.head(`${target.org}/main/${cold.hash}.narinfo`)).toBeNull();
			recordNixAccess(config, target.cache.id, hash);
			await expect.poll(async () => (await findPublishedPath(db, target.cache.id, hash))?.lastAccessedAt).not.toBeNull();
			const first = (await findPublishedPath(db, target.cache.id, hash))!.lastAccessedAt;
			recordNixAccess(config, target.cache.id, hash);
			await config.close();
			expect((await findPublishedPath(db, target.cache.id, hash))!.lastAccessedAt).toEqual(first);
		} finally { await config.close(); }
	});

	it("does not delete any victim when all remaining bytes are pinned", async () => {
		const target = await setup(8);
		const cold = await nix(target);
		const pinned = await nix(target, "2");
		await db.insert(uploadSessions).values({ id: crypto.randomUUID(), cacheId: target.cache.id, storePathHash: pinned.hash,
			storePath: pinned.row.storePath, narHash: pinned.row.narHash, narSize: 999, fileSize: 4, compression: "zstd",
			status: "finalizing", expiresAt: new Date(0) });
		await api(target.org, "", "PUT", { storageLimit: 4 });
		expect((await go(target, "a", "aaaa")).status).toBe(503);
		expect(await findPublishedPath(db, target.cache.id, cold.hash)).toBeDefined();
		expect(await env.PUBLIC_BUCKET.head(`${target.org}/main/${cold.hash}.narinfo`)).not.toBeNull();
		expect(await findPublishedPath(db, target.cache.id, pinned.hash)).toBeDefined();
	});

	it("rolls back an oversized protected Nix publication before withdrawing existing narinfos", async () => {
		const target = await setup(4);
		const cold = await nix(target);
		const config = resolveConfig(env);
		try {
			const hash = "3".repeat(32);
			await expect(withOrgCapacity(config, target.org, [{ cacheId: target.cache.id, storePathHash: hash }], async tx => {
				const blob = await createBlobObject(tx, { fileHash: crypto.randomUUID(), fileSize: 5, compression: "zstd", r2Key: crypto.randomUUID() });
				await createPublishedPath(tx, { cacheId: target.cache.id, storePathHash: hash, storePath: `/nix/store/${hash}-large`,
					narHash: "sha256:fixture", narSize: 999, blobObjectId: blob.id, referencesJson: "[]", signaturesJson: "[]", deriver: null, system: null });
			})).rejects.toMatchObject({ status: 413, retryable: false } satisfies Partial<CapacityError>);
			expect(await env.PUBLIC_BUCKET.head(`${target.org}/main/${cold.hash}.narinfo`)).not.toBeNull();
			expect(await findPublishedPath(db, target.cache.id, hash)).toBeUndefined();
		} finally { await config.close(); }
	});

	it("does not record failed authentication or missing Go reads", async () => {
		const target = await setup(4, true);
		expect((await go(target, "a", "aaaa")).status).toBe(201);
		expect((await go(target, "a", undefined, "GET", false)).status).toBe(401);
		expect((await go(target, "b")).status).toBe(404);
		const [entry] = await db.select().from(goEntries).where(eq(goEntries.cacheId, target.cache.id));
		expect(entry.lastAccessedAt).toBeNull();
	});

	it("orders Nix victims by the newer of push and observed use", async () => {
		const target = await setup(8);
		const hot = await nix(target);
		const cold = await nix(target, "2");
		await db.update(publishedPaths).set({ lastPushedAt: new Date(100) }).where(eq(publishedPaths.id, cold.row.id));
		const config = resolveConfig(env);
		recordNixAccess(config, target.cache.id, hot.hash);
		await config.close();
		expect((await go(target, "a", "aaaa")).status).toBe(201);
		expect(await findPublishedPath(db, target.cache.id, hot.hash)).toBeDefined();
		expect(await findPublishedPath(db, target.cache.id, cold.hash)).toBeUndefined();
	});

	it("fails retryably without deleting a partial batch when the victim budget is exhausted", async () => {
		const target = await setup(257);
		await db.insert(goEntries).values(Array.from({ length: 257 }, (_, i) => ({
			id: crypto.randomUUID(), cacheId: target.cache.id, generation: target.cache.goGeneration,
			action: i.toString(16).padStart(64, "0"), output: "0".repeat(64), r2Key: crypto.randomUUID(), size: 1,
			uploadedAt: new Date(0), expiresAt: new Date(Date.now() + 86400_000),
		})));
		await api(target.org, "", "PUT", { storageLimit: 1 });
		const response = await go(target, "f", "f");
		expect(response.status).toBe(503);
		expect(response.headers.get("retry-after")).toBe("1");
		expect((await db.select().from(goEntries).where(eq(goEntries.cacheId, target.cache.id))).filter(e => e.uploadedAt)).toHaveLength(257);
	});

	it("skips an in-flight locked Go victim instead of waiting or deleting it", async () => {
		const target = await setup(4);
		expect((await go(target, "a", "aaaa")).status).toBe(201);
		await db.transaction(async tx => {
			await tx.select().from(goEntries).where(eq(goEntries.cacheId, target.cache.id)).for("update");
			expect((await go(target, "b", "bbbb")).status).toBe(503);
		});
		expect((await go(target, "a")).status).toBe(200);
	});

	it.each(["pending", "uploading", "streaming"])("pins a Nix path with an active %s session", async status => {
		const target = await setup(4);
		const pinned = await nix(target);
		await db.insert(uploadSessions).values({ id: crypto.randomUUID(), cacheId: target.cache.id, storePathHash: pinned.hash,
			storePath: pinned.row.storePath, narHash: pinned.row.narHash, narSize: 999, fileSize: 4, compression: "zstd",
			status, expiresAt: new Date(Date.now() + 3600_000) });
		expect((await go(target, "a", "aaaa")).status).toBe(503);
		expect(await findPublishedPath(db, target.cache.id, pinned.hash)).toBeDefined();
		expect(await env.PUBLIC_BUCKET.head(`${target.org}/main/${pinned.hash}.narinfo`)).not.toBeNull();
	});

	it("always serializes publication, including unlimited organizations", async () => {
		const target = await setup(null);
		const config = resolveConfig(env);
		let publication: Promise<number> | undefined;
		try {
			await db.transaction(async tx => {
				await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + target.org}, 0))`);
				publication = withOrgCapacity(config, target.org, [], async () => 42);
				await expect.poll(async () => Number((await tx.execute(sql`select count(*) as n from pg_locks
					where locktype='advisory' and not granted`)).rows[0].n)).toBeGreaterThan(0);
			});
			expect(await publication).toBe(42);
		} finally { await publication; await config.close(); }
	});
});
