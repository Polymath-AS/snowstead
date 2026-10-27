import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createCache, createBlobObject, createPublishedPath, ensureCache } from "../src/db/repository.js";
import { orgs, uploadSessions, apiTokens, orgApiKeys, bandwidthDaily } from "../src/db/schema.js";
import { signingPublicKey } from "../src/signing.js";

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

describe("admin cache stats", () => {
	it("reports only aggregate global usage to the operator, distinguishing shared bytes and live uploads", async () => {
		expect((await admin("/overview", {}, "test-auth-token")).status).toBe(403);
		const before = await (await admin("/overview")).json<Record<string, number>>();
		const org = `overview-${crypto.randomUUID()}`;
		await db.insert(orgs).values({ id: org, slug: org });
		const a = await createCache(db, `overview-${crypto.randomUUID().slice(0, 8)}`);
		const { cache: b } = await ensureCache(db, a.name, true, org);
		const blob = await createBlobObject(db, { fileHash: crypto.randomUUID(), fileSize: 400, compression: "zstd", r2Key: crypto.randomUUID() });
		for (const cache of [a, b]) await createPublishedPath(db, {
			cacheId: cache.id, storePathHash: "2".repeat(32), storePath: `/nix/store/${"2".repeat(32)}-private-name`,
			narHash: `sha256:${"1".repeat(52)}`, narSize: 900, blobObjectId: blob.id,
			referencesJson: "[]", deriver: null, system: null, signaturesJson: "[]",
		});
		const now = new Date();
		const future = new Date(now.getTime() + 3_600_000);
		const past = new Date(now.getTime() - 3_600_000);
		for (const [status, size, expiresAt] of [["pending", 111, future], ["uploading", 222, future], ["pending", 444, past], ["completed", 888, future]] as const) {
			await db.insert(uploadSessions).values({ id: crypto.randomUUID(), cacheId: a.id, storePathHash: crypto.randomUUID(), storePath: "private-path",
				narHash: "hash", narSize: size, fileHash: crypto.randomUUID(), fileSize: size, compression: "zstd", status, expiresAt });
		}
		for (const [expiresAt, revokedAt] of [[future, null], [past, null], [future, now]]) {
			await db.insert(apiTokens).values({ jti: crypto.randomUUID(), subject: "hidden-person", caches: ["*"], permsJson: '["push"]', expiresAt, revokedAt, createdBy: "admin" });
		}
		for (const revokedAt of [null, now]) await db.insert(orgApiKeys).values({ id: crypto.randomUUID(), orgId: org, name: "hidden-key", secretHash: "hidden-secret", revokedAt });
		await db.insert(bandwidthDaily).values({ orgId: org, day: now.toISOString().slice(0, 10), bytes: 1234 });
		await db.insert(bandwidthDaily).values({ orgId: org, day: "2000-01-01", bytes: 9999 });
		const response = await admin("/overview");
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(await response.json()).toEqual({
			orgs: before.orgs + 1, caches: before.caches + 2, paths: before.paths + 2,
			storedBytes: before.storedBytes + 800, physicalStoredBytes: before.physicalStoredBytes + 400,
			pendingBytes: before.pendingBytes + 333, uploadsPending: before.uploadsPending + 2,
			privateServedThisMonth: before.privateServedThisMonth + 1234, activeTokens: before.activeTokens + 1, apiKeys: before.apiKeys + 1,
		});
	});

	it("counts a cache's paths and lists the newest", async () => {
		const cache = await createCache(db, `stats-${crypto.randomUUID().slice(0, 8)}`);
		const blob = await createBlobObject(db, {
			fileHash: crypto.randomUUID().replaceAll("-", "").padEnd(64, "0"),
			fileSize: 300,
			compression: "zstd",
			r2Key: `nars/${crypto.randomUUID()}`,
		});
		for (const [hash, label] of [["2".repeat(32), "older"], ["3".repeat(32), "newer"]]) {
			await createPublishedPath(db, {
				cacheId: cache.id,
				storePathHash: hash,
				storePath: `/nix/store/${hash}-${label}`,
				narHash: `sha256:${"1".repeat(52)}`,
				narSize: 900,
				blobObjectId: blob.id,
				referencesJson: "[]",
				deriver: null,
				system: null,
				signaturesJson: "[]",
			});
		}

		const list = await admin("/caches");
		const { caches } = await list.json<{ caches: { name: string; paths: number; size: number; addedLastWeek: number }[] }>();
		expect(caches.find((c) => c.name === cache.name)).toMatchObject({ paths: 2, size: 600, addedLastWeek: 2 });

		const res = await admin(`/caches/${cache.name}`);
		expect(res.status).toBe(200);
		const detail = await res.json<{ paths: number; publicKey: string | null; recentPaths: { storePath: string; size: number }[] }>();
		expect(detail.paths).toBe(2);
		expect(detail.recentPaths.map((p) => p.storePath)).toEqual([`/nix/store/${"3".repeat(32)}-newer`, `/nix/store/${"2".repeat(32)}-older`]);
		expect(detail.recentPaths[0].size).toBe(300);
	});

	it("counts an empty cache as zero", async () => {
		const name = `empty-${crypto.randomUUID().slice(0, 8)}`;
		await createCache(db, name);
		const res = await admin(`/caches/${name}`);
		expect(await res.json()).toMatchObject({ name, paths: 0, size: 0, lastAddedAt: null, recentPaths: [] });
	});

	it("answers 404 for a cache that doesn't exist", async () => {
		const res = await admin("/caches/no-such-cache");
		expect(res.status).toBe(404);
	});
});

describe("signing public key", () => {
	it("matches the key Nix derives, from a full secret key and from a seed", async () => {
		const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
		const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
		const seed = pkcs8.slice(pkcs8.length - 32);
		const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
		const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
		const expected = `test-1:${b64(pub)}`;

		expect(await signingPublicKey("test-1", b64(new Uint8Array([...seed, ...pub])))).toBe(expected);
		expect(await signingPublicKey("test-1", b64(seed))).toBe(expected);
		expect(await signingPublicKey("test-1", "")).toBeNull();
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
		await env.CACHE_BUCKET.put(blob.r2Key, new Uint8Array(10));
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
