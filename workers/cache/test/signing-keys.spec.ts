import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createBlobObject, createPublishedPath, findCacheByName } from "../src/db/repository.js";
import { computeFingerprint } from "../src/signing.js";
import { cacheKeyName } from "../src/cache-keys.js";

const db = testDb();

function admin(path: string, method = "GET", body?: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/admin${path}`, {
		method,
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

async function createdCache(): Promise<{ name: string; publicKey: string }> {
	const name = `keys-${crypto.randomUUID().slice(0, 8)}`;
	expect((await admin("/caches", "POST", { name })).status).toBe(201);
	const { publicKey } = await (await admin(`/caches/${name}`)).json<{ publicKey: string }>();
	return { name, publicKey };
}

/** Publishes a path straight to the database and backfills its narinfo; the backfill's answer. */
async function backfill(cacheName: string, hash: string): Promise<{ written: number; skipped: string[] }> {
	const cache = await findCacheByName(db, cacheName);
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
		storePath: `/nix/store/${hash}-signed`,
		narHash: `sha256:${"1".repeat(52)}`,
		narSize: 20,
		blobObjectId: blob.id,
		referencesJson: "[]",
		deriver: null,
		system: null,
		signaturesJson: "[]",
	});
	const res = await admin("/narinfo/backfill", "POST", { after: path.id - 1, limit: 1 });
	expect(res.status).toBe(200);
	return res.json();
}

async function publish(cacheName: string, hash: string): Promise<string> {
	expect(await backfill(cacheName, hash)).toMatchObject({ written: 1 });
	return (await SELF.fetch(`http://example.com/${cacheName}/${hash}.narinfo`)).text();
}

async function verifies(narinfo: string, publicKey: string, storePath: string): Promise<boolean> {
	const [keyName, keyBase64] = publicKey.split(":");
	const sig = narinfo.split("\n").find((line) => line.startsWith(`Sig: ${keyName}:`));
	if (!sig) return false;
	const signature = Uint8Array.from(atob(sig.slice(`Sig: ${keyName}:`.length)), (c) => c.charCodeAt(0));
	const key = await crypto.subtle.importKey("raw", Uint8Array.from(atob(keyBase64), (c) => c.charCodeAt(0)), "Ed25519", false, ["verify"]);
	const fingerprint = computeFingerprint({ storePath, narHash: `sha256:${"1".repeat(52)}`, narSize: 20 }, []);
	return crypto.subtle.verify("Ed25519", key, signature, new TextEncoder().encode(fingerprint));
}

describe("cache signing keys", () => {
	it("gives each new cache a key of its own", async () => {
		const a = await createdCache();
		const b = await createdCache();

		expect(a.publicKey).toMatch(new RegExp(`^${cacheKeyName(env.SIGNING_KEY_NAME, a.name)}:[A-Za-z0-9+/]{43}=$`));
		expect(a.publicKey.split(":")[1]).not.toBe(b.publicKey.split(":")[1]);
	});

	it("signs a cache's paths with its key, and only its key", async () => {
		const a = await createdCache();
		const b = await createdCache();
		const hash = "4".repeat(32);

		const narinfo = await publish(a.name, hash);
		expect(await verifies(narinfo, a.publicKey, `/nix/store/${hash}-signed`)).toBe(true);
		expect(await verifies(narinfo, b.publicKey, `/nix/store/${hash}-signed`)).toBe(false);
		expect(narinfo.match(/^Sig: /gm)).toHaveLength(1);
	});

	it("keeps only the sealed secret, bound to the cache", async () => {
		const { name } = await createdCache();
		const cache = await findCacheByName(db, name);

		expect(cache?.signingKeySealed).toMatch(/^v1:/);
		// Moved onto another cache, the sealed key doesn't open.
		const other = await createdCache();
		await db.execute(`update caches set signing_key_sealed = '${cache?.signingKeySealed}' where name = '${other.name}'`);
		const hash = "6".repeat(32);
		expect(await backfill(other.name, hash)).toMatchObject({ written: 0, skipped: [`${other.name}/${hash}`] });
	});

	it("leaves a cache from before keys on the service's key", async () => {
		const name = `old-${crypto.randomUUID().slice(0, 8)}`;
		await db.execute(`insert into caches (name) values ('${name}')`);
		const { publicKey } = await (await admin(`/caches/${name}`)).json<{ publicKey: string }>();
		expect(publicKey.split(":")[0]).toBe(env.SIGNING_KEY_NAME);

		const hash = "5".repeat(32);
		expect(await verifies(await publish(name, hash), publicKey, `/nix/store/${hash}-signed`)).toBe(true);
	});
});
