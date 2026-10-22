import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createBlobObject, createPublishedPath, findCache } from "../src/db/repository.js";
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

function keysApi(name: string, method = "GET", body?: unknown, suffix = "", org = "default", token = "test-admin-secret"): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/orgs/${org}/caches/${name}/signing-keys${suffix}`, {
		method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

async function nixSecret(): Promise<{ secret: string; publicKey: string }> {
	const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
	const seed = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)).slice(-32);
	const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	const bytes = new Uint8Array(64); bytes.set(seed); bytes.set(pub, 32);
	const name = `byok-${crypto.randomUUID()}`;
	return { secret: `${name}:${btoa(String.fromCharCode(...bytes))}`, publicKey: `${name}:${btoa(String.fromCharCode(...pub))}` };
}

/** Publishes a path straight to the database and backfills its narinfo; the backfill's answer. */
async function backfill(cacheName: string, hash: string): Promise<{ written: number; skipped: string[] }> {
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
	it("authorizes signing management only within the API key's org and never audits imported secrets", async () => {
		async function org() {
			const name = `org-${crypto.randomUUID().slice(0, 8)}`;
			const call = (path: string, method: string, body: unknown) => SELF.fetch(`http://example.com/_api/v1/orgs/${name}${path}`, {
				method, headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" }, body: JSON.stringify(body),
			});
			expect((await call("", "PUT", { slug: name, storageLimit: null })).status).toBe(200);
			expect((await call("/caches", "POST", { name: "main" })).status).toBe(201);
			const { key } = await (await call("/keys", "POST", { name: "test" })).json<{ key: string }>();
			return { name, key };
		}
		const a = await org(); const b = await org();
		const imported = await nixSecret();
		const staged = await keysApi("main", "POST", { secretKey: imported.secret }, "", a.name, a.key);
		expect(staged.status).toBe(201);
		const { id } = await staged.json<{ id: string }>();
		for (const [method, body, suffix] of [["GET", undefined, ""], ["POST", {}, ""], ["POST", {}, `/${id}/activate`]] as const) {
			expect((await keysApi("main", method, body, suffix, b.name, a.key)).status).toBe(403);
		}
		expect((await keysApi("main", "POST", {}, `/${id}/activate`, b.name, b.key)).status).toBe(404);
		const text = await (await keysApi("main", "GET", undefined, "", a.name, a.key)).text();
		expect(text).toContain(imported.publicKey);
		expect(text).not.toContain(imported.secret.split(":")[1]);
		const audit = await (await SELF.fetch(`http://example.com/_api/v1/orgs/${a.name}/audit`, { headers: { authorization: `Bearer ${a.key}` } })).text();
		expect(audit).toContain("signing-key.stage");
		expect(audit).not.toContain(imported.secret.split(":")[1]);
	});

	it("imports sealed BYOK, stages trust overlap, and rotates a previously cached signing key without rewriting old narinfo", async () => {
		const a = await createdCache();
		const b = await createdCache();
		const oldHash = "7".repeat(32);
		const old = await publish(a.name, oldHash);
		const imported = await nixSecret();
		const staged = await keysApi(a.name, "POST", { secretKey: imported.secret });
		expect(staged.status).toBe(201);
		const key = await staged.json<{ id: string; publicKey: string; state: string }>();
		expect(key).toMatchObject({ publicKey: imported.publicKey, state: "staged" });
		expect(JSON.stringify(key)).not.toContain(imported.secret);
		expect((await keysApi(a.name, "POST", { secretKey: imported.secret })).status).toBe(409);
		expect((await keysApi(b.name, "POST", { trustedPublicKeys: [a.publicKey, key.publicKey] }, `/${key.id}/activate`)).status).toBe(404);
		expect((await keysApi(a.name, "POST", {}, `/${key.id}/activate`)).status).toBe(409);
		expect(await verifies(await publish(a.name, "8".repeat(32)), a.publicKey, `/nix/store/${"8".repeat(32)}-signed`)).toBe(true);
		expect((await keysApi(a.name, "POST", { trustedPublicKeys: [a.publicKey, key.publicKey] }, `/${key.id}/activate`)).status).toBe(200);
		const hash = "9".repeat(32);
		const fresh = await publish(a.name, hash);
		expect(await verifies(fresh, key.publicKey, `/nix/store/${hash}-signed`)).toBe(true);
		expect(await verifies(fresh, a.publicKey, `/nix/store/${hash}-signed`)).toBe(false);
		expect(await (await SELF.fetch(`http://example.com/${a.name}/${oldHash}.narinfo`)).text()).toBe(old);
		const status = await (await keysApi(a.name)).json<{ keys: { publicKey: string; state: string }[] }>();
		expect(status.keys).toEqual(expect.arrayContaining([
			expect.objectContaining({ publicKey: a.publicKey, state: "retired" }),
			expect.objectContaining({ publicKey: key.publicKey, state: "active" }),
		]));
		const next = await (await keysApi(a.name, "POST", {})).json<{ id: string; publicKey: string }>();
		expect((await keysApi(a.name, "POST", { trustedPublicKeys: [...status.keys.map(k => k.publicKey), next.publicKey] }, `/${next.id}/activate`)).status).toBe(200);
		const nextHash = "a".repeat(32);
		expect(await verifies(await publish(a.name, nextHash), next.publicKey, `/nix/store/${nextHash}-signed`)).toBe(true);
		expect((await keysApi(a.name, "POST", { trustedPublicKeys: [] }, `/${key.id}/activate`)).status).toBe(409);
	});

	it("rejects malformed keys and mismatched seed/public halves without echoing secrets", async () => {
		const a = await createdCache();
		const one = await nixSecret();
		const two = await nixSecret();
		const bytes = atob(one.secret.split(":")[1]).slice(0, 32) + atob(two.secret.split(":")[1]).slice(32);
		for (const secretKey of ["bad", "name:" + btoa("x".repeat(32)), "name:" + btoa(bytes), one.secret + "\n", 1]) {
			const res = await keysApi(a.name, "POST", { secretKey });
			expect(res.status).toBe(400);
			expect(await res.text()).toContain("invalid Nix secret key");
		}
		expect((await keysApi(a.name, "POST", {}, "", "default", "wrong")).status).toBe(403);
	});
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
		const cache = await findCache(db, "default", name);

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

	it("moves a cache from before keys onto a key of its own", async () => {
		const name = `old-${crypto.randomUUID().slice(0, 8)}`;
		await db.execute(`insert into caches (name) values ('${name}')`);
		const before = await (await keysApi(name)).json<{ shared: boolean; activePublicKey: string }>();
		expect(before.shared).toBe(true);

		const staged = await (await keysApi(name, "POST", {})).json<{ id: string; publicKey: string }>();
		const trusted = [before.activePublicKey, staged.publicKey];
		expect((await keysApi(name, "POST", { trustedPublicKeys: trusted }, `/${staged.id}/activate`)).status).toBe(200);

		const after = await (await keysApi(name)).json<{ shared: boolean; activePublicKey: string; keys: { publicKey: string; state: string }[] }>();
		expect(after).toMatchObject({ shared: false, activePublicKey: staged.publicKey });
		expect(after.keys).toEqual(expect.arrayContaining([expect.objectContaining({ publicKey: before.activePublicKey, state: "retired" })]));
		const hash = "6".repeat(32);
		expect(await verifies(await publish(name, hash), staged.publicKey, `/nix/store/${hash}-signed`)).toBe(true);
	});
});
