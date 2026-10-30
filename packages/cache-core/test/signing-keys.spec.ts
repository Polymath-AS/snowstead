import { env, SELF, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { eq } from "drizzle-orm";
import { describe, it, expect } from "vitest";
import { testDb } from "./db.js";
import { createCache, createBlobObject, createPublishedPath, findCache } from "../src/db/repository.js";
import { caches, cacheSigningKeys } from "../src/db/schema.js";
import worker from "../../../workers/control/src/index.js";

const db = testDb();

async function admin(path: string, method = "GET", body?: unknown, overrides?: Partial<Env>): Promise<Response> {
	const request = new Request(`http://example.com/_api/v1/admin${path}`, {
		method,
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
	if (!overrides) return SELF.fetch(request);
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, { ...env, ...overrides }, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function createdCache(): Promise<{ name: string; publicKey: string }> {
	const name = `keys-${crypto.randomUUID().slice(0, 8)}`;
	expect((await admin("/caches", "POST", { name, protocols: ["nix"] })).status).toBe(201);
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
async function backfill(cacheName: string, hash: string, overrides?: Record<string, string>): Promise<{ written: number; skipped: string[] }> {
	const cache = await findCache(db, "default", cacheName);
	if (!cache) throw new Error(`no cache ${cacheName}`);
	const body = crypto.getRandomValues(new Uint8Array(10));
	const fileHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", body)), byte => byte.toString(16).padStart(2, "0")).join("");
	const blob = await createBlobObject(db, {
		fileHash,
		fileSize: body.byteLength,
		compression: "zstd",
		r2Key: `nars/${crypto.randomUUID()}`,
	});
	await env.CACHE_BUCKET.put(blob.r2Key, body);
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
	const res = await admin("/narinfo/backfill", "POST", { after: path.id - 1, limit: 1 }, overrides);
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
	const fingerprint = `1;${storePath};sha256:${"1".repeat(52)};20;`;
	return crypto.subtle.verify("Ed25519", key, signature, new TextEncoder().encode(fingerprint));
}

describe("cache signing keys", () => {
	it("uses the Secrets Store for hosted creation and retries a failed read without falling back", async () => {
		let available = false;
		const overrides = {
			...env,
			SIGNING_MASTER_KEY: "invalid-fallback",
			REQUIRE_CACHE_SIGNING_KEYS: "true",
			SIGNING_MASTER_KEY_STORE: { get: async () => {
				if (!available) throw new Error("store unavailable");
				return env.SIGNING_MASTER_KEY;
			} },
		};
		const name = `store-${crypto.randomUUID().slice(0, 8)}`;
		const request = () => new Request("http://example.com/_api/v1/admin/caches", {
			method: "POST", headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
			body: JSON.stringify({ name, protocols: ["nix"] }),
		});
		async function create() {
			const ctx = createExecutionContext();
			const response = await worker.fetch(request(), overrides, ctx);
			await waitOnExecutionContext(ctx);
			return response;
		}
		expect((await create()).status).toBe(500);
		expect(await findCache(db, "default", name)).toBeUndefined();
		available = true;
		expect((await create()).status).toBe(201);
		const cache = await findCache(db, "default", name);
		expect(cache?.signingPublicKey).toMatch(/^snowstead-1-/);
		expect(await backfill(name, "s".repeat(32), { SIGNING_MASTER_KEY: env.SIGNING_MASTER_KEY })).toMatchObject({ written: 1 });
	});

	it("authorizes signing management only within the API key's org and never audits imported secrets", async () => {
		async function org() {
			const name = `org-${crypto.randomUUID().slice(0, 8)}`;
			const call = (path: string, method: string, body: unknown) => SELF.fetch(`http://example.com/_api/v1/orgs/${name}${path}`, {
				method, headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" }, body: JSON.stringify(body),
			});
			expect((await call("", "PUT", { slug: name, customSigningKeys: true })).status).toBe(200);
			expect((await call("/caches", "POST", { name: "main", protocols: ["nix"] })).status).toBe(201);
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
		expect(audit).toContain(imported.publicKey);
		expect(audit).not.toContain(imported.secret.split(":")[1]);
	});

	it("enforces operator-granted BYOK permission on import and activation, without disabling active keys on downgrade", async () => {
		const a = await createdCache();
		const imported = await nixSecret();
		const staged = await (await keysApi(a.name, "POST", { secretKey: imported.secret })).json<{ id: string }>();
		const trusted = [a.publicKey, imported.publicKey];
		const previous = await (await SELF.fetch("http://example.com/_api/v1/orgs/default", { headers: { authorization: "Bearer test-admin-secret" } })).json<{ customSigningKeys: boolean }>();
		const terms = (customSigningKeys: boolean) => SELF.fetch("http://example.com/_api/v1/orgs/default", {
			method: "PUT", headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
			body: JSON.stringify({ customSigningKeys }),
		});
		try {
			expect((await terms(false)).status).toBe(200);
			expect((await keysApi(a.name, "POST", { secretKey: imported.secret })).status).toBe(403);
			expect((await keysApi(a.name, "POST", { trustedPublicKeys: trusted }, `/${staged.id}/activate`)).status).toBe(403);
			expect((await terms(true)).status).toBe(200);
			expect((await keysApi(a.name, "POST", { trustedPublicKeys: trusted }, `/${staged.id}/activate`)).status).toBe(200);
			expect((await terms(false)).status).toBe(200);
			const hash = "2".repeat(32);
			expect(await verifies(await publish(a.name, hash), imported.publicKey, `/nix/store/${hash}-signed`)).toBe(true);
			const managed = await keysApi(a.name, "POST", {});
			expect(managed.status).toBe(201);
			const next = await managed.json<{ id: string; publicKey: string }>();
			expect((await keysApi(a.name, "POST", { trustedPublicKeys: [...trusted, next.publicKey] }, `/${next.id}/activate`)).status).toBe(200);
		} finally {
			await terms(previous.customSigningKeys);
		}
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

		expect(a.publicKey.split(":")[0]).not.toBe(b.publicKey.split(":")[0]);
		expect(a.publicKey.split(":")[1]).toMatch(/^[A-Za-z0-9+/]{43}=$/);
		expect(a.publicKey.split(":")[1]).not.toBe(b.publicKey.split(":")[1]);
		const history = await (await keysApi(a.name)).json<{ keys: { id: string; state: string; publicKey: string }[] }>();
		expect(history.keys).toEqual([{ id: expect.any(String), state: "active", publicKey: a.publicKey, createdAt: expect.any(String) }]);
		const other = await findCache(db, "default", b.name);
		await expect(db.insert(cacheSigningKeys).values({
			id: crypto.randomUUID(), cacheId: other!.id, signingKeyName: "different-name", signingPublicKey: `different-name:${a.publicKey.split(":")[1]}`,
			managedPublicKey: a.publicKey.split(":")[1],
		})).rejects.toThrow();
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

		expect(cache?.signingKeySealed).toMatch(/^v2:/);
		// Moved onto another cache, the sealed key doesn't open.
		const other = await createdCache();
		await db.execute(`update caches set signing_key_sealed = '${cache?.signingKeySealed}' where name = '${other.name}'`);
		const hash = "6".repeat(32);
		expect(await backfill(other.name, hash)).toMatchObject({ written: 0, skipped: [`${other.name}/${hash}`] });
	});

	it("continues signing with an existing v1 sealed key without changing client trust", async () => {
		const a = await createdCache();
		const cache = (await findCache(db, "default", a.name))!;
		const imported = await nixSecret();
		const master = await crypto.subtle.importKey("raw", Uint8Array.from(atob(env.SIGNING_MASTER_KEY), c => c.charCodeAt(0)), "AES-GCM", false, ["encrypt"]);
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(`cache:${cache.id}`) }, master,
			Uint8Array.from(atob(imported.secret.split(":")[1]), c => c.charCodeAt(0)));
		const box = new Uint8Array(iv.length + encrypted.byteLength);
		box.set(iv); box.set(new Uint8Array(encrypted), iv.length);
		await db.update(caches).set({
			signingKeyName: imported.publicKey.split(":")[0], signingPublicKey: imported.publicKey,
			signingKeySealed: `v1:${btoa(String.fromCharCode(...box))}`,
		}).where(eq(caches.id, cache.id));
		const hash = "h".repeat(32);
		const narinfo = await publish(a.name, hash);
		expect(await verifies(narinfo, imported.publicKey, `/nix/store/${hash}-signed`)).toBe(true);
		expect((await (await admin(`/caches/${a.name}`)).json<{ publicKey: string }>()).publicKey).toBe(imported.publicKey);
	});

	it("rejects altered key identity and ciphertext even after warming the signer, and restores from a sealed backup", async () => {
		const a = await createdCache();
		const cache = (await findCache(db, "default", a.name))!;
		const backup = { signingKeyName: cache.signingKeyName, signingPublicKey: cache.signingPublicKey, signingKeySealed: cache.signingKeySealed };
		expect(await verifies(await publish(a.name, "b".repeat(32)), a.publicKey, `/nix/store/${"b".repeat(32)}-signed`)).toBe(true);
		const sealed = cache.signingKeySealed!;
		const changes = [
			{ signingKeyName: "substituted" },
			{ signingPublicKey: (await nixSecret()).publicKey },
			{ signingKeySealed: sealed.replace(sealed.split(":")[1], crypto.randomUUID()) },
			{ signingKeySealed: sealed.slice(0, -8) + "AAAAAAAA" },
			{ signingKeySealed: null },
		];
		for (const [i, change] of changes.entries()) {
			await db.update(caches).set({ ...backup, ...change }).where(eq(caches.id, cache.id));
			const hash = String(i + 1).repeat(32);
			expect(await backfill(a.name, hash)).toMatchObject({ written: 0, skipped: [`${a.name}/${hash}`] });
			expect(await env.PUBLIC_BUCKET.head(`${a.name}/${hash}.narinfo`)).toBeNull();
		}
		await db.update(caches).set(backup).where(eq(caches.id, cache.id));
		expect(await backfill(a.name, "7".repeat(32), {})).toMatchObject({ written: 1 });
		expect(await backfill(a.name, "c".repeat(32), { SIGNING_MASTER_KEY: btoa("x".repeat(32)) })).toMatchObject({ written: 0 });
		expect(await backfill(a.name, "8".repeat(32), {})).toMatchObject({ written: 1 });
		expect(await verifies(await publish(a.name, "d".repeat(32)), a.publicKey, `/nix/store/${"d".repeat(32)}-signed`)).toBe(true);
	});

	it("requires per-cache keys in hosted mode and rolls back creation when sealing fails", async () => {
		const name = `hosted-${crypto.randomUUID().slice(0, 8)}`;
		const hosted = { REQUIRE_CACHE_SIGNING_KEYS: "true", SIGNING_MASTER_KEY: "" };
		expect((await admin("/caches", "POST", { name, protocols: ["nix"] }, hosted)).status).toBe(503);
		expect(await findCache(db, "default", name)).toBeUndefined();
		expect((await admin("/caches", "POST", { name, protocols: ["nix"] }, { ...hosted, SIGNING_MASTER_KEY: "invalid" })).status).toBe(500);
		expect(await findCache(db, "default", name)).toBeUndefined();
		expect((await admin("/caches", "POST", { name, protocols: ["nix"] }, { REQUIRE_CACHE_SIGNING_KEYS: "true" })).status).toBe(201);
		const publicKey = (await (await admin(`/caches/${name}`)).json<{ publicKey: string }>()).publicKey;
		const hash = "f".repeat(32);
		expect(await backfill(name, hash, { REQUIRE_CACHE_SIGNING_KEYS: "true" })).toMatchObject({ written: 1 });
		const narinfo = await (await env.PUBLIC_BUCKET.get(`${name}/${hash}.narinfo`))!.text();
		expect(await verifies(narinfo, publicKey, `/nix/store/${hash}-signed`)).toBe(true);
		const old = `old-${crypto.randomUUID().slice(0, 8)}`;
		await createCache(db, old);
		expect(await backfill(old, "g".repeat(32), { REQUIRE_CACHE_SIGNING_KEYS: "true" })).toMatchObject({ written: 0 });
	});

	it("leaves a cache from before keys on the service's key", async () => {
		const name = `old-${crypto.randomUUID().slice(0, 8)}`;
		await createCache(db, name);
		const { publicKey } = await (await admin(`/caches/${name}`)).json<{ publicKey: string }>();
		expect(publicKey.split(":")[0]).toBe(env.SIGNING_KEY_NAME);

		const hash = "5".repeat(32);
		expect(await verifies(await publish(name, hash), publicKey, `/nix/store/${hash}-signed`)).toBe(true);
	});

	it("moves a cache from before keys onto a key of its own", async () => {
		const name = `old-${crypto.randomUUID().slice(0, 8)}`;
		await createCache(db, name);
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
