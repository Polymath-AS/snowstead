import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

const unique = (prefix: string) => `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
const OPERATOR = "test-admin-secret";

function orgApi(path: string, credential: string, method = "GET", body?: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/orgs${path}`, {
		method,
		headers: { authorization: `Bearer ${credential}`, "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

/** An org with a cache and an API key, set up by the operator. */
async function orgWithKey() {
	const org = unique("org");
	const cache = unique("cache");
	expect((await orgApi(`/${org}`, OPERATOR, "PUT", { storageLimit: null })).status).toBe(200);
	expect((await orgApi(`/${org}/caches`, OPERATOR, "POST", { name: cache })).status).toBe(201);
	const res = await orgApi(`/${org}/keys`, OPERATOR, "POST", { name: "terraform" });
	expect(res.status).toBe(201);
	const { id, key } = await res.json<{ id: string; key: string }>();
	return { org, cache, id, key };
}

describe("org API keys", () => {
	it("are shown once and listed without their secret", async () => {
		const { org, id, key } = await orgWithKey();
		expect(key).toMatch(/^snowstead_key_[a-z0-9]{16}_[A-Za-z0-9_-]{43}$/);

		const res = await orgApi(`/${org}/keys`, key);
		const { keys } = await res.json<{ keys: Record<string, unknown>[] }>();
		expect(keys).toEqual([{ id, name: "terraform", createdAt: expect.any(String), revokedAt: null }]);
		expect(JSON.stringify(keys)).not.toContain(key.split("_").at(-1));
	});

	it("reach their own org's caches and storage", async () => {
		const { org, cache, key } = await orgWithKey();

		expect((await orgApi(`/${org}`, key)).status).toBe(200);
		const list = await orgApi(`/${org}/caches`, key);
		expect((await list.json<{ caches: { name: string }[] }>()).caches.map((c) => c.name)).toEqual([cache]);

		const created = await orgApi(`/${org}/caches`, key, "POST", { name: unique("cache") });
		expect(await created.json()).toMatchObject({ created: true });
	});

	it("can't reach another org, even naming it", async () => {
		const a = await orgWithKey();
		const b = await orgWithKey();

		for (const path of [`/${b.org}`, `/${b.org}/caches`, `/${b.org}/tokens`, `/${b.org}/keys`, `/${b.org}/caches/${b.cache}`]) {
			expect((await orgApi(path, a.key)).status, path).toBe(403);
		}
		// Through its own org, another org's cache is missing.
		expect((await orgApi(`/${a.org}/caches/${b.cache}`, a.key)).status).toBe(404);
		const del = await orgApi(`/${a.org}/caches/${b.cache}/paths/delete`, a.key, "POST", { before: new Date().toISOString() });
		expect(del.status).toBe(404);
		// Nor can it take the name.
		expect((await orgApi(`/${a.org}/caches`, a.key, "POST", { name: b.cache })).status).toBe(409);
	});

	it("can't set the storage limit or make keys", async () => {
		const { org, key } = await orgWithKey();

		expect((await orgApi(`/${org}`, key, "PUT", { storageLimit: null })).status).toBe(403);
		expect((await orgApi(`/${org}/keys`, key, "POST", { name: "another" })).status).toBe(403);
	});

	it("stop working once revoked, and revoking again is fine", async () => {
		const { org, id, key } = await orgWithKey();

		expect((await orgApi(`/${org}/keys/${id}/revoke`, key, "POST")).status).toBe(200);
		expect((await orgApi(`/${org}`, key)).status).toBe(403);
		expect((await orgApi(`/${org}/keys/${id}/revoke`, OPERATOR, "POST")).status).toBe(200);
	});

	it("can't revoke another org's key", async () => {
		const a = await orgWithKey();
		const b = await orgWithKey();

		expect((await orgApi(`/${a.org}/keys/${b.id}/revoke`, a.key, "POST")).status).toBe(404);
		expect((await orgApi(`/${b.org}`, b.key)).status).toBe(200);
	});

	it.each([
		["no key", ""],
		["the push token secret", "test-auth-token"],
		["a made-up key", "snowstead_key_aaaaaaaaaaaaaaaa_bm90LWEtcmVhbC1zZWNyZXQ"],
	])("refuse %s", async (_label, credential) => {
		const { org } = await orgWithKey();
		expect([401, 403]).toContain((await orgApi(`/${org}`, credential)).status);
	});

	it("refuse a key with the right id and the wrong secret", async () => {
		const { org, key } = await orgWithKey();
		const wrong = key.slice(0, -4) + (key.endsWith("AAAA") ? "BBBB" : "AAAA");
		expect((await orgApi(`/${org}`, wrong)).status).toBe(403);
	});
});

describe("org tokens through the org API", () => {
	it("are the org's, and another org's can't be revoked through it", async () => {
		const a = await orgWithKey();
		const b = await orgWithKey();

		const made = await orgApi(`/${a.org}/tokens`, a.key, "POST", { subject: "ci", caches: [a.cache], perms: ["push"] });
		expect(await made.json()).toMatchObject({ org: a.org });
		const other = await orgApi(`/${b.org}/tokens`, b.key, "POST", { subject: "ci", caches: [b.cache], perms: ["push"] });
		const { jti } = await other.json<{ jti: string }>();

		const list = await orgApi(`/${a.org}/tokens`, a.key);
		expect((await list.json<{ tokens: { org: string }[] }>()).tokens.every((t) => t.org === a.org)).toBe(true);
		expect((await orgApi(`/${a.org}/tokens/${jti}/revoke`, a.key, "POST", { reason: "test" })).status).toBe(404);
		// Nor can its tokens name another org's caches.
		const cross = await orgApi(`/${a.org}/tokens`, a.key, "POST", { subject: "ci", caches: [b.cache], perms: ["push"] });
		expect(cross.status).toBe(400);
	});
});

describe("unknown orgs", () => {
	it("answer 404 to the operator and refuse keys", async () => {
		expect((await orgApi(`/${unique("org")}/caches`, OPERATOR)).status).toBe(404);
		expect((await orgApi(`/not%20an%20org`, OPERATOR)).status).toBe(404);
	});
});
