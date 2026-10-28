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
	expect((await orgApi(`/${org}`, OPERATOR, "PUT", { slug: org })).status).toBe(200);
	expect((await orgApi(`/${org}/caches`, OPERATOR, "POST", { name: cache, protocols: ["nix"] })).status).toBe(201);
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
		expect(JSON.stringify(keys)).not.toContain(key.slice("snowstead_key_".length + 17));
	});

	it("reach their own org's caches and storage", async () => {
		const { org, cache, key } = await orgWithKey();

		expect((await orgApi(`/${org}`, key)).status).toBe(200);
		const list = await orgApi(`/${org}/caches`, key);
		expect((await list.json<{ caches: { name: string }[] }>()).caches.map((c) => c.name)).toEqual([cache]);

		const created = await orgApi(`/${org}/caches`, key, "POST", { name: unique("cache"), protocols: ["nix"] });
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
		// A cache of the same name in its own org is its own.
		expect(await (await orgApi(`/${a.org}/caches`, a.key, "POST", { name: b.cache, protocols: ["nix"] })).json()).toMatchObject({ created: true, path: `${a.org}/${b.cache}` });
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
		const issued = await made.json<{ jti: string; org: string }>();
		expect(issued.org).toBe(a.org);
		const other = await orgApi(`/${b.org}/tokens`, b.key, "POST", { subject: "ci", caches: [b.cache], perms: ["push"] });
		const { jti } = await other.json<{ jti: string }>();

		const list = await orgApi(`/${a.org}/tokens`, a.key);
		expect((await list.json<{ tokens: { jti: string; org: string }[] }>()).tokens).toEqual([
			expect.objectContaining({ jti: issued.jti, org: a.org }),
		]);
		expect((await orgApi(`/${a.org}/tokens/${jti}/revoke`, a.key, "POST", { reason: "test" })).status).toBe(404);
		const theirs = await orgApi(`/${b.org}/tokens`, b.key);
		expect((await theirs.json<{ tokens: { jti: string; revokedAt: string | null }[] }>()).tokens).toEqual([
			expect.objectContaining({ jti, revokedAt: null }),
		]);
		// Nor can its tokens name another org's caches.
		const cross = await orgApi(`/${a.org}/tokens`, a.key, "POST", { subject: "ci", caches: [b.cache], perms: ["push"] });
		expect(cross.status).toBe(400);
	});
});

describe("unknown orgs", () => {
	it("answer 404 to the operator for missing or invalid orgs", async () => {
		expect((await orgApi(`/${unique("org")}/caches`, OPERATOR)).status).toBe(404);
		expect((await orgApi(`/not%20an%20org`, OPERATOR)).status).toBe(404);
	});
});

describe("org audit log", () => {
	type Entry = { id: number; actor: string; action: string; cache: string | null; status: number; detail: Record<string, unknown> };

	async function audit(org: string, credential: string, query = ""): Promise<{ entries: Entry[]; next: number | null }> {
		const res = await orgApi(`/${org}/audit${query}`, credential);
		expect(res.status).toBe(200);
		return res.json();
	}

	/** Audit writes finish after their response: wait until the log has caught up. */
	async function auditUntil(org: string, credential: string, done: (entries: Entry[]) => boolean): Promise<Entry[]> {
		for (let i = 0; i < 50; i++) {
			const { entries } = await audit(org, credential, "?limit=200");
			if (done(entries)) return entries;
			await new Promise((resolve) => setTimeout(resolve, 20));
		}
		throw new Error("audit log never caught up");
	}

	it("holds what happened in the org, by whom, and nothing of another org", async () => {
		const a = await orgWithKey();
		const b = await orgWithKey();
		const made = await orgApi(`/${a.org}/tokens`, a.key, "POST", { subject: "ci", caches: [a.cache], perms: ["push"] });
		const { token } = await made.json<{ token: string }>();
		await SELF.fetch("http://example.com/_api/v1/get-missing-paths", {
			method: "POST",
			headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
			body: JSON.stringify({ cache: a.cache, storePathHashes: ["0".repeat(32)] }),
		});

		const entries = await auditUntil(a.org, a.key, (e) => e.some((x) => x.action === "push"));
		expect(entries.map((e) => e.action)).toEqual(expect.arrayContaining(["key.create", "cache.create", "token.create", "push"]));
		expect(entries.find((e) => e.action === "token.create")?.actor).toBe(`key:${a.id}`);
		expect(entries.find((e) => e.action === "key.create")?.actor).toBe("admin");

		const theirs = await auditUntil(b.org, b.key, (e) => e.some((x) => x.action === "key.create"));
		expect(theirs.every((e) => e.action !== "token.create" && e.action !== "push")).toBe(true);
		expect((await orgApi(`/${b.org}/audit`, a.key)).status).toBe(403);
	});

	it("names the dashboard user the operator acts for, and believes no one else", async () => {
		const { org, key, id } = await orgWithKey();
		const as = (credential: string, name: string) =>
			SELF.fetch(`http://example.com/_api/v1/orgs/${org}/caches`, {
				method: "POST",
				headers: { authorization: `Bearer ${credential}`, "content-type": "application/json", "x-snowstead-actor": "dev@example.com" },
				body: JSON.stringify({ name, protocols: ["nix"] }),
			});
		const byUser = unique("cache");
		const byKey = unique("cache");
		expect((await as(OPERATOR, byUser)).status).toBe(201);
		expect((await as(key, byKey)).status).toBe(201);

		const entries = await auditUntil(org, key, (e) => e.filter((x) => x.action === "cache.create").length === 3);
		expect(entries.find((e) => e.cache === byUser)?.actor).toBe("user:dev@example.com");
		expect(entries.find((e) => e.cache === byKey)?.actor).toBe(`key:${id}`);
	});

	it("keeps who made and revoked each token", async () => {
		const { org, cache, key, id } = await orgWithKey();
		const asUser = (path: string, body: unknown) =>
			SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, {
				method: "POST",
				headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json", "x-snowstead-actor": "dev@example.com" },
				body: JSON.stringify(body),
			});
		const mine = await (await asUser("/tokens", { subject: "laptop", caches: [cache], perms: ["push"] })).json<{ jti: string }>();
		const theirs = await (await orgApi(`/${org}/tokens`, key, "POST", { subject: "ci", caches: [cache], perms: ["push"] })).json<{ jti: string }>();
		expect((await asUser(`/tokens/${theirs.jti}/revoke`, { reason: "left" })).status).toBe(200);

		const { tokens } = await (await orgApi(`/${org}/tokens`, key)).json<{ tokens: { jti: string; createdBy: string; revokedBy: string | null }[] }>();
		expect(tokens.find((t) => t.jti === mine.jti)).toMatchObject({ createdBy: "user:dev@example.com", revokedBy: null });
		expect(tokens.find((t) => t.jti === theirs.jti)).toMatchObject({ createdBy: `key:${id}`, revokedBy: "user:dev@example.com" });
	});

	it("names the caches, tokens, and keys it records, and never a secret", async () => {
		const { org, cache, id, key } = await orgWithKey();
		const made = await orgApi(`/${org}/tokens`, key, "POST", { subject: "ci", caches: [cache], perms: ["push"] });
		const { jti, token } = await made.json<{ jti: string; token: string }>();
		await orgApi(`/${org}/caches`, key, "POST", { name: cache, retentionDays: 14 });

		const entries = await auditUntil(org, key, (e) => e.filter((x) => x.action === "cache.create").length === 2);
		const [changed, created] = entries.filter((e) => e.action === "cache.create");
		expect(created).toMatchObject({ cache, status: 201, detail: { private: false, retentionDays: null } });
		expect(changed).toMatchObject({ cache, status: 200, detail: { private: false, retentionDays: 14 } });
		expect(entries.find((e) => e.action === "token.create")?.detail).toEqual({ jti, subject: "ci" });
		expect(entries.find((e) => e.action === "key.create")?.detail).toEqual({ key: id, name: "terraform" });
		expect(JSON.stringify(entries)).not.toContain(token);
		expect(JSON.stringify(entries)).not.toContain(key.slice(`snowstead_key_${id}_`.length));
	});

	it("pages newest first", async () => {
		const { org, key } = await orgWithKey();
		for (let i = 0; i < 3; i++) {
			await orgApi(`/${org}/caches`, key, "POST", { name: unique("cache"), protocols: ["nix"] });
		}
		const all = await auditUntil(org, key, (e) => e.filter((x) => x.action === "cache.create").length === 4);
		const ids = all.map((e) => e.id);
		expect(ids).toEqual([...ids].sort((a, b) => b - a));

		const first = await audit(org, key, "?limit=2");
		expect(first.entries.map((e) => e.id)).toEqual(all.slice(0, 2).map((e) => e.id));
		expect(first.next).toBe(first.entries[1].id);
		const second = await audit(org, key, `?limit=2&before=${first.next}`);
		expect(second.entries.map((e) => e.id)).toEqual(all.slice(2, 4).map((e) => e.id));
		expect(second.next).toBe(second.entries[1].id);
		const last = await audit(org, key, `?limit=200&before=${second.next}`);
		expect(last.entries.map((e) => e.id)).toEqual(ids.slice(4));
		expect(last.next).toBeNull();
	});

	it.each(["?limit=0", "?limit=1000", "?before=x"])("refuses %s", async (query) => {
		const { org, key } = await orgWithKey();
		expect((await orgApi(`/${org}/audit${query}`, key)).status).toBe(400);
	});
});
