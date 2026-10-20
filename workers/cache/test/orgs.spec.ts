import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { signJwt, TOKEN_ISSUER, TOKEN_AUDIENCE } from "../src/jwt.js";

const unique = (prefix: string) => `${prefix}-${crypto.randomUUID().slice(0, 8)}`;

function admin(path: string, method = "GET", body?: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/admin${path}`, {
		method,
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

/** The org API, as the operator. */
function orgApi(path: string, method = "GET", body?: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/orgs${path}`, {
		method,
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

function createSessions(cache: string, sizes: number[], token = "test-auth-token"): Promise<Response> {
	const paths = sizes.map((fileSize) => {
		const hash = crypto.randomUUID().replaceAll("-", "").slice(0, 32).replace(/[eotu]/g, "a");
		return {
			storePath: `/nix/store/${hash}-hello`,
			storePathHash: hash,
			narHash: `sha256:${"1".repeat(52)}`,
			narSize: fileSize,
			fileHash: crypto.randomUUID().replaceAll("-", "").padEnd(64, "0"),
			fileSize,
			compression: "zstd",
		};
	});
	return SELF.fetch(`http://example.com/_api/v1/caches/${cache}/upload-sessions/batch`, {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify({ paths }),
	});
}

async function orgWithCache(storageLimit: number | null) {
	const org = unique("org");
	const cache = unique("cache");
	expect((await orgApi(`/${org}`, "PUT", { storageLimit })).status).toBe(200);
	expect((await admin("/caches", "POST", { name: cache, org })).status).toBe(201);
	return { org, cache };
}

describe("orgs", () => {
	it("creates an org, changes its limit, and reports its usage", async () => {
		const org = unique("org");
		expect((await orgApi(`/${org}`)).status).toBe(404);

		const created = await orgApi(`/${org}`, "PUT", { storageLimit: 1000 });
		expect(await created.json()).toEqual({ id: org, storageLimit: 1000, used: 0, pending: 0 });

		const raised = await orgApi(`/${org}`, "PUT", { storageLimit: null });
		expect(await raised.json()).toMatchObject({ storageLimit: null });
	});

	it.each([-1, 1.5, "10GB"])("rejects a limit of %s", async (storageLimit) => {
		expect((await orgApi(`/${unique("org")}`, "PUT", { storageLimit })).status).toBe(400);
	});

	it("lists only an org's caches", async () => {
		const a = await orgWithCache(null);
		const b = await orgWithCache(null);

		const res = await admin(`/caches?org=${a.org}`);
		const { caches } = await res.json<{ caches: { name: string; org: string }[] }>();
		expect(caches).toEqual([expect.objectContaining({ name: a.cache, org: a.org })]);
		expect(caches.map((c) => c.name)).not.toContain(b.cache);
	});

	it("won't hand one org's cache name to another", async () => {
		const a = await orgWithCache(null);
		const b = await orgWithCache(null);

		const res = await admin("/caches", "POST", { name: a.cache, org: b.org, private: true });
		expect(res.status).toBe(409);
		// Nor to a request without an org.
		expect((await admin("/caches", "POST", { name: a.cache })).status).toBe(409);
	});

	it("needs the org to exist before its caches", async () => {
		expect((await admin("/caches", "POST", { name: unique("cache"), org: unique("org") })).status).toBe(404);
	});
});

describe("storage limit", () => {
	it("accepts pushes that fit and refuses one that doesn't", async () => {
		const { org, cache } = await orgWithCache(1000);

		expect((await createSessions(cache, [400, 400])).status).toBe(201);
		// Uploads under way count, so a second push can't take the same space.
		const refused = await createSessions(cache, [300]);
		expect(refused.status).toBe(507);
		expect(await refused.json()).toEqual({
			error: "Not enough storage: this push needs 300 bytes, and 200 bytes of your 1.0 KB is left.",
		});

		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ used: 0, pending: 800 });
		expect((await createSessions(cache, [200])).status).toBe(201);
	});

	it("refuses a whole batch that doesn't fit", async () => {
		const { org, cache } = await orgWithCache(1000);

		expect((await createSessions(cache, [600, 600])).status).toBe(507);
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: 0 });
	});

	it("lets two pushes at once take no more than the limit", async () => {
		const { cache } = await orgWithCache(1000);

		const results = await Promise.all(Array.from({ length: 4 }, () => createSessions(cache, [400])));
		expect(results.map((r) => r.status).sort()).toEqual([201, 201, 507, 507]);
	});

	it("doesn't limit an org without one, or a cache without an org", async () => {
		const { cache } = await orgWithCache(null);
		expect((await createSessions(cache, [10 ** 12])).status).toBe(201);

		const loose = unique("cache");
		expect((await admin("/caches", "POST", { name: loose })).status).toBe(201);
		expect((await createSessions(loose, [10 ** 12])).status).toBe(201);
	});
});

describe("org tokens", () => {
	async function token(body: Record<string, unknown>): Promise<Response> {
		return admin("/tokens", "POST", { subject: "test", perms: ["push"], ...body });
	}

	it("pushes to its org's caches and lists with them", async () => {
		const { org, cache } = await orgWithCache(null);

		const res = await token({ caches: [cache], org });
		expect(res.status).toBe(201);
		const { token: jwt, jti } = await res.json<{ token: string; jti: string }>();
		expect((await createSessions(cache, [100], jwt)).status).toBe(201);

		const list = await admin(`/tokens?org=${org}`);
		const { tokens } = await list.json<{ tokens: { jti: string; org: string }[] }>();
		expect(tokens).toEqual([expect.objectContaining({ jti, org })]);
	});

	it("can't name another org's cache, or every cache", async () => {
		const a = await orgWithCache(null);
		const b = await orgWithCache(null);

		expect((await token({ caches: [b.cache], org: a.org })).status).toBe(400);
		expect((await token({ caches: ["*"], org: a.org })).status).toBe(400);
	});

	it("can't push to another org's cache even when it names it", async () => {
		const a = await orgWithCache(null);
		const b = await orgWithCache(null);
		// The admin API never signs this; a token is still checked against it.
		const now = Math.floor(Date.now() / 1000);
		const jwt = await signJwt({
			jti: crypto.randomUUID(),
			sub: "test",
			iss: TOKEN_ISSUER,
			aud: TOKEN_AUDIENCE,
			caches: [b.cache],
			perms: ["push"],
			org: a.org,
			iat: now,
			exp: now + 600,
		}, env.JWT_SECRET);
		expect((await createSessions(b.cache, [100], jwt)).status).toBe(403);
	});
});
