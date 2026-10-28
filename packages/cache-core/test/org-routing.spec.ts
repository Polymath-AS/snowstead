import { env, SELF } from "cloudflare:test";
import { expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Client } from "pg";
import { orgs } from "../src/db/schema.js";
import { listOrgs } from "../src/db/repository.js";
import { testDb } from "./db.js";
import { signJwt, TOKEN_ISSUER, TOKEN_AUDIENCE } from "../src/jwt.js";

const db = testDb();

it("lists canonical current and moving addresses only to operators, without usage", async () => {
	const id = `routing-${crypto.randomUUID().slice(0, 8)}`;
	await db.insert(orgs).values({ id, slug: id });
	const inventory = (authorization?: string) => SELF.fetch("http://example.com/_api/v1/admin/orgs", {
		headers: authorization === undefined ? {} : { authorization: `Bearer ${authorization}` },
	});
	expect((await inventory()).status).toBe(401);
	const now = Math.floor(Date.now() / 1000);
	const token = await signJwt({ jti: crypto.randomUUID(), sub: "test", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, org: id, caches: ["*"], perms: ["pull"], iat: now, exp: now + 600 }, env.JWT_SECRET);
	expect((await inventory(token)).status).toBe(403);
	const listed = async () => {
		const response = await inventory("test-admin-secret");
		expect(response.status).toBe(200);
		return (await response.json<{ orgs: { id: string; slug: string; movingFrom: string | null }[] }>()).orgs.find(org => org.id === id);
	};
	expect(await listed()).toEqual({ id, slug: id, movingFrom: null, storageLimit: null, privateCaches: true, customSigningKeys: false });
	await db.update(orgs).set({ slug: `${id}-new`, movingFrom: id }).where(eq(orgs.id, id));
	expect(await listed()).toEqual({ id, slug: `${id}-new`, movingFrom: id, storageLimit: null, privateCaches: true, customSigningKeys: false });
});

it("filters routing IDs in SQL and keeps unrelated inventory out of scoped responses", async () => {
	const id = `filtered-${crypto.randomUUID().slice(0, 8)}`;
	await db.insert(orgs).values({ id, slug: id, movingFrom: `${id}-old` });
	const request = (query: string, authorization = "test-admin-secret") => SELF.fetch(`http://example.com/_api/v1/admin/orgs${query}`, {
		headers: { authorization: `Bearer ${authorization}` },
	});
	const before = await request(`?id=${id}`);
	expect(before.status).toBe(200);
	const body = await before.text();
	expect(JSON.parse(body)).toEqual({ orgs: [{ id, slug: id, movingFrom: `${id}-old`, storageLimit: null, privateCaches: true, customSigningKeys: false }] });
	await db.insert(orgs).values(Array.from({ length: 1000 }, (_, i) => ({ id: `${id}-unrelated-${i}`, slug: `${id}-unrelated-${i}` })));
	expect(await (await request(`?id=${id}`)).text()).toBe(body);
	expect(await (await request(`?id=${id}-missing`)).json()).toEqual({ orgs: [] });
	const two = await request(`?id=${id}-unrelated-0&id=${id}`);
	expect((await two.json<{ orgs: { id: string }[] }>()).orgs.map(org => org.id)).toEqual([id, `${id}-unrelated-0`]);
	const maximum = new URLSearchParams(Array.from({ length: 50 }, (_, i) => ["id", i === 0 ? id : `${id}-missing-${i}`]));
	expect(await (await request(`?${maximum}`)).text()).toBe(body);
	const unfiltered = await request("");
	expect((await unfiltered.json<{ orgs: { id: string }[] }>()).orgs.some(org => org.id === `${id}-unrelated-999`)).toBe(true);

	// Capture the SQL sent to real Postgres: filtering a materialized global
	// inventory in JavaScript would return the same rows but fail this check.
	const client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
	// Like connect(), handle late socket-close events; failed queries still reject.
	client.on("error", () => {});
	await client.connect();
	try {
		const statements: { query: string; params: unknown[] }[] = [];
		const observed = drizzle(client, { logger: { logQuery(query, params) { statements.push({ query, params }); } } });
		expect(await listOrgs(observed, [id])).toEqual(JSON.parse(body).orgs);
		expect(statements).toHaveLength(1);
		expect(statements[0].query).toMatch(/where .*"id" in \(\$1\)/i);
		expect(statements[0].params).toEqual([id]);
		expect(await listOrgs(observed, [])).toEqual([]);
	} finally {
		await client.end();
	}

	const now = Math.floor(Date.now() / 1000);
	const token = await signJwt({ jti: crypto.randomUUID(), sub: "test", iss: TOKEN_ISSUER, aud: TOKEN_AUDIENCE, org: id, caches: ["*"], perms: ["pull"], iat: now, exp: now + 600 }, env.JWT_SECRET);
	expect((await request(`?id=${id}`, token)).status).toBe(403);
	expect((await SELF.fetch(`http://example.com/_api/v1/admin/orgs?id=${id}`)).status).toBe(401);
	for (const query of ["?ids=anything", "?id=", `?id=${id}&other=1`, `?id=${id}&id=`, "?id=one,two", "?id=%00", "?id=%2F", "?id=%ZZ", `?id=${"a".repeat(129)}`, `?${new URLSearchParams(Array.from({ length: 51 }, () => ["id", id]))}`]) {
		const rejected = await request(query);
		expect(rejected.status, query).toBe(400);
		expect(await rejected.json()).not.toHaveProperty("orgs");
	}
	expect((await request(`?id=${"a".repeat(8193)}`)).status).toBe(414);
});

it.each(["?", "?id=a&", "?&id=a", "?id=a&&id=b"])("rejects empty raw query components in %s without exposing inventory", async (query) => {
	const url = `http://example.com/_api/v1/admin/orgs${query}`;
	const request = new Request(url, { headers: { authorization: "Bearer test-admin-secret" } });
	// Workerd preserves the delimiter even though URL.search collapses a lone ?.
	expect(request.url).toBe(url);
	expect(new URL(request.url).search).toBe(query === "?" ? "" : query);
	const response = await SELF.fetch(request);
	expect(response.status).toBe(400);
	expect(await response.json()).not.toHaveProperty("orgs");
	expect((await SELF.fetch(new Request(url))).status).toBe(401);
});
