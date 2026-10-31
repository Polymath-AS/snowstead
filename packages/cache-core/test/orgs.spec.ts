import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { signJwt, TOKEN_ISSUER, TOKEN_AUDIENCE } from "../src/jwt.js";
import { createStream, finalizeUploads, postUpload, stageUpload, uploadPart } from "./upload.js";

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

/** A token signed as the service would, for any claims, including ones the API never makes. */
async function sign(caches: string[], perms: ("push" | "pull")[], org?: string): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return signJwt({
		jti: crypto.randomUUID(),
		sub: "test",
		iss: TOKEN_ISSUER,
		aud: TOKEN_AUDIENCE,
		caches,
		perms,
		...(org === undefined ? {} : { org }),
		iat: now,
		exp: now + 600,
	}, env.JWT_SECRET);
}

async function createSessions(cache: string, sizes: number[], token: string): Promise<Response> {
	const paths = sizes.map((fileSize) => {
		const hash = crypto.randomUUID().replaceAll("-", "").slice(0, 32).replace(/[eotu]/g, "a");
		return {
			storePath: `/nix/store/${hash}-hello`,
			storePathHash: hash,
			narHash: `sha256:${"1".repeat(52)}`,
			narSize: fileSize,
			compression: "zstd",
		};
	});
	const created = await SELF.fetch(`http://example.com/_api/v1/caches/${cache}/upload-streams/batch`, {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify({ paths }),
	});
	if (created.status !== 201) return created;
	const body = await created.json<{ sessions: { sessionId: string; partSize: number }[] }>();
	for (const [i, session] of body.sessions.entries()) {
		// Reserve in protocol-sized batches without uploading synthetic large bodies.
		const parts = Array.from({ length: Math.ceil(sizes[i] / session.partSize) }, (_, n) => ({ partNumber: n + 1, size: Math.min(session.partSize, sizes[i] - n * session.partSize) }));
		for (let offset = 0; offset < parts.length; offset += 100) {
			const response = await postUpload(`/uploads/${session.sessionId}/parts`, { parts: parts.slice(offset, offset + 100) }, token);
			if (response.status !== 200) {
				expect((await postUpload(`/uploads/${session.sessionId}/abort`, {}, token)).status).toBe(200);
				return response;
			}
		}
	}
	return Response.json(body, { status: 201 });
}

/** An org with one cache, and a token that pushes to it. */
async function orgWithCache(storageLimit: number | null, isPrivate = false) {
	const org = unique("org");
	const cache = unique("cache");
	expect((await orgApi(`/${org}`, "PUT", { slug: org, storageLimit })).status).toBe(200);
	expect((await orgApi(`/${org}/caches`, "POST", { name: cache, private: isPrivate, protocols: ["nix"] })).status).toBe(201);
	return { org, cache, token: await sign(["*"], ["push", "pull"], org) };
}

describe("orgs", () => {
	it("registers concurrently without losing quota updates and returns conflicts for competing slug claims", async () => {
		for (let round = 0; round < 8; round++) {
			const org = unique("org");
			const responses = await Promise.all(Array.from({ length: 8 }, (_, i) =>
				orgApi(`/${org}`, "PUT", { slug: org, ...(i === 0 ? { storageLimit: 1234, privateCaches: false, customSigningKeys: true } : {}) })));
			expect(responses.map(r => r.status)).toEqual(Array(8).fill(200));
			expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ id: org, slug: org, storageLimit: 1234, privateCaches: false, customSigningKeys: true });
		}
		const slug = unique("claimed");
		const claimants = Array.from({ length: 8 }, () => unique("org"));
		const responses = await Promise.all(claimants.map(org => orgApi(`/${org}`, "PUT", { slug })));
		expect(responses.map(r => r.status).sort()).toEqual([200, 409, 409, 409, 409, 409, 409, 409]);
		const winner = claimants[responses.findIndex(r => r.status === 200)];
		expect(await (await orgApi(`/${winner}`)).json()).toMatchObject({ id: winner, slug, storageLimit: null, privateCaches: true, customSigningKeys: false });
		// Existing orgs racing to rename hit UPDATE's unique constraint instead.
		const movers = [unique("org"), unique("org")];
		for (const org of movers) expect((await orgApi(`/${org}`, "PUT", { slug: org, storageLimit: 1234 })).status).toBe(200);
		const destination = unique("renamed");
		const renamed = await Promise.all(movers.map(org => orgApi(`/${org}`, "PUT", { slug: destination })));
		expect(renamed.map(r => r.status).sort()).toEqual([200, 409]);
		for (const org of movers) expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ storageLimit: 1234 });
	});

	it("exposes generic operator-only limits, validates updates, and preserves omitted values", async () => {
		const org = unique("org");
		expect((await orgApi(`/${org}`)).status).toBe(404);

		const created = await orgApi(`/${org}`, "PUT", { slug: org, storageLimit: 1000 });
		expect(created.headers.get("cache-control")).toBe("no-store");
		expect(await created.json()).toEqual({ id: org, slug: org, movingFrom: null, storageLimit: 1000, privateCaches: true, customSigningKeys: false, used: 0, pending: 0, servedThisMonth: 0 });
		const limits = { storageLimit: 0, privateCaches: false, customSigningKeys: true };
		expect(await (await orgApi(`/${org}`, "PUT", limits)).json()).toMatchObject(limits);
		for (const body of [{}, { slug: org }]) {
			expect(await (await orgApi(`/${org}`, "PUT", body)).json()).toMatchObject(limits);
		}
		for (const body of [
			{ tierId: "commercial" }, { tier: {} },
			...[-1, 1.5, "10GB", Number.MAX_SAFE_INTEGER + 1, true].map(storageLimit => ({ storageLimit })),
			{ privateCaches: null }, { privateCaches: "true" }, { customSigningKeys: null }, { customSigningKeys: 1 },
		]) expect((await orgApi(`/${org}`, "PUT", body)).status).toBe(400);
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject(limits);
		const { key } = await (await orgApi(`/${org}/keys`, "POST", { name: "test" })).json<{ key: string }>();
		for (const body of [{ storageLimit: null }, { privateCaches: true }, { customSigningKeys: false }]) {
			expect((await SELF.fetch(`http://example.com/_api/v1/orgs/${org}`, {
				method: "PUT", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: JSON.stringify(body),
			})).status).toBe(403);
		}
		const inventory = await admin("/orgs");
		expect(inventory.headers.get("cache-control")).toBe("no-store");
		expect((await inventory.json<{ orgs: unknown[] }>()).orgs).toContainEqual({ id: org, slug: org, movingFrom: null, ...limits });
		expect((await SELF.fetch("http://example.com/_api/v1/admin/orgs")).status).toBe(401);
		expect((await SELF.fetch("http://example.com/_api/v1/admin/orgs", { headers: { authorization: `Bearer ${key}` } })).status).toBe(403);

		const raised = await orgApi(`/${org}`, "PUT", { storageLimit: null });
		expect(await raised.json()).toMatchObject({ slug: org, storageLimit: null, privateCaches: false, customSigningKeys: true });
	});

	it("needs a slug to be created", async () => {
		expect((await orgApi(`/${unique("org")}`, "PUT", {})).status).toBe(400);
	});

	it.each(["Acme", "-acme", "acme-", "a".repeat(40), "default", "nar", "private"])("refuses the slug %s", async (slug) => {
		expect((await orgApi(`/${unique("org")}`, "PUT", { slug })).status).toBe(400);
	});

	it("gives each slug to one org", async () => {
		const a = await orgWithCache(null);
		expect((await orgApi(`/${unique("org")}`, "PUT", { slug: a.org })).status).toBe(409);
	});

	it("renames an org and relocates its caches", async () => {
		const { org, cache } = await orgWithCache(null);
		const renamed = unique("renamed");
		expect(await (await orgApi(`/${org}`, "PUT", { slug: renamed })).json()).toMatchObject({ slug: renamed });
		expect(await (await orgApi(`/${org}/caches/${cache}`)).json()).toMatchObject({ path: `${renamed}/${cache}` });
	});

	it("lists only an org's caches", async () => {
		const a = await orgWithCache(null);
		await orgWithCache(null);

		const res = await orgApi(`/${a.org}/caches`);
		const { caches } = await res.json<{ caches: { name: string; org: string; path: string }[] }>();
		expect(caches).toEqual([expect.objectContaining({ name: a.cache, org: a.org, path: `${a.org}/${a.cache}` })]);
	});

	it("lets every org have a cache of the same name, each at its own path", async () => {
		const a = await orgWithCache(null);
		const b = await orgWithCache(null);

		const res = await orgApi(`/${b.org}/caches`, "POST", { name: a.cache, protocols: ["nix"] });
		expect(await res.json()).toMatchObject({ created: true, path: `${b.org}/${a.cache}` });
		expect((await SELF.fetch(`http://example.com/${a.org}/${a.cache}/nix-cache-info`)).status).toBe(200);
		expect((await SELF.fetch(`http://example.com/${b.org}/${a.cache}/nix-cache-info`)).status).toBe(200);
	});

	it("needs the org to exist before its caches", async () => {
		expect((await admin("/caches", "POST", { name: unique("cache"), org: unique("org"), protocols: ["nix"] })).status).toBe(404);
	});
});

describe("storage limit", () => {
	async function streams(cache: string, token: string, count: number, narSize = 1) {
		const sessions = [];
		for (let i = 0; i < count; i++) {
			const hash = crypto.randomUUID().replaceAll("-", "").replace(/[eotu]/g, "a");
			sessions.push(await createStream(cache, { storePath: `/nix/store/${hash}-quota`, storePathHash: hash, narHash: `sha256:${"1".repeat(52)}`, narSize, compression: "zstd" }, token));
		}
		return sessions;
	}

	function reserve(token: string, uploads: { sessionId: string; parts: { partNumber: number; size: number }[] }[]) {
		return SELF.fetch("http://example.com/_api/v1/uploads/parts", { method: "POST",
			headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ uploads }) });
	}

	it("stages duplicate NARs independently without double-reserving part retries", async () => {
		const bytes = crypto.getRandomValues(new Uint8Array(16));
		const fileHash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(b => b.toString(16).padStart(2, "0")).join("");
		const { org, cache, token } = await orgWithCache(32);
		const sessions = await streams(cache, token, 3, 32);
		const uploads = sessions.map(s => ({ sessionId: s.sessionId, parts: [{ partNumber: 1, size: bytes.length }] }));
		for (let retry = 0; retry < 2; retry++) expect(await (await reserve(token, uploads)).json()).toMatchObject({ results: sessions.map(() => ({ parts: [{ partNumber: 1 }] })) });
		const items = [];
		for (const s of sessions.slice(0, 2)) items.push({ sessionId: s.sessionId, narHash: `sha256:${"1".repeat(52)}`, narSize: 32, fileHash, fileSize: bytes.length, parts: [await uploadPart(s.sessionId, bytes, token)] });
		expect(await env.PUBLIC_BUCKET.head(`nar/${fileHash}/zstd.nar`)).toBeNull();
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: 48, used: 0 });
		expect(await finalizeUploads(items.reverse(), token)).toMatchObject([{ published: true }, { published: true }]);
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: 16, used: 32 });
		for (const s of sessions.slice(0, 2)) expect(await env.CACHE_BUCKET.head(`staging/${s.sessionId}`)).not.toBeNull();
	});

	it("admits staging beyond retained capacity but rejects an individually oversized object", async () => {
		const { org, cache, token } = await orgWithCache(1000);

		expect((await createSessions(cache, [400, 400], token)).status).toBe(201);
		expect((await createSessions(cache, [300], token)).status).toBe(201);
		const refused = await createSessions(cache, [1001], token);
		expect(refused.status).toBe(413);
		expect(await refused.json()).toEqual({ error: "Object exceeds cache capacity" });
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ used: 0, pending: 1100 });
		expect((await createSessions(cache, [200], token)).status).toBe(201);
	});

	it("stages a batch whose individual objects fit even when its sum exceeds retained capacity", async () => {
		const { org, cache, token } = await orgWithCache(1000);

		expect((await createSessions(cache, [600, 600], token)).status).toBe(201);
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: 1200 });
	});

	it("admits concurrent pushes independently of retained capacity", async () => {
		const { org, cache, token } = await orgWithCache(1000);

		const results = await Promise.all(Array.from({ length: 4 }, () => createSessions(cache, [400], token)));
		expect(results.map((r) => r.status)).toEqual([201, 201, 201, 201]);
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: 1600, used: 0 });
	});

	it("bounds temporary bytes separately, including orgs without retained limits", async () => {
		const { cache, token } = await orgWithCache(null);
		expect((await createSessions(cache, [1024], token)).status).toBe(201);
		const busy = await createSessions(cache, [10 ** 12], token);
		expect(busy.status).toBe(429);
		expect(await busy.json()).toEqual({ error: "Upload staging is busy; retry" });

		const loose = unique("cache");
		expect((await admin("/caches", "POST", { name: loose, protocols: ["nix"] })).status).toBe(201);
		expect((await createSessions(loose, [1024], "test-auth-token")).status).toBe(201);
		expect((await createSessions(loose, [10 ** 12], "test-auth-token")).status).toBe(429);
	});

	it("serializes competing staging reservations without reserving retained bytes", async () => {
		const size = 256 * 1024 ** 2;
		const { org, cache, token } = await orgWithCache(size);
		const results = await Promise.all(Array.from({ length: 4 }, () => createSessions(cache, [size], token)));
		expect(results.map(r => r.status).sort()).toEqual([201, 201, 429, 429]);
		for (const response of results.filter(r => r.status === 429)) expect(await response.json()).toEqual({ error: "Upload staging is busy; retry" });
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: size * 2, used: 0 });
	});

	it("grants stream parts beyond retained capacity with replay and per-object bounds", async () => {
		const { org, cache, token } = await orgWithCache(10);
		const sessions = await streams(cache, token, 2);
		expect((await createSessions(cache, [9], token)).status).toBe(201);
		const uploads = sessions.map(({ sessionId }, i) => ({ sessionId, parts: [{ partNumber: 1, size: 8 - i }] }));
		for (let replay = 0; replay < 2; replay++) {
			expect(await (await reserve(token, uploads)).json()).toMatchObject({ results: [{ parts: [{ partNumber: 1 }] }, { parts: [{ partNumber: 1 }] }] });
			expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: 24, used: 0 });
		}
		expect(await (await reserve(token, [{ sessionId: sessions[0].sessionId, parts: [{ partNumber: 2, size: 3 }] }])).json()).toMatchObject({ results: [{ status: 413 }] });
		expect(await (await reserve(token, [{ sessionId: sessions[0].sessionId, parts: [{ partNumber: 1, size: 9 }] }])).json()).toMatchObject({ results: [{ status: 409 }] });
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: 24, used: 0 });
	});

	it("bounds aggregate durable stream staging while permitting existing grant replays", async () => {
		const size = 256 * 1024 ** 2;
		const { org, cache, token } = await orgWithCache(size);
		const sessions = await streams(cache, token, 3, size);
		const uploads = sessions.slice(0, 2).map(({ sessionId, partSize }) => ({ sessionId, parts: Array.from({ length: size / partSize }, (_, i) => ({ partNumber: i + 1, size: partSize })) }));
		for (const upload of uploads) expect(await (await reserve(token, [upload])).json()).toMatchObject({ results: [{ parts: upload.parts.map(p => ({ partNumber: p.partNumber })) }] });
		expect(await (await reserve(token, [{ sessionId: sessions[2].sessionId, parts: [{ partNumber: 1, size: 1 }] }])).json()).toMatchObject({ results: [{ status: 429 }] });
		expect(await (await reserve(token, uploads)).json()).toMatchObject({ results: uploads.map(upload => ({ parts: upload.parts.map(p => ({ partNumber: p.partNumber })) })) });
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ pending: size * 2, used: 0 });
	});
});

describe("the default org", () => {
	it("holds caches made without an org, at their name, as on a self-hosted install", async () => {
		const name = unique("cache");
		expect(await (await admin("/caches", "POST", { name, protocols: ["nix"] })).json()).toMatchObject({ created: true, path: name });

		const res = await orgApi(`/default/caches/${name}`);
		expect(await res.json()).toMatchObject({ name, org: "default", path: name });
		expect((await SELF.fetch(`http://example.com/${name}/nix-cache-info`)).status).toBe(200);
	});

	it("is where a token without an org, or the push secret, pushes", async () => {
		const name = unique("cache");
		expect((await admin("/caches", "POST", { name, protocols: ["nix"] })).status).toBe(201);
		const other = await orgWithCache(null);
		const orgless = await sign(["*"], ["push"]);

		expect((await createSessions(name, [100], orgless)).status).toBe(201);
		expect((await createSessions(name, [100], "test-auth-token")).status).toBe(201);
		// Another org's cache isn't among the default org's.
		expect((await createSessions(other.cache, [100], orgless)).status).toBe(404);
		expect((await createSessions(other.cache, [100], "test-auth-token")).status).toBe(404);
	});
});

describe("org tokens", () => {
	async function token(org: string, body: Record<string, unknown>): Promise<Response> {
		return orgApi(`/${org}/tokens`, "POST", { subject: "test", perms: ["push"], ...body });
	}

	it("name only their org's caches; * is all of them", async () => {
		const a = await orgWithCache(null);
		const b = await orgWithCache(null);

		expect((await token(a.org, { caches: [b.cache] })).status).toBe(400);
		const all = await token(a.org, { caches: ["*"] });
		expect(all.status).toBe(201);
		const { token: jwt } = await all.json<{ token: string }>();
		expect((await createSessions(a.cache, [100], jwt)).status).toBe(201);
		expect((await createSessions(b.cache, [100], jwt)).status).toBe(404);
	});

	it("find caches only in their own org, whatever they name", async () => {
		const a = await orgWithCache(null);
		const b = await orgWithCache(null);
		// The admin API never signs this; a token is still held to its org.
		const forged = await sign([b.cache], ["push"], a.org);
		expect((await createSessions(b.cache, [100], forged)).status).toBe(404);
	});

	it("from the admin API are the default org's", async () => {
		const name = unique("cache");
		expect((await admin("/caches", "POST", { name, protocols: ["nix"] })).status).toBe(201);
		const res = await admin("/tokens", "POST", { subject: "ci", caches: [name], perms: ["push"] });
		expect(await res.json()).toMatchObject({ org: "default" });
	});

	it("can't look up another org's missing paths", async () => {
		const { cache } = await orgWithCache(null);
		const res = await SELF.fetch("http://example.com/_api/v1/get-missing-paths", {
			method: "POST",
			headers: { authorization: `Bearer ${await sign([cache], ["push"], unique("org"))}`, "content-type": "application/json" },
			body: JSON.stringify({ cache, storePathHashes: ["0".repeat(32)] }),
		});
		expect(res.status).toBe(404);
	});
});

describe("private org caches", () => {
	function pull(path: string, token: string): Promise<Response> {
		return SELF.fetch(`http://example.com/${path}/nix-cache-info`, { headers: { authorization: `Bearer ${token}` } });
	}

	it("are served at their org's path, to their org's tokens only", async () => {
		const { org, cache } = await orgWithCache(null, true);
		const path = `${org}/${cache}`;

		expect((await pull(path, await sign([cache], ["pull"], org))).status).toBe(200);
		expect((await pull(path, await sign([cache], ["pull"], unique("org")))).status).toBe(403);
		expect((await pull(path, await sign([cache], ["pull"]))).status).toBe(403);
		expect((await SELF.fetch(`http://example.com/${path}/nix-cache-info`)).status).toBe(401);
	});

	it("get their entry rewritten, with their org, when auth is synced", async () => {
		const { org, cache } = await orgWithCache(null, true);
		await env.AUTH_KV.put(`private/${org}/${cache}`, "1");

		expect((await admin("/auth/sync", "POST", {})).status).toBe(200);
		expect(JSON.parse((await env.AUTH_KV.get(`private/${org}/${cache}`)) ?? "{}")).toEqual({ org, id: expect.any(Number), gen: expect.any(String) });
	});
});

describe("public org caches", () => {
	it("are stored where the CDN serves them, pointing back up to the shared NARs", async () => {
		const { org, cache, token } = await orgWithCache(null);
		const body = crypto.getRandomValues(new Uint8Array(16));
		const fileHash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", body))].map((b) => b.toString(16).padStart(2, "0")).join("");
		const hash = "r".repeat(32);
		const item = await stageUpload(cache, {
			storePath: `/nix/store/${hash}-hello`, storePathHash: hash, narHash: `sha256:${"1".repeat(52)}`,
			narSize: 32, compression: "zstd",
		}, body, token);
		expect(await finalizeUploads([item], token)).toMatchObject([{ published: true }]);

		const stored = await env.PUBLIC_BUCKET.get(`${org}/${cache}/${hash}.narinfo`);
		const narinfo = (await stored?.text()) ?? "";
		expect(narinfo).toContain(`URL: ../../nar/${fileHash}/zstd.nar`);
		const detail = await (await orgApi(`/${org}/caches/${cache}`)).json<{ publicKey: string }>();
		expect(narinfo.split("\n").some(line => line.startsWith(`Sig: ${detail.publicKey.split(":")[0]}:`))).toBe(true);
		expect(await env.PUBLIC_BUCKET.head(`${org}/${cache}/nix-cache-info`)).not.toBeNull();
	});
});

describe("token caches", () => {
	function decode(jwt: string): { caches: string[] } {
		const payload = jwt.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
		return JSON.parse(atob(payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), "=")));
	}

	async function token(org: string, caches: string[], perms: string[] = ["push"]): Promise<Response> {
		return orgApi(`/${org}/tokens`, "POST", { subject: "test", perms, caches });
	}

	it("push to their org's caches by id and list them by name", async () => {
		const { org, cache } = await orgWithCache(null);
		const res = await token(org, [cache]);
		expect(res.status).toBe(201);
		const { token: jwt, jti } = await res.json<{ token: string; jti: string }>();

		expect(decode(jwt).caches).toEqual([expect.stringMatching(/^id:\d+$/)]);
		expect((await createSessions(cache, [100], jwt)).status).toBe(201);
		const { tokens } = await (await orgApi(`/${org}/tokens`)).json<{ tokens: { jti: string; org: string; caches: string[] }[] }>();
		expect(tokens).toEqual([expect.objectContaining({ jti, org, caches: [cache] })]);
	});

	it("take in caches a pattern matches, made before or after", async () => {
		const { org } = await orgWithCache(null);
		await orgApi(`/${org}/caches`, "POST", { name: "ci-linux", protocols: ["nix"] });
		const { token: jwt } = await (await token(org, ["ci-*"])).json<{ token: string }>();
		await orgApi(`/${org}/caches`, "POST", { name: "ci-darwin", protocols: ["nix"] });
		await orgApi(`/${org}/caches`, "POST", { name: "release", protocols: ["nix"] });

		expect((await createSessions("ci-linux", [10], jwt)).status).toBe(201);
		expect((await createSessions("ci-darwin", [10], jwt)).status).toBe(201);
		expect((await createSessions("release", [10], jwt)).status).toBe(403);
	});

	it.each(["CI-*", "ci *", "ci/*", "x".repeat(65) + "*"])("refuse the pattern %s", async (pattern) => {
		const { org } = await orgWithCache(null);
		expect((await token(org, [pattern])).status).toBe(400);
	});

	it("from before ids, naming caches by name, still work", async () => {
		const { org, cache } = await orgWithCache(null);
		expect((await createSessions(cache, [10], await sign([cache], ["push"], org))).status).toBe(201);
	});

	it("pull from a private cache by id once its entry has it", async () => {
		const { org, cache } = await orgWithCache(null, true);
		const { token: jwt } = await (await token(org, [cache], ["pull"])).json<{ token: string }>();
		const pull = () => SELF.fetch(`http://example.com/${org}/${cache}/nix-cache-info`, { headers: { authorization: `Bearer ${jwt}` } });

		expect((await pull()).status).toBe(200);
	});
});

describe("slug changes", () => {
	/** Publishes one path to the cache, as the client does. */
	async function publish(cache: string, token: string, hash: string): Promise<void> {
		const body = crypto.getRandomValues(new Uint8Array(16));
		const item = await stageUpload(cache, {
			storePath: `/nix/store/${hash}-hello`, storePathHash: hash, narHash: `sha256:${"1".repeat(52)}`,
			narSize: 32, compression: "zstd",
		}, body, token);
		expect(await finalizeUploads([item], token)).toMatchObject([{ published: true }]);
	}

	/** Calls POST /move until it's done. */
	async function move(org: string): Promise<void> {
		let cursor: unknown = undefined;
		for (let calls = 1; calls <= 20; calls++) {
			const answer = await (await orgApi(`/${org}/move`, "POST", { cursor })).json<{ done: boolean; next?: unknown }>();
			if (answer.done) return;
			cursor = answer.next;
		}
		throw new Error("move never finished");
	}

	it("move a public cache's narinfo to the new slug, without paths deleted since", async () => {
		const { org, cache, token } = await orgWithCache(null);
		const [kept, deleted] = ["k".repeat(32), "d".repeat(32)];
		await publish(cache, token, kept);
		await publish(cache, token, deleted);
		const renamed = unique("renamed");

		const answer = await orgApi(`/${org}`, "PUT", { slug: renamed });
		expect(await answer.json()).toMatchObject({ slug: renamed, movingFrom: org });
		expect(await env.PUBLIC_BUCKET.head(`${renamed}/${cache}/nix-cache-info`)).not.toBeNull();
		// Its old slug stays its own, and one change finishes before the next.
		expect((await orgApi(`/${unique("org")}`, "PUT", { slug: org })).status).toBe(409);
		expect((await orgApi(`/${org}`, "PUT", { slug: unique("again") })).status).toBe(409);
		const del = await orgApi(`/${org}/caches/${cache}/paths/delete`, "POST", { storePathHashes: [deleted] });
		expect(del.status).toBe(200);

		await move(org);
		const narinfo = await (await env.PUBLIC_BUCKET.get(`${renamed}/${cache}/${kept}.narinfo`))?.text();
		expect(narinfo).toContain(`StorePath: /nix/store/${kept}-hello`);
		expect(narinfo).toContain("URL: ../../nar/");
		expect(await env.PUBLIC_BUCKET.head(`${renamed}/${cache}/${deleted}.narinfo`)).toBeNull();
		expect((await env.PUBLIC_BUCKET.list({ prefix: `${org}/` })).objects).toEqual([]);
		expect(await (await orgApi(`/${org}`)).json()).toMatchObject({ slug: renamed, movingFrom: null });
		// Done, the old slug is free again.
		expect((await orgApi(`/${unique("org")}`, "PUT", { slug: org })).status).toBe(200);
	});

	it("keep a private cache private at both slugs while it moves", async () => {
		const { org, cache, token } = await orgWithCache(null, true);
		const hash = "p".repeat(32);
		await publish(cache, token, hash);
		const renamed = unique("renamed");
		const pull = (path: string) => SELF.fetch(`http://example.com/${path}/${hash}.narinfo`);

		expect((await orgApi(`/${org}`, "PUT", { slug: renamed })).status).toBe(200);
		expect((await pull(`${renamed}/${cache}`)).status).toBe(401);
		expect((await pull(`${org}/${cache}`)).status).toBe(401);

		await move(org);
		const reader = await sign([cache], ["pull"], org);
		const moved = await SELF.fetch(`http://example.com/${renamed}/${cache}/${hash}.narinfo`, { headers: { authorization: `Bearer ${reader}` } });
		expect(moved.status).toBe(200);
		expect(await env.CACHE_BUCKET.head(`narinfo/${org}/${cache}/${hash}.narinfo`)).toBeNull();
		// The old marker stays, so the old address stays private too.
		expect((await pull(`${org}/${cache}`)).status).toBe(401);
		expect(await env.PUBLIC_BUCKET.head(`${org}/${cache}/${hash}.narinfo`)).toBeNull();
	});
});

describe("orgs without private-cache permission", () => {
	it("keep their private caches private and readable, but push to none and make no more", async () => {
		const { org, cache, token } = await orgWithCache(null, true);
		const reader = await sign([cache], ["pull"], org);
		const pull = () => SELF.fetch(`http://example.com/${org}/${cache}/nix-cache-info`, { headers: { authorization: `Bearer ${reader}` } });
		const pushTo = (name: string) => createSessions(name, [16], token);
		expect((await orgApi(`/${org}`, "PUT", { privateCaches: false })).status).toBe(200);

		const refused = await pushTo(cache);
		expect(refused.status).toBe(403);
		expect(await refused.json()).toMatchObject({ error: expect.stringContaining("private caches") });
		expect((await pull()).status).toBe(200);
		expect((await SELF.fetch(`http://example.com/${org}/${cache}/nix-cache-info`)).status).toBe(401);
		expect((await orgApi(`/${org}/caches`, "POST", { name: unique("cache"), private: true, protocols: ["nix"] })).status).toBe(403);
		// Its own settings still change, and public caches are as before.
		expect((await orgApi(`/${org}/caches`, "POST", { name: cache, private: true, retentionDays: 30 })).status).toBe(200);
		const open = unique("cache");
		expect((await orgApi(`/${org}/caches`, "POST", { name: open, protocols: ["nix"] })).status).toBe(201);
		expect((await pushTo(open)).status).toBe(201);

		expect((await orgApi(`/${org}`, "PUT", { privateCaches: true })).status).toBe(200);
		expect((await pushTo(cache)).status).toBe(201);
	});
});
