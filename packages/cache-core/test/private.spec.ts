import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll, vi } from "vitest";
import { testDb } from "./db.js";
import { createBlobObject, createPublishedPath, findCache, revokeApiToken, setCachePublic } from "../src/db/repository.js";

const db = testDb();
const PRIVATE = "private-test";
const OTHER = "private-other";
const PUBLIC = "public-test";
const HASH = "2".repeat(32);
const FILE_HASH = "b".repeat(64);
const NAR = new Uint8Array([5, 6, 7, 8]);
// Each cache's NAR has a file hash of its own.
const fileHash = (cache: string) => `${cache === PRIVATE ? "c0" : "d0"}${FILE_HASH.slice(2)}`;

function admin(path: string, body?: unknown): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1/admin${path}`, {
		method: body === undefined ? "GET" : "POST",
		headers: { authorization: "Bearer test-admin-secret", "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

async function token(caches: string[], perms: string[], expiresInDays?: number | null): Promise<{ token: string; jti: string }> {
	const res = await admin("/tokens", { subject: "test", caches, perms, expiresInDays });
	expect(res.status).toBe(201);
	return res.json();
}

function read(path: string, auth?: string): Promise<Response> {
	return SELF.fetch(`http://example.com${path}`, { headers: auth ? { authorization: auth } : {} });
}

const basic = (secret: string) => `Basic ${btoa(`nix:${secret}`)}`;

let pull: string;

beforeAll(async () => {
	expect((await admin("/caches", { name: PRIVATE, private: true, protocols: ["nix"] })).status).toBe(201);
	expect((await admin("/caches", { name: OTHER, private: true, protocols: ["nix"] })).status).toBe(201);
	expect((await admin("/caches", { name: PUBLIC, protocols: ["nix"] })).status).toBe(201);

	for (const name of [PRIVATE, PUBLIC]) {
		const cache = await findCache(db, "default", name);
		const blob = await createBlobObject(db, {
			fileHash: fileHash(name),
			fileSize: NAR.byteLength,
			compression: "zstd",
			r2Key: `nars/sha256/${fileHash(name)}/zstd.nar`,
		});
		await createPublishedPath(db, {
			cacheId: cache!.id,
			storePathHash: HASH,
			storePath: `/nix/store/${HASH}-secret`,
			narHash: `sha256:${"1".repeat(52)}`,
			narSize: 8,
			blobObjectId: blob.id,
			referencesJson: "[]",
			deriver: null,
			system: null,
			signaturesJson: "[]",
		});
		await env.CACHE_BUCKET.put(blob.r2Key, NAR);
	}
	expect((await admin("/narinfo/backfill", { limit: 1000 })).status).toBe(200);

	pull = (await token([PRIVATE], ["pull"])).token;
});

const nar = (cache: string) => `/${cache}/nar/${fileHash(cache)}/zstd.nar`;

describe("private caches", () => {
	it.each([null, 30, undefined])("honor a token lifetime of %s and keep it revocable", async (expiresInDays) => {
		const response = await admin("/tokens", { subject: "lifetime-test", caches: [PRIVATE], perms: ["pull"], expiresInDays });
		expect(response.status).toBe(201);
		const issued = await response.json<{ token: string; jti: string; expiresAt: string | null }>();
		const claims = JSON.parse(atob(issued.token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/")));
		if (expiresInDays === null) {
			expect(issued.expiresAt).toBeNull();
			expect(claims).not.toHaveProperty("exp");
		} else {
			expect(Date.parse(issued.expiresAt!)).toBeGreaterThan(Date.now());
			expect(claims.exp - claims.iat).toBe((expiresInDays ?? 90) * 86400);
		}
		const listed = await (await admin("/tokens")).json<{ tokens: { jti: string; expiresAt: string | null }[] }>();
		expect(listed.tokens.find((t) => t.jti === issued.jti)?.expiresAt).toBe(issued.expiresAt);
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(issued.token))).status).toBe(200);
		expect((await admin(`/tokens/${issued.jti}/revoke`, { reason: "lifetime test" })).status).toBe(200);
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(issued.token))).status).toBe(401);
		if (expiresInDays === null) {
			const entries = await env.AUTH_KV.list({ prefix: `revoked/${issued.jti}` });
			expect(entries.keys).toEqual([{ name: `revoked/${issued.jti}` }]);
		}
	});

	it.each([
		{ label: "narinfo", path: `/${PRIVATE}/${HASH}.narinfo` },
		{ label: "NARs", path: nar(PRIVATE) },
		{ label: "nix-cache-info", path: `/${PRIVATE}/nix-cache-info` },
		{ label: "missing paths", path: `/${PRIVATE}/${"3".repeat(32)}.narinfo` },
	])("refuse $label without credentials, with a Basic challenge", async ({ path }) => {
		const res = await read(path);
		expect(res.status).toBe(401);
		expect(res.headers.get("www-authenticate")).toContain("Basic");
	});

	it("serve a pull token, as bearer or as netrc-style Basic auth, privately", async () => {
		for (const auth of [`Bearer ${pull}`, basic(pull)]) {
			const res = await read(`/${PRIVATE}/${HASH}.narinfo`, auth);
			expect(res.status).toBe(200);
			expect(res.headers.get("cache-control")).toBe("private, no-cache");
			expect(await res.text()).toContain(`StorePath: /nix/store/${HASH}-secret`);
		}
		const narRes = await read(nar(PRIVATE), basic(pull));
		expect(narRes.status).toBe(200);
		expect(narRes.headers.get("cache-control")).toBe("private, no-cache");
		expect(new Uint8Array(await narRes.arrayBuffer())).toEqual(NAR);
		expect((await read(`/${PRIVATE}/nix-cache-info`, basic(pull))).status).toBe(200);
	});

	it("never serve an authorized response to an anonymous request from the cache", async () => {
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(pull))).status).toBe(200);
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`)).status).toBe(401);
		expect((await read(nar(PRIVATE))).status).toBe(401);
	});

	it("authorizes conditional metadata and HEAD before using cached validators", async () => {
		const url = `http://example.com/${PRIVATE}/${HASH}.narinfo`;
		const initial = await SELF.fetch(url, { headers: { authorization: basic(pull), "x-snowstead-cdn-read": "1" } });
		expect(initial.status).toBe(200);
		expect(initial.headers.get("x-snowstead-cdn-read")).toBeNull();
		const etag = initial.headers.get("etag")!;
		expect(etag).toBeTruthy();
		await initial.text();
		const wrongCache = (await token([OTHER], ["pull"])).token;
		for (const method of ["GET", "HEAD"]) {
			for (const [auth, status] of [[basic(pull), 304], [basic(wrongCache), 403], ["", 401]] as const) {
				const response = await SELF.fetch(url, { method, headers: { authorization: auth, "if-none-match": etag, "x-snowstead-cdn-read": "1" } });
				expect(response.status).toBe(status);
				if (status === 304) expect(response.headers.get("cache-control")).toBe("private, no-cache");
				await response.text();
			}
		}
	});

	it("refuse tokens without pull on this cache", async () => {
		const pushOnly = (await token([PRIVATE], ["push"])).token;
		const otherCache = (await token([OTHER], ["pull"])).token;
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(pushOnly))).status).toBe(403);
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(otherCache))).status).toBe(403);
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic("not-a-token"))).status).toBe(401);
	});

	it("refuse a revoked token", async () => {
		const { token: revoked, jti } = await token([PRIVATE], ["pull"]);
		expect((await admin(`/tokens/${jti}/revoke`, { reason: "test" })).status).toBe(200);
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(revoked))).status).toBe(401);
	});

	it.each([null, 90])("refuse a token with lifetime %s revoked before KV held revocations, once synced", async (expiresInDays) => {
		const { token: old, jti } = await token([PRIVATE], ["pull"], expiresInDays);
		await revokeApiToken(db, jti, "admin", "revoked in the database only");
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(old))).status).toBe(200);

		const sync = await admin("/auth/sync", {});
		expect(sync.status).toBe(200);
		expect((await read(`/${PRIVATE}/${HASH}.narinfo`, basic(old))).status).toBe(401);
	});

	it("refuse writes with a revoked token too", async () => {
		const { token: push, jti } = await token([PRIVATE], ["push"]);
		expect((await admin(`/tokens/${jti}/revoke`, { reason: "test" })).status).toBe(200);
		const res = await SELF.fetch("http://example.com/_api/v1/get-missing-paths", {
			method: "POST",
			headers: { authorization: `Bearer ${push}`, "content-type": "application/json" },
			body: JSON.stringify({ cache: PRIVATE, storePathHashes: [HASH] }),
		});
		expect(res.status).toBe(401);
	});

	it("pick up visibility set only in the database once synced", async () => {
		const name = `synced-${crypto.randomUUID().slice(0, 8)}`;
		expect((await admin("/caches", { name, protocols: ["nix"] })).status).toBe(201);
		await setCachePublic(db, (await findCache(db, "default", name))?.id ?? 0, false);
		expect((await read(`/${name}/nix-cache-info`)).status).toBe(200);
		for (const method of ["GET", "HEAD"]) {
			for (const suffix of ["nix-cache-info", `${HASH}.narinfo`, `nar/${fileHash(PRIVATE)}/zstd.nar`]) {
				const response = await SELF.fetch(`http://example.com/${name}/${suffix}`, { method, headers: { "x-snowstead-cdn-read": "1" } });
				expect(response.status).toBe(404);
				expect(response.headers.get("x-snowstead-cdn-read")).toBeNull();
			}
		}

		expect((await admin("/auth/sync", {})).status).toBe(200);
		expect((await read(`/${name}/nix-cache-info`)).status).toBe(401);
	});

	it("leave public caches open", async () => {
		const res = await read(`/${PUBLIC}/${HASH}.narinfo`);
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toContain("public");
	});

	it("switch visibility both ways", async () => {
		const name = `flip-${crypto.randomUUID().slice(0, 8)}`;
		expect((await admin("/caches", { name, protocols: ["nix"] })).status).toBe(201);
		expect((await read(`/${name}/nix-cache-info`)).status).toBe(200);

		const toPrivate = await admin("/caches", { name, private: true });
		expect(await toPrivate.json()).toMatchObject({ private: true, created: false, changed: true });
		expect((await read(`/${name}/nix-cache-info`)).status).toBe(401);

		const toPublic = await admin("/caches", { name, private: false });
		expect(await toPublic.json()).toMatchObject({ private: false, changed: true });
		expect((await read(`/${name}/nix-cache-info`)).status).toBe(200);

		const { caches } = await (await admin("/caches")).json<{ caches: { name: string; private: boolean }[] }>();
		expect(caches.find((c) => c.name === PRIVATE)?.private).toBe(true);
		expect(caches.find((c) => c.name === name)?.private).toBe(false);
	});
});

describe("private NARs", () => {
	it("are refused through a cache none of whose paths uses them", async () => {
		const other = (await token([OTHER], ["pull"])).token;
		// The NAR exists, under PRIVATE; asked for through OTHER by its hash.
		const res = await read(`/${OTHER}/nar/${fileHash(PRIVATE)}/zstd.nar`, `Bearer ${other}`);
		expect(res.status).toBe(404);
	});

	it("stop being served once their path is deleted, though cached", async () => {
		const name = "private-deleted";
		const hash = "4".repeat(32);
		const file = `e0${FILE_HASH.slice(2)}`;
		expect((await admin("/caches", { name, private: true, protocols: ["nix"] })).status).toBe(201);
		const cache = await findCache(db, "default", name);
		const blob = await createBlobObject(db, { fileHash: file, fileSize: NAR.byteLength, compression: "zstd", r2Key: `nars/sha256/${file}/zstd.nar` });
		await createPublishedPath(db, {
			cacheId: cache!.id,
			storePathHash: hash,
			storePath: `/nix/store/${hash}-gone`,
			narHash: `sha256:${"1".repeat(52)}`,
			narSize: 8,
			blobObjectId: blob.id,
			referencesJson: "[]",
			deriver: null,
			system: null,
			signaturesJson: "[]",
		});
		await env.CACHE_BUCKET.put(blob.r2Key, NAR);
		expect((await admin("/narinfo/backfill", { limit: 1000 })).status).toBe(200);
		const auth = `Bearer ${(await token([name], ["pull"])).token}`;

		// Read once each, so both are in the Cache API.
		expect((await read(`/${name}/${hash}.narinfo`, auth)).status).toBe(200);
		expect((await read(`/${name}/nar/${file}/zstd.nar`, auth)).status).toBe(200);

		expect((await admin(`/caches/${name}/paths/delete`, { storePathHashes: [hash] })).status).toBe(200);
		expect((await read(`/${name}/${hash}.narinfo`, auth)).status).toBe(404);
		expect((await read(`/${name}/nar/${file}/zstd.nar`, auth)).status).toBe(404);
	});

	it("count the bytes of every private NAR served, cached or not, toward the org", async () => {
		const served = async () => {
			const res = await SELF.fetch("http://example.com/_api/v1/orgs/default", { headers: { authorization: "Bearer test-admin-secret" } });
			return (await res.json<{ servedThisMonth: number }>()).servedThisMonth;
		};
		// Earlier reads record after their responses.
		await new Promise((resolve) => setTimeout(resolve, 200));
		const before = await served();

		expect((await read(nar(PRIVATE), basic(pull))).status).toBe(200);
		expect((await read(nar(PRIVATE), basic(pull))).status).toBe(200);
		expect((await SELF.fetch(`http://example.com${nar(PRIVATE)}`, { method: "HEAD", headers: { authorization: basic(pull) } })).status).toBe(200);
		expect((await read(nar(PUBLIC))).status).toBe(200);

		await vi.waitFor(async () => expect(await served()).toBe(before + 2 * NAR.byteLength));
	});
});
