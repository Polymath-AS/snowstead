import { env, SELF } from "cloudflare:test";
import { describe, it, expect, afterAll } from "vitest";
import { eq } from "drizzle-orm";
import { testDb } from "./db.js";
import { findBlobObject } from "../src/db/repository.js";
import { publishedPaths, uploadSessions } from "../src/db/schema.js";
import { runGarbageCollection } from "../../../workers/control/src/gc.js";
import { resolveConfig } from "../src/config.js";

const db = testDb();
const config = resolveConfig(env);
afterAll(() => config.close());

const NIX32 = "0123456789abcdfghijklmnpqrsvwxyz";
const unique = (prefix: string) => `${prefix}-${crypto.randomUUID().slice(0, 8)}`;

function storePathHash(): string {
	return [...crypto.getRandomValues(new Uint8Array(32))].map((b) => NIX32[b % 32]).join("");
}

/** A NAR body and the SHA-256 R2 checks its upload against. */
async function nar(size: number): Promise<{ body: Uint8Array; fileHash: string }> {
	const body = crypto.getRandomValues(new Uint8Array(size));
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
	return { body, fileHash: [...digest].map((b) => b.toString(16).padStart(2, "0")).join("") };
}

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

function api(path: string, body: unknown, token = "test-auth-token"): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1${path}`, {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

function deletePaths(cache: string, body: unknown, org?: string): Promise<Response> {
	return org === undefined ? admin(`/caches/${cache}/paths/delete`, "POST", body) : orgApi(`/${org}/caches/${cache}/paths/delete`, "POST", body);
}

/** Pushes one path as the client does, and returns the sessions' status. */
async function push(cache: string, hash: string, { body, fileHash }: { body: Uint8Array; fileHash: string }, token = "test-auth-token", name = "hello"): Promise<number> {
	const res = await api(`/caches/${cache}/upload-sessions/batch`, {
		paths: [{
			storePath: `/nix/store/${hash}-${name}`,
			storePathHash: hash,
			narHash: `sha256:${"1".repeat(52)}`,
			narSize: body.byteLength,
			fileHash,
			fileSize: body.byteLength,
			compression: "zstd",
		}],
	}, token);
	if (res.status !== 201) return res.status;
	const { sessions: [session] } = await res.json<{ sessions: { sessionId: string }[] }>();
	const put = await SELF.fetch(`http://example.com/_api/v1/uploads/${session.sessionId}/blob`, {
		method: "PUT",
		headers: { authorization: `Bearer ${token}` },
		body,
	});
	expect(put.status).toBe(200);
	const commit = await api("/uploads/commit", { sessionIds: [session.sessionId] }, token);
	expect(await commit.json()).toMatchObject({ results: [{ published: true }] });
	return 201;
}

async function used(org: string): Promise<number> {
	return (await (await orgApi(`/${org}`)).json<{ used: number }>()).used;
}

/** Ends the sessions that uploaded a NAR, as an hour passing would. */
async function expireSessions(fileHash: string): Promise<void> {
	await db.update(uploadSessions).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(uploadSessions.fileHash, fileHash));
}

describe("deleting published paths", () => {
	it("keeps published data on an over-quota downgrade and immediately blocks new pushes", async () => {
		const org = unique("org");
		const cache = unique("cache");
		expect((await orgApi(`/${org}`, "PUT", { slug: org, storageLimit: 100 })).status).toBe(200);
		expect((await orgApi(`/${org}/caches`, "POST", { name: cache })).status).toBe(201);
		const { token } = await (await orgApi(`/${org}/tokens`, "POST", { subject: "ci", caches: [cache], perms: ["push"] })).json<{ token: string }>();
		const hash = storePathHash();
		expect(await push(cache, hash, await nar(40), token)).toBe(201);
		expect((await orgApi(`/${org}`, "PUT", { storageLimit: 10 })).status).toBe(200);
		expect(await used(org)).toBe(40);
		expect(await push(cache, storePathHash(), await nar(1), token)).toBe(507);
		expect((await SELF.fetch(`http://example.com/${org}/${cache}/${hash}.narinfo`)).status).toBe(200);
		expect(await env.PUBLIC_BUCKET.head(`${org}/${cache}/${hash}.narinfo`)).not.toBeNull();
		// An unrelated registration cannot reset the lowered limit or erase data.
		expect((await orgApi(`/${org}`, "PUT", { slug: org })).status).toBe(200);
		expect(await used(org)).toBe(40);
		expect(await push(cache, storePathHash(), await nar(1), token)).toBe(507);
		expect((await orgApi(`/${org}`, "PUT", { storageLimit: 100 })).status).toBe(200);
		expect(await push(cache, storePathHash(), await nar(1), token)).toBe(201);
	});

	it("frees its org's storage, so a push that was refused fits", async () => {
		const org = unique("org");
		const cache = unique("cache");
		expect((await orgApi(`/${org}`, "PUT", { slug: org, storageLimit: 100 })).status).toBe(200);
		expect((await orgApi(`/${org}/caches`, "POST", { name: cache })).status).toBe(201);
		const made = await orgApi(`/${org}/tokens`, "POST", { subject: "ci", caches: [cache], perms: ["push"] });
		const { token } = await made.json<{ token: string }>();
		const a = storePathHash();
		expect(await push(cache, a, await nar(40), token)).toBe(201);
		expect(await push(cache, storePathHash(), await nar(40), token)).toBe(201);
		expect(await used(org)).toBe(80);
		expect(await push(cache, storePathHash(), await nar(40), token)).toBe(507);

		const res = await deletePaths(cache, { storePathHashes: [a] }, org);
		expect(await res.json()).toEqual({ deleted: [a], notFound: [], more: false });
		expect(await used(org)).toBe(40);
		expect(await push(cache, storePathHash(), await nar(40), token)).toBe(201);
	});

	it("withdraws the narinfo, and a repeat is not an error", async () => {
		const cache = unique("cache");
		expect((await admin("/caches", "POST", { name: cache })).status).toBe(201);
		const hash = storePathHash();
		const body = await nar(16);
		expect(await push(cache, hash, body)).toBe(201);
		const narinfo = `http://example.com/${cache}/${hash}.narinfo`;
		// Read once, so the Worker has it cached too.
		expect((await SELF.fetch(narinfo)).status).toBe(200);

		expect(await (await deletePaths(cache, { storePathHashes: [hash] })).json()).toMatchObject({ deleted: [hash] });
		expect((await SELF.fetch(narinfo)).status).toBe(404);
		expect(await env.PUBLIC_BUCKET.head(`${cache}/${hash}.narinfo`)).toBeNull();

		const again = await deletePaths(cache, { storePathHashes: [hash, hash] });
		expect(await again.json()).toEqual({ deleted: [], notFound: [hash], more: false });

		// A later push sees it missing and publishes it again.
		const missing = await api("/get-missing-paths", { cache, storePathHashes: [hash] });
		expect(await missing.json()).toMatchObject({ missing: [hash] });
		expect(await push(cache, hash, body)).toBe(201);
		expect((await SELF.fetch(narinfo)).status).toBe(200);
	});

	it("withdraws a private cache's narinfo", async () => {
		const cache = unique("cache");
		expect((await admin("/caches", "POST", { name: cache, private: true })).status).toBe(201);
		const pull = await admin("/tokens", "POST", { subject: "test", caches: [cache], perms: ["pull"] });
		const { token } = await pull.json<{ token: string }>();
		const hash = storePathHash();
		expect(await push(cache, hash, await nar(16))).toBe(201);
		const read = () => SELF.fetch(`http://example.com/private/${cache}/${hash}.narinfo`, {
			headers: { authorization: `Basic ${btoa(`nix:${token}`)}` },
		});
		expect((await read()).status).toBe(200);

		expect((await deletePaths(cache, { storePathHashes: [hash] })).status).toBe(200);
		expect((await read()).status).toBe(404);
		expect(await env.CACHE_BUCKET.head(`narinfo/${cache}/${hash}.narinfo`)).toBeNull();
	});

	it("also withdraws cached orphan narinfo when no database row exists", async () => {
		const cache = unique("orphan");
		expect((await admin("/caches", "POST", { name: cache })).status).toBe(201);
		const hash = storePathHash();
		await env.PUBLIC_BUCKET.put(`${cache}/${hash}.narinfo`, "orphan narinfo");
		const url = `http://example.com/${cache}/${hash}.narinfo`;
		expect((await SELF.fetch(url)).status).toBe(200);
		expect(await (await deletePaths(cache, { storePathHashes: [hash] })).json()).toMatchObject({ deleted: [], notFound: [hash] });
		expect((await SELF.fetch(url)).status).toBe(404);
	});

	it("deletes only paths published before the cutoff", async () => {
		const cache = unique("cache");
		expect((await admin("/caches", "POST", { name: cache })).status).toBe(201);
		const hashes = [storePathHash(), storePathHash()];
		for (const hash of hashes) expect(await push(cache, hash, await nar(16))).toBe(201);
		await db.update(publishedPaths).set({ createdAt: new Date("2000-01-01T00:00:00Z") }).where(eq(publishedPaths.storePathHash, hashes[0]));

		const res = await deletePaths(cache, { before: "2001-01-01T00:00:00Z" });
		const { deleted, more } = await res.json<{ deleted: string[]; more: boolean }>();
		expect(deleted).toEqual([hashes[0]]);
		expect(more).toBe(false);
		expect(await (await admin(`/caches/${cache}`)).json()).toMatchObject({ paths: 1, size: 16 });
		expect((await SELF.fetch(`http://example.com/${cache}/${hashes[0]}.narinfo`)).status).toBe(404);
		expect((await SELF.fetch(`http://example.com/${cache}/${hashes[1]}.narinfo`)).status).toBe(200);
	});

	it("leaves another cache's path to the same NAR, and GC deletes the NAR after the last", async () => {
		const first = unique("cache");
		const second = unique("cache");
		for (const name of [first, second]) expect((await admin("/caches", "POST", { name })).status).toBe(201);
		const shared = await nar(16);
		const [a, b] = [storePathHash(), storePathHash()];
		expect(await push(first, a, shared)).toBe(201);
		expect(await push(second, b, shared)).toBe(201);
		const narKey = `nar/${shared.fileHash}/zstd.nar`;

		expect((await deletePaths(first, { storePathHashes: [a] })).status).toBe(200);
		await expireSessions(shared.fileHash);
		expect((await runGarbageCollection(config)).errors).toEqual([]);
		expect((await SELF.fetch(`http://example.com/${second}/${b}.narinfo`)).status).toBe(200);
		expect(await findBlobObject(db, shared.fileHash, "zstd")).toBeDefined();
		expect(await env.PUBLIC_BUCKET.head(narKey)).not.toBeNull();

		expect((await deletePaths(second, { storePathHashes: [b] })).status).toBe(200);
		expect((await runGarbageCollection(config)).errors).toEqual([]);
		expect(await findBlobObject(db, shared.fileHash, "zstd")).toBeUndefined();
		expect(await env.PUBLIC_BUCKET.head(narKey)).toBeNull();
	});

	it("keeps a NAR while an upload session names it", async () => {
		const cache = unique("cache");
		expect((await admin("/caches", "POST", { name: cache })).status).toBe(201);
		const hash = storePathHash();
		const body = await nar(16);
		expect(await push(cache, hash, body)).toBe(201);
		expect((await deletePaths(cache, { storePathHashes: [hash] })).status).toBe(200);

		// A push of the same NAR may be under way, its bytes already in place.
		await runGarbageCollection(config);
		expect(await findBlobObject(db, body.fileHash, "zstd")).toBeDefined();

		await expireSessions(body.fileHash);
		await runGarbageCollection(config);
		expect(await findBlobObject(db, body.fileHash, "zstd")).toBeUndefined();
	});

	it.each([
		{ label: "neither field", body: {} },
		{ label: "both fields", body: { storePathHashes: ["0".repeat(32)], before: new Date().toISOString() } },
		{ label: "an empty list", body: { storePathHashes: [] } },
		{ label: "too many hashes", body: { storePathHashes: Array.from({ length: 501 }, storePathHash) } },
		{ label: "an invalid hash", body: { storePathHashes: ["e".repeat(32)] } },
		{ label: "an invalid time", body: { before: "yesterday" } },
	])("rejects $label", async ({ body }) => {
		expect((await deletePaths("delete-test", body)).status).toBe(400);
	});

	it("lists an org's cache paths newest first, searched by name or hash", async () => {
		const org = unique("org");
		const cache = unique("cache");
		expect((await orgApi(`/${org}`, "PUT", { slug: org, storageLimit: null })).status).toBe(200);
		expect((await orgApi(`/${org}/caches`, "POST", { name: cache })).status).toBe(201);
		const { token } = await (await orgApi(`/${org}/tokens`, "POST", { subject: "ci", caches: [cache], perms: ["push"] })).json<{ token: string }>();
		const [hello, world, openssl] = [storePathHash(), storePathHash(), storePathHash()];
		expect(await push(cache, hello, await nar(10), token, "hello-2.12")).toBe(201);
		expect(await push(cache, world, await nar(20), token, "Hello_World")).toBe(201);
		expect(await push(cache, openssl, await nar(30), token, "openssl-3.0")).toBe(201);

		const search = async (query: string) => {
			const res = await orgApi(`/${org}/caches/${cache}/paths?${query}`);
			expect(res.status, query).toBe(200);
			return res.json<{ paths: { storePathHash: string; size: number; addedAt: string }[]; next: number | null }>();
		};
		const hashes = async (query: string) => (await search(query)).paths.map((p) => p.storePathHash);

		expect(await hashes("")).toEqual([openssl, world, hello]);
		expect(await hashes("q=HELLO")).toEqual([world, hello]);
		// LIKE's wildcards are matched as themselves.
		expect(await hashes("q=_")).toEqual([world]);
		expect(await hashes(`q=${openssl.slice(0, 8)}`)).toEqual([openssl]);
		expect(await hashes(`q=${encodeURIComponent(`/nix/store/${openssl}-openssl-3.0`)}`)).toEqual([openssl]);
		// The store directory isn't part of a path's name.
		expect(await hashes("q=store")).toEqual([]);

		const first = await search("limit=2");
		expect(first.paths.map((p) => [p.storePathHash, p.size])).toEqual([[openssl, 30], [world, 20]]);
		const rest = await search(`limit=2&before=${first.next}`);
		expect(rest).toMatchObject({ paths: [{ storePathHash: hello, size: 10, addedAt: expect.any(String) }], next: null });

		expect((await orgApi(`/${org}/caches/${unique("cache")}/paths`)).status).toBe(404);
		expect((await orgApi(`/${org}/caches/${cache}/paths?limit=0`)).status).toBe(400);
	});

	it("deletes a whole cache, freeing its storage and its name", async () => {
		const org = unique("org");
		const cache = unique("cache");
		expect((await orgApi(`/${org}`, "PUT", { slug: org, storageLimit: null })).status).toBe(200);
		expect((await orgApi(`/${org}/caches`, "POST", { name: cache })).status).toBe(201);
		const keep = unique("cache");
		expect((await orgApi(`/${org}/caches`, "POST", { name: keep })).status).toBe(201);
		const { token } = await (await orgApi(`/${org}/tokens`, "POST", { subject: "ci", caches: [cache, keep], perms: ["push"] })).json<{ token: string }>();
		const [a, b, c] = [storePathHash(), storePathHash(), storePathHash()];
		const shared = await nar(30);
		expect(await push(cache, a, await nar(10), token)).toBe(201);
		expect(await push(cache, b, shared, token)).toBe(201);
		expect(await push(keep, c, shared, token)).toBe(201);
		expect(await used(org)).toBe(70);
		// A staged key goes with its cache.
		expect((await orgApi(`/${org}/caches/${cache}/signing-keys`, "POST", {})).status).toBe(201);

		const res = await orgApi(`/${org}/caches/${cache}/delete`, "POST");
		expect(await res.json()).toEqual({ deleted: true, name: cache, paths: 2 });
		expect(await used(org)).toBe(30);
		expect((await orgApi(`/${org}/caches/${cache}`)).status).toBe(404);
		expect(await env.PUBLIC_BUCKET.head(`${org}/${cache}/nix-cache-info`)).toBeNull();
		expect(await env.PUBLIC_BUCKET.head(`${org}/${cache}/${a}.narinfo`)).toBeNull();
		expect((await SELF.fetch(`http://example.com/${org}/${cache}/${a}.narinfo`)).status).toBe(404);
		// The other cache and the NAR it shares are untouched, even after GC.
		await expireSessions(shared.fileHash);
		await runGarbageCollection(config);
		expect((await SELF.fetch(`http://example.com/${org}/${keep}/${c}.narinfo`)).status).toBe(200);
		expect(await findBlobObject(db, shared.fileHash, "zstd")).toBeDefined();

		// The name is free, and a cache made under it starts empty.
		const again = await orgApi(`/${org}/caches`, "POST", { name: cache });
		expect(await again.json()).toMatchObject({ created: true });
		expect(await (await orgApi(`/${org}/caches/${cache}`)).json()).toMatchObject({ paths: 0 });
		expect((await orgApi(`/${org}/caches/${unique("cache")}/delete`, "POST")).status).toBe(404);
	});

	it("answers 404 for a cache that doesn't exist, and needs the admin secret", async () => {
		expect((await deletePaths(unique("cache"), { storePathHashes: ["0".repeat(32)] })).status).toBe(404);
		const res = await SELF.fetch(`http://example.com/_api/v1/admin/caches/${unique("cache")}/paths/delete`, {
			method: "POST",
			headers: { authorization: "Bearer test-auth-token", "content-type": "application/json" },
			body: JSON.stringify({ storePathHashes: ["0".repeat(32)] }),
		});
		expect(res.status).toBe(403);
	});
});
