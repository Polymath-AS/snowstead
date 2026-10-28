import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { handleDownload, type DownloadConfig } from "../src/download.js";
import downloadEntry from "../../../workers/download/src/index.js";
import byteEntry from "../../../workers/bytes/src/index.js";
import { handleRequest as handleNixRequest } from "../../../workers/nix/src/router.js";
import type { WorkerConfig } from "../src/config.js";
import { signJwt, type TokenClaims } from "../src/jwt.js";
import { claimsDigest } from "../src/credentials.js";
import {
	publicationKey, publicationUrl, routeKey, statusKey, grantKey, tokenKey, witnessKey, LEGACY_KEY_POLICY,
	type ActiveGrant, type CacheStatus, type RouteRecord,
} from "../src/publication-protocol.js";

const cacheId = 900001;
const orgId = "org_download_test";
const path = "download-test/main";
const body = "A17_bcZ!890";
const command = () => ({ version: 2 as const, nonce: crypto.randomUUID(), operationId: crypto.randomUUID() });
let grant: ActiveGrant;
let status: CacheStatus;
let route: RouteRecord;
let claims: TokenClaims;
let token: string;
const config: DownloadConfig = {
	authority: env.CACHE_BUCKET, privateBucket: env.CACHE_BUCKET, publicBucket: env.PUBLIC_BUCKET,
	jwtSecret: "download-test-secret",
};

async function write(key: string, record: unknown) { await env.CACHE_BUCKET.put(key, JSON.stringify(record)); }
function request(resource = publicationUrl(grant), headers: HeadersInit = {}, method = "GET") {
	return new Request(`https://cache.invalid/${path}/${resource}`, { method, headers });
}
const auth = () => ({ authorization: `Basic ${btoa(`nix:${token}`)}` });

beforeEach(async () => {
	grant = { ...command(), orgId, cacheId, epoch: crypto.randomUUID(), storePathHash: "5".repeat(32),
		state: "active", publicationId: crypto.randomUUID(), fileHash: "c".repeat(64), compression: "none",
		fileSize: body.length, narinfoSize: 7, narEtag: '"nar-download-test"', narinfoEtag: '"info-download-test"',
		publishedAt: 1_750_000_001 };
	status = { ...command(), orgId, cacheId, epoch: grant.epoch, name: "main", visibility: "private", state: "active" };
	route = { ...command(), orgId, cacheId, path, state: "active" };
	claims = { jti: crypto.randomUUID(), sub: "download-test", iss: "snowstead", aud: "snowstead",
		org: orgId, caches: [`id:${cacheId}`], perms: ["pull"], iat: Math.floor(Date.now() / 1000) };
	token = await signJwt(claims, config.jwtSecret);
	await write(routeKey(path), route);
	await write(statusKey(cacheId), status);
	await write(grantKey(cacheId, status.epoch, grant.storePathHash), grant);
	await write(tokenKey(claims.jti), { ...command(), jti: claims.jti, state: "active", claimsDigest: await claimsDigest(claims) });
	await write(LEGACY_KEY_POLICY, { ...command(), keyId: "legacy-hs256", state: "active" });
	for (const bucket of [env.CACHE_BUCKET, env.PUBLIC_BUCKET]) {
		await bucket.put(publicationKey(grant, "nar"), body);
		await bucket.put(publicationKey(grant, "narinfo"), "narinfo");
	}
});

describe("fresh publication admission", () => {
	it("cuts over direct Nix ingress without SQL, KV, or deferred accounting on public and private reads", async () => {
		const reader = new Proxy({ publicationReads: true, bucket: config.authority,
			publicBucket: config.publicBucket, jwtSecret: config.jwtSecret } as WorkerConfig, {
			get(target, property, receiver) {
				if (["db", "authKv", "defer"].includes(String(property))) throw new Error(`Forbidden read dependency: ${String(property)}`);
				return Reflect.get(target, property, receiver);
			},
		});
		for (const visibility of ["private", "public"] as const) {
			await write(statusKey(cacheId), { ...status, visibility });
			const response = await handleNixRequest(request(undefined, visibility === "private" ? auth() : {}), reader);
			expect(response.status).toBe(200);
			expect(await response.text()).toBe(body);
			expect((await handleNixRequest(request(undefined, auth(), "HEAD"), reader)).status).toBe(200);
		}
		await write(grantKey(cacheId, status.epoch, grant.storePathHash), {
			...command(), orgId, cacheId, epoch: status.epoch, storePathHash: grant.storePathHash, state: "tombstone",
		});
		expect((await handleNixRequest(request(undefined, auth()), reader)).status).toBe(404);
	});
	it("serves non-expiring tokens as netrc Basic and Bearer without SQL bindings", async () => {
		for (const headers of [auth(), { authorization: `Bearer ${token}` }]) {
			const response = await handleDownload(request(undefined, headers), config);
			expect(response.status).toBe(200);
			expect(await response.text()).toBe(body);
			expect(response.headers.get("cache-control")).toBe("private, no-store");
		}
	});
	it.each([
		{ method: "GET", headers: {} }, { method: "HEAD", headers: {} },
		{ method: "GET", headers: { range: "bytes=2-4" } },
		{ method: "GET", headers: { "if-none-match": '"nar-download-test"' } },
		{ method: "GET", headers: { "if-match": '"wrong"' } },
	])("rechecks revoked token before $method with $headers", async ({ method, headers }) => {
		const warm = await handleDownload(request(undefined, auth()), config);
		expect(warm.status).toBe(200); await warm.body?.cancel();
		await write(tokenKey(claims.jti), { ...command(), jti: claims.jti, state: "revoked", claimsDigest: await claimsDigest(claims) });
		const response = await handleDownload(request(undefined, { ...headers, ...auth() }, method), config);
		expect(response.status).toBe(401);
		expect(response.headers.get("etag")).toBeNull();
		expect(response.headers.get("cloudflare-cdn-cache-control")).toBe("no-store");
	});
	it("does not enroll unknown or colliding JTIs from a valid signature", async () => {
		const changed = await signJwt({ ...claims, caches: ["*"], perms: ["pull", "push"] }, config.jwtSecret);
		expect((await handleDownload(request(undefined, { authorization: `Bearer ${changed}` }), config)).status).toBe(401);
		await env.CACHE_BUCKET.delete(tokenKey(claims.jti));
		expect((await handleDownload(request(undefined, auth()), config)).status).toBe(401);
	});
	it("denies key withdrawal even with a previously verified token", async () => {
		await (await handleDownload(request(undefined, auth()), config)).body?.cancel();
		await write(LEGACY_KEY_POLICY, { ...command(), keyId: "legacy-hs256", state: "revoked" });
		expect((await handleDownload(request(undefined, auth()), config)).status).toBe(401);
	});
	it.each(["pull", "scope", "org"])("preserves signed %s restrictions even when policy enrolls the token", async (restriction) => {
		const limited: TokenClaims = { ...claims,
			perms: restriction === "pull" ? ["push"] : ["pull"],
			caches: restriction === "scope" ? ["id:123"] : claims.caches,
			org: restriction === "org" ? "org_someone_else" : orgId };
		token = await signJwt(limited, config.jwtSecret);
		await write(tokenKey(claims.jti), { ...command(), jti: claims.jti, state: "active", claimsDigest: await claimsDigest(limited) });
		expect((await handleDownload(request(undefined, auth()), config)).status).toBe(403);
	});
	it("denies deleted grants despite existing bytes and conditional requests", async () => {
		await write(grantKey(cacheId, status.epoch, grant.storePathHash), {
			...command(), orgId, cacheId, epoch: status.epoch, storePathHash: grant.storePathHash, state: "tombstone",
		});
		expect((await handleDownload(request(undefined, { ...auth(), "if-none-match": grant.narEtag }), config)).status).toBe(404);
	});
	it.each(["orgId", "cacheId", "epoch", "storePathHash"] as const)("rejects a grant whose %s disagrees with its key/status", async (field) => {
		const wrong = { ...grant, [field]: field === "cacheId" ? cacheId + 1 : field === "epoch" ? crypto.randomUUID() : field === "storePathHash" ? "6".repeat(32) : "org_other" };
		await write(grantKey(cacheId, status.epoch, grant.storePathHash), wrong);
		expect((await handleDownload(request(undefined, auth()), config)).status).toBe(404);
	});
	it("serves anonymous public content only while route, status, and grant are active", async () => {
		await write(statusKey(cacheId), { ...status, visibility: "public" });
		const response = await handleDownload(request(), config);
		expect(await response.text()).toBe(body);
		await write(statusKey(cacheId), { ...status, visibility: "public", state: "retired" });
		expect((await handleDownload(request(), config)).status).toBe(404);
	});
	it("makes stale legacy witnesses fail closed after their path is withdrawn", async () => {
		await write(witnessKey(cacheId, status.epoch, grant.fileHash, grant.compression), {
			...command(), orgId, cacheId, epoch: status.epoch, storePathHash: grant.storePathHash,
			publicationId: grant.publicationId, fileHash: grant.fileHash, compression: grant.compression,
		});
		const legacy = `nar/${grant.fileHash}/${grant.compression}.nar`;
		const response = await handleDownload(request(legacy, auth()), config);
		expect(await response.text()).toBe(body);
		await write(grantKey(cacheId, status.epoch, grant.storePathHash), { ...grant, publicationId: crypto.randomUUID() });
		expect((await handleDownload(request(legacy, auth()), config)).status).toBe(404);
	});
	it.each([undefined, { ...command(), state: "active", orgId, cacheId, path, version: 99 }, { ...command(), state: "active", orgId, cacheId, path, objectKey: "authority/secret" }])("fails closed on absent/unknown/conflicting route authority", async (record) => {
		if (record === undefined) await env.CACHE_BUCKET.delete(routeKey(path));
		else await write(routeKey(path), record);
		const response = await handleDownload(request(undefined, auth()), config);
		expect(response.status).toBe(record === undefined ? 404 : 503);
	});
	it("does not expose an unscoped global NAR URL", async () => {
		expect((await handleDownload(new Request(`https://cache.invalid/nar/${grant.fileHash}/none.nar`), config)).status).toBe(404);
	});
	it("maps owner hosts to canonical identity but rejects foreign hosts", async () => {
		const bindings = { AUTHORITY: env.CACHE_BUCKET, PRIVATE_BYTES: env.CACHE_BUCKET, PUBLIC_BYTES: env.PUBLIC_BUCKET,
			JWT_SECRET: config.jwtSecret, OWNER_HOST_SUFFIX: ".snowstead.test", CANONICAL_HOST: "cache.snowstead.test", BYTE_NAMESPACE: "test-v2" };
		const response = await downloadEntry.fetch(new Request(`https://download-test.snowstead.test/main/${publicationUrl(grant)}`, { headers: auth() }), bindings);
		expect(response.status).toBe(200); expect(await response.text()).toBe(body);
		expect((await downloadEntry.fetch(new Request(`https://attacker.invalid/main/${publicationUrl(grant)}`), bindings)).status).toBe(404);
	});
	it("restricts the binding-only byte service to structured data keys", async () => {
		const bindings = { PRIVATE_BYTES: env.CACHE_BUCKET, PUBLIC_BYTES: env.PUBLIC_BUCKET, BYTE_NAMESPACE: "test-v2" };
		const response = await byteEntry.fetch(new Request(`https://bytes.internal/test-v2/private/${publicationKey(grant, "nar")}`), bindings);
		expect(await response.text()).toBe(body);
		expect((await byteEntry.fetch(new Request(`https://bytes.internal/test-v2/private/${tokenKey(claims.jti)}`), bindings)).status).toBe(404);
	});
});
