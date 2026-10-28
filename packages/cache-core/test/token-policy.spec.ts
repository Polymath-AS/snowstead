import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { enrollToken, revokeTokenPolicy, initializeVerifierKey, revokeVerifierKey, enrollLegacyToken, recoverTokenPolicies } from "../src/token-policy.js";
import { resolveConfig, type WorkerConfig } from "../src/config.js";
import { TokenPolicy, KeyPolicy, LEGACY_KEY_POLICY, readAuthority, tokenKey } from "../src/publication-protocol.js";
import { claimsDigest } from "../src/credentials.js";
import { isRevoked, recordRevocation } from "../src/revocations.js";
import type { TokenClaims } from "../src/jwt.js";
import { signJwt } from "../src/jwt.js";
import { apiTokens, authorityJournal } from "../src/db/schema.js";
import { createApiToken, revokeApiToken } from "../src/db/repository.js";
import { AuthorityJournal } from "../src/authority-journal.js";

let config: WorkerConfig;
let claims: TokenClaims;
beforeEach(() => {
	config = resolveConfig(env);
	claims = { jti: crypto.randomUUID(), sub: "policy-test", iss: "snowstead", aud: "snowstead", org: "org_policy_test",
		caches: ["id:17", "ci-*"], perms: ["pull"], iat: Math.floor(Date.now() / 1000) };
});
afterEach(async () => { await config.close(); });

function withPut(put: R2Bucket["put"]): WorkerConfig {
	const bucket = new Proxy(config.bucket, { get(target, key) {
		if (key === "put") return put;
		const value = Reflect.get(target, key);
		return typeof value === "function" ? value.bind(target) : value;
	} });
	return { ...config, bucket };
}

describe("durable token issuance and revocation policy", () => {
	it("enrolls exact non-expiring claims idempotently and permanently revokes them", async () => {
		expect(await enrollToken(config, claims)).toEqual({ state: "committed" });
		const original = await readAuthority(config.bucket, tokenKey(claims.jti), TokenPolicy);
		expect(original).toMatchObject({ state: "active", jti: claims.jti, claimsDigest: await claimsDigest(claims) });
		expect(await enrollToken(config, claims)).toEqual({ state: "committed" });
		expect(await readAuthority(config.bucket, tokenKey(claims.jti), TokenPolicy)).toEqual(original);
		expect(await revokeTokenPolicy(config, claims.jti)).toEqual({ state: "committed" });
		expect(await isRevoked(config, claims.jti)).toBe(true);
		await expect(enrollToken(config, claims)).rejects.toThrow("revoked JTI");
	});
	it("rejects broader claims reusing an enrolled JTI", async () => {
		await enrollToken(config, claims);
		await expect(enrollToken(config, { ...claims, caches: ["*"], perms: ["pull", "push"] })).rejects.toThrow("identity mismatch");
	});
	it("retains revocation inside the verifier's expiry skew window", async () => {
		claims = { ...claims, iat: claims.iat - 3600, exp: claims.iat - 1 };
		await enrollToken(config, claims);
		expect(await recordRevocation(config, claims.jti)).toEqual({ state: "committed" });
		expect(await isRevoked(config, claims.jti)).toBe(true);
		const object = await config.bucket.head(tokenKey(claims.jti));
		expect(object).not.toBeNull();
	});
	it("makes an unknown token's tombstone prohibit later enrollment", async () => {
		expect(await revokeTokenPolicy(config, claims.jti)).toEqual({ state: "committed" });
		await expect(enrollToken(config, claims)).rejects.toThrow("revoked JTI");
	});
	it("fences an absent-but-unresolved active PUT before acknowledging revocation", async () => {
		let delayed: (() => Promise<R2Object | null>) | undefined;
		const unknown = withPut(async (...args) => {
			delayed = () => env.CACHE_BUCKET.put(...args);
			throw new Error("unknown PUT outcome");
		});
		expect(await enrollToken(unknown, claims)).toMatchObject({ state: "pending" });
		expect(await config.bucket.head(tokenKey(claims.jti))).toBeNull();
		expect(await revokeTokenPolicy(config, claims.jti)).toEqual({ state: "committed" });
		expect(await delayed!()).toBeNull();
		expect(await isRevoked(config, claims.jti)).toBe(true);
	});
	it("records a lost-response creation that won before applying revocation", async () => {
		const unknown = withPut(async (...args) => {
			await env.CACHE_BUCKET.put(...args);
			throw new Error("accepted response lost");
		});
		expect(await enrollToken(unknown, claims)).toMatchObject({ state: "pending" });
		expect((await readAuthority(config.bucket, tokenKey(claims.jti), TokenPolicy))?.state).toBe("active");
		expect(await revokeTokenPolicy(config, claims.jti)).toEqual({ state: "committed" });
		expect(await isRevoked(config, claims.jti)).toBe(true);
	});
	it("does not call an unknown revocation completed while its predecessor remains", async () => {
		await enrollToken(config, claims);
		const unknown = withPut(async () => { throw new Error("unknown PUT outcome"); });
		expect(await revokeTokenPolicy(unknown, claims.jti)).toMatchObject({ state: "pending" });
		expect(await isRevoked(config, claims.jti)).toBe(false);
		expect(await revokeTokenPolicy(config, claims.jti)).toEqual({ state: "committed" });
		expect(await isRevoked(config, claims.jti)).toBe(true);
	});
});

describe("controlled verifier key policy", () => {
	beforeEach(async () => {
		// The singleton key is disposable test state, never production state.
		await config.db.delete(authorityJournal).where(eq(authorityJournal.resourceKey, LEGACY_KEY_POLICY));
		await config.bucket.delete(LEGACY_KEY_POLICY);
	});
	it("requires explicit initialization, is idempotent, and cannot resurrect", async () => {
		expect(await readAuthority(config.bucket, LEGACY_KEY_POLICY, KeyPolicy)).toBeUndefined();
		expect(await initializeVerifierKey(config)).toEqual({ state: "committed" });
		const original = await readAuthority(config.bucket, LEGACY_KEY_POLICY, KeyPolicy);
		expect(original?.state).toBe("active");
		await initializeVerifierKey(config);
		expect(await readAuthority(config.bucket, LEGACY_KEY_POLICY, KeyPolicy)).toEqual(original);
		await revokeVerifierKey(config);
		await expect(initializeVerifierKey(config)).rejects.toThrow("revoked verifier key");
		expect((await readAuthority(config.bucket, LEGACY_KEY_POLICY, KeyPolicy))?.state).toBe("revoked");
	});
	it("can revoke before initialization and requires a configured secret to initialize", async () => {
		await expect(initializeVerifierKey({ ...config, jwtSecret: undefined })).rejects.toThrow("not configured");
		await revokeVerifierKey(config);
		await expect(initializeVerifierKey(config)).rejects.toThrow("revoked verifier key");
	});
	it("recovers initialization after the active PUT response was lost", async () => {
		expect(await initializeVerifierKey(withPut(async (...args) => {
			await env.CACHE_BUCKET.put(...args);
			throw new Error("lost response");
		}))).toMatchObject({ state: "pending" });
		expect(await recoverTokenPolicies(config)).toContainEqual({ state: "committed" });
		expect((await readAuthority(config.bucket, LEGACY_KEY_POLICY, KeyPolicy))?.state).toBe("active");
		expect(await initializeVerifierKey(config)).toEqual({ state: "committed" });
	});
	it("fences delayed initialization and recovers a lost revocation response", async () => {
		let delayed: (() => Promise<R2Object | null>) | undefined;
		expect(await initializeVerifierKey(withPut(async (...args) => {
			delayed = () => env.CACHE_BUCKET.put(...args);
			throw new Error("delayed");
		}))).toMatchObject({ state: "pending" });
		expect(await revokeVerifierKey(withPut(async (...args) => {
			await env.CACHE_BUCKET.put(...args);
			throw new Error("lost response");
		}))).toMatchObject({ state: "pending" });
		expect(await delayed!()).toBeNull();
		expect(await recoverTokenPolicies(config)).toContainEqual({ state: "committed" });
		await expect(initializeVerifierKey(config)).rejects.toThrow("revoked verifier key");
	});
});

describe("controlled legacy enrollment", () => {
	async function inventory() {
		claims = { ...claims, org: undefined, caches: ["ci-*", "main"] };
		await createApiToken(config.db, { jti: claims.jti, subject: claims.sub, caches: claims.caches,
			permsJson: JSON.stringify(claims.perms), expiresAt: claims.exp === undefined ? null : new Date(claims.exp * 1000), createdBy: "test" });
		await config.db.update(apiTokens).set({ createdAt: new Date(claims.iat * 1000) }).where(eq(apiTokens.jti, claims.jti));
	}
	const signed = () => signJwt(claims, config.jwtSecret!);
	it("enrolls signed inventoried non-expiring claims only", async () => {
		await expect(enrollLegacyToken(config, await signed())).rejects.toThrow("inventory");
		await inventory();
		await expect(enrollLegacyToken(config, await signJwt(claims, "wrong secret"))).rejects.toThrow("Invalid legacy token");
		expect(await enrollLegacyToken(config, await signed())).toEqual({ state: "committed" });
		expect((await readAuthority(config.bucket, tokenKey(claims.jti), TokenPolicy))?.claimsDigest).toBe(await claimsDigest(claims));
	});
	it.each(["sub", "org", "caches", "perms", "exp", "iat"] as const)("rejects inventory mismatch in %s", async (field) => {
		await inventory();
		const changed = { ...claims, [field]: { sub: "other", org: "other", caches: ["*"], perms: ["pull", "push"],
			exp: claims.iat + 3600, iat: claims.iat - 120 }[field] };
		await expect(enrollLegacyToken(config, await signJwt(changed, config.jwtSecret!))).rejects.toThrow("inventory mismatch");
		expect(await config.bucket.head(tokenKey(claims.jti))).toBeNull();
	});
	it.each(["sql", "kv", "r2"])("rejects %s-revoked inventory", async (store) => {
		await inventory();
		if (store === "sql") await revokeApiToken(config.db, claims.jti, "test", "test");
		if (store === "kv") await config.authKv.put(`revoked/${claims.jti}`, "1");
		if (store === "r2") await revokeTokenPolicy(config, claims.jti);
		await expect(enrollLegacyToken(config, await signed())).rejects.toThrow(/revoked/);
	});
	it("allows exp+60 skew but not expired credentials", async () => {
		claims = { ...claims, iat: claims.iat - 3600, exp: claims.iat - 10 };
		await inventory();
		expect(await enrollLegacyToken(config, await signed())).toEqual({ state: "committed" });
		claims = { ...claims, jti: crypto.randomUUID(), exp: Math.floor(Date.now() / 1000) - 61 };
		await inventory();
		await expect(enrollLegacyToken(config, await signed())).rejects.toThrow(/Invalid legacy token|Expired legacy token/);
	});
});

describe("bounded token recovery", () => {
	it("recovers lost accepted issuance responses and rejects unbounded work", async () => {
		expect(await enrollToken(withPut(async (...args) => {
			await env.CACHE_BUCKET.put(...args); throw new Error("lost response");
		}), claims)).toMatchObject({ state: "pending" });
		expect((await recoverTokenPolicies(config, 1)).length).toBe(1);
		await expect(recoverTokenPolicies(config, 101)).rejects.toThrow("limit");
		await expect(recoverTokenPolicies(config, 0)).rejects.toThrow("limit");
	});
	it("retains revocation intent if the original won and settlement preceded a crash", async () => {
		const pending = await enrollToken(withPut(async (...args) => {
			await env.CACHE_BUCKET.put(...args); throw new Error("lost response");
		}), claims);
		if (pending.state === "committed") throw new Error("expected pending");
		const journal = new AuthorityJournal(config.db, config.bucket);
		const operation = await journal.read(pending.operationId);
		await journal.fence(operation.operationId, JSON.stringify({ ...JSON.parse(operation.successor), state: "revoked", nonce: crypto.randomUUID() }));
		expect((await journal.recover(operation.operationId)).state).toBe("accepted");
		await recoverTokenPolicies(config);
		expect(await isRevoked(config, claims.jti)).toBe(true);
		await expect(enrollToken(config, claims)).rejects.toThrow("revoked JTI");
	});
});
