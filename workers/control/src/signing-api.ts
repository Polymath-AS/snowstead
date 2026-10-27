import * as v from "valibot";
import { and, eq } from "drizzle-orm";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import { findCache, findOrg } from "@snowstead/cache-core/db/repository";
import { caches, cacheSigningKeys } from "@snowstead/cache-core/db/schema";
import { importCacheKey, newCacheKey } from "@snowstead/cache-core/cache-keys";
import { signingPublicKey } from "@snowstead/cache-core/signing";
import { errorResponse, jsonResponse } from "@snowstead/cache-core/responses";
import { parseBody } from "@snowstead/cache-core/schemas";

const SigningRequest = v.object({
	secretKey: v.optional(v.string("invalid Nix secret key")),
	// Anything else is no confirmation, which activation refuses below.
	trustedPublicKeys: v.fallback(v.optional(v.array(v.string())), undefined),
}, "expected JSON object");

/** Authenticated by org-api; never serialize a row containing a sealed secret. */
export async function handleSigningApi(request: Request, config: WorkerConfig, org: string, name: string, id?: string): Promise<Response> {
	const cache = await findCache(config.db, org, name);
	if (!cache) return errorResponse("no cache", 404);
	const scope = eq(cacheSigningKeys.cacheId, cache.id);
	if (request.method === "GET" && !id) {
		return config.db.transaction(async tx => {
			const [locked] = await tx.select().from(caches).where(eq(caches.id, cache.id)).for("share");
			const rows = await tx.select().from(cacheSigningKeys).where(scope);
			const current = locked.signingPublicKey ?? await signingPublicKey(config.signingKeyName, config.signingPrivateKey);
			// shared: it signs with the service's key, which every cache without one of its own shares.
			return jsonResponse({ activePublicKey: current, shared: locked.signingPublicKey === null, keys: [
				...rows.map(k => ({ id: k.id, publicKey: k.signingPublicKey, state: k.state, createdAt: k.createdAt })),
				...(!rows.some(k => k.signingPublicKey === current) && current ? [{ id: null, publicKey: current, state: "active" }] : []),
			] });
		});
	}
	if (request.method !== "POST") return errorResponse("Not Found", 404);
	if (!await config.signingMasterKey()) return errorResponse("managed signing requires SIGNING_MASTER_KEY", 409);
	const body = await parseBody(request, SigningRequest);
	if (body instanceof Response) return body;
	const permission = await findOrg(config.db, org);
	if (!id) {
		let key;
		if (body.secretKey !== undefined) {
			if (!permission?.customSigningKeys) return errorResponse("custom signing keys are not allowed for this organization", 403);
			try { key = await importCacheKey(config, cache.id, body.secretKey); }
			catch { return errorResponse("invalid Nix secret key", 400); }
		} else {
			key = await newCacheKey(config, cache);
		}
		if (!key) return errorResponse("managed signing unavailable", 409);
		// Serialize with activation and other staging requests for this cache.
		const made = await config.db.transaction(async tx => {
			const [current] = await tx.select().from(caches).where(eq(caches.id, cache.id)).for("update");
			if (key.signingKeyName === current.signingKeyName || key.signingKeyName === config.signingKeyName) return false;
			const rows = await tx.insert(cacheSigningKeys).values({ cacheId: cache.id, ...key }).onConflictDoNothing().returning();
			return rows.length > 0;
		});
		return made ? jsonResponse({ id: key.id, publicKey: key.signingPublicKey, state: "staged" }, 201) : errorResponse("key name or managed public key already used", 409);
	}
	const result = await config.db.transaction(async tx => {
		const [current] = await tx.select().from(caches).where(eq(caches.id, cache.id)).for("update");
		const rows = await tx.select().from(cacheSigningKeys).where(scope);
		const target = rows.find(k => k.id === id);
		if (!target) return errorResponse("no signing key", 404);
		if (target.state !== "staged" || !target.signingKeySealed) return errorResponse("key is not staged", 409);
		if (!target.managedPublicKey && !permission?.customSigningKeys) return errorResponse("custom signing keys are not allowed for this organization", 403);
		const oldPublic = current.signingPublicKey ?? await signingPublicKey(config.signingKeyName, config.signingPrivateKey);
		const required = [...rows.map(k => k.signingPublicKey), ...(oldPublic ? [oldPublic] : [])];
		const trusted = body.trustedPublicKeys;
		if (!trusted || !required.every(k => trusted.includes(k))) {
			return errorResponse("confirm trustedPublicKeys includes all existing and staged public keys before activation", 409);
		}
		if (oldPublic && !rows.some(k => k.signingPublicKey === oldPublic)) {
			await tx.insert(cacheSigningKeys).values({ id: crypto.randomUUID(), cacheId: cache.id, signingKeyName: oldPublic.split(":")[0], signingPublicKey: oldPublic, state: "retired" });
		}
		await tx.update(cacheSigningKeys).set({ state: "retired", signingKeySealed: null }).where(and(scope, eq(cacheSigningKeys.state, "active")));
		await tx.update(cacheSigningKeys).set({ state: "active" }).where(eq(cacheSigningKeys.id, target.id));
		await tx.update(caches).set({ signingKeyName: target.signingKeyName, signingPublicKey: target.signingPublicKey, signingKeySealed: target.signingKeySealed }).where(eq(caches.id, cache.id));
		return jsonResponse({ id, publicKey: target.signingPublicKey, state: "active" });
	});
	return result;
}
