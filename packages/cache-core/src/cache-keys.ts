import type { WorkerConfig } from "./config.js";
import type { Cache } from "./db/types.js";
import { findCacheById } from "./db/repository.js";
import { importSigningKey } from "./signing.js";

/**
 * Each cache signs its paths with a key of its own, so one leaking or being
 * revoked touches only that cache. The secret half is sealed with AES-GCM
 * under SIGNING_MASTER_KEY, bound to its full identity, and the public half
 * is kept in the clear for showing. Shared-key signing is available only
 * with the explicit self-hosted opt-out from required per-cache keys.
 */
export interface SigningKey {
	readonly name: string;
	readonly key: CryptoKey | undefined;
}

export interface NewCacheKey {
	readonly id: string;
	readonly signingKeyName: string;
	readonly signingPublicKey: string;
	readonly signingKeySealed: string;
	/** Canonical public bytes for the managed-key uniqueness constraint. */
	readonly managedPublicKey: string | null;
}

const encoder = new TextEncoder();
const SEALED_VERSION = "v2";

function base64(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes));
}

function unbase64(text: string): Uint8Array<ArrayBuffer> {
	const binary = atob(text);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

let masterKey: { material: string; key: CryptoKey } | undefined;

async function importMasterKey(material: string): Promise<CryptoKey> {
	if (masterKey?.material === material) return masterKey.key;
	const bytes = unbase64(material);
	if (bytes.length !== 32) {
		throw new Error("SIGNING_MASTER_KEY must be 32 bytes, base64");
	}
	try {
		const key = await crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
		masterKey = { material, key };
		return key;
	} finally {
		bytes.fill(0);
	}
}

function boundTo(cacheId: number, id: string, name: string, publicKey: string): Uint8Array<ArrayBuffer> {
	return encoder.encode(JSON.stringify([SEALED_VERSION, cacheId, id, name, publicKey]));
}

/** A key for a new cache, or null when no master key is set to seal one. */
export async function newCacheKey(config: WorkerConfig, cache: { readonly id: number }): Promise<NewCacheKey | null> {
	if (!await config.signingMasterKey()) return null;

	const id = crypto.randomUUID();
	const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
	if (!("privateKey" in pair)) throw new Error("Ed25519 generated no key pair");
	// PKCS#8 for Ed25519 ends with the 32-byte seed.
	const exported = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
	const seed = exported.subarray(-32);
	const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	const secret = new Uint8Array(64);
	secret.set(seed);
	secret.set(publicKey, 32);

	try {
		return await sealCacheKey(config, cache.id, id, `${config.signingKeyName}-${cache.id}-${id}`, secret, true);
	} finally {
		exported.fill(0);
		secret.fill(0);
	}
}

export async function importCacheKey(config: WorkerConfig, cacheId: number, material: string): Promise<NewCacheKey> {
	const match = /^([A-Za-z0-9][A-Za-z0-9._/+-]{0,199}):([A-Za-z0-9+/]{86}==)$/.exec(material);
	if (!match) throw new Error("invalid Nix secret key");
	const secret = unbase64(match[2]);
	if (secret.length !== 64 || base64(secret) !== match[2]) throw new Error("invalid Nix secret key");
	const prefix = new Uint8Array([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]);
	const pkcs8 = new Uint8Array(48);
	pkcs8.set(prefix); pkcs8.set(secret.subarray(0, 32), 16);
	try {
		const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
		const publicKey = await crypto.subtle.importKey("raw", secret.subarray(32), "Ed25519", false, ["verify"]);
		const challenge = encoder.encode("Snowstead Nix key import validation");
		if (!await crypto.subtle.verify("Ed25519", publicKey, await crypto.subtle.sign("Ed25519", privateKey, challenge), challenge)) {
			throw new Error("invalid Nix secret key");
		}
		return await sealCacheKey(config, cacheId, crypto.randomUUID(), match[1], secret, false);
	} finally {
		secret.fill(0);
		pkcs8.fill(0);
	}
}

async function sealCacheKey(config: WorkerConfig, cacheId: number, id: string, name: string, secret: Uint8Array<ArrayBuffer>, managed: boolean): Promise<NewCacheKey> {
	const master = await config.signingMasterKey();
	if (!master) throw new Error("SIGNING_MASTER_KEY required");
	const publicBytes = base64(secret.slice(32));
	const publicKey = `${name}:${publicBytes}`;
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const sealed = new Uint8Array(await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv, additionalData: boundTo(cacheId, id, name, publicKey) },
		await importMasterKey(master),
		secret,
	));
	const box = new Uint8Array(iv.length + sealed.length);
	box.set(iv);
	box.set(sealed, iv.length);

	return {
		id,
		signingKeyName: name,
		signingPublicKey: publicKey,
		signingKeySealed: `${SEALED_VERSION}:${id}:${base64(box)}`,
		managedPublicKey: managed ? publicBytes : null,
	};
}

async function unseal(config: WorkerConfig, cache: Cache): Promise<SigningKey> {
	if (!cache.signingKeySealed || !cache.signingKeyName || !cache.signingPublicKey) throw new Error("incomplete signing key");
	const [version, id, material] = cache.signingKeySealed.split(":");
	const master = await config.signingMasterKey();
	if (!master || (version !== SEALED_VERSION && version !== "v1")) {
		// Signing such a cache with the service key would hand out paths its
		// users can't verify: better to fail the publish loudly.
		throw new Error(`cannot unseal the signing key of ${cache.name}`);
	}
	// Existing v1 keys must keep working: changing their public key would
	// invalidate clients' trust. New keys authenticate their full identity.
	const box = unbase64(version === "v1" ? id : material);
	const secret = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: box.slice(0, 12), additionalData: version === "v1"
			? encoder.encode(`cache:${cache.id}`)
			: boundTo(cache.id, id, cache.signingKeyName, cache.signingPublicKey) },
		await importMasterKey(master),
		box.slice(12),
	);
	const bytes = new Uint8Array(secret);
	try {
		return { name: cache.signingKeyName, key: await importSigningKey(bytes) };
	} finally {
		bytes.fill(0);
	}
}

// Re-read the active sealed version at every publish. No isolate can keep
// selecting an obsolete key indefinitely after activation elsewhere.
const keys = new Map<number, { version: string; master: CryptoKey; key: Promise<SigningKey> }>();
const MAX_KEYS = 256;
// Only the explicitly configured self-hosted service key remains in env.
let shared: { material: string; key: Promise<CryptoKey> } | undefined;

/** The key a cache's narinfo is signed with. */
export async function signingKeyFor(config: WorkerConfig, cacheId: number): Promise<SigningKey> {
	const cache = await findCacheById(config.db, cacheId);
	if (!cache) throw new Error("no cache for signing");
	if (cache.signingKeySealed || cache.signingKeyName || cache.signingPublicKey) {
		const master = await importMasterKey(await config.signingMasterKey());
		const version = JSON.stringify([cache.signingKeyName, cache.signingPublicKey, cache.signingKeySealed]);
		const known = keys.get(cacheId);
		if (known?.version === version && known.master === master) return known.key;
		const pending = { version, master, key: unseal(config, cache) };
		if (keys.size >= MAX_KEYS) keys.delete(keys.keys().next().value!);
		keys.set(cacheId, pending);
		try { return await pending.key; }
		catch (error) {
			if (keys.get(cacheId) === pending) keys.delete(cacheId);
			throw error;
		}
	}
	if (config.requireCacheSigningKeys) throw new Error("this cache requires its own signing key");
	if (!config.signingPrivateKey) return { name: config.signingKeyName, key: undefined };
	if (shared?.material !== config.signingPrivateKey) {
		const bytes = unbase64(config.signingPrivateKey);
		shared = { material: config.signingPrivateKey, key: importSigningKey(bytes).finally(() => bytes.fill(0)) };
	}
	return { name: config.signingKeyName, key: await shared.key };
}
