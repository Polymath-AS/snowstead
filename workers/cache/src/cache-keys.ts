import type { WorkerConfig } from "./config.js";
import type { Cache } from "./db/types.js";
import { findCacheById } from "./db/repository.js";

/**
 * Each cache signs its paths with a key of its own, so one leaking or being
 * revoked touches only that cache. The secret half is sealed with AES-GCM
 * under SIGNING_MASTER_KEY, bound to the cache's id, and the public half
 * is kept in the clear for showing. Caches from before this, and every
 * cache when no master key is set (self-hosting with one key), sign with
 * SIGNING_PRIVATE_KEY.
 */
export interface SigningKey {
	readonly name: string;
	/** A Nix secret key without its name: base64 of the seed then the public key. */
	readonly secret: string;
}

export interface NewCacheKey {
	readonly signingKeyName: string;
	readonly signingPublicKey: string;
	readonly signingKeySealed: string;
}

const encoder = new TextEncoder();
const SEALED_VERSION = "v1:";

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
	const key = await crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
	masterKey = { material, key };
	return key;
}

/**
 * A cache's key name: the service's, such as snowstead-1, with the cache's
 * path in it (snowstead-acme/main-1). Nix picks a trusted key by its name,
 * so names must not repeat across orgs, and a path doesn't.
 */
export function cacheKeyName(serviceKeyName: string, cachePath: string): string {
	const match = /^(.*)-(\d+)$/.exec(serviceKeyName);
	return match ? `${match[1]}-${cachePath}-${match[2]}` : `${serviceKeyName}-${cachePath}`;
}

function boundTo(cacheId: number): Uint8Array<ArrayBuffer> {
	return encoder.encode(`cache:${cacheId}`);
}

/** A key for a new cache, or null when no master key is set to seal one. */
export async function newCacheKey(config: WorkerConfig, cache: { readonly id: number; readonly path: string }): Promise<NewCacheKey | null> {
	if (!config.signingMasterKey) return null;

	const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
	if (!("privateKey" in pair)) throw new Error("Ed25519 generated no key pair");
	// PKCS#8 for Ed25519 ends with the 32-byte seed.
	const seed = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)).slice(-32);
	const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	const secret = new Uint8Array(64);
	secret.set(seed);
	secret.set(publicKey, 32);

	return sealCacheKey(config, cache.id, cacheKeyName(config.signingKeyName, cache.path), secret);
}

export async function importCacheKey(config: WorkerConfig, cacheId: number, material: string): Promise<NewCacheKey> {
	const match = /^([A-Za-z0-9][A-Za-z0-9._/+-]{0,199}):([A-Za-z0-9+/]{86}==)$/.exec(material);
	if (!match) throw new Error("invalid Nix secret key");
	const secret = unbase64(match[2]);
	if (secret.length !== 64 || base64(secret) !== match[2]) throw new Error("invalid Nix secret key");
	const prefix = new Uint8Array([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]);
	const pkcs8 = new Uint8Array(48);
	pkcs8.set(prefix); pkcs8.set(secret.slice(0, 32), 16);
	const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
	const publicKey = await crypto.subtle.importKey("raw", secret.slice(32), "Ed25519", false, ["verify"]);
	const challenge = encoder.encode("Snowstead Nix key import validation");
	if (!await crypto.subtle.verify("Ed25519", publicKey, await crypto.subtle.sign("Ed25519", privateKey, challenge), challenge)) {
		throw new Error("invalid Nix secret key");
	}
	return sealCacheKey(config, cacheId, match[1], secret);
}

async function sealCacheKey(config: WorkerConfig, cacheId: number, name: string, secret: Uint8Array<ArrayBuffer>): Promise<NewCacheKey> {
	if (!config.signingMasterKey) throw new Error("SIGNING_MASTER_KEY required");
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const sealed = new Uint8Array(await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv, additionalData: boundTo(cacheId) },
		await importMasterKey(config.signingMasterKey),
		secret,
	));
	const box = new Uint8Array(iv.length + sealed.length);
	box.set(iv);
	box.set(sealed, iv.length);

	return {
		signingKeyName: name,
		signingPublicKey: `${name}:${base64(secret.slice(32))}`,
		signingKeySealed: SEALED_VERSION + base64(box),
	};
}

async function unseal(config: WorkerConfig, cache: Cache): Promise<SigningKey | undefined> {
	if (!cache.signingKeySealed || !cache.signingKeyName) return undefined;
	if (!config.signingMasterKey || !cache.signingKeySealed.startsWith(SEALED_VERSION)) {
		// Signing such a cache with the service key would hand out paths its
		// users can't verify: better to fail the publish loudly.
		throw new Error(`cannot unseal the signing key of ${cache.name}`);
	}
	const box = unbase64(cache.signingKeySealed.slice(SEALED_VERSION.length));
	const secret = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: box.slice(0, 12), additionalData: boundTo(cache.id) },
		await importMasterKey(config.signingMasterKey),
		box.slice(12),
	);
	return { name: cache.signingKeyName, secret: base64(new Uint8Array(secret)) };
}

// Re-read the active sealed version at every publish. No isolate can keep
// selecting an obsolete key indefinitely after activation elsewhere.
const keys = new Map<number, { version: string; key: SigningKey }>();
const MAX_KEYS = 256;

/** The key a cache's narinfo is signed with. */
export async function signingKeyFor(config: WorkerConfig, cacheId: number): Promise<SigningKey> {
	const cache = await findCacheById(config.db, cacheId);
	if (!cache) throw new Error("no cache for signing");
	const version = JSON.stringify([cacheId, config.signingMasterKey, cache.signingKeyName, cache.signingKeySealed]);
	const known = keys.get(cacheId);
	if (known?.version === version) return known.key;
	keys.delete(cacheId);
	const own = await unseal(config, cache);
	const key = own ?? { name: config.signingKeyName, secret: config.signingPrivateKey };
	if (own) {
		if (keys.size >= MAX_KEYS) keys.delete(keys.keys().next().value!);
		keys.set(cacheId, { version, key: own });
	}
	return key;
}
