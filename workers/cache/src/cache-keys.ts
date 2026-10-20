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

	const iv = crypto.getRandomValues(new Uint8Array(12));
	const sealed = new Uint8Array(await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv, additionalData: boundTo(cache.id) },
		await importMasterKey(config.signingMasterKey),
		secret,
	));
	const box = new Uint8Array(iv.length + sealed.length);
	box.set(iv);
	box.set(sealed, iv.length);

	const name = cacheKeyName(config.signingKeyName, cache.path);
	return {
		signingKeyName: name,
		signingPublicKey: `${name}:${base64(publicKey)}`,
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

// Keys never change once a cache has one, so isolates keep them.
const keys = new Map<number, SigningKey>();
const MAX_KEYS = 10_000;

/** The key a cache's narinfo is signed with. */
export async function signingKeyFor(config: WorkerConfig, cacheId: number): Promise<SigningKey> {
	const known = keys.get(cacheId);
	if (known) return known;

	const cache = await findCacheById(config.db, cacheId);
	const own = cache ? await unseal(config, cache) : undefined;
	const key = own ?? { name: config.signingKeyName, secret: config.signingPrivateKey };
	if (own) {
		if (keys.size >= MAX_KEYS) keys.clear();
		keys.set(cacheId, own);
	}
	return key;
}
