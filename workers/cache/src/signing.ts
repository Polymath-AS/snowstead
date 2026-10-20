import type { PublishedPath } from "./db/types.js";

const textEncoder = new TextEncoder();

export function computeFingerprint(path: Pick<PublishedPath, "storePath" | "narHash" | "narSize">, refs: readonly string[]): string {
	const refPaths = refs.map(r => `/nix/store/${r}`);
	return `1;${path.storePath};${path.narHash};${path.narSize};${refPaths.join(",")}`;
}

const PKCS8_ED25519_PREFIX = new Uint8Array([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

let cachedKeyMaterial: string | undefined;
let cachedKey: CryptoKey | undefined;

async function getSigningKey(privateKeyBase64: string): Promise<CryptoKey> {
	if (cachedKey && cachedKeyMaterial === privateKeyBase64) {
		return cachedKey;
	}

	const keyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
	const seed = keyBytes.slice(0, 32);
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
	pkcs8.set(PKCS8_ED25519_PREFIX);
	pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
	const pkcs8Buffer = new ArrayBuffer(pkcs8.byteLength);
	new Uint8Array(pkcs8Buffer).set(pkcs8);

	const key = await crypto.subtle.importKey(
		"pkcs8",
		pkcs8Buffer,
		{ name: "Ed25519" },
		false,
		["sign"],
	);

	cachedKeyMaterial = privateKeyBase64;
	cachedKey = key;
	return key;
}

/**
 * The `name:base64` public key Nix needs in trusted-public-keys, or null when
 * no signing key is set. A Nix secret key holds the seed and then the public
 * key; a bare 32-byte seed has its public key derived.
 */
export async function signingPublicKey(keyName: string, privateKeyBase64: string): Promise<string | null> {
	if (!privateKeyBase64) {
		return null;
	}

	const keyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
	if (keyBytes.length === 64) {
		return `${keyName}:${btoa(String.fromCharCode(...keyBytes.slice(32)))}`;
	}

	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
	pkcs8.set(PKCS8_ED25519_PREFIX);
	pkcs8.set(keyBytes.slice(0, 32), PKCS8_ED25519_PREFIX.length);
	const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
	const jwk = await crypto.subtle.exportKey("jwk", key);
	if (jwk.x === undefined) {
		throw new Error("Ed25519 key exported without a public part");
	}
	const publicBase64 = jwk.x.replaceAll("-", "+").replaceAll("_", "/").padEnd(44, "=");

	return `${keyName}:${publicBase64}`;
}

export async function signNarinfo(
	fingerprint: string,
	keyName: string,
	privateKeyBase64: string,
): Promise<string> {
	if (!privateKeyBase64) {
		return "";
	}

	const key = await getSigningKey(privateKeyBase64);
	const data = textEncoder.encode(fingerprint);
	const signature = await crypto.subtle.sign("Ed25519", key, data);
	const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

	return `${keyName}:${sigBase64}`;
}
