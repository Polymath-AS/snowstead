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

/** Import transient Nix key material as a non-extractable signing-only key. */
export async function importSigningKey(keyBytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
	pkcs8.set(PKCS8_ED25519_PREFIX);
	pkcs8.set(keyBytes.subarray(0, 32), PKCS8_ED25519_PREFIX.length);
	try {
		return await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
	} finally {
		pkcs8.fill(0);
	}
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
	key: CryptoKey | undefined,
): Promise<string> {
	if (!key) {
		return "";
	}

	const data = textEncoder.encode(fingerprint);
	const signature = await crypto.subtle.sign("Ed25519", key, data);
	const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

	return `${keyName}:${sigBase64}`;
}
