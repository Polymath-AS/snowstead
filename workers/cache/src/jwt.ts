import type { TokenPermission } from "./db/types.js";

export type TokenClaims = {
	readonly jti: string;
	readonly sub: string;
	readonly iss: string;
	readonly aud: string;
	readonly caches: readonly string[];
	readonly perms: readonly TokenPermission[];
	readonly exp: number;
	readonly iat: number;
};

export type JwtVerifyResult =
	| { readonly kind: "ok"; readonly claims: TokenClaims }
	| { readonly kind: "error"; readonly reason: string };

function base64UrlEncode(data: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < data.length; i++) {
		binary += String.fromCharCode(data[i]);
	}
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(str: string): Uint8Array {
	const base64 = str.replaceAll("-", "+").replaceAll("_", "/");
	const paddingNeeded = (4 - (base64.length % 4)) % 4;
	const padded = paddingNeeded > 0 ? base64 + "====".slice(0, paddingNeeded) : base64;
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

const HMAC_ALGO = { name: "HMAC", hash: "SHA-256" } as const;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Cache the imported CryptoKey at module scope. Workers isolates are reused
// across requests on the same edge node, so this avoids a costly importKey
// call on every verify.
let cachedSecret = "";
let cachedKey: CryptoKey | undefined;

async function getKey(secret: string): Promise<CryptoKey> {
	if (secret === cachedSecret && cachedKey !== undefined) {
		return cachedKey;
	}
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		HMAC_ALGO,
		false,
		["sign", "verify"],
	);
	cachedSecret = secret;
	cachedKey = key;
	return key;
}

const EXPECTED_HEADER_JSON = '{"alg":"HS256","typ":"JWT"}';
const HEADER_B64 = base64UrlEncode(encoder.encode(EXPECTED_HEADER_JSON));
export const TOKEN_ISSUER = "helios-cache";
export const TOKEN_AUDIENCE = "helios-cache";
const MAX_TOKEN_BYTES = 4096;
const MAX_CLOCK_SKEW_SECONDS = 60;
export const MAX_CACHES_PER_TOKEN = 50;
export const MAX_PERMS_PER_TOKEN = 10;

export const VALID_PERMISSIONS: ReadonlySet<string> = new Set<string>(["pull", "push"]);

export function isTokenPermission(value: string): value is TokenPermission {
	return VALID_PERMISSIONS.has(value);
}

function validateClaims(obj: Record<string, unknown>): JwtVerifyResult {
	const jti = obj["jti"];
	if (typeof jti !== "string" || jti.length === 0) {
		return { kind: "error", reason: "invalid token" };
	}

	const sub = obj["sub"];
	if (typeof sub !== "string" || sub.length === 0) {
		return { kind: "error", reason: "invalid token" };
	}

	const exp = obj["exp"];
	if (typeof exp !== "number") {
		return { kind: "error", reason: "invalid token" };
	}

	const iat = obj["iat"];
	if (typeof iat !== "number") {
		return { kind: "error", reason: "invalid token" };
	}

	const iss = obj["iss"];
	if (typeof iss !== "string" || iss !== TOKEN_ISSUER) {
		return { kind: "error", reason: "invalid token" };
	}

	const aud = obj["aud"];
	if (typeof aud !== "string" || aud !== TOKEN_AUDIENCE) {
		return { kind: "error", reason: "invalid token" };
	}

	if (!Number.isSafeInteger(exp) || !Number.isSafeInteger(iat)) {
		return { kind: "error", reason: "invalid token" };
	}

	// Reject tokens issued in the future, allowing a small clock skew between nodes.
	const now = Date.now() / 1000;
	if (iat > now + MAX_CLOCK_SKEW_SECONDS) {
		return { kind: "error", reason: "invalid token" };
	}

	if (exp <= iat) {
		return { kind: "error", reason: "invalid token" };
	}

	const rawCaches = obj["caches"];
	if (!Array.isArray(rawCaches) || rawCaches.length === 0) {
		return { kind: "error", reason: "invalid token" };
	}
	if (rawCaches.length > MAX_CACHES_PER_TOKEN) {
		return { kind: "error", reason: "invalid token" };
	}
	const validatedCaches: string[] = [];
	for (let i = 0; i < rawCaches.length; i++) {
		const entry: unknown = rawCaches[i];
		if (typeof entry !== "string" || entry.length === 0) {
			return { kind: "error", reason: "invalid token" };
		}
		validatedCaches.push(entry);
	}

	const rawPerms = obj["perms"];
	if (!Array.isArray(rawPerms) || rawPerms.length === 0) {
		return { kind: "error", reason: "invalid token" };
	}
	if (rawPerms.length > MAX_PERMS_PER_TOKEN) {
		return { kind: "error", reason: "invalid token" };
	}
	const validatedPerms: TokenPermission[] = [];
	for (let i = 0; i < rawPerms.length; i++) {
		const perm: unknown = rawPerms[i];
		if (typeof perm !== "string" || !isTokenPermission(perm)) {
			return { kind: "error", reason: "invalid token" };
		}
		validatedPerms.push(perm);
	}

	return {
		kind: "ok",
		claims: { jti, sub, iss, aud, caches: validatedCaches, perms: validatedPerms, exp, iat },
	};
}

export async function verifyJwt(token: string, secret: string): Promise<JwtVerifyResult> {
	if (token.length > MAX_TOKEN_BYTES) {
		return { kind: "error", reason: "invalid token" };
	}

	const firstDot = token.indexOf(".");
	if (firstDot === -1) {
		return { kind: "error", reason: "invalid token" };
	}
	const secondDot = token.indexOf(".", firstDot + 1);
	if (secondDot === -1 || token.indexOf(".", secondDot + 1) !== -1) {
		return { kind: "error", reason: "invalid token" };
	}

	const headerB64 = token.slice(0, firstDot);
	const payloadB64 = token.slice(firstDot + 1, secondDot);
	const signatureB64 = token.slice(secondDot + 1);

	// Compare the encoded header directly — saves a base64 decode and string parse.
	if (headerB64 !== HEADER_B64) {
		return { kind: "error", reason: "invalid token" };
	}

	// Parse the payload first so we can short-circuit on expiry before paying for HMAC verify.
	let payloadJson: string;
	try {
		payloadJson = decoder.decode(base64UrlDecode(payloadB64));
	} catch {
		return { kind: "error", reason: "invalid token" };
	}

	let rawParsed: unknown;
	try {
		rawParsed = JSON.parse(payloadJson);
	} catch {
		return { kind: "error", reason: "invalid token" };
	}

	if (typeof rawParsed !== "object" || rawParsed === null) {
		return { kind: "error", reason: "invalid token" };
	}

	const claims: Record<string, unknown> = Object.fromEntries(Object.entries(rawParsed));

	const earlyExp = claims["exp"];
	if (typeof earlyExp === "number" && earlyExp <= Date.now() / 1000 - MAX_CLOCK_SKEW_SECONDS) {
		return { kind: "error", reason: "invalid token" };
	}

	const key = await getKey(secret);
	let signature: Uint8Array;
	try {
		signature = base64UrlDecode(signatureB64);
	} catch {
		return { kind: "error", reason: "invalid token" };
	}

	const data = encoder.encode(token.slice(0, secondDot));
	// Copy into a fresh ArrayBuffer because Uint8Array.buffer is ArrayBufferLike,
	// which the CF runtime's BufferSource type does not accept.
	const sigBuf = new ArrayBuffer(signature.byteLength);
	new Uint8Array(sigBuf).set(signature);
	const valid = await crypto.subtle.verify("HMAC", key, sigBuf, data);
	if (!valid) {
		return { kind: "error", reason: "invalid token" };
	}

	return validateClaims(claims);
}

export async function signJwt(claims: TokenClaims, secret: string): Promise<string> {
	const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(claims)));

	const key = await getKey(secret);
	const signingInput = `${HEADER_B64}.${payloadB64}`;
	const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(signingInput)));

	return `${signingInput}.${base64UrlEncode(signature)}`;
}

export function hasPermission(claims: TokenClaims, perm: TokenPermission): boolean {
	return claims.perms.includes(perm);
}

export function hasCacheAccess(claims: TokenClaims, cacheName: string): boolean {
	return claims.caches.includes("*") || claims.caches.includes(cacheName);
}
