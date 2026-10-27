import * as v from "valibot";
import type { TokenPermission } from "./db/types.js";
import { DEFAULT_ORG_ID } from "./db/schema.js";
import { valueOf } from "./schemas.js";

export type TokenClaims = {
	readonly jti: string;
	readonly sub: string;
	readonly iss: string;
	readonly aud: string;
	readonly caches: readonly string[];
	readonly perms: readonly TokenPermission[];
	/** The org the token's caches belong to; it may push to no other org's. */
	readonly org?: string;
	readonly exp?: number;
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
export const TOKEN_ISSUER = "snowstead";
export const TOKEN_AUDIENCE = "snowstead";
const MAX_TOKEN_BYTES = 4096;
const MAX_CLOCK_SKEW_SECONDS = 60;
export const MAX_CACHES_PER_TOKEN = 50;
export const MAX_PERMS_PER_TOKEN = 10;

/** What a token lets its holder do with its caches. */
export const Permission = v.picklist(["pull", "push", "go:read", "go:write"] satisfies TokenPermission[], (issue) => `invalid permission: ${String(issue.input)}, expected "pull", "push", "go:read", or "go:write"`);

const NonEmpty = v.pipe(v.string(), v.nonEmpty());

/** A token's claims, as signing writes them; a token without all of them is invalid. */
const Claims = v.pipe(
	v.object({
		jti: NonEmpty,
		sub: NonEmpty,
		iss: v.literal(TOKEN_ISSUER),
		aud: v.literal(TOKEN_AUDIENCE),
		caches: v.pipe(v.array(NonEmpty), v.nonEmpty(), v.maxLength(MAX_CACHES_PER_TOKEN)),
		perms: v.pipe(v.array(Permission), v.nonEmpty(), v.maxLength(MAX_PERMS_PER_TOKEN)),
		org: v.optional(NonEmpty),
		exp: v.optional(v.pipe(v.number(), v.safeInteger())),
		iat: v.pipe(v.number(), v.safeInteger()),
	}),
	// Not issued in the future, allowing a small clock skew between nodes.
	v.check(({ iat }) => iat <= Date.now() / 1000 + MAX_CLOCK_SKEW_SECONDS),
	v.check(({ exp, iat }) => exp === undefined || exp > iat),
);

function validateClaims(payload: unknown): JwtVerifyResult {
	const claims = valueOf(Claims, payload);
	return claims ? { kind: "ok", claims } : { kind: "error", reason: "invalid token" };
}

// Tokens verified recently, so a client sending one with every request pays
// for its HMAC once per isolate: verifying was a third of a private cache
// read's CPU. An entry lasts as long as the token would verify, at most
// VERIFIED_MAX_MS; revocation is checked apart from this, on every request.
const VERIFIED_MAX_MS = 5 * 60_000;
// Tokens run to MAX_TOKEN_BYTES; this keeps the memo to a few megabytes.
const VERIFIED_MAX_ENTRIES = 1_000;
const verified = new Map<string, { readonly claims: TokenClaims; readonly secret: string; readonly until: number }>();

export async function verifyJwt(token: string, secret: string): Promise<JwtVerifyResult> {
	const now = Date.now();
	const known = verified.get(token);
	if (known && known.secret === secret && known.until > now) {
		return { kind: "ok", claims: known.claims };
	}
	const result = await verifyToken(token, secret);
	if (result.kind === "ok") {
		if (verified.size >= VERIFIED_MAX_ENTRIES) verified.clear();
		const expires = result.claims.exp === undefined ? Infinity : (result.claims.exp + MAX_CLOCK_SKEW_SECONDS) * 1000;
		verified.set(token, { claims: result.claims, secret, until: Math.min(expires, now + VERIFIED_MAX_MS) });
	}
	return result;
}

async function verifyToken(token: string, secret: string): Promise<JwtVerifyResult> {
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

	const early = valueOf(v.object({ exp: v.number() }), rawParsed);
	if (early && early.exp <= Date.now() / 1000 - MAX_CLOCK_SKEW_SECONDS) {
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

	return validateClaims(rawParsed);
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

/**
 * Whether a token may reach a cache of this org: only its own org's, so an
 * org's token is no use on another's cache. A token without an org is the
 * default org's, as tokens from before orgs are, and so is a cache whose
 * private entry names none.
 */
export function isOrgsToken(claims: TokenClaims, cacheOrg: string | null): boolean {
	return (claims.org ?? DEFAULT_ORG_ID) === (cacheOrg ?? DEFAULT_ORG_ID);
}

/**
 * Whether a token's caches include this one. Each entry is `id:<cache id>`,
 * one cache however it's renamed, or a pattern over its org's cache names
 * where * matches any run of characters: `*` is every cache, `ci-*` every
 * cache whose name starts with ci-, and a plain name, as tokens from before
 * ids carry, is that cache.
 */
export function hasCacheAccess(claims: TokenClaims, cache: { readonly id?: number; readonly name: string }): boolean {
	return claims.caches.some((entry) =>
		entry.startsWith(CACHE_ID_PREFIX) ? cache.id !== undefined && entry === cacheIdEntry(cache.id) : matchesPattern(entry, cache.name),
	);
}

export const CACHE_ID_PREFIX = "id:";

export function cacheIdEntry(id: number): string {
	return `${CACHE_ID_PREFIX}${id}`;
}

export function isCachePattern(entry: string): boolean {
	return entry.includes("*");
}

function matchesPattern(pattern: string, name: string): boolean {
	if (!isCachePattern(pattern)) return pattern === name;
	const parts = pattern.split("*");
	const last = parts.length - 1;
	if (!name.startsWith(parts[0]) || !name.endsWith(parts[last]) || name.length < parts[0].length + parts[last].length) {
		return false;
	}
	let at = parts[0].length;
	for (const part of parts.slice(1, last)) {
		const found = name.indexOf(part, at);
		if (found === -1 || found + part.length > name.length - parts[last].length) return false;
		at = found + part.length;
	}
	return true;
}
