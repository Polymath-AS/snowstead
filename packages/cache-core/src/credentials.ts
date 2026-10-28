import type { TokenClaims } from "./jwt.js";
import { TokenPolicy, KeyPolicy, LEGACY_KEY_POLICY, tokenKey, readAuthority } from "./publication-protocol.js";
import type { ReadBucket } from "./read-storage.js";

/** Bearer or netrc Basic password. Multiple/conflicting values fail closed. */
export function extractCredential(request: Request): string | undefined {
	const header = request.headers.get("authorization");
	if (!header || header.includes(",")) return undefined;
	const space = header.indexOf(" ");
	if (space === -1) return undefined;
	const scheme = header.slice(0, space).toLowerCase();
	const value = header.slice(space + 1).trim();
	if (scheme === "bearer") return value || undefined;
	if (scheme !== "basic") return undefined;
	let decoded: string;
	try { decoded = atob(value); } catch { return undefined; }
	const colon = decoded.indexOf(":");
	return colon === -1 ? undefined : decoded.slice(colon + 1) || undefined;
}

/** Stable across claim serialization/order and shared by issuance and readers. */
export async function claimsDigest(claims: TokenClaims): Promise<string> {
	const bytes = new TextEncoder().encode(JSON.stringify([
		claims.jti, claims.sub, claims.iss, claims.aud, claims.org ?? null,
		claims.caches, claims.perms, claims.iat, claims.exp ?? null,
	]));
	return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
		.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Positive issuance and verifier-key authority; no KV or SQL fallback. */
export async function tokenIsActive(bucket: Pick<ReadBucket, "get">, claims: TokenClaims): Promise<boolean> {
	const [policy, key] = await Promise.all([
		readAuthority(bucket, tokenKey(claims.jti), TokenPolicy),
		readAuthority(bucket, LEGACY_KEY_POLICY, KeyPolicy),
	]);
	return policy?.state === "active" && policy.jti === claims.jti &&
		policy.claimsDigest === await claimsDigest(claims) && key?.state === "active";
}
