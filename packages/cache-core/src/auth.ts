import type { WorkerConfig } from "./config.js";
import type { TokenClaims } from "./jwt.js";
import { verifyJwt, hasPermission, hasCacheAccess, isOrgsToken } from "./jwt.js";
import { privateCache } from "./visibility.js";
import { isRevoked } from "./revocations.js";
import { findOrgApiKey } from "./db/repository.js";
import { errorResponse } from "./responses.js";

/** Build a JSON error response. Always sets cache-control: no-store so auth failures don't get cached. */
function authError(message: string, status: number): Response {
	return errorResponse(message, status, status === 401 ? { "www-authenticate": "Bearer" } : {});
}

/** Extract bearer token from Authorization header, or return an error response. */
function extractBearer(request: Request): string | Response {
	const authHeader = request.headers.get("authorization");
	if (!authHeader) {
		return authError("Unauthorized", 401);
	}
	const spaceIdx = authHeader.indexOf(" ");
	if (spaceIdx === -1) {
		return authError("Unauthorized", 401);
	}
	const scheme = authHeader.slice(0, spaceIdx);
	const token = authHeader.slice(spaceIdx + 1);
	if (scheme.toLowerCase() !== "bearer" || token.length === 0) {
		return authError("Unauthorized", 401);
	}
	return token;
}

const tsEncoder = new TextEncoder();

/**
 * Timing-safe string comparison. Hashes both inputs with SHA-256 then
 * compares digests byte-by-byte with constant-time XOR accumulation.
 * Prevents timing side-channel attacks on secret comparison.
 */
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
	const [da, db] = await Promise.all([
		crypto.subtle.digest("SHA-256", tsEncoder.encode(a)),
		crypto.subtle.digest("SHA-256", tsEncoder.encode(b)),
	]);
	const ba = new Uint8Array(da);
	const bb = new Uint8Array(db);
	let diff = a.length ^ b.length;
	for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
	return diff === 0;
}

/**
 * The token in a request: a bearer token, or the password of HTTP Basic auth,
 * which is what Nix sends for a substituter listed in its netrc file.
 */
function extractCredential(request: Request): string | undefined {
	const header = request.headers.get("authorization");
	if (!header) return undefined;
	const space = header.indexOf(" ");
	if (space === -1) return undefined;
	const scheme = header.slice(0, space).toLowerCase();
	const value = header.slice(space + 1).trim();
	if (scheme === "bearer") return value || undefined;
	if (scheme !== "basic") return undefined;
	let decoded: string;
	try {
		decoded = atob(value);
	} catch {
		return undefined;
	}
	const colon = decoded.indexOf(":");
	return colon === -1 ? undefined : decoded.slice(colon + 1) || undefined;
}

function readAuthError(message: string, status: number): Response {
	// Basic, so Nix and curl answer with their netrc credentials.
	return errorResponse(message, status, status === 401 ? { "www-authenticate": 'Basic realm="snowstead"' } : {});
}

/**
 * Authorizes a read of the private cache at `cachePath`: a token of its org
 * granting `pull` on it by name. Returns the response to send instead, or
 * undefined to proceed.
 */
export async function authorizeRead(request: Request, config: WorkerConfig, cachePath: string, cacheName: string): Promise<Response | undefined> {
	const token = extractCredential(request);
	if (!token) {
		return readAuthError("Unauthorized", 401);
	}
	if (!config.jwtSecret) {
		return readAuthError("Forbidden", 403);
	}
	const result = await verifyJwt(token, config.jwtSecret);
	// The signature vouches for the claims; only revocation needs looking up,
	// and that is in KV, so private reads never touch the database.
	if (result.kind !== "ok" || (await isRevoked(config, result.claims.jti))) {
		return readAuthError("Unauthorized", 401);
	}
	// The cache's org and id are in its private entry; one from before them
	// names none to check against until the entries are synced.
	const cache = await privateCache(config, cachePath);
	const id = cache.isPrivate ? cache.id : undefined;
	if (!hasPermission(result.claims, "pull") || !hasCacheAccess(result.claims, { id, name: cacheName })) {
		return readAuthError("Forbidden", 403);
	}
	if (cache.isPrivate && cache.org !== undefined && !isOrgsToken(result.claims, cache.org)) {
		return readAuthError("Forbidden", 403);
	}
	return undefined;
}

/** Represents the authenticated caller for write operations. */
export type AuthIdentity =
	| { readonly kind: "jwt"; readonly claims: TokenClaims }
	| { readonly kind: "legacy" }
	// The operator; through the dashboard, on behalf of a signed-in user.
	| { readonly kind: "admin"; readonly onBehalfOf?: string }
	| { readonly kind: "orgKey"; readonly org: string; readonly keyId: string };

export type AuthResult =
	| { readonly kind: "ok"; readonly identity: AuthIdentity }
	| { readonly kind: "error"; readonly response: Response };

/**
 * Authenticate a write request. Checks in order:
 * 1. If JWT_SECRET is configured, try JWT verification + active check
 * 2. If AUTH_TOKEN is configured, try static bearer token match
 * 3. If neither is configured, fail closed (403)
 */
export async function authenticateWrite(
	request: Request,
	config: WorkerConfig,
): Promise<AuthResult> {
	// Require at least one auth method to be configured, otherwise reject.
	if (!config.jwtSecret && !config.authToken) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}

	const bearer = extractBearer(request);
	if (bearer instanceof Response) {
		return { kind: "error", response: bearer };
	}

	// Prefer JWT when a secret is set; fall back to the legacy token if JWT verification fails.
	if (config.jwtSecret) {
		const result = await verifyJwt(bearer, config.jwtSecret);
		if (result.kind === "ok") {
			if (await isRevoked(config, result.claims.jti)) {
				return { kind: "error", response: authError("Unauthorized", 401) };
			}
			return { kind: "ok", identity: { kind: "jwt", claims: result.claims } };
		}
		if (!config.authToken) {
			return { kind: "error", response: authError("Unauthorized", 401) };
		}
	}

	if (config.authToken && await timingSafeEqual(bearer, config.authToken)) {
		return { kind: "ok", identity: { kind: "legacy" } };
	}

	return { kind: "error", response: authError("Forbidden", 403) };
}

// The header the dashboard names its signed-in user in, so the audit log
// says who did what rather than "admin". Only believed next to ADMIN_SECRET.
const ON_BEHALF_OF_HEADER = "x-snowstead-actor";
const MAX_ON_BEHALF_OF_LENGTH = 254;

function adminIdentity(request: Request): AuthIdentity {
	const onBehalfOf = request.headers.get(ON_BEHALF_OF_HEADER)?.trim() ?? "";
	if (onBehalfOf === "" || onBehalfOf.length > MAX_ON_BEHALF_OF_LENGTH || /[\s\p{Cc}]/u.test(onBehalfOf)) {
		return { kind: "admin" };
	}
	return { kind: "admin", onBehalfOf };
}

/** Authenticate an admin request using ADMIN_SECRET. */
export async function authenticateAdmin(
	request: Request,
	config: WorkerConfig,
): Promise<AuthResult> {
	if (!config.adminSecret) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}

	const bearer = extractBearer(request);
	if (bearer instanceof Response) {
		return { kind: "error", response: bearer };
	}

	if (!(await timingSafeEqual(bearer, config.adminSecret))) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}

	return { kind: "ok", identity: adminIdentity(request) };
}

const ORG_KEY_PREFIX = "snowstead_key_";
const ORG_KEY_ID = /^[a-z0-9]{16}$/;

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashSecret(secret: string): Promise<string> {
	return hex(await crypto.subtle.digest("SHA-256", tsEncoder.encode(secret)));
}

/**
 * A new org API key, `snowstead_key_<id>_<secret>`: the id finds its row
 * and the secret proves it, and only the secret's hash is kept. Shown once.
 */
export async function generateOrgApiKey(): Promise<{ id: string; key: string; secretHash: string }> {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
	const id = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => alphabet[b % alphabet.length]).join("");
	const secret = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
		.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
	return { id, key: `${ORG_KEY_PREFIX}${id}_${secret}`, secretHash: await hashSecret(secret) };
}

/**
 * Authenticates a request to one org's API: the operator's ADMIN_SECRET,
 * which reaches every org, or an unrevoked API key of that org.
 */
export async function authenticateOrg(
	request: Request,
	config: WorkerConfig,
	org: string,
): Promise<AuthResult> {
	const bearer = extractBearer(request);
	if (bearer instanceof Response) {
		return { kind: "error", response: bearer };
	}

	if (config.adminSecret && (await timingSafeEqual(bearer, config.adminSecret))) {
		return { kind: "ok", identity: adminIdentity(request) };
	}

	if (!bearer.startsWith(ORG_KEY_PREFIX)) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}
	const rest = bearer.slice(ORG_KEY_PREFIX.length);
	const id = rest.slice(0, 16);
	const secret = rest.slice(17);
	if (!ORG_KEY_ID.test(id) || rest[16] !== "_" || secret.length === 0) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}
	const key = await findOrgApiKey(config.db, id);
	// Hashed either way, so a missing key takes as long as a wrong one.
	const valid = await timingSafeEqual(await hashSecret(secret), key?.secretHash ?? "");
	if (!key || !valid || key.revokedAt !== null || key.orgId !== org) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}
	return { kind: "ok", identity: { kind: "orgKey", org, keyId: id } };
}

/** Extract the actor identifier for audit logging. */
export function actorId(identity: AuthIdentity): string {
	switch (identity.kind) {
		case "jwt": return identity.claims.jti;
		case "legacy": return "legacy";
		case "admin": return identity.onBehalfOf === undefined ? "admin" : `user:${identity.onBehalfOf}`;
		case "orgKey": return `key:${identity.keyId}`;
	}
}
