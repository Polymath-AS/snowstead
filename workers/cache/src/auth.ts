import type { WorkerConfig } from "./config.js";
import type { TokenClaims } from "./jwt.js";
import { verifyJwt, hasPermission, hasCacheAccess } from "./jwt.js";
import { isRevoked } from "./revocations.js";

/** Build a JSON error response. Always sets cache-control: no-store so auth failures don't get cached. */
function authError(message: string, status: number): Response {
	const headers: Record<string, string> = {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store",
	};
	if (status === 401) {
		headers["www-authenticate"] = "Bearer";
	}
	return new Response(JSON.stringify({ error: message }), { status, headers });
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
	const headers: Record<string, string> = {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store",
	};
	if (status === 401) {
		// Basic, so Nix and curl answer with their netrc credentials.
		headers["www-authenticate"] = 'Basic realm="helios-cache"';
	}
	return new Response(JSON.stringify({ error: message }), { status, headers });
}

/**
 * Authorizes a read of a private cache: a token granting `pull` on it.
 * Returns the response to send instead, or undefined to proceed.
 */
export async function authorizeRead(request: Request, config: WorkerConfig, cacheName: string): Promise<Response | undefined> {
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
	if (!hasPermission(result.claims, "pull") || !hasCacheAccess(result.claims, cacheName)) {
		return readAuthError("Forbidden", 403);
	}
	return undefined;
}

/** Represents the authenticated caller for write operations. */
export type AuthIdentity =
	| { readonly kind: "jwt"; readonly claims: TokenClaims }
	| { readonly kind: "legacy" }
	| { readonly kind: "admin" };

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
	if (typeof bearer !== "string") {
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

/** Authenticate an admin request using ADMIN_SECRET. */
export async function authenticateAdmin(
	request: Request,
	config: WorkerConfig,
): Promise<AuthResult> {
	if (!config.adminSecret) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}

	const bearer = extractBearer(request);
	if (typeof bearer !== "string") {
		return { kind: "error", response: bearer };
	}

	if (!(await timingSafeEqual(bearer, config.adminSecret))) {
		return { kind: "error", response: authError("Forbidden", 403) };
	}

	return { kind: "ok", identity: { kind: "admin" } };
}

/** Extract the actor identifier for audit logging. */
export function actorId(identity: AuthIdentity): string {
	switch (identity.kind) {
		case "jwt": return identity.claims.jti;
		case "legacy": return "legacy";
		case "admin": return "admin";
	}
}
