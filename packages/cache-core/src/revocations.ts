import type { WorkerConfig } from "./config.js";

/**
 * Token revocations, in KV, so checking a token never touches the
 * database: a JWT carries its own permissions, and this is the only state
 * its holder's requests need. An entry expires with the token it revokes,
 * or stays permanently for a token with no expiry.
 *
 * KV reads are cached at the edge for KV_CACHE_TTL_SECONDS, and so are
 * misses, so a revocation reaches every location within that time; tokens
 * found not revoked are also remembered per isolate for as long.
 */
const KV_CACHE_TTL_SECONDS = 30;
const MEMO_MAX_ENTRIES = 10_000;
const notRevokedUntil = new Map<string, number>();

function revokedKey(jti: string): string {
	return `revoked/${jti}`;
}

export async function isRevoked(config: WorkerConfig, jti: string): Promise<boolean> {
	const now = Date.now();
	const until = notRevokedUntil.get(jti);
	if (until !== undefined && until > now) {
		return false;
	}
	if ((await config.authKv.get(revokedKey(jti), { cacheTtl: KV_CACHE_TTL_SECONDS })) !== null) {
		notRevokedUntil.delete(jti);
		return true;
	}
	if (notRevokedUntil.size >= MEMO_MAX_ENTRIES) {
		notRevokedUntil.clear();
	}
	notRevokedUntil.set(jti, now + KV_CACHE_TTL_SECONDS * 1000);
	return false;
}

/** Records a revocation; the database stays the record of who revoked what and why. */
export async function recordRevocation(config: WorkerConfig, jti: string, expiresAt: Date | null): Promise<void> {
	notRevokedUntil.delete(jti);
	if (expiresAt === null) {
		await config.authKv.put(revokedKey(jti), "1");
		return;
	}
	const expiration = Math.floor(expiresAt.getTime() / 1000);
	// KV expirations must be at least 60 seconds ahead; a token expiring
	// sooner than that is refused for its expiry anyway.
	if (expiration < Date.now() / 1000 + 60) return;
	await config.authKv.put(revokedKey(jti), "1", { expiration });
}
