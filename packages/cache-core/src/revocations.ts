import type { WorkerConfig } from "./config.js";
import { TokenPolicy, tokenKey, readAuthority } from "./publication-protocol.js";
import { revokeTokenPolicy } from "./token-policy.js";
import type { PolicyResult } from "./token-policy.js";

/**
 * Legacy write/read paths check fresh R2 tombstones too. Missing policies
 * still consult old KV revocations until the issuance inventory is migrated.
 * The v2 private reader requires positive issuance and never uses this legacy
 * fallback. KV has no bounded propagation promise and cannot authorize v2.
 */
const KV_CACHE_TTL_SECONDS = 30;

function revokedKey(jti: string): string {
	return `revoked/${jti}`;
}

export async function isRevoked(config: WorkerConfig, jti: string): Promise<boolean> {
	const policy = await readAuthority(config.bucket, tokenKey(jti), TokenPolicy);
	if (policy?.state === "revoked") return true;
	return (await config.authKv.get(revokedKey(jti), { cacheTtl: KV_CACHE_TTL_SECONDS })) !== null;
}

/** R2 fence first; retain a permanent KV mirror for old deployments during cutover. */
export async function recordRevocation(config: WorkerConfig, jti: string): Promise<PolicyResult> {
	const result = await revokeTokenPolicy(config, jti);
	if (result.state === "committed") await config.authKv.put(revokedKey(jti), "1");
	return result;
}
