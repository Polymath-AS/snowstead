import type { WorkerConfig } from "./config.js";
import type { AuthIdentity } from "./auth.js";
import { actorId } from "./auth.js";
import { createAuditLog } from "./db/repository.js";
import { DEFAULT_ORG_ID } from "./db/schema.js";

/**
 * The org an entry belongs to: an API key's or a token's own, which is the
 * org of anything it can reach. The operator acts on no one org unless the
 * caller says which.
 */
function orgOf(identity: AuthIdentity): string | null {
	switch (identity.kind) {
		case "orgKey": return identity.org;
		case "jwt": return identity.claims.org ?? DEFAULT_ORG_ID;
		// The shared push secret is a self-hosted install's, which is all the default org.
		case "legacy": return DEFAULT_ORG_ID;
		case "admin": return null;
	}
}

/** Records what a caller did, after the response if need be; a failure is only logged. */
export function writeAuditLog(
	config: WorkerConfig,
	identity: AuthIdentity,
	action: string,
	cacheName: string | null,
	status: number,
	detail: string,
	ip: string | null,
	org: string | null = orgOf(identity),
): void {
	config.defer(
		createAuditLog(config.db, {
			actor: actorId(identity),
			action,
			cacheName,
			detail,
			ip,
			status,
			orgId: org,
		}).catch((err) => {
			console.error("Failed to write audit log", err);
		}),
	);
}
