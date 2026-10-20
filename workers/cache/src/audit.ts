import type { WorkerConfig } from "./config.js";
import type { AuthIdentity } from "./auth.js";
import { actorId } from "./auth.js";
import { createAuditLog } from "./db/repository.js";

/** Records what a caller did, after the response if need be; a failure is only logged. */
export function writeAuditLog(
	config: WorkerConfig,
	identity: AuthIdentity,
	action: string,
	cacheName: string | null,
	status: number,
	detail: string,
	ip: string | null,
): void {
	config.defer(
		createAuditLog(config.db, {
			actor: actorId(identity),
			action,
			cacheName,
			detail,
			ip,
			status,
		}).catch((err) => {
			console.error("Failed to write audit log", err);
		}),
	);
}
