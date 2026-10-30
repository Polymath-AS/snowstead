import { DurableObject, tracing } from "cloudflare:workers";
import { connect } from "./db/connection.js";
import type { Db } from "./db/connection.js";
import type { Cache } from "./db/types.js";
import { createUploadSessionsWithinLimit, reserveStreamParts } from "./db/repository.js";
import { reserveGoUpload } from "./go-cache.js";
import { errorResponse } from "./responses.js";
import { errorForLog } from "./logging.js";

/** One shared Nix/Go admission queue per org; Postgres remains authoritative. */
export class UploadCoordinator extends DurableObject<Env> {
	private tail: Promise<void> = Promise.resolve();
	private pending = 0;

	reserveNix(org: string, rows: Parameters<typeof createUploadSessionsWithinLimit>[2]) {
		return this.run("nix", db => createUploadSessionsWithinLimit(db, org, rows));
	}

	reserveNixParts(org: string, sessionId: string, parts: readonly { partNumber: number; size: number }[]) {
		return this.run("nix", db => reserveStreamParts(db, org, sessionId, parts));
	}

	reserveGo(cache: Cache, action: string, output: string, size: number) {
		return this.run("go", db => reserveGoUpload(db, cache, action, output, size));
	}

	private async run<T>(protocol: string, operation: (db: Db) => Promise<T>): Promise<T | Response> {
		const busy = () => errorResponse("Upload reservation queue is busy; retry", 429, { "retry-after": "1" });
		if (this.pending >= 64) return busy();
		const arrived = Date.now();
		this.pending++;
		const result = this.tail.then(async () => {
			// Waiting consumes no database connection. Never time out an admitted
			// transaction: its commit outcome must be known before releasing the slot.
			const queueMs = Date.now() - arrived;
			if (queueMs > 2000) return busy();
			return tracing.enterSpan("upload_reservation", async span => {
				if (span.isTraced) span.setAttributes({ "snowstead.protocol": protocol, "snowstead.queue_ms": queueMs });
				const connection = connect(this.env.HYPERDRIVE.connectionString);
				try {
					return await operation(connection.db);
				} catch (error) {
					console.error("Upload reservation failed", errorForLog(error));
					throw new Error("Upload reservation failed");
				} finally {
					await connection.close();
				}
			});
		}).finally(() => { this.pending--; });
		// SQL/transport failure must not poison the next queued operation.
		this.tail = result.then(() => {}, () => {});
		return result;
	}
}
