import type { WorkerConfig } from "./config.js";
import {
	findExpiredSessions,
	transitionSessionStatus,
	deleteUploadSession,
	findUnreferencedBlobObjects,
	deleteBlobObject,
} from "./db/repository.js";
import type { UploadSessionStatus } from "./db/types.js";

export interface GcResult {
	readonly expiredSessions: number;
	readonly deletedBlobs: number;
	readonly errors: string[];
}

export async function runGarbageCollection(config: WorkerConfig): Promise<GcResult> {
	const errors: string[] = [];
	let expiredSessions = 0;
	let deletedBlobs = 0;

	// Phase 1: Expire abandoned upload sessions
	const now = new Date().toISOString();
	const expired = await findExpiredSessions(config.db, now);

	for (const session of expired) {
		try {
			const transitioned = await transitionSessionStatus(
				config.db,
				session.id,
				session.status as UploadSessionStatus,
				"expired",
			);
			if (!transitioned) continue;

			if (session.r2UploadId && session.r2UploadKey) {
				try {
					const multipart = config.bucket.resumeMultipartUpload(session.r2UploadKey, session.r2UploadId);
					await multipart.abort();
				} catch {
					// Multipart may already be completed or aborted
				}
			}

			if (session.r2UploadKey) {
				try {
					await config.bucket.delete(session.r2UploadKey);
				} catch {
					// R2 object may not exist
				}
			}

			await deleteUploadSession(config.db, session.id);
			expiredSessions++;
		} catch (err) {
			errors.push(`Failed to expire session ${session.id}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

	// Phase 2: Delete unreferenced blob objects
	const unreferenced = await findUnreferencedBlobObjects(config.db);

	for (const blob of unreferenced) {
		try {
			// Delete DB record first to prevent re-referencing during R2 delete
			await deleteBlobObject(config.db, blob.id);
			try {
				await config.bucket.delete(blob.r2Key);
			} catch {
				// R2 object may already be gone
			}
			deletedBlobs++;
		} catch (err) {
			errors.push(`Failed to delete blob ${blob.id}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

	return { expiredSessions, deletedBlobs, errors };
}
