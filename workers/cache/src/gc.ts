import { bucketForKey, narKey } from "./layout.js";
import type { WorkerConfig } from "./config.js";
import {
	findExpiredSessions,
	transitionSessionStatus,
	deleteUploadSession,
	deleteUnreferencedBlobObjects,
	deleteExpiredApiTokens,
	deleteExpiredAuditLogs,
} from "./db/repository.js";
import type { BlobObject, UploadSessionStatus } from "./db/types.js";

const VALID_TRANSITION_STATUSES = new Set<string>(["pending", "uploading"]);

function isTransitionableStatus(s: string): s is UploadSessionStatus {
	return VALID_TRANSITION_STATUSES.has(s);
}

const AUDIT_LOG_RETENTION_DAYS = 30;
const R2_DELETE_MAX_KEYS = 1000;
const GC_BLOB_BATCH = 1000;
const GC_BLOB_BATCHES = 20;

function chunks<T>(items: readonly T[], size: number): T[][] {
	const out: T[][] = [];
	for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
	return out;
}

export interface GcResult {
	readonly expiredSessions: number;
	readonly deletedBlobs: number;
	readonly expiredTokens: number;
	readonly expiredAuditLogs: number;
	readonly errors: string[];
}

export async function runGarbageCollection(config: WorkerConfig): Promise<GcResult> {
	const errors: string[] = [];
	let expiredSessions = 0;
	let deletedBlobs = 0;
	let expiredTokens = 0;
	let expiredAuditLogs = 0;

	const now = new Date();
	const expired = await findExpiredSessions(config.db, now);

	for (const session of expired) {
		try {
			// findExpiredSessions already excludes "completed" and "expired",
			// but validate to satisfy the type system without an assertion.
			if (!isTransitionableStatus(session.status)) continue;

			const transitioned = await transitionSessionStatus(
				config.db,
				session.id,
				session.status,
				"expired",
			);
			if (!transitioned) continue;

			if (session.r2UploadId && session.r2UploadKey) {
				try {
					const multipart = bucketForKey(config, session.r2UploadKey).resumeMultipartUpload(session.r2UploadKey, session.r2UploadId);
					await multipart.abort();
				} catch {
					// Multipart may already be completed or aborted
				}
			}

			if (session.r2UploadKey) {
				try {
					await bucketForKey(config, session.r2UploadKey).delete(session.r2UploadKey);
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

	// R2 deletes up to 1000 keys a call, so a batch costs a few subrequests
	// however many blobs it holds; a cache emptied at once is swept over runs.
	for (let batch = 0; batch < GC_BLOB_BATCHES; batch++) {
		let blobs: BlobObject[];
		try {
			// Rows first, so nothing is published against a blob whose NAR is going.
			blobs = await deleteUnreferencedBlobObjects(config.db, new Date(), GC_BLOB_BATCH);
		} catch (err) {
			errors.push(`Failed to delete blobs: ${err instanceof Error ? err.message : String(err)}`);
			break;
		}
		// Both layouts: publishing may have copied a NAR to the other bucket.
		const privateKeys = new Set<string>();
		const publicKeys = new Set<string>();
		for (const blob of blobs) {
			privateKeys.add(narKey(blob.fileHash, blob.compression, true));
			publicKeys.add(narKey(blob.fileHash, blob.compression, false));
			(bucketForKey(config, blob.r2Key) === config.bucket ? privateKeys : publicKeys).add(blob.r2Key);
		}
		try {
			await Promise.all([
				...chunks([...privateKeys], R2_DELETE_MAX_KEYS).map((keys) => config.bucket.delete(keys)),
				...chunks([...publicKeys], R2_DELETE_MAX_KEYS).map((keys) => config.publicBucket.delete(keys)),
			]);
		} catch (err) {
			errors.push(`Failed to delete the NARs of ${blobs.length} blobs: ${err instanceof Error ? err.message : String(err)}`);
		}
		deletedBlobs += blobs.length;
		if (blobs.length < GC_BLOB_BATCH) break;
	}

	try {
		expiredTokens = await deleteExpiredApiTokens(config.db, now);
	} catch (err) {
		errors.push(`Failed to delete expired tokens: ${err instanceof Error ? err.message : String(err)}`);
	}

	try {
		const cutoff = new Date(Date.now() - AUDIT_LOG_RETENTION_DAYS * 86400_000);
		expiredAuditLogs = await deleteExpiredAuditLogs(config.db, cutoff);
	} catch (err) {
		errors.push(`Failed to delete expired audit logs: ${err instanceof Error ? err.message : String(err)}`);
	}

	return { expiredSessions, deletedBlobs, expiredTokens, expiredAuditLogs, errors };
}
