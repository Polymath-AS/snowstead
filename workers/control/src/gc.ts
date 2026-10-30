import { bucketForKey, narKey } from "@snowstead/cache-core/layout";
import { sweepGoEntries } from "@snowstead/cache-core/go-cache";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import {
	findExpiredSessions,
	transitionSessionStatus,
	deleteUploadSession,
	deleteUploadSessions,
	findExpiredCompletedSessions,
	ensureBlobObjects,
	deleteUnreferencedBlobObjects,
	deleteExpiredApiTokens,
	deleteExpiredAuditLogs,
	listCachesWithRetention,
	narSourcePinned,
	withUploadSourceCleanup,
} from "@snowstead/cache-core/db/repository";
import { deleteCachePaths } from "@snowstead/cache-core/path-deletion";
import { messageOf } from "@snowstead/cache-core/responses";
import type { BlobObject, UploadSessionStatus } from "@snowstead/cache-core/db/types";

const VALID_TRANSITION_STATUSES = new Set<string>(["pending", "uploading", "streaming", "finalizing", "aborted"]);

function isTransitionableStatus(s: string): s is UploadSessionStatus {
	return VALID_TRANSITION_STATUSES.has(s);
}

const AUDIT_LOG_RETENTION_DAYS = 30;
const R2_DELETE_MAX_KEYS = 1000;
const GC_BLOB_BATCH = 1000;
const GC_BLOB_BATCHES = 20;
// Paths a cache's retention deletes per run: a cache with more expiring
// is caught up over runs, as the blob sweep is.
const RETENTION_BATCH = 500;
const RETENTION_BATCHES_PER_RUN = 20;
const DAY_MS = 24 * 60 * 60 * 1000;

function chunks<T>(items: readonly T[], size: number): T[][] {
	const out: T[][] = [];
	for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
	return out;
}

export interface GcResult {
	readonly expiredSessions: number;
	readonly expiredPaths: number;
	readonly deletedBlobs: number;
	readonly expiredTokens: number;
	readonly expiredAuditLogs: number;
	readonly errors: string[];
}

export async function runGarbageCollection(config: WorkerConfig): Promise<GcResult> {
	const errors: string[] = [];
	let expiredSessions = 0;
	let expiredPaths = 0;
	let deletedBlobs = 0;
	let expiredTokens = 0;
	let expiredAuditLogs = 0;

	const now = new Date();
	try {
		await sweepGoEntries(config);
	} catch (error) {
		errors.push(`Go sweep: ${messageOf(error)}`);
	}
	const expired = await findExpiredSessions(config.db, now);

	for (const session of expired) {
		try {
			// A pre-streaming canonical MPU may still have a completion in flight.
			// Keep its durable reservation until that outcome has been reconciled.
			if (session.r2UploadId && session.r2UploadKey && !session.r2UploadKey.startsWith("staging/")) continue;
			await withUploadSourceCleanup(config.db, async tx => {
				if (session.r2UploadKey && await narSourcePinned(tx, session.r2UploadKey)) return;
				if (!isTransitionableStatus(session.status)) return;

				// Adopt canonical bytes before dropping their last reservation;
				// the reference-aware blob sweep owns shared-object deletion.
				if (session.fileHash && session.r2UploadKey && !session.r2UploadKey.startsWith("staging/")) {
					await ensureBlobObjects(tx, [{
						fileHash: session.fileHash, fileSize: session.fileSize,
						compression: session.compression, r2Key: session.r2UploadKey,
					}]);
				}

				const transitioned = await transitionSessionStatus(tx, session.id, session.status, "expired");
				if (!transitioned) return;

				if (session.r2UploadId && session.r2UploadKey) {
					try {
						await bucketForKey(config, session.r2UploadKey).resumeMultipartUpload(session.r2UploadKey, session.r2UploadId).abort();
					} catch {
						// Multipart may already be completed or aborted.
					}
				}

				if (session.r2UploadKey?.startsWith("staging/")) await config.bucket.delete(session.r2UploadKey);
				await deleteUploadSession(tx, session.id);
				expiredSessions++;
			});
		} catch (err) {
			errors.push(`Failed to expire session ${session.id}: ${messageOf(err)}`);
		}
	}

	// Completed sessions served their purpose once published, but stayed
	// forever: every query over upload_sessions read past them. Their
	// canonical NARs are adopted first, as abandoned ones are above, so one
	// completed but never published goes to the sweep instead of staying.
	for (let batch = 0; batch < GC_BLOB_BATCHES; batch++) {
		try {
			const count = await withUploadSourceCleanup(config.db, async tx => {
				const done = await findExpiredCompletedSessions(tx, now, GC_BLOB_BATCH);
				const unpinned = [];
				for (const session of done) {
					if (session.r2UploadKey && await narSourcePinned(tx, session.r2UploadKey)) continue;
					if (session.r2UploadKey?.startsWith("staging/")) await config.bucket.delete(session.r2UploadKey);
					unpinned.push(session);
				}
				await ensureBlobObjects(tx, unpinned.flatMap(s =>
					s.fileHash && s.r2UploadKey && !s.r2UploadKey.startsWith("staging/")
						? [{ fileHash: s.fileHash, fileSize: s.fileSize, compression: s.compression, r2Key: s.r2UploadKey }] : []));
				await deleteUploadSessions(tx, unpinned.map((s) => s.id));
				return unpinned.length;
			});
			expiredSessions += count;
			if (count < GC_BLOB_BATCH) break;
		} catch (err) {
			errors.push(`Failed to delete completed sessions: ${messageOf(err)}`);
			break;
		}
	}

	// Before the blob sweep, so the NARs retention frees go in the same run.
	let caches: Awaited<ReturnType<typeof listCachesWithRetention>> = [];
	try {
		caches = await listCachesWithRetention(config.db);
	} catch (err) {
		errors.push(`Failed to list caches with retention: ${messageOf(err)}`);
	}
	let retentionBudget = RETENTION_BATCHES_PER_RUN;
	for (const cache of caches) {
		const lastPushedBefore = new Date(now.getTime() - (cache.retentionDays ?? 0) * DAY_MS);
		while (retentionBudget > 0) {
			retentionBudget--;
			try {
				const deleted = await deleteCachePaths(config, cache, { lastPushedBefore, limit: RETENTION_BATCH });
				expiredPaths += deleted.length;
				if (deleted.length < RETENTION_BATCH) break;
			} catch (err) {
				errors.push(`Failed to expire paths of ${cache.name}: ${messageOf(err)}`);
				break;
			}
		}
	}

	// R2 deletes up to 1000 keys a call, so a batch costs a few subrequests
	// however many blobs it holds; a cache emptied at once is swept over runs.
	for (let batch = 0; batch < GC_BLOB_BATCHES; batch++) {
		let blobs: BlobObject[];
		try {
			blobs = await deleteUnreferencedBlobObjects(config.db, GC_BLOB_BATCH, async (pending) => {
				// Both layouts: publishing may have copied a NAR to the other bucket.
				const privateKeys = new Set<string>();
				const publicKeys = new Set<string>();
				for (const blob of pending) {
					privateKeys.add(narKey(blob.fileHash, blob.compression, true));
					publicKeys.add(narKey(blob.fileHash, blob.compression, false));
					(bucketForKey(config, blob.r2Key) === config.bucket ? privateKeys : publicKeys).add(blob.r2Key);
				}
				// A rejected sibling must not release the transaction's fence while
				// another delete is still running against a potentially re-used key.
				const results = await Promise.allSettled([
					...chunks([...privateKeys], R2_DELETE_MAX_KEYS).map((keys) => config.bucket.delete(keys)),
					...chunks([...publicKeys], R2_DELETE_MAX_KEYS).map((keys) => config.publicBucket.delete(keys)),
				]);
				for (const result of results) {
					if (result.status === "rejected") throw result.reason;
				}
			});
		} catch (err) {
			errors.push(`Failed to delete blobs: ${messageOf(err)}`);
			break;
		}
		deletedBlobs += blobs.length;
		if (blobs.length < GC_BLOB_BATCH) break;
	}

	try {
		expiredTokens = await deleteExpiredApiTokens(config.db, now);
	} catch (err) {
		errors.push(`Failed to delete expired tokens: ${messageOf(err)}`);
	}

	try {
		const cutoff = new Date(Date.now() - AUDIT_LOG_RETENTION_DAYS * 86400_000);
		expiredAuditLogs = await deleteExpiredAuditLogs(config.db, cutoff);
	} catch (err) {
		errors.push(`Failed to delete expired audit logs: ${messageOf(err)}`);
	}

	return { expiredSessions, expiredPaths, deletedBlobs, expiredTokens, expiredAuditLogs, errors };
}
