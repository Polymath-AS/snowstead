import { and, or, eq, isNull, inArray, notExists, sql, asc } from "drizzle-orm";
import * as v from "valibot";
import type { WorkerConfig } from "./config.js";
import type { Db } from "./db/connection.js";
import type { CacheAt } from "./db/repository.js";
import { cacheHasGoEntries, findCacheById } from "./db/repository.js";
import type { NarinfoPath, NarinfoBlob } from "./narinfo.js";
import { renderNarinfo } from "./narinfo.js";
import { signingKeyFor } from "./cache-keys.js";
import { computeFingerprint, signNarinfo } from "./signing.js";
import { NarHash, valueOf } from "./schemas.js";
import { bucketFor, bucketForKey, IMMUTABLE } from "./layout.js";
import { AuthorityJournal } from "./authority-journal.js";
import {
	ActiveGrant, PathGrant, CacheStatus, RouteRecord, grantKey, statusKey, routeKey,
	publicationKey, publicationUrl, LegacyWitness, witnessKey,
} from "./publication-protocol.js";
import {
	publicationCaches as lifecycles, publicationPaths as paths, publicationJobs as jobs,
	publicationRevisions as revisions, publicationPins as pins, publishedPaths, blobObjects, caches, authorityJournal,
} from "./db/schema.js";

type Lifecycle = typeof lifecycles.$inferSelect;
type Job = typeof jobs.$inferSelect;
type Revision = typeof revisions.$inferSelect;
type Tx = Parameters<Parameters<Db["transaction"]>[0]>[0];
type Database = Db | Tx;
const MAX_PENDING_PUBLICATIONS = 128;

// Integration contract: retain publication history/aliases, not live catalog
// rows. Cache/blob IDs are historical values, without FKs to those catalogs.
// Canonical blob GC must exclude revisions having prepared/active pins under
// the upload_sessions SHARE lock. Reservation takes ROW EXCLUSIVE on that same
// table before looking up the canonical blob and acquiring its prepared pin.
// Authorization and stopping legacy writers belong to the caller. Never use
// initialization as an implicit request-time backfill of populated caches.

export type PublicationResult =
	| { readonly state: "active"; readonly grant: ActiveGrant; readonly alreadyExisted: boolean }
	| { readonly state: "pending"; readonly operationId: string }
	| { readonly state: "inactive" };
export interface LifecycleResult { readonly state: string; readonly epoch: string; readonly isPublic: boolean }

/** Read-only initialized-lifecycle detection; never auto-enroll or activate. */
export async function readPublicationCache(config: WorkerConfig, cacheId: number): Promise<Lifecycle | undefined> {
	return (await config.db.select().from(lifecycles).where(eq(lifecycles.cacheId, cacheId)))[0];
}

function identity(row: Lifecycle) { return { orgId: row.orgId, cacheId: row.cacheId }; }
function command(operationId: string = crypto.randomUUID()) { return { version: 2 as const, operationId, nonce: crypto.randomUUID() }; }
function pathWhere(cacheId: number, epoch: string, hash: string | typeof publishedPaths.storePathHash) {
	return and(eq(paths.cacheId, cacheId), eq(paths.epoch, epoch), eq(paths.storePathHash, hash));
}
async function lifecycle(db: Database, cacheId: number, lock = false): Promise<Lifecycle> {
	const query = db.select().from(lifecycles).where(eq(lifecycles.cacheId, cacheId));
	const [row] = await (lock ? query.for("update") : query);
	if (!row) throw new Error("Publication cache is not initialized");
	return row;
}
function checkIdentity(row: Lifecycle, cache: CacheAt) {
	if (row.orgId !== cache.orgId || row.path !== cache.path || row.name !== cache.name) {
		throw new Error("Publication cache identity changed: explicit route migration required");
	}
}

/**
 * Explicit initialization only, NOT a read/request auto-enrollment path. Existing
 * populated caches remain inactive until the explicit backfill APIs are used.
 * Cutover must also stop legacy writers that do not obey the lifecycle lock.
 */
export async function initializePublicationCache(config: WorkerConfig, cache: CacheAt): Promise<LifecycleResult> {
	await config.db.transaction(async (tx) => {
		const [known] = await tx.select().from(lifecycles).where(eq(lifecycles.cacheId, cache.id));
		if (known) { checkIdentity(known, cache); return; }
		// The cache row also serializes simultaneous first initializers.
		await tx.select().from(caches).where(eq(caches.id, cache.id)).for("update");
		const current = await findCacheById(tx, cache.id);
		if (!current || current.path !== cache.path || current.isPublic !== cache.isPublic) throw new Error("Cache changed before initialization; reload and retry");
		const [existing] = await tx.select().from(lifecycles).where(eq(lifecycles.cacheId, cache.id));
		if (existing) { checkIdentity(existing, cache); return; }
		const [populated] = await tx.select({ id: publishedPaths.id }).from(publishedPaths).where(eq(publishedPaths.cacheId, cache.id)).limit(1);
		await tx.insert(lifecycles).values({
			cacheId: cache.id, orgId: cache.orgId, path: cache.path, name: cache.name,
			epoch: crypto.randomUUID(), isPublic: cache.isPublic,
			state: populated ? "inactive" : "initializing", phase: populated ? null : "initialize-status",
		});
	});
	return advanceLifecycle(config, cache.id);
}

/** Each phase has one durable command. Duplicate drivers dispatch that same CAS. */
async function advanceLifecycle(config: WorkerConfig, cacheId: number): Promise<LifecycleResult> {
	for (let step = 0; step < 4; step++) {
		const row = await config.db.transaction(async (tx) => {
			const row = await lifecycle(tx, cacheId, true);
			if (!row.phase || row.phase === "retire-paths" || row.phase === "backfill-copy" || row.commandId) return row;
			let bytes: string;
			const route = row.phase === "initialize-route" || row.phase === "backfill-route";
			if (route) {
				bytes = JSON.stringify(v.parse(RouteRecord, { ...command(), ...identity(row), path: row.path, state: "active" }));
			} else {
				const activating = row.phase === "visibility-activate";
				bytes = JSON.stringify(v.parse(CacheStatus, {
					...command(), ...identity(row), name: row.name,
					epoch: activating ? row.targetEpoch : row.epoch,
					visibility: (activating ? row.targetPublic : row.isPublic) ? "public" : "private",
					state: row.phase.endsWith("drain") ? "draining" : row.phase === "retire-status" ? "retired" : "active",
				}));
			}
			const [updated] = await tx.update(lifecycles).set({
				commandId: JSON.parse(bytes).operationId, commandKey: route ? routeKey(row.path) : statusKey(cacheId),
				commandExpected: route ? row.routeEtag : row.statusEtag, commandBytes: bytes,
			}).where(eq(lifecycles.cacheId, cacheId)).returning();
			return updated!;
		});
		if (!row.commandId) return row;
		const journal = new AuthorityJournal(config.db, config.bucket);
		await journal.reserve({ operationId: row.commandId, resourceKey: row.commandKey!, predecessorEtag: row.commandExpected, payload: row.commandBytes! });
		const result = await journal.recover(row.commandId);
		if (result.state !== "accepted") return row;
		await config.db.transaction(async (tx) => {
			// Initialization/backfill also lock cache before lifecycle. Do not
			// invert that order when committing the catalog visibility change.
			if (row.phase === "visibility-activate") await tx.select().from(caches).where(eq(caches.id, cacheId)).for("update");
			const current = await lifecycle(tx, cacheId, true);
			if (current.commandId !== row.commandId) return;
			const update: Partial<typeof lifecycles.$inferInsert> = {
				commandId: null, commandBytes: null, commandKey: null, commandExpected: null,
				...(row.phase === "initialize-route" || row.phase === "backfill-route"
					? { routeBytes: result.successor, routeEtag: result.winningEtag }
					: { statusBytes: result.successor, statusEtag: result.winningEtag }),
			};
			if (row.phase === "initialize-status") update.phase = "initialize-route";
			else if (row.phase === "backfill-drain") update.phase = "backfill-copy";
			else if (row.phase === "backfill-activate") update.phase = "backfill-route";
			else if (row.phase === "visibility-drain") update.phase = "visibility-activate";
			else if (row.phase === "retire-drain") update.phase = "retire-paths";
			else if (row.phase === "retire-status") { update.phase = null; update.state = "retired"; }
			else {
				update.phase = null; update.state = "active";
				if (row.phase === "visibility-activate") {
					update.epoch = row.targetEpoch!; update.isPublic = row.targetPublic!;
					update.targetEpoch = null; update.targetPublic = null;
					await tx.update(caches).set({ isPublic: row.targetPublic! }).where(eq(caches.id, cacheId));
				}
			}
			await tx.update(lifecycles).set(update).where(eq(lifecycles.cacheId, cacheId));
		});
	}
	return lifecycle(config.db, cacheId);
}

/**
 * Operator-only migration entry point. The SQL barrier precedes the first R2
 * command; no ordinary publication, withdrawal, or visibility change is allowed
 * while migrating. Existing memberships remain intact. All legacy writers must
 * honor this barrier; this is not an online dual-writer migration protocol.
 * Scoped legacy witnesses are repaired, but unscoped global NAR URLs are NOT
 * preserved. Operator approval of that client cutoff is a release prerequisite.
 */
export async function beginPublicationBackfill(config: WorkerConfig, cache: CacheAt): Promise<LifecycleResult> {
	await config.db.transaction(async (tx) => {
		// Reject active/changing caches without holding their catalog row
		// against publication finalization's membership FK check.
		const [known] = await tx.select().from(lifecycles).where(eq(lifecycles.cacheId, cache.id));
		if (known && known.state !== "inactive" && known.state !== "migrating") throw new Error("Backfill requires an inactive legacy cache");
		const [catalog] = await tx.select().from(caches).where(eq(caches.id, cache.id)).for("update");
		if (!catalog) throw new Error("Cannot backfill a deleted cache");
		const current = await findCacheById(tx, cache.id);
		if (!current || current.path !== cache.path || current.isPublic !== cache.isPublic) throw new Error("Cache changed before backfill; reload and retry");
		await tx.insert(lifecycles).values({ cacheId: cache.id, orgId: cache.orgId, path: cache.path, name: cache.name,
			epoch: crypto.randomUUID(), isPublic: cache.isPublic, state: "inactive" }).onConflictDoNothing();
		const row = await lifecycle(tx, cache.id, true); checkIdentity(row, cache);
		if (row.state === "migrating") return;
		if (row.state !== "inactive") throw new Error("Backfill requires an inactive legacy cache");
		await tx.update(lifecycles).set({ state: "migrating", phase: "backfill-drain" }).where(eq(lifecycles.cacheId, cache.id));
	});
	return advanceLifecycle(config, cache.id);
}

/** Compare every membership field, including catalog identity and both timestamps. */
function unchangedBackfillMembership() {
	const original = sql`${jobs.pathJson}::jsonb`;
	return sql`(${publishedPaths.id}, ${publishedPaths.cacheId}, ${publishedPaths.storePathHash}, ${publishedPaths.storePath},
		${publishedPaths.narHash}, ${publishedPaths.narSize}, ${publishedPaths.blobObjectId}, ${publishedPaths.referencesJson},
		${publishedPaths.deriver}, ${publishedPaths.system}, ${publishedPaths.signaturesJson}, ${publishedPaths.createdAt}, ${publishedPaths.lastPushedAt})
		is not distinct from (
		(${original} ->> 'id')::bigint, (${original} ->> 'cacheId')::integer, ${original} ->> 'storePathHash', ${original} ->> 'storePath',
		${original} ->> 'narHash', (${original} ->> 'narSize')::bigint, (${original} ->> 'blobObjectId')::bigint, ${original} ->> 'referencesJson',
		${original} ->> 'deriver', ${original} ->> 'system', ${original} ->> 'signaturesJson',
		(${original} ->> 'createdAtExact')::timestamptz, (${original} ->> 'lastPushedAtExact')::timestamptz)`;
}

/** At most `limit` jobs per call; retry pending commands before allocating more. */
export async function backfillPublicationBatch(config: WorkerConfig, cache: CacheAt, limit = 25): Promise<{ state: string; processed: number; pending: number }> {
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PENDING_PUBLICATIONS) throw new Error("Backfill limit must be 1–128");
	await advanceLifecycle(config, cache.id);
	const row = await lifecycle(config.db, cache.id); checkIdentity(row, cache);
	if (row.state !== "migrating") throw new Error("Backfill has not begun");
	if (row.phase !== "backfill-copy") return { state: row.state, processed: 0, pending: 1 };
	const retry = await config.db.select().from(jobs).where(and(eq(jobs.cacheId, cache.id), eq(jobs.epoch, row.epoch), eq(jobs.kind, "backfill"),
		or(eq(jobs.state, "pending"), eq(jobs.witnessReady, false)))).orderBy(asc(jobs.storePathHash)).limit(limit);
	const allocated = await config.db.transaction(async (tx) => {
		await tx.execute(sql`lock table upload_sessions in row exclusive mode`);
		const locked = await lifecycle(tx, cache.id, true);
		if (locked.state !== "migrating" || locked.phase !== "backfill-copy" || retry.length === limit) return [];
		const outstanding = await tx.select({ id: jobs.id }).from(jobs).where(and(eq(jobs.cacheId, cache.id), eq(jobs.epoch, locked.epoch), eq(jobs.kind, "backfill"), eq(jobs.witnessReady, false))).limit(MAX_PENDING_PUBLICATIONS);
		const available = Math.min(limit - retry.length, MAX_PENDING_PUBLICATIONS - outstanding.length);
		if (available <= 0) return [];
		const memberships = await tx.select({ path: publishedPaths, blob: blobObjects,
			createdAtExact: sql<string>`${publishedPaths.createdAt}::text`, lastPushedAtExact: sql<string>`${publishedPaths.lastPushedAt}::text`,
		}).from(publishedPaths)
			.innerJoin(blobObjects, eq(blobObjects.id, publishedPaths.blobObjectId))
			.where(and(eq(publishedPaths.cacheId, cache.id), notExists(tx.select().from(paths).where(and(
				pathWhere(cache.id, locked.epoch, publishedPaths.storePathHash), sql`(${paths.activeRevision} is not null or ${paths.pendingJob} is not null)`,
			))))).orderBy(asc(publishedPaths.id)).limit(available);
		const ids: string[] = [];
		for (const membership of memberships) {
			const { path, blob } = membership;
			if (!/^[0-9a-f]{64}$/.test(blob.fileHash)) throw new Error("Legacy canonical blob has no valid hex SHA-256");
			const id = crypto.randomUUID(), revisionId = crypto.randomUUID();
			const stub = { ...identity(locked), epoch: locked.epoch, storePathHash: path.storePathHash, publicationId: revisionId } as ActiveGrant;
			await tx.insert(paths).values({ cacheId: cache.id, epoch: locked.epoch, storePathHash: path.storePathHash }).onConflictDoNothing();
			const [slot] = await tx.select().from(paths).where(pathWhere(cache.id, locked.epoch, path.storePathHash)).for("update");
			await tx.insert(revisions).values({ id: revisionId, cacheId: cache.id, epoch: locked.epoch, storePathHash: path.storePathHash,
				blobId: blob.id, isPublic: locked.isPublic, narKey: publicationKey(stub, "nar"), narinfoKey: publicationKey(stub, "narinfo") });
			await tx.insert(pins).values({ revisionId, kind: "prepared" });
			await tx.insert(jobs).values({ id, cacheId: cache.id, epoch: locked.epoch, storePathHash: path.storePathHash, kind: "backfill", revisionId,
				pathJson: JSON.stringify({ ...path, createdAtExact: membership.createdAtExact, lastPushedAtExact: membership.lastPushedAtExact }),
				blobJson: JSON.stringify(blob), predecessorEtag: slot!.grantEtag });
			await tx.update(paths).set({ pendingJob: id }).where(pathWhere(cache.id, locked.epoch, path.storePathHash));
			ids.push(id);
		}
		return ids;
	});
	let pending = 0;
	for (const id of [...retry.map((job) => job.id), ...allocated]) {
		const job = await recoverPublication(config, id);
		if (job.state !== "done") { pending++; continue; }
		const blob = JSON.parse(job.blobJson) as NarinfoBlob;
		if (await repairLegacyPublicationWitness(config, cache.id, blob.fileHash, blob.compression) !== "ready") { pending++; continue; }
		await config.db.update(jobs).set({ witnessReady: true }).where(and(eq(jobs.id, id), eq(jobs.state, "done")));
	}
	return { state: "migrating", processed: retry.length + allocated.length, pending };
}

/**
 * SQL proves full coverage and unchanged membership under the lifecycle lock.
 * Only then may the journal move status from draining to active. Retrying this
 * API completes unknown activation/route outcomes without allocating new epochs.
 */
export async function finishPublicationBackfill(config: WorkerConfig, cache: CacheAt): Promise<LifecycleResult> {
	await config.db.transaction(async (tx) => {
		const row = await lifecycle(tx, cache.id, true); checkIdentity(row, cache);
		if (row.state === "active") return;
		if (row.state !== "migrating") throw new Error("Backfill has not begun");
		if (row.phase !== "backfill-copy") return;
		const [unfinished] = await tx.select().from(jobs).where(and(eq(jobs.cacheId, cache.id), eq(jobs.epoch, row.epoch), eq(jobs.kind, "backfill"),
			or(sql`${jobs.state} <> 'done'`, eq(jobs.witnessReady, false)))).limit(1);
		if (unfinished) return;
		const [changed] = await tx.select().from(jobs).where(and(eq(jobs.cacheId, cache.id), eq(jobs.epoch, row.epoch), eq(jobs.kind, "backfill"),
			notExists(tx.select().from(publishedPaths).where(unchangedBackfillMembership())))).limit(1);
		if (changed) throw new Error("Legacy membership changed during backfill; mutation quarantine required");
		const [uncovered] = await tx.select().from(publishedPaths).where(and(eq(publishedPaths.cacheId, cache.id),
			notExists(tx.select().from(paths).where(and(pathWhere(cache.id, row.epoch, publishedPaths.storePathHash), sql`${paths.activeRevision} is not null`, isNull(paths.pendingJob)))))).limit(1);
		if (uncovered) return;
		await tx.update(lifecycles).set({ phase: "backfill-activate" }).where(eq(lifecycles.cacheId, cache.id));
	});
	return advanceLifecycle(config, cache.id);
}

/** Empty-only, including unknown activations/preparations, under a SQL barrier. */
export async function changePublicationVisibility(config: WorkerConfig, cache: CacheAt, isPublic: boolean): Promise<LifecycleResult> {
	await config.db.transaction(async (tx) => {
		// Go reservations take a shared cache lock and check this lifecycle.
		await tx.select().from(caches).where(eq(caches.id, cache.id)).for("update");
		const row = await lifecycle(tx, cache.id, true); checkIdentity(row, cache);
		if (row.state === "changing" && row.targetPublic === isPublic) return;
		if (row.state !== "active") throw new Error("Publication lifecycle transition is pending or inactive");
		if (row.isPublic === isPublic) return;
		const [occupied] = await tx.select().from(paths).where(and(eq(paths.cacheId, cache.id),
			sql`(${paths.activeRevision} is not null or ${paths.pendingJob} is not null)`)).limit(1);
		const [legacy] = await tx.select().from(publishedPaths).where(eq(publishedPaths.cacheId, cache.id)).limit(1);
		if (occupied || legacy || await cacheHasGoEntries(tx, cache.id)) throw new Error("Visibility requires an empty cache with no pending publications or Go uploads");
		await tx.update(lifecycles).set({ state: "changing", phase: "visibility-drain", targetEpoch: crypto.randomUUID(), targetPublic: isPublic }).where(eq(lifecycles.cacheId, cache.id));
	});
	return advanceLifecycle(config, cache.id);
}

/** Ordinary publication converges on the existing active identity; no replacement API. */
export async function publishPublication(config: WorkerConfig, cache: CacheAt, path: NarinfoPath, blob: NarinfoBlob): Promise<PublicationResult> {
	const reserved = await config.db.transaction(async (tx): Promise<PublicationResult | { jobId: string; reused: boolean }> => {
		// Coordinate the source pin with canonical GC's SHARE lock; no R2 here.
		await tx.execute(sql`lock table upload_sessions in row exclusive mode`);
		const row = await lifecycle(tx, cache.id, true); checkIdentity(row, cache);
		if (row.state !== "active") return { state: "inactive" };
		await tx.insert(paths).values({ cacheId: cache.id, epoch: row.epoch, storePathHash: path.storePathHash }).onConflictDoNothing();
		const [slot] = await tx.select().from(paths).where(pathWhere(cache.id, row.epoch, path.storePathHash)).for("update");
		if (slot!.pendingJob) return { jobId: slot!.pendingJob, reused: true };
		if (slot!.activeRevision) {
			await tx.update(publishedPaths).set({ lastPushedAt: new Date() }).where(and(eq(publishedPaths.cacheId, cache.id), eq(publishedPaths.storePathHash, path.storePathHash)));
			return { state: "active", grant: v.parse(ActiveGrant, JSON.parse(slot!.grantBytes!)), alreadyExisted: true };
		}
		const pending = await tx.select({ id: jobs.id }).from(jobs).where(and(eq(jobs.cacheId, cache.id), eq(jobs.state, "pending"))).limit(MAX_PENDING_PUBLICATIONS);
		if (pending.length >= MAX_PENDING_PUBLICATIONS) throw new Error("Publication queue is full; recover pending operations first");
		if (!/^[0-9a-f]{64}$/.test(blob.fileHash) || !Number.isSafeInteger(blob.fileSize) || blob.fileSize < 0) throw new Error("Publication requires a hex SHA-256 and exact safe file size");
		const [canonical] = await tx.select().from(blobObjects).where(and(eq(blobObjects.fileHash, blob.fileHash), eq(blobObjects.compression, blob.compression), eq(blobObjects.r2Key, blob.r2Key), eq(blobObjects.fileSize, blob.fileSize)));
		if (!canonical) throw new Error("Canonical blob must be registered before publication");
		const id = crypto.randomUUID();
		const revisionId = crypto.randomUUID();
		const stub = { ...identity(row), epoch: row.epoch, storePathHash: path.storePathHash, publicationId: revisionId, fileHash: blob.fileHash } as ActiveGrant;
		await tx.insert(revisions).values({ id: revisionId, cacheId: cache.id, epoch: row.epoch, storePathHash: path.storePathHash,
			blobId: canonical.id, isPublic: row.isPublic, narKey: publicationKey(stub, "nar"), narinfoKey: publicationKey(stub, "narinfo") });
		await tx.insert(pins).values({ revisionId, kind: "prepared" });
		await tx.insert(jobs).values({ id, cacheId: cache.id, epoch: row.epoch, storePathHash: path.storePathHash, kind: "publish", revisionId,
			pathJson: JSON.stringify(path), blobJson: JSON.stringify(blob), predecessorEtag: slot!.grantEtag });
		await tx.update(paths).set({ pendingJob: id }).where(pathWhere(cache.id, row.epoch, path.storePathHash));
		return { jobId: id, reused: false };
	});
	if (!("jobId" in reserved)) {
		if (reserved.state === "active") await repairLegacyPublicationWitness(config, reserved.grant.cacheId, reserved.grant.fileHash, reserved.grant.compression).catch(() => {});
		return reserved;
	}
	const result = await recoverPublication(config, reserved.jobId);
	if (result.kind === "publish" && result.state === "done") {
		const grant = v.parse(ActiveGrant, JSON.parse(result.grantBytes!));
		await repairLegacyPublicationWitness(config, grant.cacheId, grant.fileHash, grant.compression).catch(() => {});
		return { state: "active", grant, alreadyExisted: reserved.reused };
	}
	return { state: "pending", operationId: reserved.jobId };
}

function hex(bytes: ArrayBuffer): string { return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }
async function revision(config: WorkerConfig, id: string): Promise<Revision> {
	const [row] = await config.db.select().from(revisions).where(eq(revisions.id, id));
	if (!row) throw new Error("Missing publication revision");
	return row;
}

/**
 * Exactly one dispatch per immutable destination, claimed durably before I/O.
 * If an issued PUT is unknown and its object is absent, do NOT resend or GC it:
 * a delayed PUT could otherwise recreate an already-deleted immutable key.
 * Presence with the persisted checksum proves that unique dispatch committed.
 * A crash before dispatch can therefore strand a pin; it never grants access.
 */
async function prepareRepresentation(config: WorkerConfig, job: Job, kind: "nar" | "narinfo"): Promise<boolean> {
	let rev = await revision(config, job.revisionId);
	const phase = kind === "nar" ? revisions.narPhase : revisions.narinfoPhase;
	if (rev.state !== "prepared") return rev.state === "active";
	if ((kind === "nar" ? rev.narPhase : rev.narinfoPhase) === "complete") return true;
	const blob = JSON.parse(job.blobJson) as NarinfoBlob;
	const bytes = new TextEncoder().encode(rev.narinfo ?? "");
	const checksum = kind === "nar" ? blob.fileHash : hex(await crypto.subtle.digest("SHA-256", bytes));
	const size = kind === "nar" ? blob.fileSize : bytes.byteLength;
	const key = kind === "nar" ? rev.narKey : rev.narinfoKey;
	const bucket = bucketFor(config, !rev.isPublic);
	// A missing/unreadable source is not an unknown destination PUT. Keep
	// `new` until the source exists, so restoring it can recover this job.
	let source: R2ObjectBody | null = null;
	if (kind === "nar" && rev.narPhase === "new") {
		try { source = await bucketForKey(config, blob.r2Key).get(blob.r2Key); } catch { return false; }
		if (!source || source.size !== size) { await source?.body.cancel(); return false; }
	}
	const [claimed] = await config.db.update(revisions).set(kind === "nar" ? { narPhase: "issued" } : { narinfoPhase: "issued" })
		.where(and(eq(revisions.id, rev.id), eq(revisions.state, "prepared"), eq(phase, "new"))).returning();
	if (claimed) {
		// No other preparation worker may dispatch this destination now.
		try {
			await bucket.put(key, kind === "nar" ? source!.body : bytes, {
				onlyIf: { etagDoesNotMatch: "*" }, sha256: checksum,
				httpMetadata: { contentType: kind === "nar" ? "application/x-nix-nar" : "text/x-nix-narinfo", cacheControl: IMMUTABLE },
			});
		} catch { return false; }
	} else await source?.body.cancel();
	const head = await bucket.head(key);
	if (!head || head.size !== size || !head.checksums.sha256 || hex(head.checksums.sha256) !== checksum) return false;
	await config.db.update(revisions).set(kind === "nar" ? { narPhase: "complete", narEtag: head.httpEtag } : { narinfoPhase: "complete", narinfoEtag: head.httpEtag })
		.where(and(eq(revisions.id, rev.id), eq(revisions.state, "prepared"), eq(phase, "issued")));
	rev = await revision(config, rev.id);
	return (kind === "nar" ? rev.narPhase : rev.narinfoPhase) === "complete";
}

/** Recovery by durable operation ID; safe for independent concurrent workers. */
export async function recoverPublication(config: WorkerConfig, operationId: string, withdraw = false): Promise<Job> {
	let [job] = await config.db.select().from(jobs).where(eq(jobs.id, operationId));
	if (!job) throw new Error("Unknown publication job");
	if (job.state !== "pending") return job;
	const row = await lifecycle(config.db, job.cacheId);
	if (job.kind === "backfill" && (withdraw || row.state !== "migrating" || row.phase !== "backfill-copy")) {
		throw new Error("Backfill jobs require the draining migration barrier and cannot be withdrawn");
	}
	if (job.kind !== "withdraw" && !job.grantBytes) {
		let rev = await revision(config, job.revisionId);
		if (!rev.narinfo) {
			const path = JSON.parse(job.pathJson) as NarinfoPath;
			const blob = JSON.parse(job.blobJson) as NarinfoBlob;
			const canonical = { ...path, narHash: valueOf(NarHash, path.narHash) ?? path.narHash };
			const refs = JSON.parse(path.referencesJson) as string[];
			const cache = await findCacheById(config.db, job.cacheId);
			if (!cache) throw new Error("Publication cache is missing");
			const key = await signingKeyFor(config, cache);
			const sig = await signNarinfo(computeFingerprint(canonical, refs), key.name, key.key);
			if (!sig) throw new Error("Publication requires a signing key");
			const url = publicationUrl({ publicationId: rev.id, storePathHash: job.storePathHash, fileHash: blob.fileHash } as ActiveGrant);
			const narinfo = renderNarinfo(canonical, blob, url, refs, JSON.parse(path.signaturesJson), [sig]);
			await config.db.update(revisions).set({ narinfo }).where(and(eq(revisions.id, rev.id), isNull(revisions.narinfo)));
		}
		if (!await prepareRepresentation(config, job, "nar") || !await prepareRepresentation(config, job, "narinfo")) return job;
		rev = await revision(config, job.revisionId);
		const blob = JSON.parse(job.blobJson) as NarinfoBlob;
		const grant = v.parse(ActiveGrant, {
			...command(job.id), ...identity(row), epoch: job.epoch, storePathHash: job.storePathHash, state: "active",
			publicationId: rev.id, fileHash: blob.fileHash, compression: blob.compression, fileSize: blob.fileSize,
			narinfoSize: new TextEncoder().encode(rev.narinfo!).byteLength, narEtag: rev.narEtag, narinfoEtag: rev.narinfoEtag,
			publishedAt: job.kind === "backfill" ? Math.floor(new Date(JSON.parse(job.pathJson).createdAt).getTime() / 1000) : Math.floor(Date.now() / 1000),
		});
		await config.db.update(jobs).set({ grantBytes: JSON.stringify(grant) }).where(and(eq(jobs.id, job.id), isNull(jobs.grantBytes), eq(jobs.state, "pending")));
		[job] = await config.db.select().from(jobs).where(eq(jobs.id, operationId));
	}
	const journal = new AuthorityJournal(config.db, config.bucket);
	await journal.reserve({ operationId: job!.id, resourceKey: grantKey(job!.cacheId, job!.epoch, job!.storePathHash), predecessorEtag: job!.predecessorEtag, payload: job!.grantBytes! });
	if (withdraw && job!.kind === "publish") {
		await journal.fence(job!.id, JSON.stringify(v.parse(PathGrant, { ...command(job!.id), ...identity(row), epoch: job!.epoch, storePathHash: job!.storePathHash, state: "tombstone" })));
	}
	const outcome = await journal.recover(job!.id);
	if (outcome.state !== "accepted" && outcome.state !== "excluded") return job!;
	await config.db.transaction(async (tx) => {
		await lifecycle(tx, job!.cacheId, true);
		const [current] = await tx.select().from(jobs).where(eq(jobs.id, job!.id)).for("update");
		if (current!.state !== "pending") return;
		const [slot] = await tx.select().from(paths).where(pathWhere(job!.cacheId, job!.epoch, job!.storePathHash)).for("update");
		if (slot!.pendingJob !== job!.id) throw new Error("Publication reservation was lost");
		const active = job!.kind !== "withdraw" && outcome.state === "accepted";
		if (active) {
			const path = JSON.parse(job!.pathJson) as NarinfoPath;
			const rev = await tx.select().from(revisions).where(eq(revisions.id, job!.revisionId)).then((rows) => rows[0]!);
			if (rev.state !== "prepared" || rev.narPhase !== "complete" || rev.narinfoPhase !== "complete") throw new Error("Activation has incomplete dependencies");
			if (job!.kind === "backfill") {
				const [unchanged] = await tx.select({ id: publishedPaths.id }).from(publishedPaths).innerJoin(jobs, eq(jobs.id, job!.id))
					.where(unchangedBackfillMembership()).limit(1);
				if (!unchanged) throw new Error("Legacy membership changed during backfill; mutation quarantine required");
			} else {
				await tx.insert(publishedPaths).values({ ...path, cacheId: job!.cacheId, blobObjectId: rev.blobId });
			}
			await tx.insert(pins).values({ revisionId: rev.id, kind: "active" }).onConflictDoNothing();
			await tx.update(revisions).set({ state: "active" }).where(eq(revisions.id, rev.id));
		} else {
			await tx.delete(publishedPaths).where(and(eq(publishedPaths.cacheId, job!.cacheId), eq(publishedPaths.storePathHash, job!.storePathHash)));
			await tx.delete(pins).where(and(eq(pins.revisionId, job!.revisionId), eq(pins.kind, "active")));
			await tx.update(revisions).set({ state: "retired" }).where(eq(revisions.id, job!.revisionId));
		}
		await tx.delete(pins).where(and(eq(pins.revisionId, job!.revisionId), eq(pins.kind, "prepared")));
		await tx.update(paths).set({ activeRevision: active ? job!.revisionId : null, pendingJob: null,
			grantBytes: outcome.state === "excluded" ? outcome.fenceSuccessor : outcome.successor, grantEtag: outcome.winningEtag })
			.where(pathWhere(job!.cacheId, job!.epoch, job!.storePathHash));
		await tx.update(jobs).set({ state: outcome.state === "excluded" ? "excluded" : "done" }).where(eq(jobs.id, job!.id));
	});
	return (await config.db.select().from(jobs).where(eq(jobs.id, operationId)))[0]!;
}

/** Withdrawals share the path barrier and fence unresolved grant activation. */
export async function withdrawPublications(config: WorkerConfig, cache: CacheAt, hashes: readonly string[]): Promise<{ withdrawn: string[]; pending: string[] }> {
	const withdrawn: string[] = [], pending: string[] = [];
	for (const hash of new Set(hashes)) {
		let complete = false;
		for (let attempt = 0; attempt < 3; attempt++) {
			const reserved = await config.db.transaction(async (tx) => {
				const row = await lifecycle(tx, cache.id, true); checkIdentity(row, cache);
				if (row.state !== "active" && row.state !== "retiring") throw new Error("Publication cache is inactive or changing visibility");
				const [slot] = await tx.select().from(paths).where(pathWhere(cache.id, row.epoch, hash)).for("update");
				if (!slot) return null;
				if (slot.pendingJob) return slot.pendingJob;
				if (!slot.activeRevision) return null;
				const [original] = await tx.select().from(jobs).where(and(eq(jobs.revisionId, slot.activeRevision), inArray(jobs.kind, ["publish", "backfill"])));
				const id = crypto.randomUUID();
				const grant = v.parse(PathGrant, { ...command(id), ...identity(row), epoch: row.epoch, storePathHash: hash, state: "tombstone" });
				await tx.insert(jobs).values({ id, cacheId: cache.id, epoch: row.epoch, storePathHash: hash, kind: "withdraw", revisionId: slot.activeRevision,
					pathJson: original!.pathJson, blobJson: original!.blobJson, predecessorEtag: slot.grantEtag, grantBytes: JSON.stringify(grant) });
				await tx.update(paths).set({ pendingJob: id }).where(pathWhere(cache.id, row.epoch, hash));
				return id;
			});
			if (!reserved) { complete = true; break; }
			const result = await recoverPublication(config, reserved, true);
			if (result.state === "pending") break;
			const blob = JSON.parse(result.blobJson) as NarinfoBlob;
			await repairLegacyPublicationWitness(config, result.cacheId, blob.fileHash, blob.compression).catch(() => {});
		}
		(complete ? withdrawn : pending).push(hash);
	}
	return { withdrawn, pending };
}

/**
 * Compatibility hints are availability work, never publication authority.
 * An obsolete hint remains deny-only until this bounded repair chooses another
 * independently active matching path. Unknown hint writes use the same journal
 * barrier. Call this explicitly on recovery/admin refresh as well as mutations.
 */
export async function repairLegacyPublicationWitness(config: WorkerConfig, cacheId: number, fileHash: string, compression: string): Promise<"ready" | "pending" | "unavailable"> {
	const row = await lifecycle(config.db, cacheId);
	const key = witnessKey(cacheId, row.epoch, fileHash, compression);
	const journal = new AuthorityJournal(config.db, config.bucket);
	const [unresolved] = await config.db.select().from(authorityJournal).where(and(eq(authorityJournal.resourceKey, key), inArray(authorityJournal.state, ["pending", "fencing", "frozen"])));
	if (unresolved) {
		const result = await journal.recover(unresolved.operationId);
		if (result.state !== "accepted") return "pending";
	}
	const candidates = await config.db.select().from(paths).where(and(eq(paths.cacheId, cacheId), eq(paths.epoch, row.epoch), sql`${paths.activeRevision} is not null`,
		sql`${paths.grantBytes}::jsonb ->> 'fileHash' = ${fileHash}`, sql`${paths.grantBytes}::jsonb ->> 'compression' = ${compression}`)).limit(1);
	const matching = candidates.map((slot) => v.parse(ActiveGrant, JSON.parse(slot.grantBytes!)))
		.filter((grant) => grant.fileHash === fileHash && grant.compression === compression);
	if (!matching.length) return "unavailable";
	const current = await config.bucket.get(key);
	if (current) {
		const witness = v.parse(LegacyWitness, await current.json());
		if (witness.cacheId !== cacheId || witness.orgId !== row.orgId || witness.epoch !== row.epoch || witness.fileHash !== fileHash || witness.compression !== compression) {
			throw new Error("Legacy witness identity mismatch: mutation quarantine required");
		}
		const [hinted] = await config.db.select().from(paths).where(pathWhere(cacheId, row.epoch, witness.storePathHash));
		if (hinted?.activeRevision) {
			const grant = v.parse(ActiveGrant, JSON.parse(hinted.grantBytes!));
			if (grant.publicationId === witness.publicationId && grant.cacheId === witness.cacheId && grant.epoch === witness.epoch &&
				grant.orgId === witness.orgId && grant.fileHash === witness.fileHash && grant.compression === witness.compression) return "ready";
		}
		const [known] = await config.db.select().from(authorityJournal).where(and(eq(authorityJournal.resourceKey, key), eq(authorityJournal.winningEtag, current.etag), eq(authorityJournal.state, "accepted")));
		if (!known) throw new Error("Unjournaled legacy witness: mutation quarantine required");
	} else {
		const [history] = await config.db.select().from(authorityJournal).where(eq(authorityJournal.resourceKey, key)).limit(1);
		if (history) throw new Error("Permanent legacy witness disappeared: mutation quarantine required");
	}
	const grant = matching[0]!;
	const witness = v.parse(LegacyWitness, { ...command(), ...identity(row), epoch: row.epoch,
		storePathHash: grant.storePathHash, publicationId: grant.publicationId, fileHash, compression });
	try {
		await journal.reserve({ operationId: witness.operationId, resourceKey: key, predecessorEtag: current?.etag ?? null, payload: JSON.stringify(witness) });
	} catch { return "pending"; } // Another repair can hold the durable per-key barrier.
	return (await journal.recover(witness.operationId)).state === "accepted" ? "ready" : "pending";
}

/** Disable first; reconcile/fence every path before terminal retirement. */
export async function retirePublicationCache(config: WorkerConfig, cache: CacheAt): Promise<LifecycleResult> {
	await config.db.transaction(async (tx) => {
		const row = await lifecycle(tx, cache.id, true); checkIdentity(row, cache);
		if (row.state === "retiring" || row.state === "retired") return;
		if (row.state !== "active") throw new Error("Publication cache must finish its current lifecycle transition first");
		await tx.update(lifecycles).set({ state: "retiring", phase: "retire-drain" }).where(eq(lifecycles.cacheId, cache.id));
	});
	let row = await advanceLifecycle(config, cache.id);
	if (row.state !== "retiring") return row;
	const current = await lifecycle(config.db, cache.id);
	if (current.phase !== "retire-paths") return current;
	const occupied = await config.db.select().from(paths).where(and(eq(paths.cacheId, cache.id), eq(paths.epoch, current.epoch), sql`(${paths.activeRevision} is not null or ${paths.pendingJob} is not null)`)).limit(100);
	await withdrawPublications(config, cache, occupied.map((slot) => slot.storePathHash));
	await config.db.transaction(async (tx) => {
		const locked = await lifecycle(tx, cache.id, true);
		if (locked.phase !== "retire-paths") return;
		const [remaining] = await tx.select().from(paths).where(and(eq(paths.cacheId, cache.id), sql`(${paths.activeRevision} is not null or ${paths.pendingJob} is not null)`)).limit(1);
		if (!remaining) await tx.update(lifecycles).set({ phase: "retire-status" }).where(eq(lifecycles.cacheId, cache.id));
	});
	row = await advanceLifecycle(config, cache.id);
	return row;
}

/** Only retired, unpinned, completely settled immutable keys may be deleted. */
export async function collectRetiredPublications(config: WorkerConfig, limit = 100): Promise<{ deleted: number; pending: number }> {
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new Error("GC limit must be 1–1000");
	const selected = await config.db.transaction(async (tx) => {
		const rows = await tx.select().from(revisions).where(and(
			inArray(revisions.state, ["retired", "deleting"]), eq(revisions.narPhase, "complete"), eq(revisions.narinfoPhase, "complete"),
			notExists(tx.select().from(pins).where(eq(pins.revisionId, revisions.id))),
		)).limit(limit).for("update", { skipLocked: true });
		if (rows.length) await tx.update(revisions).set({ state: "deleting" }).where(inArray(revisions.id, rows.map((row) => row.id)));
		return rows;
	});
	let deleted = 0;
	for (const rev of selected) {
		try {
			await bucketFor(config, !rev.isPublic).delete([rev.narKey, rev.narinfoKey]);
			await config.db.update(revisions).set({ state: "deleted" }).where(and(eq(revisions.id, rev.id), eq(revisions.state, "deleting")));
			deleted++;
		} catch { /* A durable deleting row is retried next sweep, with the same exact keys. */ }
	}
	return { deleted, pending: selected.length - deleted };
}
