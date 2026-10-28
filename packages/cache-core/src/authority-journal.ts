import { and, eq, inArray } from "drizzle-orm";
import type { Db } from "./db/connection.js";
import { authorityJournal as journal } from "./db/schema.js";

export type AuthorityOperation = typeof journal.$inferSelect;
export interface AuthorityCommand {
	readonly operationId: string;
	readonly resourceKey: string;
	/** null means If-None-Match: *, never an unconditional write. */
	readonly predecessorEtag: string | null;
	/** Exact serialized domain-validated v2 record, including nonce and operationId. */
	readonly payload: string;
}

type Bucket = Pick<R2Bucket, "get" | "put">;
const unresolved = ["pending", "fencing"];

function commandNonce(operationId: string, payload: string): string {
	const record = JSON.parse(payload) as { version?: unknown; nonce?: unknown; operationId?: unknown } | null;
	if (!record || record.version !== 2 || record.operationId !== operationId ||
		typeof record.nonce !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(record.nonce)) {
		throw new Error("Authority bytes must contain version 2, a UUID nonce, and the exact operation ID");
	}
	return record.nonce;
}

/**
 * Only this writer may mutate its authority keys. No DELETE, unconditional PUT,
 * rebasing, or expired-reservation escape exists. SQL loss must quarantine writes.
 * Callers own domain validation, lifecycle authorization, and payload pins; keep
 * those pins until this journal durably reports accepted/excluded. `accepted`
 * is a historical serving effect, not a claim the record remains current.
 *
 * Use a request-local Db connection (including independent connections for
 * concurrent workers). No transaction spans R2 I/O. Exact input payload bytes
 * are the stored wire format, compatible with the shared publication schemas.
 */
export class AuthorityJournal {
	constructor(private readonly db: Db, private readonly bucket: Bucket) {}

	async read(operationId: string): Promise<AuthorityOperation> {
		const [row] = await this.db.select().from(journal).where(eq(journal.operationId, operationId));
		if (!row) throw new Error("Unknown authority operation");
		return row;
	}

	/** Commit exact bytes and condition before any dispatch. Idempotency is exact. */
	async reserve(command: AuthorityCommand): Promise<AuthorityOperation> {
		if (!command.operationId || !command.resourceKey ||
			(command.predecessorEtag !== null && !/^[A-Za-z0-9_-]+$/.test(command.predecessorEtag))) {
			throw new Error("Invalid authority command identity or ETag");
		}
		const nonce = commandNonce(command.operationId, command.payload);
		await this.db.insert(journal).values({ ...command, nonce, successor: command.payload }).onConflictDoNothing();
		const [row] = await this.db.select().from(journal).where(eq(journal.operationId, command.operationId));
		if (!row) throw new Error("Authority key has an unresolved reservation");
		if (row.resourceKey !== command.resourceKey || row.predecessorEtag !== command.predecessorEtag || row.payload !== command.payload) {
			throw new Error("Authority operation ID reused with a different command");
		}
		return row;
	}

	/**
	 * Allocate at most one competing CAS against the ORIGINAL predecessor. SQL
	 * phase CAS arbitrates concurrent allocators; losers use the winner's bytes.
	 * This does not dispatch. An already accepted original is returned unchanged;
	 * withdrawal after that requires a new authorized reserve, never a rebase.
	 * The caller supplies a tombstone or a fresh-nonce preservation of the old
	 * domain record as appropriate; canceling replacement is NOT withdrawal.
	 */
	async fence(operationId: string, payload: string): Promise<AuthorityOperation> {
		const row = await this.read(operationId);
		if (row.state !== "pending") return row;
		const nonce = commandNonce(operationId, payload);
		if (nonce === row.nonce) throw new Error("Competing fence must have a fresh nonce");
		await this.db.update(journal).set({
			state: "fencing", fenceNonce: nonce,
			fenceSuccessor: payload,
		}).where(and(eq(journal.operationId, operationId), eq(journal.state, "pending")));
		return this.read(operationId);
	}

	private async settle(operationId: string, state: "accepted" | "excluded" | "frozen", etag: string | null): Promise<AuthorityOperation> {
		// The UPDATE's row lock/phase CAS ensures stale observers cannot overwrite
		// durable acceptance after another worker has released the reservation.
		await this.db.update(journal).set({ state, winningEtag: etag }).where(and(
			eq(journal.operationId, operationId), inArray(journal.state, unresolved),
		));
		return this.read(operationId);
	}

	/**
	 * Observe then retry only the current persisted CAS. Throws on read/SQL
	 * failures; unknown PUT failures return unresolved, including predecessor/404.
	 * Repeat until terminal. Duplicate workers may dispatch identical bytes.
	 */
	async recover(operationId: string): Promise<AuthorityOperation> {
		let row = await this.read(operationId);
		if (!unresolved.includes(row.state)) return row;
		const current = await this.bucket.get(row.resourceKey);
		const bytes = current ? await current.text() : null;
		// A fence can be allocated and win during the read. Interpret the
		// observation using the latest durable command, not a stale phase.
		row = await this.read(operationId);
		if (!unresolved.includes(row.state)) return row;
		if (current && bytes === row.successor) return this.settle(operationId, "accepted", current.etag);
		if (current && row.fenceSuccessor && bytes === row.fenceSuccessor) return this.settle(operationId, "excluded", current.etag);
		if ((current?.etag ?? null) !== row.predecessorEtag) return this.settle(operationId, "frozen", null);

		// Re-read after R2 observation: a competing fence may have been allocated.
		// A worker already dispatched before allocation can still race it, but
		// both use the SAME predecessor and only one can win.
		const dispatch = await this.read(operationId);
		if (!unresolved.includes(dispatch.state)) return dispatch;
		const isFence = dispatch.state === "fencing";
		const successor = isFence ? dispatch.fenceSuccessor! : dispatch.successor;
		let result: R2Object | null;
		try {
			result = await this.bucket.put(dispatch.resourceKey, successor, {
				onlyIf: dispatch.predecessorEtag === null ? { etagDoesNotMatch: "*" } : { etagMatches: dispatch.predecessorEtag },
			});
		} catch {
			return this.read(operationId);
		}
		if (result) return this.settle(operationId, isFence ? "excluded" : "accepted", result.etag);
		// Precondition failure is not proof of failure: another retry may have
		// accepted the original/fence. Its exact bytes must be observed next.
		return this.read(operationId);
	}
}
