import { sql } from "drizzle-orm";
import type { Db } from "./db/connection.js";
import { uploadParts, uploadSessions } from "./db/schema.js";
import type { UploadSession } from "./db/types.js";

/** Versioned locators route to one org without a Postgres session lookup. */
export function streamSessionId(org: string): string {
	return `s2.${org}.${crypto.randomUUID()}`;
}

export function streamSessionOrg(id: string): string | undefined {
	return /^s2\.([A-Za-z0-9_-]{1,128})\.[a-f0-9-]{36}$/.exec(id)?.[1];
}

export type StreamError = { error: string; status: number };
export type StreamPart = { partNumber: number; size: number; etag: string | null };
export type StreamReceipt = {
	sessionId: string; narHash: string; narSize: number; fileHash: string; fileSize: number;
	parts: readonly { partNumber: number; etag: string }[];
};

/**
 * Import a sealed SQLite stream into the existing global installation fence.
 * SQL has only a cleanup record before this boundary. Replays are immutable,
 * including when SQL committed but its acknowledgement was lost.
 */
export async function bridgeUploadStreams(db: Db, streams: readonly { session: UploadSession; parts: StreamPart[] }[]): Promise<Map<string, UploadSession>> {
	if (streams.length === 0) return new Map();
	return db.transaction(async tx => {
		const ids = streams.map(s => s.session.id);
		const currentById = new Map((await tx.select().from(uploadSessions)
			.where(sql`${uploadSessions.id} = ANY(${sql.param(ids)}::text[])`).orderBy(uploadSessions.id).for("update")).map(s => [s.id, s]));
		const fresh: typeof streams[number][] = [];
		for (const stream of streams) {
			const { session } = stream;
			const current = currentById.get(session.id);
			if (!current || current.expiresAt <= new Date() || !["streaming", "finalizing", "completed"].includes(current.status)) {
				throw new Error("Upload expired or aborted");
			}
			if (current.status !== "streaming") {
				if (current.fileHash !== session.fileHash || current.fileSize !== session.fileSize) throw new Error("Sealed stream cannot change");
				continue;
			}
			fresh.push(stream);
		}
		if (fresh.length) {
			await tx.insert(uploadParts).values(fresh.flatMap(({ session, parts }) => parts.map(p => ({ ...p, sessionId: session.id }))));
			const receipts = JSON.stringify(fresh.map(({ session }) => ({ id: session.id, hash: session.fileHash, size: session.fileSize })));
			await tx.execute(sql`UPDATE ${uploadSessions} SET file_hash = receipt.hash, file_size = receipt.size, status = 'finalizing'
				FROM jsonb_to_recordset(${receipts}::jsonb) AS receipt(id text, hash text, size bigint)
				WHERE ${uploadSessions.id} = receipt.id`);
			for (const { session } of fresh) currentById.set(session.id, session);
		}
		return currentById;
	});
}

/** SQLite is authoritative for grants, sealing, and abort/finalize exclusion. */
export class StreamState {
	constructor(private readonly storage: DurableObjectStorage) {
		storage.sql.exec(`
			CREATE TABLE IF NOT EXISTS streams_v2 (
				id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL,
				expires INTEGER NOT NULL, bytes INTEGER NOT NULL DEFAULT 0, capacity INTEGER
			);
			CREATE INDEX IF NOT EXISTS streams_v2_expiry ON streams_v2(expires);
			CREATE TABLE IF NOT EXISTS stream_parts_v2 (
				session TEXT NOT NULL, number INTEGER NOT NULL, size INTEGER NOT NULL, etag TEXT,
				PRIMARY KEY (session, number)
			);
		`);
	}

	get(ids: readonly string[]): UploadSession[] {
		return ids.flatMap(id => {
			const row = this.storage.sql.exec<{ payload: string }>("SELECT payload FROM streams_v2 WHERE id = ?", id).toArray()[0];
			if (!row) return [];
			const session = JSON.parse(row.payload) as UploadSession;
			return [{ ...session, createdAt: new Date(session.createdAt), expiresAt: new Date(session.expiresAt) }];
		});
	}

	parts(id: string): StreamPart[] {
		return this.storage.sql.exec<{ partNumber: number; size: number; etag: string | null }>(
			"SELECT number AS partNumber, size, etag FROM stream_parts_v2 WHERE session = ? ORDER BY number", id,
		).toArray();
	}

	pending(): { id: string; bytes: number }[] {
		return this.storage.sql.exec<{ id: string; bytes: number }>(
			"SELECT id, bytes FROM streams_v2 WHERE expires > ? AND status IN ('streaming', 'finalizing') AND bytes > 0", Date.now(),
		).toArray();
	}

	/** Admission must precede SQL cleanup records; refusals do not own sessions. */
	checkCreate(count: number): StreamError | undefined {
		const active = this.storage.sql.exec<{ count: number }>("SELECT count(*) AS count FROM streams_v2 WHERE expires > ? AND status IN ('streaming', 'finalizing')", Date.now()).one().count;
		if (active + count <= 8192) return;
		console.warn({ event: "upload_admission_rejected", reason: "active_session_limit", active, requested: count, limit: 8192 });
		return { error: "Too many active upload sessions; finish or abort existing uploads", status: 429 };
	}

	create(sessions: readonly UploadSession[], capacity: number | null): StreamError | undefined {
		return this.storage.transactionSync(() => {
			const refused = this.checkCreate(sessions.length);
			if (refused) return refused;
			for (const session of sessions) this.storage.sql.exec(
				"INSERT INTO streams_v2 (id, payload, status, expires, capacity) VALUES (?, ?, ?, ?, ?)",
				session.id, JSON.stringify(session), session.status, session.expiresAt.getTime(), capacity,
			);
		});
	}

	reserve(inputs: readonly { sessionId: string; parts: readonly { partNumber: number; size: number }[] }[]): Map<string, StreamError | undefined> {
		return this.storage.transactionSync(() => {
			const results = new Map<string, StreamError | undefined>();
			for (const { sessionId, parts } of inputs) {
				const session = this.get([sessionId])[0];
				const reserved = new Map(this.parts(sessionId).map(p => [p.partNumber, p.size]));
				const fresh = parts.filter(p => !reserved.has(p.partNumber));
				const requested = fresh.reduce((n, p) => n + p.size, 0);
				const row = this.storage.sql.exec<{ capacity: number | null }>("SELECT capacity FROM streams_v2 WHERE id = ?", sessionId).toArray()[0];
				let error: StreamError | undefined;
				if (!session || session.expiresAt.getTime() <= Date.now()) error = { error: "Not found", status: 404 };
				else if (session.status !== "streaming") error = { error: "Conflict", status: 409 };
				else if (!session.partSize || parts.length < 1 || parts.length > 100 || new Set(parts.map(p => p.partNumber)).size !== parts.length
					|| parts.some(p => !Number.isSafeInteger(p.partNumber) || p.partNumber < 1 || p.partNumber > 10_000 || !Number.isSafeInteger(p.size) || p.size < 1 || p.size > session.partSize!)) error = { error: "Invalid part reservations", status: 400 };
				else if (parts.some(p => reserved.has(p.partNumber) && reserved.get(p.partNumber) !== p.size)) error = { error: "Part size cannot change", status: 409 };
				else if (session.fileSize + requested > 5 * 1024 ** 4) error = { error: "NAR exceeds the multipart object limit", status: 400 };
				else if (row?.capacity != null && session.fileSize + requested > row.capacity) error = { error: "Object exceeds cache capacity", status: 413 };
				else {
					// Staging is distinct from retained capacity. Bound concurrent work,
					// rather than evicting useful paths before their replacements verify.
					const staged = this.storage.sql.exec<{ bytes: number }>("SELECT coalesce(sum(bytes), 0) AS bytes FROM streams_v2 WHERE expires > ? AND status IN ('streaming', 'finalizing')", Date.now()).one().bytes;
					const budget = Math.min(5 * 1024 ** 4, Math.max(512 * 1024 ** 2, (row?.capacity ?? 256 * 1024 ** 3) * 2));
					if (staged + requested > budget) error = { error: "Upload staging is busy; retry", status: 429 };
				}
				results.set(sessionId, error);
				if (error || !session) continue;
				for (const part of fresh) this.storage.sql.exec("INSERT INTO stream_parts_v2 (session, number, size) VALUES (?, ?, ?)", sessionId, part.partNumber, part.size);
				if (fresh.length) this.save({ ...session, fileSize: session.fileSize + requested });
			}
			return results;
		});
	}

	seal(inputs: readonly StreamReceipt[]): Map<string, { session: UploadSession; parts: StreamPart[] } | StreamError> {
		return this.storage.transactionSync(() => {
			const results = new Map<string, { session: UploadSession; parts: StreamPart[] } | StreamError>();
			for (const input of inputs) {
				const session = this.get([input.sessionId])[0];
				const reserved = this.parts(input.sessionId);
				const parts = [...input.parts].sort((a, b) => a.partNumber - b.partNumber);
				let error: StreamError | undefined;
				if (!session || session.expiresAt.getTime() <= Date.now()) error = { error: "Not found", status: 404 };
				else if (!["streaming", "finalizing", "completed"].includes(session.status)) error = { error: "Conflict", status: 409 };
				else if (input.narHash !== session.narHash || input.narSize !== session.narSize || input.fileSize !== session.fileSize
					|| reserved.length === 0 || reserved.length !== parts.length
					|| reserved.some((p, i) => p.partNumber !== i + 1 || parts[i]?.partNumber !== p.partNumber || !parts[i]?.etag
						|| (i < reserved.length - 1 && p.size !== session.partSize))) error = { error: "Stream metadata or parts do not match reservations", status: 400 };
				else if (session.status !== "streaming" && (session.fileHash !== input.fileHash || reserved.some((p, i) => p.etag !== parts[i]?.etag))) error = { error: "Sealed stream cannot change", status: 409 };
				if (error || !session) { results.set(input.sessionId, error!); continue; }
				if (session.status === "streaming") {
					for (const part of parts) this.storage.sql.exec("UPDATE stream_parts_v2 SET etag = ? WHERE session = ? AND number = ?", part.etag, session.id, part.partNumber);
					this.save({ ...session, fileHash: input.fileHash, status: "finalizing" });
				}
				results.set(session.id, { session: this.get([session.id])[0], parts: this.parts(session.id) });
			}
			return results;
		});
	}

	/** Inline bytes use the same admission and immutable receipt as streamed parts. */
	sealInline(inputs: readonly StreamReceipt[]): Map<string, { session: UploadSession; parts: StreamPart[] } | StreamError> {
		const results = new Map<string, { session: UploadSession; parts: StreamPart[] } | StreamError>();
		for (const input of inputs) {
			const session = this.get([input.sessionId])[0];
			if (!session || session.r2UploadId !== null || session.partSize !== 1024 ** 2 || session.narSize > 1024 ** 2
				|| input.fileSize < 1 || input.fileSize > 1024 ** 2) {
				results.set(input.sessionId, { error: "Not an inline upload", status: 409 });
				continue;
			}
			if (session.status === "streaming") {
				const error = this.reserve([{ sessionId: session.id, parts: [{ partNumber: 1, size: input.fileSize }] }]).get(session.id);
				if (error) { results.set(session.id, error); continue; }
			}
			for (const [id, result] of this.seal([input])) results.set(id, result);
		}
		return results;
	}

	abort(id: string): UploadSession | undefined {
		return this.storage.transactionSync(() => {
			const session = this.get([id])[0];
			if (!session || !["streaming", "aborted"].includes(session.status)) return undefined;
			this.save({ ...session, status: "aborted" });
			return this.get([id])[0];
		});
	}

	complete(ids: readonly string[]): void {
		for (const session of this.get(ids)) if (session.status === "finalizing") this.save({ ...session, status: "completed" });
	}

	prune(): void {
		this.storage.transactionSync(() => {
			// SQL owns the stage cleanup record, including sealed/ambiguous work.
			this.storage.sql.exec("DELETE FROM stream_parts_v2 WHERE session IN (SELECT id FROM streams_v2 WHERE expires < ?)", Date.now());
			this.storage.sql.exec("DELETE FROM streams_v2 WHERE expires < ?", Date.now());
		});
	}

	private save(session: UploadSession): void {
		this.storage.sql.exec("UPDATE streams_v2 SET payload = ?, status = ?, bytes = ? WHERE id = ?", JSON.stringify(session), session.status, session.fileSize, session.id);
	}
}
