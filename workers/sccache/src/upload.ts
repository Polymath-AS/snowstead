import { and, eq, isNull } from "drizzle-orm";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import type { Cache } from "@snowstead/cache-core/db/types";
import { caches as cacheRows, sccacheEntries } from "@snowstead/cache-core/db/schema";
import { CapacityError } from "@snowstead/cache-core/capacity";
import { publishSccacheUpload } from "@snowstead/cache-core/sccache";
import { errorResponse } from "@snowstead/cache-core/responses";
import { uuidv7 } from "@snowstead/cache-core/uuid";

/** Drain probes and duplicate writes while enforcing their declared length. */
export async function consumeBody(request: Request, size: number): Promise<void> {
	const fixed = new FixedLengthStream(size);
	await Promise.all([(request.body ?? new Blob([]).stream()).pipeTo(fixed.writable), fixed.readable.pipeTo(new WritableStream())]);
}

/** Transfer to an attempt-owned key without a SQL connection or cleanup locks. */
export async function uploadArchive(request: Request, config: WorkerConfig, cache: Cache, action: string, size: number): Promise<Response> {
	await config.releaseDb();
	const reservation = await config.uploadCoordinator.getByName(cache.orgId, { locationHint: "weur" }).reserveSccache(cache, action, size);
	if (reservation instanceof Response) return reservation;
	if (!reservation.uploadedAt && reservation.size !== size) return errorResponse("Upload in progress; retry", 409);
	let attempt: string | undefined;
	let adopted = false;
	try {
		let storedAt = reservation.storedAt ?? reservation.uploadedAt;
		// Recover an immutable transfer made before stored_at was introduced.
		if (!storedAt) storedAt = (await config.bucket.head(reservation.r2Key))?.uploaded ?? null;
		if (storedAt) await consumeBody(request, size);
		else {
			attempt = `sccache-attempt/${reservation.id}/${uuidv7()}`;
			const fixed = new FixedLengthStream(size);
			const abort = new AbortController();
			const pumping = (request.body ?? new Blob([]).stream()).pipeTo(fixed.writable, { signal: abort.signal });
			pumping.catch(() => {});
			const storing = config.bucket.put(attempt, fixed.readable, { httpMetadata: { contentType: "application/octet-stream" } });
			try {
				const [stored] = await Promise.all([storing, pumping]);
				if (!stored) throw new Error("Missing sccache upload result");
				storedAt = stored.uploaded;
			} catch (error) {
				abort.abort(error);
				await Promise.allSettled([storing, pumping]);
				throw error;
			}
		}
		// Cache -> entry, then release before entering the org capacity gate.
		// Reset/delete/GC can finish during transfer; they must never be undone.
		const state = await config.db.transaction(async tx => {
			const [current] = await tx.select().from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
			if (!current || current.sccacheGeneration !== cache.sccacheGeneration) throw new CapacityError("Cache changed; retry", 503);
			const [entry] = await tx.select().from(sccacheEntries).where(eq(sccacheEntries.id, reservation.id)).for("update");
			if (!entry || entry.cacheId !== cache.id || entry.expiresAt.getTime() <= Date.now()) throw new CapacityError("Upload expired; retry", 503);
			if (entry.uploadedAt || entry.storedAt) return { uploadedAt: entry.uploadedAt, storedAt: entry.storedAt, won: false };
			await tx.update(sccacheEntries).set({ r2Key: attempt ?? entry.r2Key, storedAt }).where(eq(sccacheEntries.id, entry.id));
			return { uploadedAt: null, storedAt, won: true };
		});
		adopted = state.won;
		if (!state.uploadedAt) await publishSccacheUpload(config, cache, reservation.id, state.storedAt!, new URL(request.url).origin);
		return new Response(null, { status: attempt && state.won ? 201 : 204, headers: { "cache-control": "no-store" } });
	} catch (error) {
		if (error instanceof CapacityError) return errorResponse(error.message, error.status, error.retryable ? { "retry-after": "1" } : {});
		if (error instanceof Error && /content length|FixedLengthStream|client disconnected/i.test(error.message)) {
			if (attempt) await config.db.transaction(async tx => {
				await tx.select({ id: cacheRows.id }).from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
				await tx.update(sccacheEntries).set({ cacheId: null }).where(and(eq(sccacheEntries.id, reservation.id),
					isNull(sccacheEntries.storedAt), isNull(sccacheEntries.uploadedAt)));
			});
			return errorResponse("Content length mismatch", 400);
		}
		throw error;
	} finally {
		await config.releaseDb();
		// On an uncertain SQL commit, never delete a possibly adopted object.
		// The bounded orphan sweep removes failed/abandoned attempts once their
		// reservation is gone. Definite losers can be reclaimed immediately.
		if (attempt && !adopted) {
			// Wait for any uncertain adoption transaction to commit or roll back.
			const [entry] = await config.db.select({ r2Key: sccacheEntries.r2Key }).from(sccacheEntries)
				.where(eq(sccacheEntries.id, reservation.id)).for("update");
			await config.releaseDb();
			if (entry?.r2Key !== attempt) await config.bucket.delete(attempt);
		}
	}
}
