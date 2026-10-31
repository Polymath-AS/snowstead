import { eq } from "drizzle-orm";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import type { Cache } from "@snowstead/cache-core/db/types";
import { caches as cacheRows, sccacheEntries } from "@snowstead/cache-core/db/schema";
import { CapacityError } from "@snowstead/cache-core/capacity";
import { publishSccacheUpload } from "@snowstead/cache-core/sccache";
import { errorResponse } from "@snowstead/cache-core/responses";

/** Drain probes and duplicate writes while enforcing their declared length. */
export async function consumeBody(request: Request, size: number): Promise<void> {
	const fixed = new FixedLengthStream(size);
	await Promise.all([(request.body ?? new Blob([]).stream()).pipeTo(fixed.writable), fixed.readable.pipeTo(new WritableStream())]);
}

/** Reserve, transfer immutable bytes under cleanup fences, then publish at capacity. */
export async function uploadArchive(request: Request, config: WorkerConfig, cache: Cache, action: string, size: number): Promise<Response> {
	await config.releaseDb();
	const reservation = await config.uploadCoordinator.getByName(cache.orgId, { locationHint: "weur" }).reserveSccache(cache, action, size);
	if (reservation instanceof Response) return reservation;
	let uploadedAt: Date | undefined;
	const response = await config.db.transaction(async tx => {
		// Only this action is exclusively locked. Cache SHARE locks let independent
		// uploads run concurrently while reset/delete wait for publication.
		const [current] = await tx.select().from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
		if (!current || current.sccacheGeneration !== cache.sccacheGeneration) return errorResponse("Cache changed; retry", 409);
		const [entry] = await tx.select().from(sccacheEntries).where(eq(sccacheEntries.id, reservation.id)).for("update");
		if (!entry || entry.cacheId !== cache.id || entry.expiresAt.getTime() <= Date.now()) return errorResponse("Upload expired; retry", 409);
		let alreadyStored = false;
		try {
			// Archives can differ for the same compiler key. First completed writer
			// wins; never overwrite a completed archive or refresh its retention.
			if (entry.uploadedAt) {
				await consumeBody(request, size);
				return new Response(null, { status: 204 });
			}
			if (entry.size !== size) return errorResponse("Upload in progress; retry", 409);
			// A previous transfer may be awaiting/retrying capacity publication.
			// Under the entry lock, retain its immutable bytes and original age.
			const previous = await config.bucket.head(entry.r2Key);
			if (previous) {
				alreadyStored = true;
				await consumeBody(request, size);
				uploadedAt = previous.uploaded;
				return new Response(null, { status: 204 });
			}
			const fixed = new FixedLengthStream(size);
			const abort = new AbortController();
			const pumping = (request.body ?? new Blob([]).stream()).pipeTo(fixed.writable, { signal: abort.signal });
			pumping.catch(() => {});
			const storing = config.bucket.put(entry.r2Key, fixed.readable, {
				httpMetadata: { contentType: "application/octet-stream" },
			});
			let stored;
			try {
				[stored] = await Promise.all([storing, pumping]);
			} catch (error) {
				abort.abort(error);
				// Do not let GC delete the key while a failed transfer can still finish.
				await Promise.allSettled([storing, pumping]);
				throw error;
			}
			if (!stored) throw new Error("Missing sccache upload result");
			uploadedAt = stored.uploaded;
			return new Response(null, { status: 201, headers: { "cache-control": "no-store" } });
		} catch (error) {
			if (error instanceof Error && /content length|FixedLengthStream|client disconnected/i.test(error.message)) {
				if (!entry.uploadedAt && !alreadyStored) await tx.update(sccacheEntries).set({ cacheId: null }).where(eq(sccacheEntries.id, entry.id));
				return errorResponse("Content length mismatch", 400);
			}
			throw error;
		}
	});
	if (!response.ok || !uploadedAt) return response;
	// Transfer locks are released before entering the shared org capacity gate.
	try {
		await publishSccacheUpload(config, cache, reservation.id, uploadedAt, new URL(request.url).origin);
		return response;
	} catch (error) {
		if (error instanceof CapacityError) return errorResponse(error.message, error.status, error.retryable ? { "retry-after": "1" } : {});
		throw error;
	}
}
