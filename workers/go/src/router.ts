import { and, eq, gt, isNotNull, lt, sql } from "drizzle-orm";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import type { Cache } from "@snowstead/cache-core/db/types";
import { caches as cacheRows, goEntries, orgs, publicationCaches } from "@snowstead/cache-core/db/schema";
import { findCacheByPath, findOrg, orgUsage } from "@snowstead/cache-core/db/repository";
import { authenticateWrite, actorId } from "@snowstead/cache-core/auth";
import { hasCacheAccess, hasPermission, isOrgsToken } from "@snowstead/cache-core/jwt";
import { errorResponse } from "@snowstead/cache-core/responses";
import { overLimit } from "@snowstead/cache-core/rate-limit";
import { PRIVATE_CACHES_REFUSED } from "@snowstead/cache-core/visibility";
import { activeGoEntries } from "@snowstead/cache-core/go-cache";

const RETENTION_MS = 7 * 86400_000;
const MAX_BYTES = 64 * 1024 * 1024;
const OUTPUT = "x-snowstead-output-id";

/** Explicit Go permissions only: neither Nix push/pull nor legacy secrets grant them. */
export async function handleRequest(request: Request, config: WorkerConfig): Promise<Response> {
	const url = new URL(request.url);
	const match = /^\/_api\/v1\/go\/([a-z0-9-]+)\/([a-z0-9-]+)\/v1\/actions\/([a-f0-9]{64})$/.exec(url.pathname);
	if (!match) return errorResponse("Not Found", 404);
	const read = request.method === "GET" || request.method === "HEAD";
	const target = read ? (await config.db.select({ cache: cacheRows, entry: goEntries }).from(cacheRows)
		.innerJoin(orgs, eq(cacheRows.orgId, orgs.id))
		.leftJoin(goEntries, and(eq(goEntries.cacheId, cacheRows.id), eq(goEntries.generation, cacheRows.goGeneration),
			eq(goEntries.action, match[3]), gt(goEntries.expiresAt, new Date()), isNotNull(goEntries.uploadedAt)))
		.where(and(eq(orgs.slug, match[1]), eq(cacheRows.name, match[2]))).limit(1))[0]
		: { cache: await findCacheByPath(config.db, match[1], match[2]), entry: null };
	// Keep the cache even when its action is missing: private misses still authenticate.
	if (!target?.cache) return errorResponse("Not Found", 404);
	const { cache, entry } = target;
	const write = request.method === "PUT";
	if (!write && request.method !== "GET" && request.method !== "HEAD") {
		return errorResponse("Method Not Allowed", 405, { allow: "GET, HEAD, PUT" });
	}
	if (write || !cache.isPublic) {
		const auth = await authenticateWrite(request, config);
		if (auth.kind === "error") return auth.response;
		const identity = auth.identity;
		if (identity.kind !== "jwt" || !hasPermission(identity.claims, write ? "go:write" : "go:read")
			|| !isOrgsToken(identity.claims, cache.orgId) || !hasCacheAccess(identity.claims, cache)) {
			return errorResponse("Forbidden", 403);
		}
		const limited = await overLimit(config, write ? "push" : "read", actorId(identity));
		if (limited) return limited;
	}
	if (write) return putAction(request, config, cache, match[3]);
	// Authentication may have taken time; recheck expiry before the Cache API.
	if (!entry || entry.expiresAt.getTime() <= Date.now()) return errorResponse("Not Found", 404);
	const key = new Request(`${url.origin}/_snowstead_go_cdn/${entry.r2Key}`);
	const head = request.method === "HEAD";
	const edgeCache = await caches.open("snowstead-go");
	const cached = await edgeCache.match(key);
	if (cached) {
		if (head) await cached.body?.cancel();
		return returned(cached, head, "HIT");
	}
	const result = head ? null : await config.bucket.get(entry.r2Key);
	const object = head ? await config.bucket.head(entry.r2Key) : result;
	if (!object) return errorResponse("Not Found", 404);
	const ttl = Math.min(3600, Math.floor((entry.expiresAt.getTime() - Date.now()) / 1000));
	if (ttl < 0) {
		await result?.body.cancel();
		return errorResponse("Not Found", 404);
	}
	const response = new Response(result?.body ?? null, { headers: {
		"content-type": "application/octet-stream",
		"content-length": String(entry.size),
		[OUTPUT]: entry.output,
		etag: object.httpEtag,
		"cache-control": `public, max-age=${ttl}`,
	} });
	if (!head && ttl > 0 && config.ctx) config.ctx.waitUntil(edgeCache.put(key, response.clone()));
	return returned(response, head, "MISS");
}

function returned(response: Response, head: boolean, source: string): Response {
	const headers = new Headers(response.headers);
	headers.set("cache-control", "no-store");
	headers.set("cloudflare-cdn-cache-control", "no-store");
	headers.set("x-snowstead-cache", source);
	return new Response(head ? null : response.body, { status: response.status, headers });
}

async function putAction(request: Request, config: WorkerConfig, cache: Cache, action: string): Promise<Response> {
	const output = request.headers.get(OUTPUT) ?? "";
	const length = request.headers.get("content-length") ?? "";
	if (!/^[a-f0-9]{64}$/.test(output) || !/^\d+$/.test(length)) return errorResponse("Output ID and content length are required", 400);
	const size = Number(length);
	if (!Number.isSafeInteger(size) || size > MAX_BYTES) return errorResponse("Artifact is too large", 413);
	if (size > 0 && request.body === null) return errorResponse("Artifact body is required", 400);
	// Reserve quota and a durable cleanup record before R2: a disconnect or a
	// failed SQL finalization cannot leave an untracked object behind.
	const reservation = await config.db.transaction(async (tx) => {
		await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${"org:" + cache.orgId}, 0))`);
		// The org lock serializes reservations; a shared cache lock fences
		// reset/delete/visibility without waiting for unrelated publishing bodies.
		const [current] = await tx.select().from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
		if (!current || current.goGeneration !== cache.goGeneration) return errorResponse("Cache changed; retry", 409);
		const [lifecycle] = await tx.select({ state: publicationCaches.state }).from(publicationCaches).where(eq(publicationCaches.cacheId, cache.id));
		if (lifecycle && lifecycle.state !== "active") return errorResponse("Cache lifecycle transition is pending", 409);
		const org = await findOrg(tx, cache.orgId);
		if (!org) return errorResponse("Not Found", 404);
		if (!current.isPublic && !org.privateCaches) return errorResponse(PRIVATE_CACHES_REFUSED, 403);
		const now = new Date();
		// Expired entries lose their action slot, not their cleanup record/key.
		await tx.update(goEntries).set({ cacheId: null }).where(and(eq(goEntries.cacheId, cache.id),
			eq(goEntries.generation, cache.goGeneration), eq(goEntries.action, action), lt(goEntries.expiresAt, now)));
		const [existing] = await tx.select().from(goEntries).where(and(activeGoEntries(cache, now), eq(goEntries.action, action)));
		if (existing) return existing;
		if (org.storageLimit !== null) {
			const usage = await orgUsage(tx, cache.orgId, now);
			if (usage.used + usage.pending + size > org.storageLimit) return errorResponse("Not enough storage", 413);
		}
		const id = crypto.randomUUID();
		const [entry] = await tx.insert(goEntries).values({ id, cacheId: cache.id, generation: cache.goGeneration, action,
			r2Key: `go/${cache.id}/${cache.goGeneration}/${action}/${id}`, output, size,
			expiresAt: new Date(now.getTime() + 3600_000),
		}).returning();
		return entry;
	});
	if (reservation instanceof Response) return reservation;
	if (!reservation) throw new Error("Go reservation returned no row");
	return config.db.transaction(async (tx) => {
		// Reset and cache deletion wait for a transfer already publishing. GC
		// locks the entry too, so it cannot remove an in-flight R2 put.
		const [current] = await tx.select().from(cacheRows).where(eq(cacheRows.id, cache.id)).for("share");
		if (!current || current.goGeneration !== cache.goGeneration) return errorResponse("Cache changed; retry", 409);
		const [entry] = await tx.select().from(goEntries).where(eq(goEntries.id, reservation.id)).for("update");
		if (!entry || entry.cacheId !== cache.id || entry.expiresAt.getTime() <= Date.now()) return errorResponse("Upload expired; retry", 409);
		const fixed = new FixedLengthStream(size);
		const pumping = (request.body ?? new Blob([]).stream()).pipeTo(fixed.writable);
		// Observe the producer immediately, including while R2's head is pending.
		// pipeThrough hides this promise and can log unhandled length failures.
		pumping.catch(() => {});
		const body = fixed.readable;
		try {
			const existing = await config.bucket.head(entry.r2Key);
			let uploaded = existing?.uploaded;
			if (existing || entry.output !== output || entry.size !== size) {
				// A conditional R2 failure need not consume the body. Validate even
				// duplicate/conflicting PUTs, without buffering their compiler output.
				const digest = new crypto.DigestStream("SHA-256");
				const [, bytes] = await Promise.all([body.pipeTo(digest), digest.digest, pumping]);
				const actual = [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
				if (actual !== output) return errorResponse("Artifact checksum or length mismatch", 400);
				if (entry.output !== output || entry.size !== size) return errorResponse("Action already has a different output", 409);
			} else {
				const [stored] = await Promise.all([config.bucket.put(entry.r2Key, body, { sha256: output, onlyIf: { etagDoesNotMatch: "*" },
					customMetadata: { output }, httpMetadata: { contentType: "application/octet-stream" } }), pumping]);
				if (!stored) return errorResponse("Action changed; retry", 409);
				uploaded = stored.uploaded;
			}
			if (!entry.uploadedAt) {
				if (!uploaded) throw new Error("Go upload returned no timestamp");
				await tx.update(goEntries).set({ uploadedAt: uploaded, expiresAt: new Date(uploaded.getTime() + RETENTION_MS) }).where(eq(goEntries.id, entry.id));
			}
			return new Response(null, { status: existing ? 204 : 201, headers: { "cache-control": "no-store" } });
		} catch (error) {
			if (error instanceof Error && /checksum|content length|FixedLengthStream|client disconnected/i.test(error.message)) {
				// Free an unsuccessful reservation's action slot and quota, but
				// retain its key for the sweep in case the transfer reached R2.
				if (!entry.uploadedAt) await tx.update(goEntries).set({ cacheId: null }).where(eq(goEntries.id, entry.id));
				return errorResponse("Artifact checksum or length mismatch", 400);
			}
			throw error;
		}
	});
}
