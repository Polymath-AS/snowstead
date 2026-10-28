import { and, eq, inArray } from "drizzle-orm";
import * as v from "valibot";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import { findCacheById } from "@snowstead/cache-core/db/repository";
import { publicationCaches, publicationJobs } from "@snowstead/cache-core/db/schema";
import {
	readPublicationCache, initializePublicationCache, beginPublicationBackfill, backfillPublicationBatch,
	finishPublicationBackfill, recoverPublication, repairLegacyPublicationWitness,
	changePublicationVisibility, retirePublicationCache, collectRetiredPublications,
} from "@snowstead/cache-core/publications";
import { initializeVerifierKey, revokeVerifierKey, enrollLegacyToken, recoverTokenPolicies } from "@snowstead/cache-core/token-policy";
import { parseBody } from "@snowstead/cache-core/schemas";
import { errorResponse, jsonResponse } from "@snowstead/cache-core/responses";

/** Bounded control-plane recovery; never called by download admission. */
export async function recoverPublicationWork(config: WorkerConfig): Promise<void> {
	await recoverTokenPolicies(config);
	const caches = await config.db.select().from(publicationCaches).where(inArray(publicationCaches.state, ["initializing", "changing", "retiring"])).limit(25);
	for (const row of caches) {
		const cache = await findCacheById(config.db, row.cacheId);
		if (!cache) continue;
		if (row.state === "initializing") await initializePublicationCache(config, cache);
		else if (row.state === "changing") await changePublicationVisibility(config, cache, row.targetPublic!);
		else await retirePublicationCache(config, cache);
	}
	const jobs = await config.db.select({ job: publicationJobs }).from(publicationJobs)
		.innerJoin(publicationCaches, eq(publicationCaches.cacheId, publicationJobs.cacheId))
		.where(and(eq(publicationJobs.state, "pending"), eq(publicationCaches.state, "active")))
		.orderBy(publicationJobs.id).limit(25);
	for (const { job } of jobs) {
		const recovered = await recoverPublication(config, job.id);
		if (recovered.state === "done") {
			const blob = JSON.parse(recovered.blobJson) as { fileHash: string; compression: string };
			await repairLegacyPublicationWitness(config, job.cacheId, blob.fileHash, blob.compression);
		}
	}
	await collectRetiredPublications(config);
}

const Batch = v.strictObject({ limit: v.optional(v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(100)), 25) });
const LegacyCredential = v.strictObject({ token: v.pipe(v.string(), v.minLength(1), v.maxLength(16_384)) });

/** Caller must authenticate the operator, not a dashboard actor or an org key. */
export async function handlePublicationApi(request: Request, config: WorkerConfig, route: string): Promise<Response> {
	const match = /^cache\/([1-9][0-9]*)(?:\/(initialize|backfill\/start|backfill\/batch|backfill\/finish|recover))?$/.exec(route);
	if (match) {
		const cacheId = Number(match[1]);
		if (!Number.isSafeInteger(cacheId)) return errorResponse("Invalid cache ID", 400);
		const cache = await findCacheById(config.db, cacheId);
		if (!cache) return errorResponse("Cache not found", 404);
		if (request.method === "GET" && !match[2]) {
			const row = await readPublicationCache(config, cacheId);
			return jsonResponse({ cacheId, state: row?.state ?? "legacy", epoch: row?.epoch ?? null });
		}
		if (request.method !== "POST") return errorResponse("Method Not Allowed", 405, { allow: "POST" });
		if ((match[2] === "initialize" || match[2] === "backfill/start") && !config.strongTokenPolicies) {
			return errorResponse("Enable the global strong token perimeter before cache migration", 409);
		}
		let result: { state: string };
		switch (match[2]) {
			case "initialize": result = await initializePublicationCache(config, cache); break;
			case "backfill/start": result = await beginPublicationBackfill(config, cache); break;
			case "backfill/batch": {
				const body = await parseBody(request, Batch);
				if (body instanceof Response) return body;
				return jsonResponse(await backfillPublicationBatch(config, cache, body.limit), 202);
			}
			case "backfill/finish": result = await finishPublicationBackfill(config, cache); break;
			case "recover": {
				const row = await readPublicationCache(config, cacheId);
				if (!row) return errorResponse("Cache has not been initialized", 409);
				if (row.state === "migrating") return jsonResponse(await backfillPublicationBatch(config, cache), 202);
				await recoverPublicationWork(config);
				result = { state: (await readPublicationCache(config, cacheId))!.state };
				break;
			}
			default: return errorResponse("Not Found", 404);
		}
		return jsonResponse(result, result.state === "active" || result.state === "retired" ? 200 : 202);
	}
	if (request.method !== "POST") return errorResponse("Method Not Allowed", 405, { allow: "POST" });
	if (route === "recover") {
		await recoverPublicationWork(config);
		return jsonResponse({ attempted: true });
	}
	if (route === "tokens/recover") {
		const results = await recoverTokenPolicies(config);
		return jsonResponse({ results }, results.some((result) => result.state !== "committed") ? 202 : 200);
	}
	if (route === "tokens/enroll") {
		const body = await parseBody(request, LegacyCredential);
		if (body instanceof Response) return body;
		const result = await enrollLegacyToken(config, body.token);
		return jsonResponse(result, result.state === "committed" ? 200 : result.state === "pending" ? 202 : 503);
	}
	if (route === "key/initialize" || route === "key/revoke") {
		const result = route === "key/initialize" ? await initializeVerifierKey(config) : await revokeVerifierKey(config);
		return jsonResponse(result, result.state === "committed" ? 200 : result.state === "pending" ? 202 : 503);
	}
	return errorResponse("Not Found", 404);
}
