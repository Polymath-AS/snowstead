import * as v from "valibot";
import { and, desc, eq, gt, lt } from "drizzle-orm";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import { actorId, authenticateOrg, authenticateWrite } from "@snowstead/cache-core/auth";
import { hasCacheAccess, hasPermission, isOrgsToken } from "@snowstead/cache-core/jwt";
import { findCache, findOrg, orgUsage } from "@snowstead/cache-core/db/repository";
import { evictionLogs } from "@snowstead/cache-core/db/schema";
import { evictionCandidates } from "@snowstead/cache-core/eviction";
import { deletePin, listPins, PinError, putPin } from "@snowstead/cache-core/pins";
import { evictCache } from "@snowstead/cache-core/cache-eviction";
import { writeAuditLog } from "@snowstead/cache-core/audit";
import { overLimit } from "@snowstead/cache-core/rate-limit";
import { CacheName, parseBody, parsed, StorePathBasename, valueOf } from "@snowstead/cache-core/schemas";
import { errorResponse, jsonResponse } from "@snowstead/cache-core/responses";

const PinName = v.pipe(v.string(), v.regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/));
const KeepCount = v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(10000));
const PinBody = v.strictObject({ name: PinName,
	storePath: v.pipe(v.string(), v.check(path => path.startsWith("/nix/store/") && valueOf(StorePathBasename, path.slice(11)) !== undefined, "storePath must be a full Nix store path")),
	keep: v.union([v.literal("forever"), v.strictObject({ days: KeepCount }), v.strictObject({ revisions: KeepCount })]),
});

/** Pin writers may be cache-scoped push tokens; pin readers require management. */
export async function handlePins(request: Request, config: WorkerConfig, org: string, name: string, pinName?: string): Promise<Response> {
	const cacheName = parsed(CacheName, name);
	if (cacheName instanceof Response) return cacheName;
	let auth = await authenticateOrg(request, config, org);
	if (auth.kind === "error" && request.method !== "GET") auth = await authenticateWrite(request, config);
	if (auth.kind === "error") return auth.response;
	const identity = auth.identity;
	if (identity.kind === "legacy" || (identity.kind === "jwt" && (!isOrgsToken(identity.claims, org) || !hasPermission(identity.claims, "push")))) return errorResponse("Forbidden", 403);
	const cache = await findCache(config.db, org, cacheName);
	if (!cache || !cache.protocols.includes("nix")) return errorResponse("Not Found", 404);
	if (identity.kind === "jwt" && !hasCacheAccess(identity.claims, cache)) return errorResponse("Forbidden", 403);
	if (identity.kind !== "admin" || identity.onBehalfOf !== undefined) {
		const limited = await overLimit(config, "api", actorId(identity));
		if (limited) return limited;
	}
	if (request.method === "GET") return jsonResponse({ pins: await listPins(config.db, cache.id) });
	try {
		let response: Response, action: string, detail: object;
		if (request.method === "DELETE") {
			const validName = parsed(PinName, pinName);
			if (validName instanceof Response) return validName;
			await deletePin(config.db, org, cache.id, validName);
			response = jsonResponse({ deleted: true, name: validName });
			action = "pin.delete"; detail = { name: validName };
		} else {
			const body = await parseBody(request, PinBody);
			if (body instanceof Response) return body;
			const result = await putPin(config.db, org, cache.id, body.name, body.storePath, body.keep);
			response = jsonResponse({ pin: result.pin }, result.created ? 201 : 200);
			action = result.created ? "pin.create" : "pin.update"; detail = body;
		}
		writeAuditLog(config, identity, action, cache.name, response.status, JSON.stringify(detail), request.headers.get("cf-connecting-ip"), org);
		return response;
	} catch (error) {
		if (error instanceof PinError) return errorResponse(error.message, error.status);
		throw error;
	}
}

const NextCursor = v.strictObject({ org: v.string(), used: v.pipe(v.string(), v.regex(/^-?\d{1,12}(?:\.\d{1,6})?$/)),
	kind: v.picklist(["nix", "go", "sccache"]), id: v.pipe(v.string(), v.nonEmpty(), v.maxLength(128)) });

export async function handleEvictionInfo(config: WorkerConfig, org: string, url: URL): Promise<Response> {
	const limit = Number(url.searchParams.get("limit") ?? 50);
	if (!Number.isInteger(limit) || limit < 1 || limit > 200) return errorResponse("limit must be between 1 and 200", 400);
	let next: v.InferOutput<typeof NextCursor> | undefined;
	const raw = url.searchParams.get("nextCursor");
	if (raw !== null) {
		try { if (raw.length <= 2048) next = valueOf(NextCursor, JSON.parse(atob(raw))); } catch { /* invalid cursor */ }
		if (!next || next.org !== org) return errorResponse("Invalid nextCursor", 400);
	}
	const recent = url.searchParams.get("recentCursor");
	if (recent !== null && (!/^\d+$/.test(recent) || !Number.isSafeInteger(Number(recent)) || Number(recent) < 1)) return errorResponse("Invalid recentCursor", 400);
	return config.db.transaction(async tx => {
		const now = new Date();
		const policy = (await findOrg(tx, org))!;
		const usage = await orgUsage(tx, org, now);
		const candidates = await evictionCandidates(tx, org, now, [], limit + 1, next);
		const history = await tx.select().from(evictionLogs).where(and(eq(evictionLogs.orgId, org),
			gt(evictionLogs.evictedAt, new Date(now.getTime() - 30 * 86400_000)), recent === null ? undefined : lt(evictionLogs.id, Number(recent))))
			.orderBy(desc(evictionLogs.id)).limit(limit + 1);
		const page = candidates.slice(0, limit), last = page.at(-1);
		const recentPage = history.slice(0, limit);
		return jsonResponse({
			next: { items: page.map(row => ({ product: row.kind, cache: row.name, cacheId: row.cacheId, key: row.key, size: Number(row.size), lastAccessedAt: row.lastAccessedAt })),
				bytesToFree: policy.storageLimit === null ? 0 : Math.max(0, usage.used - policy.storageLimit),
				cursor: candidates.length > limit && last ? btoa(JSON.stringify({ org, used: last.used, kind: last.kind, id: last.id })) : null },
			recent: { items: recentPage.map(({ orgId: _, ...row }) => row), cursor: history.length > limit ? String(recentPage.at(-1)!.id) : null },
		});
	}, { isolationLevel: "repeatable read", accessMode: "read only" });
}

export async function handleEvictCache(config: WorkerConfig, org: string, name: string, origin: string): Promise<Response> {
	const validName = parsed(CacheName, name);
	if (validName instanceof Response) return validName;
	const cache = await findCache(config.db, org, validName);
	if (!cache) return errorResponse("Not Found", 404);
	return jsonResponse(await evictCache(config, cache, origin));
}
