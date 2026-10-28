import * as v from "valibot";
import type { WorkerConfig } from "@snowstead/cache-core/config";
import { cachePath } from "@snowstead/cache-core/cache-path";
import { scheduleNarinfoPurge } from "@snowstead/cache-core/cdn";
import { finishSlugMove, findOrg, listCaches, publishedHashes } from "@snowstead/cache-core/db/repository";
import type { CacheAt } from "@snowstead/cache-core/db/repository";
import { NARINFO_CACHE_CONTROL, cacheInfoKey, narinfoKey, narinfoPrefix, setPublicCacheInfo } from "@snowstead/cache-core/layout";
import { narinfoCacheKey } from "@snowstead/cache-core/narinfo";
import { setPrivate } from "@snowstead/cache-core/visibility";

/**
 * Moving an org's caches to a new slug. Public caches are stored at their
 * URLs, and private ones' narinfo and visibility are keyed by them, so a
 * slug change moves objects. handlePutOrg readies the new paths (the
 * private marker, nix-cache-info) and records the old slug as `movingFrom`;
 * then each call here moves one page of narinfo, public bucket first, until
 * nothing is left under the old slug and the org lets go of it.
 *
 * A narinfo moves only while its path is still published, so a path
 * deleted mid-move doesn't come back, and only if the new path doesn't
 * already have one, pushed since. Public narinfo left behind at the old
 * URL is purged from the CDN as it goes.
 */

const MOVE_PAGE = 200;

const CURSOR = "cursor must be a previous answer's next";

/** Where a move left off: a previous answer's `next`, or nothing to start. */
export const MoveCursor = v.nullish(
	v.object({ phase: v.picklist(["public", "private"], CURSOR), cursor: v.optional(v.string(CURSOR)) }, CURSOR),
	{ phase: "public" },
);

export type MoveCursor = v.InferOutput<typeof MoveCursor>;

export type MoveResult = { readonly done: true } | { readonly done: false; readonly next: MoveCursor; readonly moved: number };

/** Copies the cache's still-published narinfo from the old slug to its path; the hashes it copied. */
async function moveNarinfo(config: WorkerConfig, cache: CacheAt, from: string, hashes: readonly string[], isPrivate: boolean): Promise<string[]> {
	const bucket = isPrivate ? config.bucket : config.publicBucket;
	const moved: string[] = [];
	for (const hash of await publishedHashes(config.db, cache.id, hashes)) {
		const target = narinfoKey(cache.path, hash, isPrivate);
		if (await bucket.head(target)) continue;
		const object = await bucket.get(narinfoKey(cachePath(from, cache.name), hash, isPrivate));
		if (!object) continue;
		await bucket.put(target, await object.arrayBuffer(), {
			httpMetadata: { contentType: "text/x-nix-narinfo", cacheControl: NARINFO_CACHE_CONTROL },
		});
		moved.push(hash);
	}
	return moved;
}

/**
 * Drops cached answers for public narinfo: the CDN's, and the Worker's own
 * in the data center handling this request (as path-deletion.ts does). At
 * the old path they're gone; at the new one a 404 cached mid-move would hide
 * a narinfo that's there now.
 */
async function forgetPublicNarinfo(config: WorkerConfig, origin: string | undefined, path: string, hashes: readonly string[]): Promise<void> {
	if (hashes.length === 0) return;
	if (origin !== undefined) {
		const narinfos = await caches.open("snowstead-narinfo");
		await Promise.all(hashes.map((h) => narinfos.delete(narinfoCacheKey(origin, path, h))));
	}
	await scheduleNarinfoPurge(config, path, hashes);
}

export async function moveSlugPage(config: WorkerConfig, orgId: string, at: MoveCursor, origin?: string): Promise<MoveResult> {
	const org = await findOrg(config.db, orgId);
	if (!org || org.movingFrom === null) return { done: true };
	const from = org.movingFrom;
	const orgCaches = new Map((await listCaches(config.db, orgId)).map((c) => [c.name, c]));
	const isPrivate = at.phase === "private";
	const bucket = isPrivate ? config.bucket : config.publicBucket;
	const prefix = narinfoPrefix(from, isPrivate);
	const page = await bucket.list({ prefix, cursor: at.cursor, limit: MOVE_PAGE });

	// <prefix><cache>/<hash>.narinfo, or <prefix><cache>/nix-cache-info. A
	// default-org cache named like the slug keeps its objects one level up
	// (<prefix><hash>.narinfo), and those stay where they are.
	const byCache = new Map<string, { cache: CacheAt | undefined; hashes: string[]; keys: string[] }>();
	for (const object of page.objects) {
		const parts = object.key.slice(prefix.length).split("/");
		if (parts.length !== 2) continue;
		const [name = "", file = ""] = parts;
		if (file !== "nix-cache-info" && !file.endsWith(".narinfo")) continue;
		const entry = byCache.get(name) ?? { cache: orgCaches.get(name), hashes: [], keys: [] };
		byCache.set(name, entry);
		entry.keys.push(object.key);
		if (file.endsWith(".narinfo")) entry.hashes.push(file.slice(0, -".narinfo".length));
	}

	let moved = 0;
	for (const [name, { cache, hashes, keys }] of byCache) {
		// A cache gone since, or of the other visibility, has nothing to move.
		const copied = cache && cache.isPublic !== isPrivate ? await moveNarinfo(config, cache, from, hashes, isPrivate) : [];
		moved += copied.length;
		await bucket.delete(keys);
		if (!isPrivate) {
			await forgetPublicNarinfo(config, origin, cachePath(from, name), hashes);
			if (cache) await forgetPublicNarinfo(config, origin, cache.path, copied);
		}
	}

	if (page.truncated) return { done: false, next: { phase: at.phase, cursor: page.cursor }, moved };
	if (!isPrivate) return { done: false, next: { phase: "private" }, moved };

	// Nothing left under the old slug: retire its paths and let it go. A
	// private cache's marker stays at its old path: an upload that resolved
	// the cache before the change (uploads.ts keeps it per isolate) must still
	// find it private, and a cache made there later writes its own.
	for (const cache of orgCaches.values()) {
		await config.publicBucket.delete(cacheInfoKey(cachePath(from, cache.name)));
	}
	await finishSlugMove(config.db, orgId);
	return { done: true };
}

/** Readies a cache's new path before the database points at it, so a private cache never reads as public there. */
export async function readyNewPath(config: WorkerConfig, cache: CacheAt, newPath: string): Promise<void> {
	if (cache.isPublic) {
		if (cache.protocols.includes("nix")) await setPublicCacheInfo(config, newPath, true);
	} else {
		await setPrivate(config, newPath, true, { org: cache.orgId, id: cache.id });
	}
}
