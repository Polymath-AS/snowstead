import type { WorkerConfig } from "./config.js";
import { pathDepth } from "./cache-path.js";
import { installNar } from "./nar-install.js";

/**
 * Where a cache's objects live. Public caches are laid out in the public
 * bucket exactly as Nix requests them, so cache.snowstead.com serves them
 * straight from R2 and the CDN:
 *
 *   <path>/nix-cache-info
 *   <path>/<hash>.narinfo
 *   nar/<file hash>/<compression>.nar      shared by every public cache
 *
 * where a cache's path is its name, or <org slug>/<name> (cache-path.ts).
 * Their narinfo points back up to nar/, which Nix resolves against the
 * cache's URL (older Nix leaves it to curl, which does the same). Private
 * caches stay in the private bucket, which only the Worker reads.
 */

export const NIX_CACHE_INFO = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n";

/** Content-addressed objects never change. */
export const IMMUTABLE = "public, max-age=31536000, immutable";

/** Narinfo can be deleted or re-signed; bound staleness if purging fails. */
export const NARINFO_CACHE_CONTROL = "public, max-age=300";

/** Names that would collide with the paths around public caches. */
export const RESERVED_CACHE_NAMES: ReadonlySet<string> = new Set(["nar", "private", "nix-cache-info"]);

export function bucketFor(config: WorkerConfig, isPrivate: boolean): R2Bucket {
	return isPrivate ? config.bucket : config.publicBucket;
}

export function narKey(fileHash: string, compression: string, isPrivate: boolean): string {
	return isPrivate ? `nars/sha256/${fileHash}/${compression}.nar` : `nar/${fileHash}/${compression}.nar`;
}

/** The bucket an upload's key belongs to, from its layout. */
export function bucketForKey(config: WorkerConfig, key: string): R2Bucket {
	return bucketFor(config, !key.startsWith("nar/"));
}

/** Where the narinfo under a path lives: a cache's, or every cache of an org slug's. */
export function narinfoPrefix(path: string, isPrivate: boolean): string {
	return isPrivate ? `narinfo/${path}/` : `${path}/`;
}

export function narinfoKey(cachePath: string, storePathHash: string, isPrivate: boolean): string {
	return `${narinfoPrefix(cachePath, isPrivate)}${storePathHash}.narinfo`;
}

/**
 * The narinfo's URL field, relative to the cache's URL: a private cache
 * serves its NARs under itself, and public NARs are shared at the root.
 */
export function narUrl(fileHash: string, compression: string, isPrivate: boolean, cachePath: string): string {
	return isPrivate ? `nar/${fileHash}/${compression}.nar` : `${"../".repeat(pathDepth(cachePath))}nar/${fileHash}/${compression}.nar`;
}

export function cacheInfoKey(cachePath: string): string {
	return `${cachePath}/nix-cache-info`;
}

/** Publishes or withdraws a cache's nix-cache-info in the public bucket. */
export async function setPublicCacheInfo(config: WorkerConfig, cachePath: string, isPublic: boolean): Promise<void> {
	if (isPublic) {
		await config.publicBucket.put(cacheInfoKey(cachePath), NIX_CACHE_INFO, {
			httpMetadata: { contentType: "text/x-nix-cache-info", cacheControl: "public, max-age=3600" },
		});
	} else {
		await config.publicBucket.delete(cacheInfoKey(cachePath));
	}
}

/**
 * Makes sure the NAR stored at `fromKey` also exists where the cache's
 * narinfo will point. A NAR first uploaded for a cache of the other
 * visibility is copied; this is the only time the Worker moves NAR bytes.
 */
export async function placeNar(
	config: WorkerConfig,
	fromKey: string,
	fileHash: string,
	compression: string,
	isPrivate: boolean,
): Promise<void> {
	const target = narKey(fileHash, compression, isPrivate);
	// This is publication of already-proven content, not a possession check.
	if (target === fromKey || await bucketFor(config, isPrivate).head(target)) return;
	const source = await bucketForKey(config, fromKey).head(fromKey);
	if (!source) throw new Error(`NAR ${fromKey} is missing`);
	const error = await installNar(config, fromKey, fileHash, compression, isPrivate, source.size);
	if (error) throw new Error(error);
}

/** The S3 bucket name an upload's key belongs to, for presigning. */
export function bucketNameForKey(config: WorkerConfig, key: string): string {
	return key.startsWith("nar/") ? config.r2PublicBucketName : config.r2BucketName;
}
