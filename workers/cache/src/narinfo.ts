import { parseNarHash } from "@snowstead/cache-domain";
import type { PublishedPath, BlobObject } from "./db/types.js";
import type { WorkerConfig } from "./config.js";
import { computeFingerprint, signNarinfo } from "./signing.js";
import { signingKeyFor } from "./cache-keys.js";
import type { SigningKey } from "./cache-keys.js";
import { IMMUTABLE, bucketFor, narinfoKey, narUrl, placeNar } from "./layout.js";

export type NarinfoPath = Pick<
	PublishedPath,
	"storePath" | "storePathHash" | "narHash" | "narSize" | "referencesJson" | "deriver" | "system" | "signaturesJson"
>;
export type NarinfoBlob = Pick<BlobObject, "fileHash" | "fileSize" | "compression" | "r2Key">;

export function renderNarinfo(
	path: NarinfoPath,
	blob: Pick<NarinfoBlob, "fileHash" | "fileSize" | "compression">,
	url: string,
	refs: readonly string[],
	storedSigs: readonly string[],
	signatures: readonly string[] = [],
): string {
	const lines: string[] = [
		`StorePath: ${path.storePath}`,
		`URL: ${url}`,
		`Compression: ${blob.compression}`,
		`FileHash: sha256:${blob.fileHash}`,
		`FileSize: ${blob.fileSize}`,
		`NarHash: ${path.narHash}`,
		`NarSize: ${path.narSize}`,
	];

	if (refs.length > 0) {
		lines.push(`References: ${refs.join(" ")}`);
	}

	if (path.deriver) {
		lines.push(`Deriver: ${path.deriver}`);
	}

	if (path.system) {
		lines.push(`System: ${path.system}`);
	}

	for (const sig of storedSigs) {
		lines.push(`Sig: ${sig}`);
	}
	for (const sig of signatures) {
		lines.push(`Sig: ${sig}`);
	}

	return lines.join("\n") + "\n";
}

/** The narinfo for a path, signed with the cache's key. */
export async function signedNarinfo(key: SigningKey, path: NarinfoPath, blob: NarinfoBlob, isPrivate: boolean, cachePath: string): Promise<string> {
	const refs: string[] = JSON.parse(path.referencesJson);
	const storedSigs: string[] = JSON.parse(path.signaturesJson);
	// Rows published before uploads canonicalised the hash may hold the SRI
	// form, which Nix would not verify a signature over.
	const narHash = parseNarHash(path.narHash);
	const canonical = typeof narHash === "object" ? path : { ...path, narHash };
	const sig = await signNarinfo(computeFingerprint(canonical, refs), key.name, key.secret);
	return renderNarinfo(canonical, blob, narUrl(blob.fileHash, blob.compression, isPrivate, cachePath), refs, storedSigs, sig ? [sig] : []);
}

/**
 * Renders, signs and stores a path's narinfo once, at publish, so serving
 * it reads one object: no database connection and no signing per request.
 * The NAR is placed first, so the narinfo never points at nothing.
 */
export async function storeNarinfo(
	config: WorkerConfig,
	cache: { readonly id: number; readonly path: string },
	path: NarinfoPath,
	blob: NarinfoBlob,
	isPrivate: boolean,
): Promise<void> {
	await placeNar(config, blob.r2Key, blob.fileHash, blob.compression, isPrivate);
	const body = await signedNarinfo(await signingKeyFor(config, cache.id), path, blob, isPrivate, cache.path);
	await bucketFor(config, isPrivate).put(narinfoKey(cache.path, path.storePathHash, isPrivate), body, {
		httpMetadata: { contentType: "text/x-nix-narinfo", cacheControl: IMMUTABLE },
	});
}

/**
 * The Cache API key for a narinfo response. Private caches use a host of
 * their own, so their entries can never answer a request for a public URL.
 */
export function narinfoCacheKey(origin: string, cachePath: string, storePathHash: string, isPrivate: boolean): Request {
	const base = isPrivate ? "https://private.snowstead.internal" : origin;
	return new Request(`${base}/${cachePath}/${storePathHash}.narinfo`, { method: "GET" });
}
