import { parseNarHash } from "@helios/cache-domain";
import type { PublishedPath, BlobObject } from "./db/types.js";
import type { WorkerConfig } from "./config.js";
import { computeFingerprint, signNarinfo } from "./signing.js";

export type NarinfoPath = Pick<
	PublishedPath,
	"storePath" | "storePathHash" | "narHash" | "narSize" | "referencesJson" | "deriver" | "system" | "signaturesJson"
>;
export type NarinfoBlob = Pick<BlobObject, "fileHash" | "fileSize" | "compression">;

export function renderNarinfo(
	path: NarinfoPath,
	blob: NarinfoBlob,
	refs: readonly string[],
	storedSigs: readonly string[],
	signatures: readonly string[] = [],
): string {
	const lines: string[] = [
		`StorePath: ${path.storePath}`,
		`URL: nar/${blob.fileHash}/${blob.compression}.nar`,
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

/** Where a path's rendered narinfo lives in the bucket. */
export function narinfoKey(cacheName: string, storePathHash: string): string {
	return `narinfo/${cacheName}/${storePathHash}.narinfo`;
}

/** The narinfo for a path, signed with the cache's key. */
export async function signedNarinfo(config: WorkerConfig, path: NarinfoPath, blob: NarinfoBlob): Promise<string> {
	const refs: string[] = JSON.parse(path.referencesJson);
	const storedSigs: string[] = JSON.parse(path.signaturesJson);
	// Rows published before uploads canonicalised the hash may hold the SRI
	// form, which Nix would not verify a signature over.
	const narHash = parseNarHash(path.narHash);
	const canonical = typeof narHash === "object" ? path : { ...path, narHash };
	const sig = await signNarinfo(computeFingerprint(canonical, refs), config.signingKeyName, config.signingPrivateKey);
	return renderNarinfo(canonical, blob, refs, storedSigs, sig ? [sig] : []);
}

/**
 * Renders, signs and stores a path's narinfo once, at publish, so serving
 * it reads one object: no database connection and no signing per request.
 */
export async function storeNarinfo(config: WorkerConfig, cacheName: string, path: NarinfoPath, blob: NarinfoBlob): Promise<void> {
	const body = await signedNarinfo(config, path, blob);
	await config.bucket.put(narinfoKey(cacheName, path.storePathHash), body, {
		httpMetadata: { contentType: "text/x-nix-narinfo" },
	});
}
