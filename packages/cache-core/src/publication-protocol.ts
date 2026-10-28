import * as v from "valibot";
import { parseCacheName, parseCompression, parseFileHash, parseStorePathHash } from "@snowstead/cache-domain";
import type { ReadBucket } from "./read-storage.js";

// Shared by the mutation service and the binding-only download service. A
// record's existence is not permission: readers also match its full identity.
const Id = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{1,128}$/));
const CacheId = v.pipe(v.number(), v.safeInteger(), v.minValue(1));
const Uuid = v.pipe(v.string(), v.uuid());
const Hash = v.pipe(v.string(), v.check((s) => typeof parseStorePathHash(s) === "string"));
const FileHash = v.pipe(v.string(), v.check((s) => typeof parseFileHash(s) === "string"));
const Bytes = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const Name = v.pipe(v.string(), v.check((s) => typeof parseCacheName(s) === "string"));
const CachePath = v.pipe(v.string(), v.check((s) => s.split("/").length <= 2 && s.split("/").every((part) => typeof parseCacheName(part) === "string")));
const identity = { orgId: Id, cacheId: CacheId };
const command = { version: v.literal(2), nonce: Uuid, operationId: Uuid };
const visibility = v.picklist(["public", "private"]);
const etag = v.pipe(v.string(), v.regex(/^"[A-Za-z0-9_-]{1,200}"$/));

export const RouteRecord = v.strictObject({
	...command, ...identity,
	path: CachePath,
	state: v.picklist(["active", "disabled"]),
});
export type RouteRecord = v.InferOutput<typeof RouteRecord>;

export const CacheStatus = v.strictObject({
	...command, ...identity,
	epoch: Uuid,
	visibility,
	name: Name,
	state: v.picklist(["active", "draining", "retired"]),
});
export type CacheStatus = v.InferOutput<typeof CacheStatus>;

const pathIdentity = { ...identity, epoch: Uuid, storePathHash: Hash };
export const ActiveGrant = v.strictObject({
	...command, ...pathIdentity,
	state: v.literal("active"),
	publicationId: Uuid,
	fileHash: FileHash,
	compression: v.pipe(v.string(), v.check((s) => typeof parseCompression(s) === "string")),
	fileSize: Bytes,
	narinfoSize: Bytes,
	narEtag: etag,
	narinfoEtag: etag,
	publishedAt: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
});
export type ActiveGrant = v.InferOutput<typeof ActiveGrant>;
export const PathGrant = v.union([
	ActiveGrant,
	v.strictObject({ ...command, ...pathIdentity, state: v.literal("tombstone") }),
]);
export type PathGrant = v.InferOutput<typeof PathGrant>;

/** A compatibility lookup hint, never an authorization decision. */
export const LegacyWitness = v.strictObject({
	...command, ...pathIdentity,
	publicationId: Uuid,
	fileHash: FileHash,
	compression: v.pipe(v.string(), v.check((s) => typeof parseCompression(s) === "string")),
});

export const TokenPolicy = v.strictObject({
	...command,
	jti: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
	state: v.picklist(["active", "revoked"]),
	// Digest of the exact signed claims, not just the JTI. A record cannot
	// accidentally enroll a different token carrying a colliding identifier.
	claimsDigest: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/)),
});
export type TokenPolicy = v.InferOutput<typeof TokenPolicy>;

export const KeyPolicy = v.strictObject({
	...command,
	keyId: v.literal("legacy-hs256"),
	state: v.picklist(["active", "revoked"]),
});

export const MAX_AUTHORITY_BYTES = 16_384;

export function routeKey(path: string): string { return `authority/v2/routes/${path}`; }
export function statusKey(cacheId: number): string { return `authority/v2/caches/${cacheId}`; }
export function grantKey(cacheId: number, epoch: string, hash: string): string {
	return `authority/v2/grants/${cacheId}/${epoch}/${hash}`;
}
export function tokenKey(jti: string): string { return `authority/v2/tokens/${encodeURIComponent(jti)}`; }
export const LEGACY_KEY_POLICY = "authority/v2/keys/legacy-hs256";
export function witnessKey(cacheId: number, epoch: string, hash: string, compression: string): string {
	return `authority/v2/legacy/${cacheId}/${epoch}/${hash}/${compression}`;
}

export type Representation = "nar" | "narinfo";

/** No free-form object key from a client or record reaches the byte bucket. */
export function publicationKey(grant: ActiveGrant, representation: Representation): string {
	return `v2/o/${grant.orgId}/c/${grant.cacheId}/e/${grant.epoch}/p/${grant.storePathHash}/r/${grant.publicationId}/${representation}`;
}

export function publicationUrl(grant: ActiveGrant): string {
	return `nar/v2/${grant.storePathHash}/${grant.publicationId}/${grant.fileHash}.nar`;
}

/** Mutable authority is always read fresh, never through an HTTP cache. */
export async function readAuthority<S extends v.GenericSchema>(bucket: Pick<ReadBucket, "get">, key: string, schema: S): Promise<v.InferOutput<S> | undefined> {
	const object = await bucket.get(key);
	if (!object) return undefined;
	if (object.size > MAX_AUTHORITY_BYTES) {
		await object.body.cancel();
		throw new Error("Oversized authority record");
	}
	const result = v.safeParse(schema, await new Response(object.body).json());
	if (!result.success) throw new Error("Invalid authority record");
	return result.output;
}
