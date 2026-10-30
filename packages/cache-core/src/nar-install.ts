import { AwsClient } from "aws4fetch";
import type { WorkerConfig } from "./config.js";
import type { UploadSession } from "./db/types.js";
import {
	acquireNarInstallation,
	setNarInstallationUpload,
	finishNarInstallation,
	installationOwns,
	hasCanonicalUploadReservations,
	findCacheById,
} from "./db/repository.js";
import { bucketFor, bucketForKey, bucketNameForKey, IMMUTABLE, narKey } from "./layout.js";
import { isPrivateCache } from "./visibility.js";
import { errorForLog } from "./logging.js";

const SINGLE_PUT_MAX = 5 * 1024 ** 3 - 1024 ** 2;
const OBJECT_MAX = 5 * 1024 ** 4;
const MIB = 1024 ** 2;

export const INSTALLATION_BUSY = "NAR installation busy; retry";
export const INSTALLATION_INCOMPLETE = "NAR installation incomplete; retry";

const installations = new WeakMap<WorkerConfig, Promise<void>>();

/** The handler must freeze the completed staging object before calling this. */
export async function installStagedNar(
	config: WorkerConfig,
	session: UploadSession & { fileHash: string },
): Promise<string | undefined> {
	if (!session.r2UploadKey?.startsWith("staging/")) return "Upload incomplete";
	if (!session.fileSize || session.fileSize > OBJECT_MAX) return "File size mismatch";
	const cache = await findCacheById(config.db, session.cacheId);
	if (!cache) return "Cache not found";
	return installNar(config, session.r2UploadKey, session.fileHash, session.compression,
		await isPrivateCache(config, cache.path), session.fileSize, session.id,
		session.partSize === null && session.r2UploadId !== null);
}

/**
 * Install immutable source bytes without replacing an existing object's
 * ownership metadata. Admission pins both the source and hash against GC.
 * No SQL transaction or connection spans hashing or transferring bytes.
 * Sources are retained: session/GC cleanup owns their lifetime.
 */
export async function installNar(...args: Parameters<typeof installPinnedNar>): Promise<string | undefined> {
	// A request shares one lazy SQL client. Backfill/publish batches may call
	// us together; never close a sibling installer's client or interleave its
	// admission transaction. Different requests still install concurrently.
	const config = args[0];
	const previous = installations.get(config);
	const slot = Promise.withResolvers<void>();
	installations.set(config, slot.promise);
	await previous;
	try {
		return await installPinnedNar(...args);
	} finally {
		slot.resolve();
		if (installations.get(config) === slot.promise) installations.delete(config);
	}
}

async function installPinnedNar(
	config: WorkerConfig,
	sourceKey: string,
	fileHash: string,
	compression: string,
	isPrivate: boolean,
	fileSize: number,
	sessionId?: string,
	allowMissingSession = false,
): Promise<string | undefined> {
	if (!Number.isSafeInteger(fileSize) || fileSize <= 0 || fileSize > OBJECT_MAX) return "File size mismatch";
	const key = narKey(fileHash, compression, isPrivate);
	const operationId = crypto.randomUUID();
	const acquired = await acquireNarInstallation(config.db, {
		key, operationId, sourceKey, fileHash, compression, isPrivate, fileSize,
	});
	await config.releaseDb();
	if (!acquired) return INSTALLATION_BUSY;

	const sourceBucket = bucketForKey(config, sourceKey);
	const destination = bucketFor(config, isPrivate);
	let multipart: R2MultipartUpload | undefined;
	let writeStarted = false;
	let success = false;
	try {
		if (!sourceKey.startsWith("staging/")) {
			const reserved = await hasCanonicalUploadReservations(config.db, sourceKey);
			await config.releaseDb();
			if (reserved) return INSTALLATION_BUSY;
		}
		const source = await sourceBucket.head(sourceKey);
		if (!source) return "Upload incomplete";
		// Early v1 staged MPUs had no ownership metadata. Only those may omit
		// it; their session-private key still proves possession. Never accept a
		// different owner's metadata, and every new stream must have its own.
		const owner = source.customMetadata?.session;
		if (sessionId !== undefined && owner !== sessionId && !(allowMissingSession && owner === undefined)) return "Upload incomplete";
		if (source.size !== fileSize) return "File size mismatch";
		if (!(await verifies(sourceBucket, source, fileHash))) return "File hash mismatch";

		const existing = await destination.head(key);
		if (existing) {
			if (existing.size !== fileSize) return "File size mismatch";
			if (!(await verifies(destination, existing, fileHash))) return "File hash mismatch";
			success = true;
			return undefined;
		}

		if (fileSize <= SINGLE_PUT_MAX) {
			const body = await readSource(sourceBucket, source);
			if (!body) return "Upload incomplete";
			writeStarted = true;
			const stored = await destination.put(key, body.body, {
				sha256: fileHash,
				httpMetadata: { contentType: "application/x-nix-nar", cacheControl: IMMUTABLE },
				onlyIf: { etagDoesNotMatch: "*" },
			});
			writeStarted = false;
			if (!body.bodyUsed) await body.body.cancel();
			if (!stored) {
				const winner = await destination.head(key);
				if (!winner || winner.size !== fileSize || !(await verifies(destination, winner, fileHash))) {
					return "File hash mismatch";
				}
			}
			success = true;
			return undefined;
		}

		// Old create-only PUTs may still arrive, and pre-deployment canonical
		// MPUs remain unsafe even after TTL. No new canonical grants are made.
		const reserved = await hasCanonicalUploadReservations(config.db, key);
		await config.releaseDb();
		if (reserved) return INSTALLATION_BUSY;
		multipart = await destination.createMultipartUpload(key, {
			httpMetadata: { contentType: "application/x-nix-nar", cacheControl: IMMUTABLE },
		});
		const registered = await setNarInstallationUpload(config.db, key, operationId, multipart.uploadId);
		await config.releaseDb();
		if (!registered) return INSTALLATION_BUSY;
		const parts = await copyParts(config, sourceBucket, source, multipart);
		// UploadPartCopy cannot condition its source. Only frozen sources are
		// allowed; detecting replacement also prevents completing mixed parts.
		if ((await sourceBucket.head(sourceKey))?.version !== source.version) return "Upload incomplete: source changed";
		const owns = await installationOwns(config.db, key, operationId);
		await config.releaseDb();
		if (!owns) return INSTALLATION_BUSY;
		writeStarted = true;
		await multipart.complete(parts);
		success = true;
		return undefined;
	} catch (error) {
		console.error("NAR installation failed", { key, operationId }, errorForLog(error));
		return INSTALLATION_INCOMPLETE;
	} finally {
		// An ambiguous PUT/complete may still be running. Keep its durable
		// gate, even after the request dies: time alone cannot fence R2.
		let terminal = success || !writeStarted;
		if (multipart && !writeStarted) {
			try { await multipart.abort(); } catch { terminal = false; }
		}
		if (terminal) await finishNarInstallation(config.db, key, operationId, source => sourceBucket.delete(source));
		await config.releaseDb();
	}
}

async function readSource(bucket: R2Bucket, source: R2Object): Promise<R2ObjectBody | undefined> {
	const object = await bucket.get(source.key, { onlyIf: { etagMatches: source.etag } });
	if (!object || !("body" in object)) return undefined;
	if (object.version === source.version) return object;
	await object.body.cancel();
	return undefined;
}

/** Hash the entire object, not multipart/composite SHA-256 or its ETag. */
async function verifies(bucket: R2Bucket, source: R2Object, fileHash: string): Promise<boolean> {
	const object = await readSource(bucket, source);
	if (!object) return false;
	const digest = new crypto.DigestStream("SHA-256");
	await object.body.pipeTo(digest);
	const hex = [...new Uint8Array(await digest.digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
	return hex === fileHash;
}

async function copyParts(
	config: WorkerConfig,
	sourceBucket: R2Bucket,
	source: R2Object,
	upload: R2MultipartUpload,
): Promise<R2UploadedPart[]> {
	// Uniform parts, at least 5 MiB, and <=10,000 parts even at 5 TiB.
	const partSize = Math.max(32 * MIB, Math.ceil(source.size / 10_000 / MIB) * MIB);
	const client = config.r2Endpoint && config.r2AccessKeyId && config.r2SecretAccessKey
		? new AwsClient({ accessKeyId: config.r2AccessKeyId, secretAccessKey: config.r2SecretAccessKey, service: "s3", region: "auto" })
		: undefined;
	const parts: R2UploadedPart[] = [];
	for (let offset = 0; offset < source.size; offset += partSize) {
		const partNumber = parts.length + 1;
		const length = Math.min(partSize, source.size - offset);
		if (client) {
			const path = `/${bucketNameForKey(config, upload.key)}/${encodeKey(upload.key)}`;
			const url = new URL(path, config.r2Endpoint);
			url.searchParams.set("uploadId", upload.uploadId);
			url.searchParams.set("partNumber", String(partNumber));
			const response = await client.fetch(url.toString(), {
				method: "PUT",
				headers: {
					"x-amz-copy-source": `/${bucketNameForKey(config, source.key)}/${encodeKey(source.key)}`,
					"x-amz-copy-source-range": `bytes=${offset}-${offset + length - 1}`,
				},
			});
			const xml = await response.text();
			const etag = /<ETag>\s*(?:"|&quot;)?([^<"]+?)(?:"|&quot;)?\s*<\/ETag>/.exec(xml)?.[1];
			if (!response.ok || /<Error[\s>]/.test(xml) || !etag) throw new Error("R2 UploadPartCopy failed");
			parts.push({ partNumber, etag });
		} else {
			const object = await sourceBucket.get(source.key, {
				onlyIf: { etagMatches: source.etag }, range: { offset, length },
			});
			if (!object || !("body" in object)) throw new Error("NAR source missing");
			if (object.version !== source.version) {
				await object.body.cancel();
				throw new Error("NAR source changed");
			}
			parts.push(await upload.uploadPart(partNumber, object.body));
		}
	}
	return parts;
}

function encodeKey(key: string): string {
	return key.split("/").map(encodeURIComponent).join("/");
}
