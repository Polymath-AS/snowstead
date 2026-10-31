import { AwsClient } from "aws4fetch";
import type { WorkerConfig } from "./config.js";
import type { UploadSession } from "./db/types.js";
import {
	acquireNarInstallations,
	setNarInstallationUpload,
	finishNarInstallations,
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

/** One SQL admission/cleanup phase around bounded, connection-free transfers. */
export async function installStagedNars(
	config: WorkerConfig,
	sessions: readonly (UploadSession & { fileHash: string; inlineBytes?: ArrayBuffer })[],
): Promise<Map<string, string | undefined>> {
	return serializeInstallations(config, async () => {
		const results = new Map<string, string | undefined>();
		const visibility = new Map<number, boolean>();
		for (const cacheId of new Set(sessions.map(session => session.cacheId))) {
			const cache = await findCacheById(config.db, cacheId);
			if (cache) visibility.set(cacheId, await isPrivateCache(config, cache.path));
		}
		const jobs: Installation[] = [];
		for (const session of sessions) {
			if (!session.r2UploadKey?.startsWith("staging/")) results.set(session.id, "Upload incomplete");
			else if (!visibility.has(session.cacheId)) results.set(session.id, "Cache not found");
			else {
				const isPrivate = visibility.get(session.cacheId)!;
				jobs.push({
					key: narKey(session.fileHash, session.compression, isPrivate), operationId: crypto.randomUUID(),
					sourceKey: session.r2UploadKey, fileHash: session.fileHash, compression: session.compression,
					isPrivate, fileSize: session.fileSize, sessionId: session.id,
					inlineBytes: session.inlineBytes,
					terminal: false,
				});
			}
		}
		const installed = await installNars(config, jobs, true);
		for (const job of jobs) results.set(job.sessionId!, installed.get(job.operationId));
		return results;
	});
}

/**
 * Install immutable source bytes without replacing an existing object's
 * ownership metadata. Admission pins both the source and hash against GC.
 * No SQL transaction or connection spans hashing or transferring bytes.
 * Sources are retained: session/GC cleanup owns their lifetime.
 */
export async function installNar(
	config: WorkerConfig, sourceKey: string, fileHash: string, compression: string, isPrivate: boolean,
	fileSize: number, sessionId?: string,
): Promise<string | undefined> {
	const job: Installation = {
		key: narKey(fileHash, compression, isPrivate), operationId: crypto.randomUUID(), sourceKey,
		fileHash, compression, isPrivate, fileSize, sessionId, terminal: false,
	};
	return serializeInstallations(config, async () => (await installNars(config, [job])).get(job.operationId));
}

async function serializeInstallations<T>(config: WorkerConfig, operation: () => Promise<T>): Promise<T> {
	// A request shares one lazy SQL client. Backfill/publish batches may call
	// us together; never close a sibling installer's client or interleave its
	// admission transaction. Different requests still install concurrently.
	const previous = installations.get(config);
	const slot = Promise.withResolvers<void>();
	installations.set(config, slot.promise);
	await previous;
	try {
		return await operation();
	} finally {
		slot.resolve();
		if (installations.get(config) === slot.promise) installations.delete(config);
	}
}

type Installation = {
	key: string;
	operationId: string;
	sourceKey: string;
	fileHash: string;
	compression: string;
	isPrivate: boolean;
	fileSize: number;
	sessionId?: string;
	/** Bounded request-owned bytes need no staging object or storage read. */
	inlineBytes?: ArrayBuffer;
	/** Only a known terminal storage outcome allows the durable gate to go. */
	terminal: boolean;
};

async function installNars(config: WorkerConfig, jobs: readonly Installation[], recoverExisting = false): Promise<Map<string, string | undefined>> {
	const results = new Map<string, string | undefined>();
	let pending = jobs.filter(job => {
		if (Number.isSafeInteger(job.fileSize) && job.fileSize > 0 && job.fileSize <= OBJECT_MAX) return true;
		results.set(job.operationId, "File size mismatch");
		return false;
	});
	while (pending.length > 0) {
		// Each key has one durable gate/source pin. Equal-content sessions
		// take successive waves, proving each source without rewriting the winner.
		const wave = new Map<string, Installation>();
		const next: Installation[] = [];
		for (const job of pending) {
			if (wave.has(job.key)) next.push(job);
			else wave.set(job.key, job);
		}
		pending = next;
		const admitted = new Set(await acquireNarInstallations(config.db, [...wave.values()].map(
			({ key, operationId, sourceKey, fileHash, compression, isPrivate, fileSize }) =>
				({ key, operationId, sourceKey, fileHash, compression, isPrivate, fileSize }),
		)));
		const ready: Installation[] = [];
		try {
			for (const job of wave.values()) {
				if (!admitted.has(job.operationId) && !recoverExisting) results.set(job.operationId, INSTALLATION_BUSY);
				else if (!job.sourceKey.startsWith("staging/") && await hasCanonicalUploadReservations(config.db, job.sourceKey)) {
					job.terminal = true;
					results.set(job.operationId, INSTALLATION_BUSY);
				} else ready.push(job);
			}
			await config.releaseDb();
			// At most four held source streams leave room for destination writes
			// under the six-connection limit. Small transfers do not access SQL.
			const small = ready.filter(job => job.fileSize <= SINGLE_PUT_MAX);
			await Promise.all(Array.from({ length: Math.min(4, small.length) }, async () => {
				for (let job = small.shift(); job; job = small.shift()) {
					results.set(job.operationId, await (admitted.has(job.operationId) ? transferNar(config, job) : recoverNar(config, job)));
				}
			}));
			// Large copies register/fence their destination MPU in SQL. Run
			// those phases only after all connection-free transfers settle.
			for (const job of ready.filter(job => job.fileSize > SINGLE_PUT_MAX)) {
				results.set(job.operationId, await (admitted.has(job.operationId) ? transferNar(config, job) : recoverNar(config, job)));
			}
		} finally {
			await finishNarInstallations(config.db, [...wave.values()].filter(job => admitted.has(job.operationId) && job.terminal),
				source => bucketForKey(config, source).delete(source));
			await config.releaseDb();
		}
	}
	return results;
}

async function transferNar(config: WorkerConfig, job: Installation): Promise<string | undefined> {
	const { key, operationId, sourceKey, fileHash, fileSize, isPrivate } = job;

	const sourceBucket = bucketForKey(config, sourceKey);
	const destination = bucketFor(config, isPrivate);
	let multipart: R2MultipartUpload | undefined;
	let writeStarted = false;
	let success = false;
	try {
		const proof = await verifySource(config, job);
		if (typeof proof === "string") return proof;
		const { source, verifiedBytes } = proof;

		// Small verified buffers can go straight to the checksum-checked,
		// create-only PUT. A losing PUT still verifies the existing winner below.
		const existing = verifiedBytes === undefined ? await destination.head(key) : null;
		if (existing) {
			if (existing.size !== fileSize) return "File size mismatch";
			if (!(await verifies(destination, existing, fileHash))) return "File hash mismatch";
			success = true;
			return undefined;
		}

		if (fileSize <= SINGLE_PUT_MAX) {
			const object = verifiedBytes === undefined ? await readSource(sourceBucket, source!) : undefined;
			const body = verifiedBytes ?? object?.body;
			if (!body) return "Upload incomplete";
			writeStarted = true;
			const stored = await destination.put(key, body, {
				sha256: fileHash,
				httpMetadata: { contentType: "application/x-nix-nar", cacheControl: IMMUTABLE },
				onlyIf: { etagDoesNotMatch: "*" },
			});
			writeStarted = false;
			if (object && !object.bodyUsed) await object.body.cancel();
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
		const parts = await copyParts(config, sourceBucket, source!, multipart);
		// UploadPartCopy cannot condition its source. Only frozen sources are
		// allowed; detecting replacement also prevents completing mixed parts.
		if ((await sourceBucket.head(sourceKey))?.version !== source!.version) return "Upload incomplete: source changed";
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
		job.terminal = terminal;
	}
}

/**
 * Sealed SQL upload sessions independently protect the canonical blob from GC.
 * A lost admission may therefore reuse verified bytes, but cannot write storage
 * or finish the old operation: its ambiguous write may still be in flight.
 */
async function recoverNar(config: WorkerConfig, job: Installation): Promise<string | undefined> {
	try {
		const destination = bucketFor(config, job.isPrivate);
		const existing = await destination.head(job.key);
		if (!existing) return INSTALLATION_BUSY;
		const proof = await verifySource(config, job);
		if (typeof proof === "string") return proof;
		if (existing.size !== job.fileSize) return "File size mismatch";
		if (!(await verifies(destination, existing, job.fileHash))) return "File hash mismatch";
		return undefined;
	} catch (error) {
		console.error("NAR recovery failed", { key: job.key, operationId: job.operationId }, errorForLog(error));
		return INSTALLATION_INCOMPLETE;
	}
}

async function verifySource(config: WorkerConfig, job: Installation): Promise<{
	source: R2Object | null | undefined;
	verifiedBytes: ArrayBuffer | undefined;
} | string> {
	const { sourceKey, fileHash, fileSize, sessionId } = job;
	const sourceBucket = bucketForKey(config, sourceKey);
	if (job.inlineBytes && fileSize > MIB) return "File size mismatch";
	const sourceBody = job.inlineBytes === undefined && fileSize <= MIB ? await sourceBucket.get(sourceKey) : undefined;
	const source = job.inlineBytes !== undefined ? undefined : fileSize <= MIB ? sourceBody : await sourceBucket.head(sourceKey);
	if (job.inlineBytes === undefined && !source) return "Upload incomplete";
	// One GET binds small-object metadata and bytes to the same version.
	// Four lanes cap these buffers at 4 MiB; large objects remain streamed.
	let verifiedBytes = job.inlineBytes;
	try {
		if (source && sessionId !== undefined && source.customMetadata?.session !== sessionId) return "Upload incomplete";
		if (source && source.size !== fileSize) return "File size mismatch";
		if (sourceBody) verifiedBytes = await sourceBody.arrayBuffer();
		if (verifiedBytes) {
			if (verifiedBytes.byteLength !== fileSize) return "File size mismatch";
			const digest = await crypto.subtle.digest("SHA-256", verifiedBytes);
			const hex = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
			if (hex !== fileHash) return "File hash mismatch";
		} else if (!source || !(await verifies(sourceBucket, source, fileHash))) return "File hash mismatch";
		return { source, verifiedBytes };
	} finally {
		if (sourceBody && !sourceBody.bodyUsed) await sourceBody.body.cancel();
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
