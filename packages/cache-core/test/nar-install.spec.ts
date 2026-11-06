import { env } from "cloudflare:test";
import { Buffer } from "node:buffer";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AwsClient } from "aws4fetch";
import { eq } from "drizzle-orm";
import { resolveConfig } from "../src/config.js";
import type { WorkerConfig } from "../src/config.js";
import { createCache, createUploadSession, acquireNarInstallations, deleteEmptyCache, finishNarInstallations, deleteUnreferencedBlobObjects } from "../src/db/repository.js";
import { narInstallations, uploadSessions } from "../src/db/schema.js";
import { installStagedNars, installNar, INSTALLATION_BUSY } from "../src/nar-install.js";
import { narKey, placeNar } from "../src/layout.js";
import { testDb } from "./db.js";

const db = testDb();
const configs: WorkerConfig[] = [];
afterEach(async () => {
	vi.restoreAllMocks();
	await Promise.all(configs.splice(0).map(config => config.close()));
});

function config(overrides: Partial<WorkerConfig> = {}): WorkerConfig {
	const base = resolveConfig(env);
	configs.push(base);
	// Preserve the lazy db getter rather than capturing its current client.
	return Object.assign(Object.create(base), overrides);
}

function bucket(base: R2Bucket, overrides: Partial<R2Bucket>): R2Bucket {
	return new Proxy(base, {
		get(target, property) {
			const value = Reflect.get(overrides, property) ?? Reflect.get(target, property, target);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
}

async function fixture(size = 16) {
	const cache = await createCache(db, `install-${crypto.randomUUID()}`);
	const id = crypto.randomUUID();
	const bytes = new Uint8Array(size);
	for (let offset = 0; offset < size; offset += 65536) crypto.getRandomValues(bytes.subarray(offset, offset + 65536));
	const fileHash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
		.map(byte => byte.toString(16).padStart(2, "0")).join("");
	const sourceKey = `staging/${id}`;
	const key = narKey(fileHash, "zstd", false);
	const session = await createUploadSession(db, {
		id, cacheId: cache.id, storePathHash: "a".repeat(32), storePath: `/nix/store/${"a".repeat(32)}-install`,
		narHash: `sha256:${"1".repeat(52)}`, narSize: 64, fileHash, fileSize: bytes.length,
		compression: "zstd", referencesJson: "[]", deriver: null, system: null,
		r2UploadKey: sourceKey, r2UploadId: null, expiresAt: new Date(Date.now() + 60_000),
	});
	await env.CACHE_BUCKET.put(sourceKey, bytes, { customMetadata: { session: id } });
	return { bytes, fileHash, sourceKey, key, session: { ...session, fileHash } };
}

async function gate(key: string) {
	return (await db.select().from(narInstallations).where(eq(narInstallations.key, key)))[0];
}

describe("verified canonical NAR installation", () => {
	it.each([false, true])("cleans a stage orphaned by cache deletion, retaining its pin on cleanup failure (%s)", async failDelete => {
		const f = await fixture();
		const privateBucket = bucket(env.CACHE_BUCKET, {
			get: async (key, options) => {
				const removed = await deleteEmptyCache(db, f.session.cacheId);
				expect(removed).toEqual({ deleted: true, staged: [] });
				return env.CACHE_BUCKET.get(key, options);
			},
			delete: async key => {
				if (failDelete) throw new Error("storage unavailable");
				await env.CACHE_BUCKET.delete(key);
			},
		});
		const result = installStagedNars(config({ bucket: privateBucket }), [f.session]);
		if (failDelete) {
			await expect(result).rejects.toThrow("storage unavailable");
			expect(await gate(f.key)).toMatchObject({ sourceKey: f.sourceKey });
			expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		} else {
			expect((await result).get(f.session.id)).toBeUndefined();
			expect(await gate(f.key)).toBeUndefined();
			expect(await env.CACHE_BUCKET.head(f.sourceKey)).toBeNull();
		}
	});

	it.each([16, 1024 ** 2, 1024 ** 2 + 1])("pins before reading, releases SQL before hashing, and retains its own stage (%s bytes)", async size => {
		const f = await fixture(size);
		const base = config();
		let released = false;
		const privateBucket = bucket(env.CACHE_BUCKET, {
			get: async (key, options) => {
				expect(await gate(f.key)).toMatchObject({ sourceKey: f.sourceKey });
				expect(released).toBe(true);
				return env.CACHE_BUCKET.get(key, options);
			},
		});
		const cfg = Object.assign(Object.create(base), {
			bucket: privateBucket,
			releaseDb: async () => { await base.releaseDb(); released = true; },
		});
		expect((await installStagedNars(cfg, [f.session])).get(f.session.id)).toBeUndefined();
		expect(Buffer.from(await (await env.PUBLIC_BUCKET.get(f.key))!.arrayBuffer()).equals(f.bytes)).toBe(true);
		expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it.each([
		["owner", false, 16], ["size", false, 16], ["hash", false, 16],
		["owner", true, 16], ["size", true, 16], ["hash", true, 16],
		["owner", false, 1024 ** 2 + 1], ["size", false, 1024 ** 2 + 1], ["hash", false, 1024 ** 2 + 1],
		["owner", true, 1024 ** 2 + 1], ["size", true, 1024 ** 2 + 1], ["hash", true, 1024 ** 2 + 1],
	] as const)("rejects bad staged %s (canonical exists: %s, bytes: %s)", async (fault, exists, size) => {
		const f = await fixture(size);
		if (exists) await env.PUBLIC_BUCKET.put(f.key, f.bytes, { customMetadata: { session: "canonical-owner" } });
		const before = await env.PUBLIC_BUCKET.head(f.key);
		await env.CACHE_BUCKET.put(f.sourceKey,
			fault === "size" ? new Uint8Array(1) : fault === "hash" ? new Uint8Array(size) : f.bytes,
			{ customMetadata: { session: fault === "owner" ? "someone-else" : f.session.id } });
		expect((await installStagedNars(config(), [f.session])).get(f.session.id)).toBe(
			fault === "owner" ? "Upload incomplete" : fault === "size" ? "File size mismatch" : "File hash mismatch",
		);
		expect((await env.PUBLIC_BUCKET.head(f.key))?.version).toBe(before?.version);
		expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it.each(["owner", "size"])("cancels the small source body rejected for %s", async fault => {
		const f = await fixture();
		await env.CACHE_BUCKET.put(f.sourceKey, fault === "size" ? new Uint8Array(1) : f.bytes,
			{ customMetadata: { session: fault === "owner" ? "someone-else" : f.session.id } });
		const object = (await env.CACHE_BUCKET.get(f.sourceKey))!;
		const cancel = vi.spyOn(object.body, "cancel");
		const privateBucket = bucket(env.CACHE_BUCKET, { get: async () => object });
		expect((await installStagedNars(config({ bucket: privateBucket }), [f.session])).get(f.session.id)).toBe(
			fault === "owner" ? "Upload incomplete" : "File size mismatch",
		);
		expect(cancel).toHaveBeenCalledOnce();
		expect(object.bodyUsed).toBe(true);
		expect(await env.PUBLIC_BUCKET.head(f.key)).toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it("rejects a small source whose body length disagrees with its metadata", async () => {
		const f = await fixture();
		await env.CACHE_BUCKET.put(f.sourceKey, new Uint8Array(1), { customMetadata: { session: f.session.id } });
		const privateBucket = bucket(env.CACHE_BUCKET, {
			get: async key => {
				const object = await env.CACHE_BUCKET.get(key);
				return object ? new Proxy(object, {
					get: (target, property) => {
						const value = Reflect.get(target, property, target);
						return property === "size" ? f.bytes.length : typeof value === "function" ? value.bind(target) : value;
					},
				}) : null;
			},
		});
		expect((await installStagedNars(config({ bucket: privateBucket }), [f.session])).get(f.session.id)).toBe("File size mismatch");
		expect(await env.PUBLIC_BUCKET.head(f.key)).toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it.each([null, 8 * 1024 ** 2])("requires stage ownership regardless of part size (%s)", async partSize => {
		const f = await fixture();
		await env.CACHE_BUCKET.put(f.sourceKey, f.bytes);
		const session = { ...f.session, r2UploadId: "assembled", partSize };
		expect((await installStagedNars(config(), [session])).get(session.id)).toBe("Upload incomplete");
		expect(await env.PUBLIC_BUCKET.head(f.key)).toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it("serializes installers sharing a request without retaining a closed db handle", async () => {
		const a = await fixture();
		const b = await fixture();
		const cfg = config();
		expect(await Promise.all([installStagedNars(cfg, [a.session]), installStagedNars(cfg, [b.session])])).toEqual([new Map([[a.session.id, undefined]]), new Map([[b.session.id, undefined]])]);
		expect(await gate(a.key)).toBeUndefined();
		expect(await gate(b.key)).toBeUndefined();
	});

	it("reuses canonical bytes without erasing session ownership or version", async () => {
		const f = await fixture();
		await db.insert(uploadSessions).values({ ...f.session, id: crypto.randomUUID(), r2UploadKey: f.key });
		const before = await env.PUBLIC_BUCKET.put(f.key, f.bytes, { customMetadata: { session: "old-owner" } });
		expect((await installStagedNars(config(), [f.session])).get(f.session.id)).toBeUndefined();
		expect(await env.PUBLIC_BUCKET.head(f.key)).toMatchObject({ version: before.version, customMetadata: { session: "old-owner" } });
	});

	it.each([
		["valid", 16], ["size", 16], ["hash", 16],
		["valid", 1024 ** 2 + 1], ["size", 1024 ** 2 + 1], ["hash", 1024 ** 2 + 1],
	] as const)("verifies and preserves a concurrent create-only canonical winner (%s, %s bytes)", async (fault, size) => {
		const f = await fixture(size);
		let winner: R2Object | undefined;
		const publicBucket = bucket(env.PUBLIC_BUCKET, {
			put: async (key, value, options) => {
				winner = (await env.PUBLIC_BUCKET.put(key,
					fault === "size" ? new Uint8Array(1) : fault === "hash" ? new Uint8Array(f.bytes.length) : f.bytes,
					{ customMetadata: { session: "old-owner" }, onlyIf: { etagDoesNotMatch: "*" } }))!;
				return env.PUBLIC_BUCKET.put(key, value, options);
			},
		});
		expect((await installStagedNars(config({ publicBucket }), [f.session])).get(f.session.id)).toBe(
			fault === "valid" ? undefined : "File hash mismatch",
		);
		expect(winner).toBeDefined();
		expect(await env.PUBLIC_BUCKET.head(f.key)).toMatchObject({ version: winner!.version, customMetadata: { session: "old-owner" } });
		expect(await gate(f.key)).toBeUndefined();
	});

	it("requires its own streamed proof even when a conditional PUT loses to a valid winner", async () => {
		const f = await fixture(1024 ** 2 + 1);
		await env.CACHE_BUCKET.put(f.sourceKey, new Uint8Array(f.bytes.length), { customMetadata: { session: f.session.id } });
		const publicBucket = bucket(env.PUBLIC_BUCKET, {
			put: async key => {
				await env.PUBLIC_BUCKET.put(key, f.bytes, { customMetadata: { session: "winner" } });
				return null;
			},
		});
		expect((await installStagedNars(config({ publicBucket }), [f.session])).get(f.session.id)).toBe("File hash mismatch");
		expect(await gate(f.key)).toBeUndefined();
		expect((await env.PUBLIC_BUCKET.head(f.key))?.customMetadata).toEqual({ session: "winner" });
	});

	it.each(["retained", "replaced", "missing", "unreadable"])("retains a lost-ack streaming write gate when its source is %s", async source => {
		const f = await fixture(1024 ** 2 + 1);
		let failed = false;
		const privateBucket = bucket(env.CACHE_BUCKET, {
			get: async (key, options) => {
				if (failed && source === "unreadable") throw new Error("Source read unavailable");
				return env.CACHE_BUCKET.get(key, options);
			},
		});
		const publicBucket = bucket(env.PUBLIC_BUCKET, {
			put: async (key, value, options) => {
				await env.PUBLIC_BUCKET.put(key, value, options);
				if (source === "replaced") await env.CACHE_BUCKET.put(f.sourceKey, new Uint8Array(f.bytes.length), {
					customMetadata: { session: f.session.id },
				});
				if (source === "missing") await env.CACHE_BUCKET.delete(f.sourceKey);
				failed = true;
				throw new Error("PUT acknowledgement lost");
			},
		});
		expect((await installStagedNars(config({ bucket: privateBucket, publicBucket }), [f.session])).get(f.session.id)).toContain("retry");
		expect(await gate(f.key)).toMatchObject({ sourceKey: f.sourceKey });
		expect(Buffer.from(await (await env.PUBLIC_BUCKET.get(f.key))!.arrayBuffer()).equals(f.bytes)).toBe(true);
	});

	it.each([false, true])("recovers verified bytes after an ambiguous PUT without releasing its gate (inline: %s)", async inline => {
		const f = await fixture();
		const session = { ...f.session, inlineBytes: inline ? f.bytes.slice().buffer : undefined };
		if (inline) await env.CACHE_BUCKET.delete(f.sourceKey);
		const publicBucket = bucket(env.PUBLIC_BUCKET, {
			put: async (key, value, options) => {
				await env.PUBLIC_BUCKET.put(key, value, options);
				throw new Error("PUT response lost");
			},
		});
		const cfg = config({ publicBucket });
		expect((await installStagedNars(cfg, [session])).get(f.session.id)).toContain("retry");
		expect(await gate(f.key)).toMatchObject({ sourceKey: f.sourceKey });
		const retained = await gate(f.key);
		const before = await env.PUBLIC_BUCKET.head(f.key);
		expect(Boolean(await env.CACHE_BUCKET.head(f.sourceKey))).toBe(!inline);
		expect(Buffer.from(await (await env.PUBLIC_BUCKET.get(f.key))!.arrayBuffer()).equals(f.bytes)).toBe(true);
		expect((await installStagedNars(config({ publicBucket }), [session])).get(f.session.id)).toBeUndefined();
		expect(await gate(f.key)).toEqual(retained);
		expect((await env.PUBLIC_BUCKET.head(f.key))?.version).toBe(before?.version);
	});

	it.each([16, 1024 ** 2 + 1])("recovers a new session without taking over an interrupted install (%s bytes)", async size => {
		const f = await fixture(size);
		await acquireNarInstallations(db, [{
			key: f.key, operationId: "interrupted-operation", sourceKey: f.sourceKey,
			fileHash: f.fileHash, compression: "zstd", isPrivate: false, fileSize: f.bytes.length,
		}]);
		const retained = await gate(f.key);
		const id = crypto.randomUUID();
		const session = await createUploadSession(db, { ...f.session, id, r2UploadKey: `staging/${id}` });
		await env.CACHE_BUCKET.put(session.r2UploadKey!, f.bytes, { customMetadata: { session: id } });
		const before = await env.PUBLIC_BUCKET.put(f.key, f.bytes, { customMetadata: { session: "original-owner" } });
		const mutation = vi.fn(() => { throw new Error("recovery must be read-only"); });
		const cfg = config({
			bucket: bucket(env.CACHE_BUCKET, { put: mutation, delete: mutation, createMultipartUpload: mutation, resumeMultipartUpload: mutation }),
			publicBucket: bucket(env.PUBLIC_BUCKET, { put: mutation, delete: mutation, createMultipartUpload: mutation, resumeMultipartUpload: mutation }),
		});
		expect((await installStagedNars(cfg, [{ ...session, fileHash: f.fileHash }])).get(id)).toBeUndefined();
		expect(mutation).not.toHaveBeenCalled();
		expect(await gate(f.key)).toEqual(retained);
		expect(await env.PUBLIC_BUCKET.head(f.key)).toMatchObject({ version: before.version, customMetadata: { session: "original-owner" } });
		expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		expect(await env.CACHE_BUCKET.head(session.r2UploadKey!)).not.toBeNull();
	});

	it.each(["source-deleted", "source-replaced", "canonical-deleted", "canonical-replaced"])("fails closed when recovery bytes change after HEAD (%s)", async fault => {
		const f = await fixture(1024 ** 2 + 1);
		await acquireNarInstallations(db, [{
			key: f.key, operationId: "interrupted-operation", sourceKey: f.sourceKey,
			fileHash: f.fileHash, compression: "zstd", isPrivate: false, fileSize: f.bytes.length,
		}]);
		await env.PUBLIC_BUCKET.put(f.key, f.bytes);
		const retained = await gate(f.key);
		const changed = fault.startsWith("source") ? env.CACHE_BUCKET : env.PUBLIC_BUCKET;
		const intercepted = bucket(changed, {
			get: async (key, options) => {
				if (fault.endsWith("deleted")) await changed.delete(key);
				else await changed.put(key, f.bytes, { customMetadata: { session: f.session.id } });
				return changed.get(key, options);
			},
		});
		const cfg = config(fault.startsWith("source") ? { bucket: intercepted } : { publicBucket: intercepted });
		expect((await installStagedNars(cfg, [f.session])).get(f.session.id)).toBe("File hash mismatch");
		expect(await gate(f.key)).toEqual(retained);
		if (fault.endsWith("deleted")) expect(await changed.head(fault.startsWith("source") ? f.sourceKey : f.key)).toBeNull();
	});

	it("retains canonical bytes through GC after the old owner releases its gate", async () => {
		const f = await fixture();
		await acquireNarInstallations(db, [{
			key: f.key, operationId: "interrupted-operation", sourceKey: f.sourceKey,
			fileHash: f.fileHash, compression: "zstd", isPrivate: false, fileSize: f.bytes.length,
		}]);
		await db.update(uploadSessions).set({ expiresAt: new Date(0) }).where(eq(uploadSessions.id, f.session.id));
		const id = crypto.randomUUID();
		const session = await createUploadSession(db, { ...f.session, id, status: "finalizing", r2UploadKey: `staging/${id}` });
		await env.CACHE_BUCKET.put(session.r2UploadKey!, f.bytes, { customMetadata: { session: id } });
		await env.PUBLIC_BUCKET.put(f.key, f.bytes);
		const privateBucket = bucket(env.CACHE_BUCKET, {
			get: async (key, options) => {
				await finishNarInstallations(db, [{ key: f.key, operationId: "interrupted-operation" }], async () => {});
				const removed = await deleteUnreferencedBlobObjects(db, 10_000, async () => {});
				expect(removed.some(blob => blob.fileHash === f.fileHash)).toBe(false);
				return env.CACHE_BUCKET.get(key, options);
			},
		});
		expect((await installStagedNars(config({ bucket: privateBucket }), [{ ...session, fileHash: f.fileHash }])).get(id)).toBeUndefined();
		expect(await gate(f.key)).toBeUndefined();
		await db.update(uploadSessions).set({ expiresAt: new Date(0) }).where(eq(uploadSessions.id, id));
		const removed = await deleteUnreferencedBlobObjects(db, 10_000, async () => {});
		expect(removed.some(blob => blob.fileHash === f.fileHash)).toBe(true);
	});

	it.each(["source-owner", "source-hash", "canonical-hash"])("requires both possession and valid canonical bytes during recovery (%s)", async fault => {
		const f = await fixture();
		await acquireNarInstallations(db, [{
			key: f.key, operationId: "interrupted-operation", sourceKey: f.sourceKey,
			fileHash: f.fileHash, compression: "zstd", isPrivate: false, fileSize: f.bytes.length,
		}]);
		const retained = await gate(f.key);
		await env.CACHE_BUCKET.put(f.sourceKey, fault === "source-hash" ? new Uint8Array(f.bytes.length) : f.bytes,
			{ customMetadata: { session: fault === "source-owner" ? "another-owner" : f.session.id } });
		const before = await env.PUBLIC_BUCKET.put(f.key, fault === "canonical-hash" ? new Uint8Array(f.bytes.length) : f.bytes);
		expect((await installStagedNars(config(), [f.session])).get(f.session.id)).toBe(
			fault === "source-owner" ? "Upload incomplete" : "File hash mismatch",
		);
		expect(await gate(f.key)).toEqual(retained);
		expect((await env.PUBLIC_BUCKET.head(f.key))?.version).toBe(before.version);
	});

	it("does not read an unpinned source when another installer owns the key", async () => {
		const f = await fixture();
		expect(await acquireNarInstallations(db, [{
			key: f.key, operationId: "another-operation", sourceKey: f.sourceKey,
			fileHash: f.fileHash, compression: "zstd", isPrivate: false, fileSize: f.bytes.length,
		}])).toEqual(["another-operation"]);
		const get = vi.fn(() => { throw new Error("must not hash"); });
		expect((await installStagedNars(config({ bucket: bucket(env.CACHE_BUCKET, { get }) }), [f.session])).get(f.session.id)).toBe(INSTALLATION_BUSY);
		expect(get).not.toHaveBeenCalled();
		expect((await gate(f.key))?.operationId).toBe("another-operation");
	});

	it.each([false, true])("waits before a large copy for an old canonical reservation (multipart: %s)", async multipart => {
		const f = await largeFixture();
		await db.insert(uploadSessions).values({
			...f.session, id: crypto.randomUUID(), fileSize: f.size,
			r2UploadKey: f.key, r2UploadId: multipart ? "legacy-multipart" : null,
			expiresAt: multipart ? new Date(0) : new Date(Date.now() + 60_000),
		});
		expect((await installStagedNars(config({ bucket: f.source, publicBucket: f.destination }),
			[{ ...f.session, fileSize: f.size }])).get(f.session.id)).toBe(INSTALLATION_BUSY);
		expect(f.upload.uploadPart).not.toHaveBeenCalled();
		expect(f.upload.complete).not.toHaveBeenCalled();
		expect(await env.PUBLIC_BUCKET.head(f.key)).toBeNull();
	});

	it("uses guarded checksum installation for cross-visibility publication", async () => {
		const f = await fixture();
		const privateKey = narKey(f.fileHash, "zstd", true);
		await env.CACHE_BUCKET.put(privateKey, f.bytes);
		await placeNar(config(), privateKey, f.fileHash, "zstd", false);
		expect(Buffer.from(await (await env.PUBLIC_BUCKET.get(f.key))!.arrayBuffer()).equals(f.bytes)).toBe(true);
		expect(await env.CACHE_BUCKET.head(privateKey)).not.toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it("reconnects after release and preserves deferred database work", async () => {
		const cfg = config();
		const before = cfg.db;
		let during = before;
		let done = false;
		cfg.defer((async () => {
			await before.select().from(narInstallations).limit(1);
			during = cfg.db;
			await during.select().from(narInstallations).limit(1);
			done = true;
		})());
		await cfg.releaseDb();
		expect(done).toBe(true);
		expect(cfg.db).not.toBe(before);
		expect(cfg.db).not.toBe(during);
		await expect(cfg.db.select().from(narInstallations).limit(1)).resolves.toBeDefined();
	});
});

/**
 * Transport stand-in: advertise a >5 GiB R2 object while hashing small real
 * bytes. This checks multipart routing/ranges without allocating or hashing
 * gigabytes in every unit run. Small-object cases above use real R2 bodies.
 */
async function largeFixture() {
	const f = await fixture();
	const size = 5 * 1024 ** 3 + 1;
	await db.update(uploadSessions).set({ fileSize: size }).where(eq(uploadSessions.id, f.session.id));
	const ranges: R2Range[] = [];
	const source = bucket(env.CACHE_BUCKET, {
		head: async key => {
			const object = await env.CACHE_BUCKET.head(key);
			return object ? new Proxy(object, { get: (target, property) => property === "size" ? size : Reflect.get(target, property, target) }) : null;
		},
		get: async (key, options) => {
			if (options?.range) ranges.push(options.range as R2Range);
			return env.CACHE_BUCKET.get(key, { onlyIf: options?.onlyIf });
		},
	});
	const upload: R2MultipartUpload = {
		key: f.key, uploadId: crypto.randomUUID(),
		uploadPart: vi.fn(async (partNumber, value) => {
			await new Response(value as ReadableStream).arrayBuffer();
			return { partNumber, etag: `part-${partNumber}` };
		}),
		complete: vi.fn(async () => ({ key: f.key }) as R2Object),
		abort: vi.fn(async () => {}),
	};
	const destination = bucket(env.PUBLIC_BUCKET, {
		createMultipartUpload: vi.fn(async () => upload),
		put: vi.fn(() => { throw new Error("large object must not use PUT"); }),
	});
	return { ...f, size, ranges, source, destination, upload };
}

describe("large NAR multipart installation", () => {
	it("streams bounded ranges without credentials, registering the upload before copying", async () => {
		const f = await largeFixture();
		const original = f.upload.uploadPart;
		f.upload.uploadPart = vi.fn(async (number, value) => {
			expect((await gate(f.key))?.uploadId).toBe(f.upload.uploadId);
			return original(number, value);
		});
		expect(await installNar(config({ bucket: f.source, publicBucket: f.destination }),
			f.sourceKey, f.fileHash, "zstd", false, f.size, f.session.id)).toBeUndefined();
		expect(f.ranges).toHaveLength(161);
		expect(f.ranges[0]).toEqual({ offset: 0, length: 32 * 1024 ** 2 });
		expect(f.ranges.at(-1)).toEqual({ offset: 5 * 1024 ** 3, length: 1 });
		expect(f.upload.complete).toHaveBeenCalledOnce();
		expect(f.upload.abort).not.toHaveBeenCalled();
		expect(await gate(f.key)).toBeUndefined();
	});

	it("uses UploadPartCopy with S3 credentials and explicit inclusive byte ranges", async () => {
		const f = await largeFixture();
		const fetch = vi.spyOn(AwsClient.prototype, "fetch").mockImplementation(async () =>
			new Response('<CopyPartResult><ETag>"copied-etag"</ETag></CopyPartResult>'));
		expect(await installNar(config({ bucket: f.source, publicBucket: f.destination,
			r2Endpoint: "https://r2.example.test", r2AccessKeyId: "access", r2SecretAccessKey: "secret",
		}), f.sourceKey, f.fileHash, "zstd", false, f.size, f.session.id)).toBeUndefined();
		expect(fetch).toHaveBeenCalledTimes(161);
		expect(fetch.mock.calls[0][1]).toMatchObject({ method: "PUT", headers: {
			"x-amz-copy-source": `/snowstead-private/${f.sourceKey}`,
			"x-amz-copy-source-range": `bytes=0-${32 * 1024 ** 2 - 1}`,
		} });
		expect(f.upload.uploadPart).not.toHaveBeenCalled();
		expect(f.upload.complete).toHaveBeenCalledWith(expect.arrayContaining([{ partNumber: 1, etag: "copied-etag" }]));
		expect(await gate(f.key)).toBeUndefined();
	});

	it("uses the same multipart installer when publishing across visibility", async () => {
		const f = await largeFixture();
		const privateKey = narKey(f.fileHash, "zstd", true);
		await env.CACHE_BUCKET.put(privateKey, f.bytes);
		await placeNar(config({ bucket: f.source, publicBucket: f.destination }), privateKey, f.fileHash, "zstd", false);
		expect(f.upload.complete).toHaveBeenCalledOnce();
		expect(f.ranges).toHaveLength(161);
		expect(await env.CACHE_BUCKET.head(privateKey)).not.toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it("aborts instead of completing when the frozen source is replaced", async () => {
		const f = await largeFixture();
		const original = f.upload.uploadPart;
		f.upload.uploadPart = vi.fn(async (number, value) => {
			const part = await original(number, value);
			await env.CACHE_BUCKET.put(f.sourceKey, f.bytes, { customMetadata: { session: f.session.id } });
			return part;
		});
		expect(await installNar(config({ bucket: f.source, publicBucket: f.destination }),
			f.sourceKey, f.fileHash, "zstd", false, f.size, f.session.id)).toContain("retry");
		expect(f.upload.complete).not.toHaveBeenCalled();
		expect(f.upload.abort).toHaveBeenCalledOnce();
		expect(await gate(f.key)).toBeUndefined();
	});

	it("keeps the gate and source on ambiguous completion, blocking a later installer", async () => {
		const f = await largeFixture();
		f.upload.complete = vi.fn(async () => { throw new Error("completion response lost"); });
		const cfg = config({ bucket: f.source, publicBucket: f.destination });
		expect(await installNar(cfg, f.sourceKey, f.fileHash, "zstd", false, f.size, f.session.id)).toContain("retry");
		expect((await gate(f.key))?.uploadId).toBe(f.upload.uploadId);
		expect(f.upload.abort).not.toHaveBeenCalled();
		expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		expect(await installNar(cfg, f.sourceKey, f.fileHash, "zstd", false, f.size, f.session.id)).toBe(INSTALLATION_BUSY);
	});

	it.each([false, true])("releases failed copy only after known abort (abort fails: %s)", async abortFails => {
		const f = await largeFixture();
		f.upload.uploadPart = vi.fn(async () => { throw new Error("part failed"); });
		if (abortFails) f.upload.abort = vi.fn(async () => { throw new Error("abort outcome unknown"); });
		expect(await installNar(config({ bucket: f.source, publicBucket: f.destination }),
			f.sourceKey, f.fileHash, "zstd", false, f.size, f.session.id)).toContain("retry");
		expect(f.upload.complete).not.toHaveBeenCalled();
		expect(f.upload.abort).toHaveBeenCalledOnce();
		expect(Boolean(await gate(f.key))).toBe(abortFails);
	});
});
