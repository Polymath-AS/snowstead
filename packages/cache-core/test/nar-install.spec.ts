import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AwsClient } from "aws4fetch";
import { eq } from "drizzle-orm";
import { resolveConfig } from "../src/config.js";
import type { WorkerConfig } from "../src/config.js";
import { createCache, createUploadSession, acquireNarInstallations, deleteEmptyCache } from "../src/db/repository.js";
import { narInstallations, uploadSessions } from "../src/db/schema.js";
import { installStagedNar, installNar, INSTALLATION_BUSY } from "../src/nar-install.js";
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

async function fixture() {
	const cache = await createCache(db, `install-${crypto.randomUUID()}`);
	const id = crypto.randomUUID();
	const bytes = crypto.getRandomValues(new Uint8Array(16));
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
		const result = installStagedNar(config({ bucket: privateBucket }), f.session);
		if (failDelete) {
			await expect(result).rejects.toThrow("storage unavailable");
			expect(await gate(f.key)).toMatchObject({ sourceKey: f.sourceKey });
			expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		} else {
			expect(await result).toBeUndefined();
			expect(await gate(f.key)).toBeUndefined();
			expect(await env.CACHE_BUCKET.head(f.sourceKey)).toBeNull();
		}
	});

	it("pins before reading, releases SQL before hashing, and retains its own stage", async () => {
		const f = await fixture();
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
		expect(await installStagedNar(cfg, f.session)).toBeUndefined();
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(f.key))!.arrayBuffer())).toEqual(f.bytes);
		expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it.each(["owner", "size", "hash"])("rejects bad staged %s even if canonical bytes already exist", async fault => {
		const f = await fixture();
		await env.PUBLIC_BUCKET.put(f.key, f.bytes, { customMetadata: { session: "canonical-owner" } });
		const before = await env.PUBLIC_BUCKET.head(f.key);
		await env.CACHE_BUCKET.put(f.sourceKey,
			fault === "size" ? new Uint8Array(1) : fault === "hash" ? new Uint8Array(16) : f.bytes,
			{ customMetadata: { session: fault === "owner" ? "someone-else" : f.session.id } });
		expect(await installStagedNar(config(), f.session)).toBe(
			fault === "owner" ? "Upload incomplete" : fault === "size" ? "File size mismatch" : "File hash mismatch",
		);
		expect((await env.PUBLIC_BUCKET.head(f.key))?.version).toBe(before?.version);
		expect(await env.CACHE_BUCKET.head(f.sourceKey)).not.toBeNull();
		expect(await gate(f.key)).toBeUndefined();
	});

	it.each([false, true])("only legacy multipart stages may omit session metadata (legacy: %s)", async legacy => {
		const f = await fixture();
		await env.CACHE_BUCKET.put(f.sourceKey, f.bytes);
		const session = { ...f.session, r2UploadId: "assembled", partSize: legacy ? null : 8 * 1024 ** 2 };
		expect(await installStagedNar(config(), session)).toBe(legacy ? undefined : "Upload incomplete");
		expect(await gate(f.key)).toBeUndefined();
	});

	it("serializes installers sharing a request without retaining a closed db handle", async () => {
		const a = await fixture();
		const b = await fixture();
		const cfg = config();
		expect(await Promise.all([installStagedNar(cfg, a.session), installStagedNar(cfg, b.session)])).toEqual([undefined, undefined]);
		expect(await gate(a.key)).toBeUndefined();
		expect(await gate(b.key)).toBeUndefined();
	});

	it("reuses canonical bytes without erasing session ownership or version", async () => {
		const f = await fixture();
		await db.insert(uploadSessions).values({ ...f.session, id: crypto.randomUUID(), r2UploadKey: f.key });
		const before = await env.PUBLIC_BUCKET.put(f.key, f.bytes, { customMetadata: { session: "old-owner" } });
		expect(await installStagedNar(config(), f.session)).toBeUndefined();
		expect(await env.PUBLIC_BUCKET.head(f.key)).toMatchObject({ version: before.version, customMetadata: { session: "old-owner" } });
	});

	it("preserves a create-only canonical PUT arriving after the absent HEAD", async () => {
		const f = await fixture();
		let arrived = false;
		const publicBucket = bucket(env.PUBLIC_BUCKET, {
			head: async key => {
				const observed = await env.PUBLIC_BUCKET.head(key);
				if (!arrived) {
					arrived = true;
					await env.PUBLIC_BUCKET.put(key, f.bytes, { customMetadata: { session: "old-owner" }, onlyIf: { etagDoesNotMatch: "*" } });
				}
				return observed;
			},
		});
		expect(await installStagedNar(config({ publicBucket }), f.session)).toBeUndefined();
		expect((await env.PUBLIC_BUCKET.head(f.key))?.customMetadata).toEqual({ session: "old-owner" });
		expect(await gate(f.key)).toBeUndefined();
	});

	it("does not read an unpinned source when another installer owns the key", async () => {
		const f = await fixture();
		expect(await acquireNarInstallations(db, [{
			key: f.key, operationId: "another-operation", sourceKey: f.sourceKey,
			fileHash: f.fileHash, compression: "zstd", isPrivate: false, fileSize: f.bytes.length,
		}])).toEqual(["another-operation"]);
		const get = vi.fn(() => { throw new Error("must not hash"); });
		expect(await installStagedNar(config({ bucket: bucket(env.CACHE_BUCKET, { get }) }), f.session)).toBe(INSTALLATION_BUSY);
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
		expect(await installStagedNar(config({ bucket: f.source, publicBucket: f.destination }),
			{ ...f.session, fileSize: f.size })).toBe(INSTALLATION_BUSY);
		expect(f.upload.uploadPart).not.toHaveBeenCalled();
		expect(f.upload.complete).not.toHaveBeenCalled();
		expect(await env.PUBLIC_BUCKET.head(f.key)).toBeNull();
	});

	it("uses guarded checksum installation for cross-visibility publication", async () => {
		const f = await fixture();
		const privateKey = narKey(f.fileHash, "zstd", true);
		await env.CACHE_BUCKET.put(privateKey, f.bytes);
		await placeNar(config(), privateKey, f.fileHash, "zstd", false);
		expect(new Uint8Array(await (await env.PUBLIC_BUCKET.get(f.key))!.arrayBuffer())).toEqual(f.bytes);
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
