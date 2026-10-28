import { env } from "cloudflare:test";
import { afterAll, describe, expect, it } from "vitest";
import { and, eq, sql } from "drizzle-orm";
import { resolveConfig, type WorkerConfig } from "../src/config.js";
import { createCache, createBlobObject, createPublishedPath, findPublishedPath } from "../src/db/repository.js";
import { publicationCaches, publicationJobs, publicationPins, publicationRevisions, publicationPaths, caches, blobObjects, publishedPaths } from "../src/db/schema.js";
import {
	initializePublicationCache, publishPublication, recoverPublication, withdrawPublications,
	changePublicationVisibility, retirePublicationCache, collectRetiredPublications, repairLegacyPublicationWitness, readPublicationCache,
	beginPublicationBackfill, backfillPublicationBatch, finishPublicationBackfill,
} from "../src/publications.js";
import { grantKey, statusKey, publicationKey, publicationUrl, witnessKey } from "../src/publication-protocol.js";
import type { NarinfoPath } from "../src/narinfo.js";

const connections: WorkerConfig[] = [];
function config(): WorkerConfig { const value = resolveConfig(env); connections.push(value); return value; }
afterAll(async () => { await Promise.all(connections.map((value) => value.close())); });

function wrapped(bucket: R2Bucket, overrides: Partial<Pick<R2Bucket, "put" | "delete">>): R2Bucket {
	return new Proxy(bucket, { get(target, property) {
		if (property in overrides) return overrides[property as keyof typeof overrides];
		const value = Reflect.get(target, property);
		return typeof value === "function" ? value.bind(target) : value;
	} });
}
function deferred() {
	let resolve!: () => void;
	const promise = new Promise<void>((done) => { resolve = done; });
	return { promise, resolve };
}
function path(hash = "0".repeat(32)): NarinfoPath {
	return { storePathHash: hash, storePath: `/nix/store/${hash}-fixture`, narHash: `sha256:${"0".repeat(52)}`, narSize: 123,
		referencesJson: "[]", signaturesJson: "[]", deriver: null, system: null };
}
async function fixture() {
	const cfg = config();
	const cache = await createCache(cfg.db, `pub-${crypto.randomUUID()}`);
	const body = `canonical-${crypto.randomUUID()}`;
	const fileHash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
	const blob = await createBlobObject(cfg.db, { fileHash, fileSize: body.length, compression: "none", r2Key: `nars/sha256/${fileHash}/none.nar` });
	await env.CACHE_BUCKET.put(blob.r2Key, body);
	return { cfg, cache, blob, body, path: path() };
}
async function activeFixture() {
	const data = await fixture();
	expect((await initializePublicationCache(data.cfg, data.cache)).state).toBe("active");
	return data;
}

describe("durable publication control", () => {
	it("only explicitly initializes verified empty caches, and refuses populated legacy caches", async () => {
		const data = await fixture();
		await createPublishedPath(data.cfg.db, { ...data.path, cacheId: data.cache.id, blobObjectId: data.blob.id });
		expect((await initializePublicationCache(data.cfg, data.cache)).state).toBe("inactive");
		expect(await env.CACHE_BUCKET.head(statusKey(data.cache.id))).toBeNull();
		expect((await publishPublication(data.cfg, data.cache, data.path, data.blob)).state).toBe("inactive");
	});

	it("verifies immutable copies, persists signed final-URL narinfo, and atomically finalizes membership/pins", async () => {
		const data = await activeFixture();
		const result = await publishPublication(data.cfg, data.cache, data.path, data.blob);
		expect(result.state).toBe("active");
		if (result.state !== "active") throw new Error("not active");
		expect(result.alreadyExisted).toBe(false);
		const bucket = data.cache.isPublic ? env.PUBLIC_BUCKET : env.CACHE_BUCKET;
		expect(await (await bucket.get(publicationKey(result.grant, "nar")))!.text()).toBe(data.body);
		const narinfo = await (await bucket.get(publicationKey(result.grant, "narinfo")))!.text();
		expect(narinfo).toContain(`URL: ${publicationUrl(result.grant)}\n`);
		expect(narinfo).toContain("Sig: snowstead-1:");
		expect((await bucket.head(publicationKey(result.grant, "nar")))!.checksums.sha256).toBeDefined();
		expect((await findPublishedPath(data.cfg.db, data.cache.id, data.path.storePathHash))!.blobObjectId).toBe(data.blob.id);
		const pins = await data.cfg.db.select().from(publicationPins).where(eq(publicationPins.revisionId, result.grant.publicationId));
		expect(pins.map((pin) => pin.kind)).toEqual(["active"]);
		const statusBefore = await (await env.CACHE_BUCKET.get(statusKey(data.cache.id)))!.text();
		const again = await publishPublication(config(), data.cache, data.path, { ...data.blob, fileHash: "1".repeat(64) });
		expect(again.state).toBe("active");
		if (again.state !== "active") throw new Error("not active");
		expect(again.alreadyExisted).toBe(true);
		expect(again.grant).toEqual(result.grant);
		expect(await (await env.CACHE_BUCKET.get(statusKey(data.cache.id)))!.text()).toBe(statusBefore);
	});

	it("concurrent ordinary publishes converge without issuing duplicate immutable copies", async () => {
		const data = await activeFixture();
		const [a, b] = await Promise.all([publishPublication(data.cfg, data.cache, data.path, data.blob), publishPublication(config(), data.cache, data.path, data.blob)]);
		const result = await publishPublication(config(), data.cache, data.path, data.blob);
		expect(result.state).toBe("active");
		if (result.state !== "active") throw new Error("not active");
		for (const previous of [a, b]) if (previous.state === "active") expect(previous.grant.publicationId).toBe(result.grant.publicationId);
		const revisions = await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.cacheId, data.cache.id));
		expect(revisions).toHaveLength(1);
	});

	it("recovers a missing canonical source without treating an undispatched copy as an unknown PUT", async () => {
		const data = await activeFixture();
		await env.CACHE_BUCKET.delete(data.blob.r2Key);
		const result = await publishPublication(data.cfg, data.cache, data.path, data.blob);
		expect(result.state).toBe("pending");
		await env.CACHE_BUCKET.put(data.blob.r2Key, data.body);
		const recovered = await publishPublication(config(), data.cache, data.path, data.blob);
		expect(recovered.state).toBe("active");
		if (recovered.state !== "active") throw new Error("not recovered");
		expect(await (await env.PUBLIC_BUCKET.get(publicationKey(recovered.grant, "nar")))!.text()).toBe(data.body);
	});

	it("rejects changed canonical bytes even when the size matches", async () => {
		const data = await activeFixture();
		await env.CACHE_BUCKET.put(data.blob.r2Key, "x".repeat(data.body.length));
		const result = await publishPublication(data.cfg, data.cache, data.path, data.blob);
		expect(result.state).toBe("pending");
		expect(await findPublishedPath(data.cfg.db, data.cache.id, data.path.storePathHash)).toBeUndefined();
		const [rev] = await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.cacheId, data.cache.id));
		expect(await env.PUBLIC_BUCKET.head(rev!.narKey)).toBeNull();
		expect((await data.cfg.db.select().from(publicationPins).where(eq(publicationPins.revisionId, rev!.id))).map((pin) => pin.kind)).toEqual(["prepared"]);
	});

	it("keeps unknown absent immutable PUTs pinned and never redispatches them", async () => {
		const data = await activeFixture();
		let sends = 0;
		const bucket = wrapped(env.PUBLIC_BUCKET, { put: async (...args) => {
			if (args[0].startsWith("v2/")) { sends++; throw new Error("unknown upload"); }
			return env.PUBLIC_BUCKET.put(...args);
		} });
		const altered = { ...data.cfg, publicBucket: bucket };
		const result = await publishPublication(altered, data.cache, data.path, data.blob);
		expect(result.state).toBe("pending");
		if (result.state !== "pending") throw new Error("not pending");
		expect((await recoverPublication(config(), result.operationId)).state).toBe("pending");
		expect(sends).toBe(1);
		const [job] = await data.cfg.db.select().from(publicationJobs).where(eq(publicationJobs.id, result.operationId));
		expect((await data.cfg.db.select().from(publicationPins).where(eq(publicationPins.revisionId, job!.revisionId))).map((pin) => pin.kind)).toEqual(["prepared"]);
		await expect(changePublicationVisibility(config(), data.cache, !data.cache.isPublic)).rejects.toThrow("empty");
		expect((await retirePublicationCache(config(), data.cache)).state).toBe("retiring");
		expect((await publishPublication(config(), data.cache, path("1".repeat(32)), data.blob)).state).toBe("inactive");
	});

	it("recovers a committed immutable PUT whose response was lost without sending another PUT", async () => {
		const data = await activeFixture();
		let sends = 0;
		const bucket = wrapped(env.PUBLIC_BUCKET, { put: async (...args) => {
			sends++; await env.PUBLIC_BUCKET.put(...args); throw new Error("lost immutable response");
		} });
		const result = await publishPublication({ ...data.cfg, publicBucket: bucket }, data.cache, data.path, data.blob);
		expect(result.state).toBe("pending");
		if (result.state !== "pending") throw new Error("not pending");
		expect((await recoverPublication(config(), result.operationId)).state).toBe("done");
		expect(sends).toBe(1);
	});

	it("withdrawal fences delayed grant activation, then GC retries only retired keys", async () => {
		const data = await activeFixture();
		const entered = deferred(), release = deferred();
		let delayed: R2Object | null | undefined;
		const bucket = wrapped(env.CACHE_BUCKET, { put: async (...args) => {
			if (args[0].startsWith("authority/v2/grants/")) {
				entered.resolve(); await release.promise;
				delayed = await env.CACHE_BUCKET.put(...args); return delayed;
			}
			return env.CACHE_BUCKET.put(...args);
		} });
		const publishing = publishPublication({ ...data.cfg, bucket }, data.cache, data.path, data.blob);
		await entered.promise;
		const withdrawal = await withdrawPublications(config(), data.cache, [data.path.storePathHash]);
		expect(withdrawal.pending).toEqual([]);
		expect(withdrawal.withdrawn).toEqual([data.path.storePathHash]);
		release.resolve();
		await publishing;
		expect(delayed).toBeNull();
		const [rev] = await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.cacheId, data.cache.id));
		expect(rev!.state).toBe("retired");
		expect(await findPublishedPath(data.cfg.db, data.cache.id, data.path.storePathHash)).toBeUndefined();
		const throwing = wrapped(env.PUBLIC_BUCKET, { delete: async () => { throw new Error("lost DELETE"); } });
		await collectRetiredPublications({ ...config(), publicBucket: throwing });
		expect((await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.id, rev!.id)))[0]!.state).toBe("deleting");
		await collectRetiredPublications(config());
		expect(await env.PUBLIC_BUCKET.head(rev!.narKey)).toBeNull();
		expect(await env.CACHE_BUCKET.head(grantKey(data.cache.id, rev!.epoch, data.path.storePathHash))).not.toBeNull();
	});

	it("records accepted-then-withdrawn when activation wins despite a lost response", async () => {
		const data = await activeFixture();
		const bucket = wrapped(env.CACHE_BUCKET, { put: async (...args) => {
			await env.CACHE_BUCKET.put(...args);
			if (args[0].startsWith("authority/v2/grants/")) throw new Error("lost grant response");
			return env.CACHE_BUCKET.head(args[0]);
		} });
		const result = await publishPublication({ ...data.cfg, bucket }, data.cache, data.path, data.blob);
		expect(result.state).toBe("pending");
		const withdrawal = await withdrawPublications(config(), data.cache, [data.path.storePathHash]);
		expect(withdrawal.pending).toEqual([]);
		const history = await data.cfg.db.select().from(publicationJobs).where(eq(publicationJobs.cacheId, data.cache.id));
		expect(history.find((job) => job.kind === "publish")!.state).toBe("done");
		expect(history.find((job) => job.kind === "withdraw")!.state).toBe("done");
	});

	it("retains prepared pins and the path barrier when SQL finalization fails after accepted activation", async () => {
		const data = await activeFixture();
		const name = `publication_fault_${crypto.randomUUID().replaceAll("-", "")}`;
		await data.cfg.db.execute(sql.raw(`CREATE FUNCTION ${name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected finalization failure'; END $$`));
		await data.cfg.db.execute(sql.raw(`CREATE TRIGGER ${name} BEFORE INSERT ON published_paths FOR EACH ROW WHEN (NEW.cache_id = ${data.cache.id}) EXECUTE FUNCTION ${name}()`));
		try {
			await expect(publishPublication(data.cfg, data.cache, data.path, data.blob)).rejects.toThrow();
			const [job] = await data.cfg.db.select().from(publicationJobs).where(eq(publicationJobs.cacheId, data.cache.id));
			const [rev] = await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.cacheId, data.cache.id));
			expect(job!.state).toBe("pending");
			expect(rev!.state).toBe("prepared");
			expect((await data.cfg.db.select().from(publicationPins).where(eq(publicationPins.revisionId, rev!.id))).map((pin) => pin.kind)).toEqual(["prepared"]);
			expect(await env.CACHE_BUCKET.head(grantKey(data.cache.id, job!.epoch, data.path.storePathHash))).not.toBeNull();
			await expect(changePublicationVisibility(config(), data.cache, false)).rejects.toThrow("empty");
		} finally {
			await data.cfg.db.execute(sql.raw(`DROP TRIGGER ${name} ON published_paths`));
			await data.cfg.db.execute(sql.raw(`DROP FUNCTION ${name}()`));
		}
		const result = await publishPublication(config(), data.cache, data.path, data.blob);
		expect(result.state).toBe("active");
		if (result.state !== "active") throw new Error("not active");
		expect((await data.cfg.db.select().from(publicationPins).where(eq(publicationPins.revisionId, result.grant.publicationId))).map((pin) => pin.kind)).toEqual(["active"]);
	});

	it("changes visibility only after emptiness, uses a fresh epoch, and permanently retires caches", async () => {
		const data = await activeFixture();
		const published = await publishPublication(data.cfg, data.cache, data.path, data.blob);
		expect(published.state).toBe("active");
		await expect(changePublicationVisibility(config(), data.cache, false)).rejects.toThrow("empty");
		const initial = (await data.cfg.db.select().from(publicationCaches).where(eq(publicationCaches.cacheId, data.cache.id)))[0]!;
		await withdrawPublications(config(), data.cache, [data.path.storePathHash]);
		const changed = await changePublicationVisibility(config(), data.cache, false);
		expect(changed.state).toBe("active");
		expect(changed.epoch).not.toBe(initial.epoch);
		expect(changed.isPublic).toBe(false);
		const result = await publishPublication(config(), data.cache, data.path, data.blob);
		expect(result.state).toBe("active");
		if (result.state !== "active") throw new Error("not active");
		expect(await env.CACHE_BUCKET.head(publicationKey(result.grant, "nar"))).not.toBeNull();
		expect((await retirePublicationCache(config(), data.cache)).state).toBe("retired");
		expect((await initializePublicationCache(config(), data.cache)).state).toBe("retired");
		expect((await publishPublication(config(), data.cache, data.path, data.blob)).state).toBe("inactive");
		await data.cfg.db.delete(caches).where(eq(caches.id, data.cache.id));
		await data.cfg.db.delete(blobObjects).where(eq(blobObjects.id, data.blob.id));
		expect((await readPublicationCache(config(), data.cache.id))!.state).toBe("retired");
		expect(await env.CACHE_BUCKET.head(statusKey(data.cache.id))).not.toBeNull();
		expect(await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.cacheId, data.cache.id))).toHaveLength(2);
	});

	it("same-byte paths own separate revisions and legacy witnesses repair to a surviving path", async () => {
		const data = await activeFixture();
		const a = await publishPublication(data.cfg, data.cache, data.path, data.blob);
		const other = path("1".repeat(32));
		const b = await publishPublication(config(), data.cache, other, data.blob);
		if (a.state !== "active" || b.state !== "active") throw new Error("not active");
		expect(a.grant.publicationId).not.toBe(b.grant.publicationId);
		await withdrawPublications(config(), data.cache, [data.path.storePathHash]);
		expect(await repairLegacyPublicationWitness(config(), data.cache.id, data.blob.fileHash, data.blob.compression)).toBe("ready");
		const witness = await (await env.CACHE_BUCKET.get(witnessKey(data.cache.id, b.grant.epoch, data.blob.fileHash, data.blob.compression)))!.json<{ publicationId: string }>();
		expect(witness.publicationId).toBe(b.grant.publicationId);
		await collectRetiredPublications(config());
		expect(await env.PUBLIC_BUCKET.head(publicationKey(a.grant, "nar"))).toBeNull();
		expect(await env.PUBLIC_BUCKET.head(publicationKey(b.grant, "nar"))).not.toBeNull();
		expect((await data.cfg.db.select().from(publicationPaths).where(and(eq(publicationPaths.cacheId, data.cache.id), eq(publicationPaths.storePathHash, other.storePathHash))))[0]!.activeRevision).toBe(b.grant.publicationId);
	});
});

async function legacyFixture(count = 1) {
	const data = await fixture();
	for (let index = 0; index < count; index++) {
		await createPublishedPath(data.cfg.db, { ...path(String(index).repeat(32)), cacheId: data.cache.id, blobObjectId: data.blob.id });
	}
	// Preserve the database's full microsecond precision, not just JS Date's ms.
	await data.cfg.db.update(publishedPaths).set({ createdAt: sql`'2024-01-02 03:04:05.123456+00'::timestamptz`,
		lastPushedAt: sql`'2025-02-03 04:05:06.654321+00'::timestamptz`, system: "x86_64-linux" }).where(eq(publishedPaths.cacheId, data.cache.id));
	return data;
}

async function authorityStatus(cacheId: number) {
	return (await env.CACHE_BUCKET.get(statusKey(cacheId)))!.json<{ state: string; epoch: string; operationId: string }>();
}

describe("explicit bounded legacy publication backfill", () => {
	it("keeps status draining through bounded copies, preserves all memberships/timestamps, then explicitly activates", async () => {
		const data = await legacyFixture(3);
		const original = await data.cfg.db.select({ row: publishedPaths, created: sql<string>`${publishedPaths.createdAt}::text`,
			pushed: sql<string>`${publishedPaths.lastPushedAt}::text` }).from(publishedPaths).where(eq(publishedPaths.cacheId, data.cache.id)).orderBy(publishedPaths.id);
		expect((await initializePublicationCache(data.cfg, data.cache)).state).toBe("inactive");
		const started = await beginPublicationBackfill(config(), data.cache);
		expect(started.state).toBe("migrating");
		expect((await authorityStatus(data.cache.id)).state).toBe("draining");
		expect((await publishPublication(config(), data.cache, data.path, data.blob)).state).toBe("inactive");
		await expect(withdrawPublications(config(), data.cache, [data.path.storePathHash])).rejects.toThrow("inactive");
		await expect(changePublicationVisibility(config(), data.cache, false)).rejects.toThrow("pending");
		await expect(retirePublicationCache(config(), data.cache)).rejects.toThrow("transition");
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("migrating");
		for (let index = 0; index < 3; index++) {
			expect(await backfillPublicationBatch(config(), data.cache, 1)).toEqual({ state: "migrating", processed: 1, pending: 0 });
			expect((await authorityStatus(data.cache.id)).state).toBe("draining");
			if (index < 2) expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("migrating");
		}
		const after = await data.cfg.db.select({ row: publishedPaths, created: sql<string>`${publishedPaths.createdAt}::text`,
			pushed: sql<string>`${publishedPaths.lastPushedAt}::text` }).from(publishedPaths).where(eq(publishedPaths.cacheId, data.cache.id)).orderBy(publishedPaths.id);
		expect(after).toEqual(original);
		const jobs = await data.cfg.db.select().from(publicationJobs).where(eq(publicationJobs.cacheId, data.cache.id));
		expect(jobs).toHaveLength(3);
		expect(jobs.every((job) => job.kind === "backfill" && job.state === "done" && job.witnessReady)).toBe(true);
		const grant = JSON.parse(jobs[0]!.grantBytes!);
		expect(grant.publishedAt).toBe(Math.floor(original[0]!.row.createdAt.getTime() / 1000));
		expect(await (await env.PUBLIC_BUCKET.get(publicationKey(grant, "narinfo")))!.text()).toContain(`URL: ${publicationUrl(grant)}\n`);
		const complete = await finishPublicationBackfill(config(), data.cache);
		expect(complete.state).toBe("active");
		expect(complete.epoch).toBe(started.epoch);
		expect((await authorityStatus(data.cache.id)).state).toBe("active");
		const repeated = await publishPublication(config(), data.cache, path(grant.storePathHash), data.blob);
		expect(repeated).toEqual({ state: "active", alreadyExisted: true, grant });
		expect((await withdrawPublications(config(), data.cache, [grant.storePathHash])).pending).toEqual([]);
	});

	it("reconciles a lost drain response before allocating any copy", async () => {
		const data = await legacyFixture();
		const bucket = wrapped(env.CACHE_BUCKET, { put: async (...args) => { await env.CACHE_BUCKET.put(...args); throw new Error("lost drain response"); } });
		await beginPublicationBackfill({ ...data.cfg, bucket }, data.cache);
		const draining = await authorityStatus(data.cache.id);
		expect(draining.state).toBe("draining");
		expect(await data.cfg.db.select().from(publicationJobs).where(eq(publicationJobs.cacheId, data.cache.id))).toHaveLength(0);
		expect((await backfillPublicationBatch(config(), data.cache, 1)).pending).toBe(0);
		expect((await authorityStatus(data.cache.id)).operationId).toBe(draining.operationId);
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("active");
	});

	it("duplicate drivers cannot resend a delayed immutable copy or activate early", async () => {
		const data = await legacyFixture();
		await beginPublicationBackfill(data.cfg, data.cache);
		const entered = deferred(), release = deferred();
		let copies = 0;
		const publicBucket = wrapped(env.PUBLIC_BUCKET, { put: async (...args) => {
			if (args[0].endsWith("/nar")) { copies++; entered.resolve(); await release.promise; }
			return env.PUBLIC_BUCKET.put(...args);
		} });
		const first = backfillPublicationBatch({ ...data.cfg, publicBucket }, data.cache, 1);
		await entered.promise;
		expect((await backfillPublicationBatch(config(), data.cache, 1)).pending).toBe(1);
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("migrating");
		expect((await authorityStatus(data.cache.id)).state).toBe("draining");
		release.resolve();
		expect((await first).pending).toBe(0);
		expect(copies).toBe(1);
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("active");
	});

	it("keeps unknown absent copy outcomes pinned, leaves membership untouched, and refuses cutover", async () => {
		const data = await legacyFixture();
		await beginPublicationBackfill(data.cfg, data.cache);
		const publicBucket = wrapped(env.PUBLIC_BUCKET, { put: async () => { throw new Error("unknown immutable PUT"); } });
		expect((await backfillPublicationBatch({ ...data.cfg, publicBucket }, data.cache, 1)).pending).toBe(1);
		expect((await backfillPublicationBatch(config(), data.cache, 1)).pending).toBe(1);
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("migrating");
		const [job] = await data.cfg.db.select().from(publicationJobs).where(eq(publicationJobs.cacheId, data.cache.id));
		expect((await data.cfg.db.select().from(publicationPins).where(eq(publicationPins.revisionId, job!.revisionId))).map((pin) => pin.kind)).toEqual(["prepared"]);
		expect((await authorityStatus(data.cache.id)).state).toBe("draining");
		expect(await findPublishedPath(data.cfg.db, data.cache.id, data.path.storePathHash)).toBeDefined();
	});

	it("requires durable compatibility-witness completion after unknown accepted grant and witness PUTs", async () => {
		const data = await legacyFixture();
		await beginPublicationBackfill(data.cfg, data.cache);
		const grantLoss = wrapped(env.CACHE_BUCKET, { put: async (...args) => {
			const result = await env.CACHE_BUCKET.put(...args);
			if (args[0].startsWith("authority/v2/grants/")) throw new Error("lost grant response");
			return result;
		} });
		expect((await backfillPublicationBatch({ ...config(), bucket: grantLoss }, data.cache, 1)).pending).toBe(1);
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("migrating");
		const witnessLoss = wrapped(env.CACHE_BUCKET, { put: async (...args) => {
			const result = await env.CACHE_BUCKET.put(...args);
			if (args[0].startsWith("authority/v2/legacy/")) throw new Error("lost witness response");
			return result;
		} });
		expect((await backfillPublicationBatch({ ...config(), bucket: witnessLoss }, data.cache, 1)).pending).toBe(1);
		const [job] = await data.cfg.db.select().from(publicationJobs).where(eq(publicationJobs.cacheId, data.cache.id));
		expect(job!.state).toBe("done");
		expect(job!.witnessReady).toBe(false);
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("migrating");
		expect((await authorityStatus(data.cache.id)).state).toBe("draining");
		expect((await backfillPublicationBatch(config(), data.cache, 1)).pending).toBe(0);
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("active");
		expect(await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.cacheId, data.cache.id))).toHaveLength(1);
	});

	it("detects even sub-millisecond membership mutation and freezes cutover", async () => {
		const data = await legacyFixture();
		await beginPublicationBackfill(data.cfg, data.cache);
		await backfillPublicationBatch(config(), data.cache, 1);
		await data.cfg.db.update(publishedPaths).set({ lastPushedAt: sql`${publishedPaths.lastPushedAt} + interval '1 microsecond'` }).where(eq(publishedPaths.cacheId, data.cache.id));
		await expect(finishPublicationBackfill(config(), data.cache)).rejects.toThrow("membership changed");
		expect((await authorityStatus(data.cache.id)).state).toBe("draining");
	});

	it("retries final activation response loss without new epochs, commands, or copies", async () => {
		const data = await legacyFixture();
		const started = await beginPublicationBackfill(data.cfg, data.cache);
		await backfillPublicationBatch(config(), data.cache, 1);
		const bucket = wrapped(env.CACHE_BUCKET, { put: async (...args) => {
			const result = await env.CACHE_BUCKET.put(...args);
			if (args[0] === statusKey(data.cache.id)) throw new Error("lost activation response");
			return result;
		} });
		expect((await finishPublicationBackfill({ ...config(), bucket }, data.cache)).state).toBe("migrating");
		const activated = await authorityStatus(data.cache.id);
		expect(activated.state).toBe("active");
		expect((await publishPublication(config(), data.cache, data.path, data.blob)).state).toBe("inactive");
		expect((await finishPublicationBackfill(config(), data.cache)).state).toBe("active");
		expect((await authorityStatus(data.cache.id)).operationId).toBe(activated.operationId);
		expect((await readPublicationCache(config(), data.cache.id))!.epoch).toBe(started.epoch);
		expect(await data.cfg.db.select().from(publicationRevisions).where(eq(publicationRevisions.cacheId, data.cache.id))).toHaveLength(1);
	});
});
