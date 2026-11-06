import { env, SELF } from "cloudflare:test";
import { describe, it, expect, afterAll } from "vitest";
import { and, eq } from "drizzle-orm";
import { testDb } from "./db.js";
import { createBlobObject, createPublishedPath, ensureCache } from "../src/db/repository.js";
import { bandwidthDaily, orgs } from "../src/db/schema.js";
import { resolveConfig } from "../src/config.js";
import { importBandwidth } from "../../../workers/control/src/bandwidth.js";

const db = testDb();
const base = resolveConfig(env);
afterAll(() => base.close());
const config = {
	...base,
	analytics: { token: "tok", accountId: "acct", dataset: "test_bandwidth", publicZone: { zoneId: "zone1", host: "cache.example.com" } },
};

type AeRow = { cache: string; org: string; product: string; bytes: number | string };

/**
 * Cloudflare's two analytics APIs over fixed tables per day: the zone's
 * GraphQL HTTP analytics, paged as the real one is, and Analytics Engine SQL.
 */
function cloudflare(zone: Record<string, Record<string, number>>, engine: Record<string, AeRow[]>) {
	const zoneQueries: Record<string, string>[] = [];
	const sql: { url: string; auth: string | null; body: string }[] = [];
	const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input);
		if (url.endsWith("/analytics_engine/sql")) {
			const body = String(init?.body);
			sql.push({ url, auth: new Headers(init?.headers).get("authorization"), body });
			const day = /toDateTime\('(\d{4}-\d{2}-\d{2}) 00:00:00'\)/.exec(body)![1];
			return Response.json({ data: engine[day] ?? [] });
		}
		const { variables } = JSON.parse(String(init?.body));
		zoneQueries.push(variables);
		const page = Object.entries(zone[variables.date] ?? {})
			.filter(([path]) => path > variables.after).sort(([a], [b]) => (a < b ? -1 : 1)).slice(0, 10_000)
			.map(([clientRequestPath, edgeResponseBytes]) => ({ sum: { edgeResponseBytes }, dimensions: { clientRequestPath } }));
		return Response.json({ data: { viewer: { zones: [{ httpRequestsAdaptiveGroups: page }] } }, errors: null });
	}) as typeof fetch;
	return { zoneQueries, sql, fetcher };
}

const hex = () => crypto.randomUUID().replaceAll("-", "");

async function nar() {
	const fileHash = hex() + hex();
	return { fileHash, blob: await createBlobObject(db, { fileHash, fileSize: 100, compression: "zstd", r2Key: crypto.randomUUID() }) };
}

async function publish(cacheId: number, { blob }: Awaited<ReturnType<typeof nar>>) {
	await createPublishedPath(db, {
		cacheId, storePathHash: hex(), storePath: `/nix/store/${hex()}-x`, narHash: `sha256:${"1".repeat(52)}`, narSize: 100,
		blobObjectId: blob.id, referencesJson: "[]", deriver: null, system: null, signaturesJson: "[]",
	});
}

/** A cache's rows for a day, by product. */
async function served(cacheId: number, day: string) {
	const rows = await db.select().from(bandwidthDaily).where(and(eq(bandwidthDaily.cacheId, cacheId), eq(bandwidthDaily.day, day)));
	return Object.fromEntries(rows.map((r) => [r.product, { bytes: r.bytes, publicBytes: r.publicBytes }]));
}

describe("bandwidth import", () => {
	it("stores the Workers' bytes by cache and product, and splits the CDN's among the public caches serving each path", async () => {
		const [a, b] = [`bwa-${hex().slice(0, 8)}`, `bwb-${hex().slice(0, 8)}`];
		const moving = `bwm-${hex().slice(0, 8)}`;
		await db.insert(orgs).values([{ id: a, slug: a }, { id: b, slug: b, movingFrom: moving }]);
		const { cache: aMain } = await ensureCache(db, "main", true, a);
		const { cache: aExtra } = await ensureCache(db, "extra", true, a);
		const { cache: aSecret } = await ensureCache(db, "secret", false, a);
		const { cache: bMain } = await ensureCache(db, "main", true, b);
		const [shared, onlyB, unknown] = [await nar(), await nar(), hex() + hex()];
		// Three public caches, two of them A's: split per cache, not per org.
		for (const cache of [aMain, aExtra, bMain]) await publish(cache.id, shared);
		await publish(bMain.id, onlyB);
		// A private cache holding the same NAR doesn't share its public traffic.
		await publish(aSecret.id, onlyB);

		// Days long past, so other tests' bandwidth is not replaced.
		const now = new Date("2001-03-01T06:00:00Z");
		const [yesterday, today] = ["2001-02-28", "2001-03-01"];
		// Counted before per-cache metering: imports leave it.
		await db.insert(bandwidthDaily).values({ orgId: a, cacheId: 0, product: "nix", day: today, bytes: 5 });
		// More rows than one page holds, so the import must page through them.
		const filler = Object.fromEntries(Array.from({ length: 10_050 }, (_, i) => [`/zz-nobody/${i}.narinfo`, 1]));
		const { zoneQueries, sql, fetcher } = cloudflare({
			[yesterday]: { [`/${b}/main/nix-cache-info`]: 3 },
			[today]: {
				...filler,
				[`/nar/${shared.fileHash}/zstd.nar`]: 1200,
				[`/nar/${onlyB.fileHash}/zstd.nar`]: 400,
				// A path the analytics key by its cache's name but no cache has.
				[`/${b}/gone/nix-cache-info`]: 70,
				[`/nar/${unknown}/zstd.nar`]: 9999,
				[`/${a}/main/${hex()}.narinfo`]: 30,
				// The CDN never serves private caches; such a path is a refused probe.
				[`/${a}/secret/${hex()}.narinfo`]: 11,
				[`/${moving}/main/nix-cache-info`]: 7,
			},
		}, {
			[today]: [
				{ cache: String(aSecret.id), org: a, product: "nix", bytes: 300 },
				{ cache: String(bMain.id), org: b, product: "go", bytes: 50.4 },
				{ cache: String(bMain.id), org: b, product: "sccache", bytes: "70" },
				// Dropped: an org that no longer exists, and a product this importer doesn't know.
				{ cache: String(bMain.id), org: `gone-${hex()}`, product: "go", bytes: 5 },
				{ cache: String(aMain.id), org: a, product: "rust", bytes: 5 },
			],
		});
		const imported = await importBandwidth(config, now, fetcher);
		expect(imported).toMatchObject({ errors: [] });
		expect(imported?.imported[today]).toEqual({ workerRows: 3, publicRows: 3, unclaimedPublicBytes: 9999 + 10_050 + 70 + 11 });
		expect(sql[0]).toMatchObject({ url: "https://api.cloudflare.com/client/v4/accounts/acct/analytics_engine/sql", auth: "Bearer tok" });
		expect(sql[0].body).toContain("FROM test_bandwidth");
		expect(sql[0].body).toContain("timestamp >= toDateTime('2001-02-28 00:00:00') AND timestamp < toDateTime('2001-03-01 00:00:00')");
		expect(zoneQueries[0]).toMatchObject({ zoneTag: "zone1", host: "cache.example.com", date: yesterday, after: "" });
		expect(zoneQueries.filter((q) => q.date === today)).toHaveLength(2);

		expect(await served(aMain.id, today)).toEqual({ nix: { bytes: 0, publicBytes: 400 + 30 } });
		expect(await served(aExtra.id, today)).toEqual({ nix: { bytes: 0, publicBytes: 400 } });
		expect(await served(aSecret.id, today)).toEqual({ nix: { bytes: 300, publicBytes: 0 } });
		expect(await served(bMain.id, today)).toEqual({
			nix: { bytes: 0, publicBytes: 400 + 400 + 7 },
			go: { bytes: 50, publicBytes: 0 },
			sccache: { bytes: 70, publicBytes: 0 },
		});
		expect(await served(bMain.id, yesterday)).toEqual({ nix: { bytes: 0, publicBytes: 3 } });

		// A later import replaces each day rather than adding to it.
		await importBandwidth(config, now, cloudflare(
			{ [today]: { [`/nar/${onlyB.fileHash}/zstd.nar`]: 50 } },
			{ [today]: [{ cache: String(aSecret.id), org: a, product: "nix", bytes: 10 }] },
		).fetcher);
		expect(await served(aMain.id, today)).toEqual({ nix: { bytes: 0, publicBytes: 0 } });
		expect(await served(aSecret.id, today)).toEqual({ nix: { bytes: 10, publicBytes: 0 } });
		expect(await served(bMain.id, today)).toEqual({
			nix: { bytes: 0, publicBytes: 50 }, go: { bytes: 0, publicBytes: 0 }, sccache: { bytes: 0, publicBytes: 0 },
		});
		expect(await served(bMain.id, yesterday)).toEqual({ nix: { bytes: 0, publicBytes: 0 } });
		expect(await served(0, today)).toMatchObject({ nix: { bytes: 5 } });
	});

	it("imports the CDN's bytes even when Analytics Engine refuses, and reports why", async () => {
		const org = `bwf-${hex().slice(0, 8)}`;
		await db.insert(orgs).values({ id: org, slug: org });
		const { cache } = await ensureCache(db, "main", true, org);
		const now = new Date("2001-04-01T06:00:00Z");
		const { fetcher } = cloudflare({ "2001-04-01": { [`/${org}/main/nix-cache-info`]: 9 } }, {});
		const refusing = (async (input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith("/sql")
			? new Response("Authentication error", { status: 403 }) : fetcher(input, init)) as typeof fetch;
		const result = await importBandwidth(config, now, refusing);
		expect(result?.errors.map((e) => [e.source, e.day, String(e.error)])).toEqual([
			["workers", "2001-03-31", "Error: Analytics Engine query failed (403): Authentication error"],
			["workers", "2001-04-01", "Error: Analytics Engine query failed (403): Authentication error"],
		]);
		expect(await served(cache.id, "2001-04-01")).toEqual({ nix: { bytes: 0, publicBytes: 9 } });
	});

	it("does nothing without analytics configured", async () => {
		expect(await importBandwidth(base, new Date(), (() => { throw new Error("no calls"); }) as typeof fetch)).toBeUndefined();
	});
});

describe("bandwidth reports", () => {
	it("give this month's bytes per org and per cache, by product, with when they were imported", async () => {
		const org = `bwo-${hex().slice(0, 8)}`;
		await db.insert(orgs).values({ id: org, slug: org });
		const { cache: main } = await ensureCache(db, "main", true, org);
		const { cache: other } = await ensureCache(db, "other", true, org);
		await publish(main.id, await nar());
		await publish(main.id, await nar());
		await publish(other.id, await nar());
		const now = new Date();
		const day = now.toISOString().slice(0, 10);
		await db.insert(bandwidthDaily).values([
			{ orgId: org, cacheId: main.id, product: "nix", day, bytes: 12, publicBytes: 34, importedAt: now },
			{ orgId: org, cacheId: main.id, product: "go", day, bytes: 8 },
			{ orgId: org, cacheId: other.id, product: "sccache", day, bytes: 1 },
			{ orgId: org, cacheId: 0, product: "nix", day, bytes: 100 }, // before per-cache metering
			{ orgId: org, cacheId: main.id, product: "nix", day: "2000-01-01", bytes: 999, publicBytes: 999 }, // another month
		]);
		const get = (path: string) => SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, { headers: { authorization: "Bearer test-admin-secret" } });
		const totals = await (await get("")).json<{ bandwidthUpdatedAt: string }>();
		expect(totals).toMatchObject({
			servedThisMonth: 121, publicServedThisMonth: 34, servedThisMonthByProduct: { nix: 146, go: 8, sccache: 1 },
		});
		expect(Date.parse(totals.bandwidthUpdatedAt)).toBeGreaterThanOrEqual(now.getTime() - 1);
		expect(await (await get("/caches/main")).json()).toMatchObject({
			servedThisMonth: 20, publicServedThisMonth: 34, servedThisMonthByProduct: { nix: 46, go: 8, sccache: 0 },
		});
		const { caches } = await (await get("/caches")).json<{ caches: { name: string; servedThisMonth: number }[] }>();
		expect(caches.map((c) => [c.name, c.servedThisMonth])).toEqual([["main", 20], ["other", 1]]);
		const overview = await (await get("/overview")).json<{ caches: { name: string; servedThisMonth: number }[] }>();
		expect(overview).toMatchObject({
			id: org, used: 300, servedThisMonth: 121, publicServedThisMonth: 34,
			caches: [
				{ name: "main", paths: 2, size: 200, addedLastWeek: 2 },
				{ name: "other", paths: 1, size: 100, addedLastWeek: 1 },
			],
		});
		expect(overview.caches.map((c) => [c.name, c.servedThisMonth])).toEqual([["main", 20], ["other", 1]]);
	});
});
