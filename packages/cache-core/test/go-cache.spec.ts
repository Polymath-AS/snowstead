import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { testDb } from "./db.js";
import { goEntries } from "../src/db/schema.js";
import { findCache, createBlobObject, createPublishedPath } from "../src/db/repository.js";
import { resolveConfig } from "../src/config.js";
import { sweepGoEntries } from "../src/go-cache.js";
import { handleRequest } from "../../../workers/go/src/router.js";

const db = testDb();
const action = "a".repeat(64);
const unique = () => `go-${crypto.randomUUID().slice(0, 8)}`;
const empty = { entries: 0, size: 0, lastAddedAt: null, retentionDays: 7 };

function api(org: string, path: string, method = "GET", body?: unknown, credential = "test-admin-secret") {
	return SELF.fetch(`http://example.com/_api/v1/orgs/${org}${path}`, { method,
		headers: { authorization: `Bearer ${credential}`, "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

async function setup(privateCache = false, name = "main") {
	const org = unique();
	expect((await api(org, "", "PUT", { slug: org })).status).toBe(200);
	expect((await api(org, "/caches", "POST", { name, private: privateCache })).status).toBe(201);
	return { org, name };
}

type Target = { org: string; name: string };
async function token(target: Target, perms = ["go:read", "go:write"], names = [target.name]) {
	const result = await api(target.org, "/tokens", "POST", { subject: "go-test", caches: names, perms });
	expect(result.status).toBe(201);
	return (await result.json<{ token: string }>()).token;
}

async function hash(body: string) {
	return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)))].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function transfer(target: Target, credential?: string, body?: string, output?: string, method = body === undefined ? "GET" : "PUT") {
	return SELF.fetch(`http://example.com/_api/v1/go/${target.org}/${target.name}/v1/actions/${action}`, {
		method, headers: { ...(credential ? { authorization: `Bearer ${credential}` } : {}),
			...(body === undefined ? {} : { "content-length": String(new TextEncoder().encode(body).length), "x-snowstead-output-id": output ?? await hash(body) }),
		}, body,
	});
}

describe("named Go caches", () => {
	it("completes a distinct upload while an earlier upload body is paused", async () => {
		const target = await setup();
		const writer = await token(target);
		const release = Promise.withResolvers<void>();
		let bodyStarted = false;
		let firstCompleted = false;
		const body = new ReadableStream<Uint8Array>({
			async pull(controller) {
				bodyStarted = true;
				await release.promise;
				controller.enqueue(new TextEncoder().encode("slow"));
				controller.close();
			},
		}, { highWaterMark: 0 });
		const config = resolveConfig(env);
		const first = handleRequest(new Request(`http://example.com/_api/v1/go/${target.org}/${target.name}/v1/actions/${action}`, {
			method: "PUT", headers: { authorization: `Bearer ${writer}`, "content-length": "4", "x-snowstead-output-id": await hash("slow") }, body,
		}), config).then(response => { firstCompleted = true; return response; });
		let second: Promise<Response> | undefined;
		try {
			// With no prefetch buffer, pull starts only after publication has
			// acquired its cache FOR SHARE and entry FOR UPDATE locks.
			await expect.poll(() => bodyStarted, { timeout: 2000 }).toBe(true);
			let secondCompleted = false;
			second = SELF.fetch(`http://example.com/_api/v1/go/${target.org}/${target.name}/v1/actions/${"b".repeat(64)}`, {
				method: "PUT", headers: { authorization: `Bearer ${writer}`, "content-length": "4", "x-snowstead-output-id": await hash("fast") }, body: "fast",
			}).then(response => { secondCompleted = true; return response; });
			await expect.poll(() => secondCompleted, { timeout: 2000 }).toBe(true);
			expect((await second).status).toBe(201);
			expect(firstCompleted).toBe(false);
			expect(await (await api(target.org, `/caches/${target.name}/go`)).json()).toMatchObject({ entries: 1, size: 4 });
		} finally {
			release.resolve();
			await Promise.allSettled([first, second]);
			await config.close();
		}
		expect((await first).status).toBe(201);
		expect(await (await api(target.org, `/caches/${target.name}/go`)).json()).toMatchObject({ entries: 2, size: 8 });
	});

	it("isolates orgs and cache names, shares visibility, and requires explicit scoped permissions", async () => {
		const a = await setup(true);
		const b = await setup(true);
		const second = { org: a.org, name: "second" };
		await api(a.org, "/caches", "POST", { name: second.name });
		const writer = await token(a);
		// A missing action must not bypass the private cache's authorization.
		for (const method of ["GET", "HEAD"]) {
			expect((await transfer(a, undefined, undefined, undefined, method)).status).toBe(401);
			expect((await transfer(a, await token(b), undefined, undefined, method)).status).toBe(403);
			expect((await transfer(a, writer, undefined, undefined, method)).status).toBe(404);
		}
		expect((await transfer(a, writer, "compiler output")).status).toBe(201);
		const read = await transfer(a, writer);
		expect(await read.text()).toBe("compiler output");
		expect(read.headers.get("cache-control")).toBe("no-store");
		// Warm hits still authenticate, including HEAD.
		expect((await transfer(a)).status).toBe(401);
		expect((await transfer(a, undefined, undefined, undefined, "HEAD")).status).toBe(401);
		expect((await transfer(a, await token(b))).status).toBe(403);
		expect((await transfer(a, await token(a, ["push", "pull"]))).status).toBe(403);
		expect((await transfer(a, await token(a, ["go:write"]))).status).toBe(403);
		expect((await transfer(a, await token(a, ["go:read"]), "new")).status).toBe(403);
		expect((await transfer(a, "test-auth-token", "new")).status).toBe(403);
		expect((await transfer(a, await token(second))).status).toBe(403);
		expect((await transfer(b, await token(b))).status).toBe(404);
		expect((await transfer(second)).status).toBe(404);
		expect((await transfer(second, writer, "new")).status).toBe(403);
		expect((await transfer(second, await token(second), "public output")).status).toBe(201);
		expect(await (await transfer(second)).text()).toBe("public output");
		const head = await transfer(second, undefined, undefined, undefined, "HEAD");
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
		expect(head.headers.get("x-snowstead-output-id")).toBe(await hash("public output"));
		// Shared visibility may change only after both protocols are empty.
		expect((await api(a.org, "/caches", "POST", { name: second.name, private: true })).status).toBe(409);
		expect((await api(a.org, "/caches", "POST", { name: a.name, private: false })).status).toBe(409);
		expect((await transfer(second)).status).toBe(200);
		await api(a.org, `/caches/${second.name}/go/reset`, "POST");
		expect((await api(a.org, "/caches", "POST", { name: second.name, private: true })).status).toBe(200);
		expect((await transfer(second)).status).toBe(401);
	});

	it.each([2, 6])("rejects an actual 4-byte stream declared as %s bytes", async length => {
		const target = await setup();
		const writer = await token(target);
		const request = new Request(`http://example.com/_api/v1/go/${target.org}/${target.name}/v1/actions/${action}`, {
			method: "PUT", headers: { authorization: `Bearer ${writer}`, "content-length": String(length), "x-snowstead-output-id": await hash("good") },
			body: new Blob(["good"]).stream(),
		});
		// Direct public router call preserves deliberately incorrect wire length;
		// SELF.fetch otherwise normalizes it before the Worker receives it.
		const config = resolveConfig(env);
		try {
			expect((await handleRequest(request, config)).status).toBe(400);
		} finally {
			await config.close();
		}
		expect((await transfer(target)).status).toBe(404);
		expect((await transfer(target, writer, "good")).status).toBe(201);
	});

	it("validates checksums, preserves immutable actions, and reports only completed real bytes", async () => {
		const target = await setup();
		const writer = await token(target);
		expect((await transfer(target, writer, "bad", await hash("good"))).status).toBe(400);
		expect(await (await api(target.org, `/caches/${target.name}/go`)).json()).toEqual(empty);
		// A bad upload must not poison the action slot or reserve its quota.
		expect((await transfer(target, writer, "good")).status).toBe(201);
		expect((await transfer(target, writer, "good")).status).toBe(204);
		expect((await transfer(target, writer, "evil", await hash("good"))).status).toBe(400);
		expect((await transfer(target, writer, "different")).status).toBe(409);
		expect(await (await transfer(target)).text()).toBe("good");
		expect(await (await api(target.org, `/caches/${target.name}/go`)).json()).toEqual({ entries: 1, size: 4, lastAddedAt: expect.any(String), retentionDays: 7 });
		const cache = await findCache(db, target.org, target.name);
		const [entry] = await db.select().from(goEntries).where(eq(goEntries.cacheId, cache!.id));
		expect(await env.PUBLIC_BUCKET.head(entry.r2Key)).toBeNull();
		expect(entry.expiresAt.getTime() - entry.uploadedAt!.getTime()).toBe(7 * 86400_000);
	});

	it("resets only its Go generation, keeps Nix and other caches, and isolates delete/recreate", async () => {
		const a = await setup();
		const b = await setup();
		const writer = await token(a);
		await transfer(a, writer, "old");
		await transfer(b, await token(b), "other");
		await (await transfer(a)).text();
		const cache = (await findCache(db, a.org, a.name))!;
		const blob = await createBlobObject(db, { fileHash: "b".repeat(64), fileSize: 9, compression: "zstd", r2Key: `nars/${unique()}` });
		await createPublishedPath(db, { cacheId: cache.id, storePathHash: "1".repeat(32), storePath: `/nix/store/${"1".repeat(32)}-kept`, narHash: `sha256:${"1".repeat(52)}`, narSize: 9, blobObjectId: blob.id, referencesJson: "[]", deriver: null, system: null, signaturesJson: "[]" });
		expect(await (await api(a.org, `/caches/${a.name}/go/reset`, "POST")).json()).toEqual(empty);
		expect((await transfer(a)).status).toBe(404);
		expect(await (await api(a.org, `/caches/${a.name}`)).json()).toMatchObject({ paths: 1, size: 9 });
		expect(await (await transfer(b)).text()).toBe("other");
		expect((await transfer(a, writer, "new")).status).toBe(201);
		expect(await (await transfer(a)).text()).toBe("new");
		expect(await sweepGoEntries(resolveConfig(env))).toBeGreaterThan(0);
		expect(await (await transfer(a)).text()).toBe("new");
		await api(a.org, `/caches/${a.name}/delete`, "POST");
		await api(a.org, "/caches", "POST", { name: a.name });
		expect((await transfer(a)).status).toBe(404);
		expect((await transfer(a, writer, "recreated")).status).toBe(403);
	});

	it("expires from upload even on warm hits and enforces shared org storage", async () => {
		const target = await setup();
		await api(target.org, "", "PUT", { storageLimit: 5 });
		const writer = await token(target);
		expect((await transfer(target, writer, "123456")).status).toBe(413);
		expect((await transfer(target, writer, "12345")).status).toBe(201);
		await (await transfer(target)).text();
		const cache = (await findCache(db, target.org, target.name))!;
		await db.update(goEntries).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(goEntries.cacheId, cache.id));
		expect((await transfer(target)).status).toBe(404);
		expect(await (await api(target.org, `/caches/${target.name}/go`)).json()).toEqual(empty);
		expect((await transfer(target, writer, "fresh")).status).toBe(201);
	});

	it("keeps private Go reads but refuses writes after the org loses private caches", async () => {
		const target = await setup(true);
		const writer = await token(target);
		expect((await transfer(target, writer, "existing")).status).toBe(201);
		await api(target.org, "", "PUT", { privateCaches: false });
		expect(await (await transfer(target, writer)).text()).toBe("existing");
		expect((await transfer(target)).status).toBe(401);
		expect((await transfer(target, writer, "existing")).status).toBe(403);
		await api(target.org, `/caches/${target.name}/go/reset`, "POST");
		expect((await transfer(target, writer, "new")).status).toBe(403);
	});

	it("returns 404 for missing orgs and caches", async () => {
		const target = await setup();
		expect((await transfer({ org: unique(), name: "main" })).status).toBe(404);
		expect((await transfer({ org: target.org, name: "missing" })).status).toBe(404);
		expect((await api(target.org, "/caches/missing/go")).status).toBe(404);
		expect((await api(target.org, "/caches/missing/go/reset", "POST")).status).toBe(404);
	});
});
