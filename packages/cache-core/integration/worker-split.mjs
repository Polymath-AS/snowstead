import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { test } from "node:test";
import { Client } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { createTestHarness } from "wrangler";

test("gateway streams Nix artifacts and shares control-plane policy across real Workers", { timeout: 120_000 }, async () => {
	const database = new URL(process.env.SNOWSTEAD_TEST_DATABASE_URL);
	const name = `snowstead_split_${process.pid}`;
	const admin = new Client({ connectionString: database.toString() });
	await admin.connect();
	await admin.query(`CREATE DATABASE "${name}"`);
	database.pathname = `/${name}`;
	let server;
	try {
		const client = new Client({ connectionString: database.toString() });
		await client.connect();
		try {
			await migrate(drizzle(client), { migrationsFolder: new URL("../migrations", import.meta.url).pathname });
		} finally {
			await client.end();
		}
		process.env.CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE = database.toString();
		process.env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = "false";
		const secrets = {
			ADMIN_SECRET: "split-admin-secret",
			JWT_SECRET: "split-jwt-secret-0123456789abcdef",
			SIGNING_MASTER_KEY: "dGVzdC1zaWduaW5nLW1hc3Rlci1rZXktMzItYnl0ZXM=",
		};
		const vars = { UPSTREAM_CACHES: "", CDN_ZONE_ID: "", PUBLIC_CACHE_ORIGIN: "" };
		server = createTestHarness({
			root: new URL("../../../", import.meta.url).pathname,
			workers: [
				{ configPath: "wrangler.jsonc" },
				{ configPath: "workers/nix/wrangler.jsonc", vars, secrets },
				{ configPath: "workers/control/wrangler.jsonc", vars, secrets },
			],
		});
		const { url } = await server.listen();
		const call = (path, init) => fetch(new URL(path, url), init);
		const api = async (path, body, token = secrets.ADMIN_SECRET) => {
			const response = await call(`/_api/v1${path}`, {
				method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
				body: JSON.stringify(body),
			});
			assert.ok(response.ok, `${path}: ${response.status} ${response.ok ? "" : await response.text()}`);
			return response;
		};
		assert.equal((await call("/healthz")).status, 200);
		assert.equal((await call("/_api/v1/admin/caches")).status, 401);
		for (const [cache, privateCache] of [["open", false], ["closed", true]]) {
			const created = await api("/admin/caches", { name: cache, private: privateCache });
			assert.equal(created.status, 201);
			await created.arrayBuffer();
			const { publicKey } = await (await call(`/_api/v1/admin/caches/${cache}`, {
				headers: { authorization: `Bearer ${secrets.ADMIN_SECRET}` },
			})).json();
			const { token, jti } = await (await api("/admin/tokens", {
				subject: "split-test", caches: [cache], perms: ["push", "pull"],
			})).json();
			assert.equal(typeof token, "string");
			const bytes = randomBytes(2 * 1024 * 1024 + 7);
			const fileHash = createHash("sha256").update(bytes).digest("hex");
			const hash = (privateCache ? "b" : "a").repeat(32);
			const { sessionId, uploadMethod } = await (await api(`/caches/${cache}/upload-sessions`, {
				storePath: `/nix/store/${hash}-split`, storePathHash: hash,
				narHash: `sha256:${"1".repeat(52)}`, narSize: bytes.length, fileHash,
				fileSize: bytes.length, compression: "zstd",
			}, token)).json();
			assert.equal(uploadMethod, "direct");
			let offset = 0;
			const upload = new ReadableStream({ pull(controller) {
				if (offset === bytes.length) return controller.close();
				const end = Math.min(offset + 16 * 1024, bytes.length);
				controller.enqueue(bytes.subarray(offset, end));
				offset = end;
			} });
			assert.equal((await call(`/_api/v1/uploads/${sessionId}/blob`, {
				method: "PUT", headers: { authorization: `Bearer ${token}`, "content-length": String(bytes.length) },
				body: upload, duplex: "half",
			})).status, 200);
			await api(`/uploads/${sessionId}/complete`, {}, token);
			await api(`/uploads/${sessionId}/publish`, {}, token);
			const path = `/${privateCache ? "private/" : ""}${cache}/${hash}.narinfo`;
			const headers = { authorization: `Bearer ${token}` };
			const info = await call(path, { headers });
			assert.equal(info.status, 200);
			const narinfo = await info.text();
			assert.ok(narinfo.includes(`Sig: ${publicKey.split(":")[0]}:`));
			const relative = /^URL: (.+)$/m.exec(narinfo)[1];
			const artifactUrl = new URL(relative, new URL(path, url));
			for (let pass = 0; pass < 2; pass++) {
				const response = await fetch(artifactUrl, { headers });
				assert.equal(response.status, 200);
				assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
			}
			const head = await fetch(artifactUrl, { method: "HEAD", headers });
			assert.equal(head.status, 200);
			assert.equal(Number(head.headers.get("content-length")), bytes.length);
			assert.equal((await head.arrayBuffer()).byteLength, 0);
			assert.equal((await call(path)).status, privateCache ? 401 : 200);
			if (privateCache) {
				assert.equal((await fetch(artifactUrl)).status, 401);
				await api(`/admin/tokens/${jti}/revoke`, { reason: "worker split regression" });
				// Revocation misses are cached for 30 seconds in each isolate and KV.
				await new Promise(resolve => setTimeout(resolve, 31_000));
				assert.equal((await call(path, { headers })).status, 401);
				assert.equal((await fetch(artifactUrl, { headers })).status, 401);
			}
		}
		// Each service rejects the other service's routes even when called directly.
		assert.equal((await server.getWorker("snowstead-nix").fetch("http://test/_api/v1/admin/caches")).status, 404);
		assert.equal((await server.getWorker("snowstead-control").fetch("http://test/open/nix-cache-info")).status, 404);
	} catch (error) {
		console.error(server?.getLogs());
		throw error;
	} finally {
		await server?.close();
		await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
		await admin.end();
	}
});
