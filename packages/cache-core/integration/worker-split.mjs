import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { test } from "node:test";
import { Client } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { createTestHarness } from "wrangler";

test("gateway streams Nix and Go artifacts and shares control-plane policy across real Workers", { timeout: 120_000 }, async () => {
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
				{ configPath: "workers/go/wrangler.jsonc", vars, secrets },
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
		const post = (path, body) => call(`/_api/v1${path}`, {
			method: "POST", headers: { authorization: `Bearer ${secrets.ADMIN_SECRET}`, "content-type": "application/json" },
			body: JSON.stringify(body),
		});
		for (const protocols of [undefined, [], ["ruby"], ["nix", "nix"]]) {
			assert.equal((await post("/admin/caches", { name: "invalid-choice", protocols })).status, 400);
		}
		for (const privateCache of [false, true]) {
			for (const protocol of ["nix", "go"]) {
				const name = `${protocol}-${privateCache ? "private" : "public"}`;
				const created = await api("/admin/caches", { name, private: privateCache, protocols: [protocol] });
				assert.deepEqual((await created.json()).protocols, [protocol]);
				const { token } = await (await api("/admin/tokens", {
					subject: "protocol-policy", caches: [name], perms: ["push", "pull", "go:read", "go:write"],
				})).json();
				const headers = { authorization: `Bearer ${token}` };
				const nix = `/${privateCache ? "private/" : ""}${name}`;
				const go = `/_api/v1/go/default/${name}/v1/actions/${"d".repeat(64)}`;
				const data = Buffer.from(`output for ${name}`);
				const goHeaders = { ...headers, "x-snowstead-output-id": createHash("sha256").update(data).digest("hex") };
				const put = () => call(go, { method: "PUT", headers: goHeaders, body: data });
				for (const method of ["GET", "HEAD"]) {
					assert.equal((await call(`${nix}/nix-cache-info`, { method, headers })).status, protocol === "nix" ? 200 : 404);
					const admitted = await call(`${nix}/nix-cache-info`, { method, headers: { ...headers, "x-snowstead-cdn-read": "1" } });
					assert.equal(admitted.status, protocol !== "nix" ? 404 : privateCache ? 200 : 204);
					assert.equal(admitted.headers.get("x-snowstead-cdn-read"), protocol === "nix" && !privateCache ? "1" : null);
					await admitted.arrayBuffer();
					assert.equal((await call(go, { method, headers })).status, 404);
				}
				assert.equal((await put()).status, protocol === "go" ? 201 : 404);
				if (protocol === "go") {
					assert.equal((await call(go, { headers })).status, 200);
					assert.equal((await call(`${nix}/${"e".repeat(32)}.narinfo`, { headers })).status, 404);
					const session = { storePath: `/nix/store/${"a".repeat(32)}-disabled`, storePathHash: "a".repeat(32),
						narHash: `sha256:${"1".repeat(52)}`, narSize: data.length, fileHash: "f".repeat(64), fileSize: data.length, compression: "zstd" };
					for (const [path, body] of [[`/caches/${name}/upload-sessions`, session], [`/caches/${name}/upload-sessions/batch`, { paths: [session] }], ["/get-missing-paths", { cache: name, storePathHashes: ["a".repeat(32)] }]]) {
						const response = await call(`/_api/v1${path}`, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) });
						assert.equal(response.status, 404, path);
					}
				}
				// Omitted protocols on a settings update never enable another product.
				assert.deepEqual((await (await api("/admin/caches", { name, retentionDays: 14 })).json()).protocols, [protocol]);
				await api("/admin/caches", { name, protocols: ["nix", "go"] });
				assert.equal((await call(`${nix}/nix-cache-info`, { headers })).status, 200);
				assert.equal((await put()).status, protocol === "go" ? 204 : 201);
				assert.equal((await post("/admin/caches", { name, protocols: [protocol] })).status, 409);
				const listed = await (await call(`/_api/v1/admin/caches/${name}`, { headers: { authorization: `Bearer ${secrets.ADMIN_SECRET}` } })).json();
				assert.deepEqual(listed.protocols, ["nix", "go"]);
			}
		}
		for (const [cache, privateCache] of [["open", false], ["closed", true]]) {
			const created = await api("/admin/caches", { name: cache, private: privateCache, protocols: ["nix", "go"] });
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
			const scopedNar = `/${privateCache ? "private/" : ""}${cache}/nar/${fileHash}/zstd.nar`;
			for (const method of ["GET", "HEAD"]) {
				for (const resource of [path, scopedNar]) {
					const response = await call(resource, { method, headers: { ...headers, "x-snowstead-cdn-read": "1" } });
					assert.equal(response.status, privateCache ? 200 : 204);
					assert.equal(response.headers.get("x-snowstead-cdn-read"), privateCache ? null : "1");
					if (!privateCache) assert.equal(response.headers.get("cache-control"), "no-store");
					const body = Buffer.from(await response.arrayBuffer());
					assert.deepEqual(body, !privateCache || method === "HEAD" ? Buffer.alloc(0) : resource === path ? Buffer.from(narinfo) : bytes);
				}
			}
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
			const { token: goToken } = await (await api("/admin/tokens", {
				subject: "go-split-test", caches: [cache], perms: ["go:read", "go:write"],
			})).json();
			const goPath = `/_api/v1/go/default/${cache}/v1/actions/${"c".repeat(64)}`;
			const goHeaders = { authorization: `Bearer ${goToken}`, "x-snowstead-output-id": fileHash };
			assert.equal((await call(goPath, { method: "PUT", headers: { ...goHeaders, authorization: `Bearer ${token}` }, body: bytes })).status, 403);
			assert.equal((await call(goPath, { method: "PUT", headers: goHeaders, body: bytes })).status, 201);
			assert.equal((await call(goPath, { method: "PUT", headers: goHeaders, body: bytes })).status, 204);
			for (let pass = 0; pass < 2; pass++) {
				const response = await call(goPath, { headers: goHeaders });
				assert.equal(response.status, 200);
				assert.equal(response.headers.get("x-snowstead-output-id"), fileHash);
				assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
			}
			const goAnonymous = await call(goPath);
			assert.equal(goAnonymous.status, privateCache ? 401 : 200);
			await goAnonymous.arrayBuffer();
			const goHead = await call(goPath, { method: "HEAD", headers: goHeaders });
			assert.equal(goHead.status, 200);
			assert.equal(Number(goHead.headers.get("content-length")), bytes.length);
			assert.equal((await goHead.arrayBuffer()).byteLength, 0);
			const management = `/_api/v1/orgs/default/caches/${cache}/go`;
			const totals = await (await call(management, { headers: { authorization: `Bearer ${secrets.ADMIN_SECRET}` } })).json();
			assert.equal(totals.entries, 1);
			assert.equal(totals.size, bytes.length);
			assert.equal((await api(`/orgs/default/caches/${cache}/go/reset`, {})).status, 200);
			assert.equal((await call(goPath, { headers: goHeaders })).status, 404);
			assert.equal((await call(path, { headers })).status, 200);
			if (privateCache) {
				assert.equal((await fetch(artifactUrl)).status, 401);
				await api(`/admin/tokens/${jti}/revoke`, { reason: "worker split regression" });
				// Revocation misses are cached for 30 seconds in each isolate and KV.
				await new Promise(resolve => setTimeout(resolve, 31_000));
				assert.equal((await call(path, { headers })).status, 401);
				assert.equal((await fetch(artifactUrl, { headers })).status, 401);
				assert.equal((await call(path, { headers: { ...headers, "x-snowstead-cdn-read": "1" } })).status, 401);
			} else {
				await api(`/admin/caches/${cache}/paths/delete`, { storePathHashes: [hash] });
				for (const method of ["GET", "HEAD"]) {
					assert.equal((await call(scopedNar, { method, headers: { "x-snowstead-cdn-read": "1" } })).status, 404);
					assert.equal((await call(path, { method })).status, 404);
				}
			}
		}
		// Each service rejects the other service's routes even when called directly.
		assert.equal((await server.getWorker("snowstead-nix").fetch("http://test/_api/v1/admin/caches")).status, 404);
		assert.equal((await server.getWorker("snowstead-control").fetch("http://test/open/nix-cache-info")).status, 404);
		assert.equal((await server.getWorker("snowstead-go").fetch("http://test/_api/v1/admin/caches")).status, 404);
	} catch (error) {
		console.error(server?.getLogs());
		throw error;
	} finally {
		await server?.close();
		await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
		await admin.end();
	}
});
