import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { test } from "node:test";
import { Client } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { createTestHarness } from "wrangler";

for (const publications of [false, true]) {
test(`gateway streams Nix and Go artifacts across real Workers (${publications ? "strong publication" : "legacy"})`, { timeout: 120_000 }, async () => {
	const database = new URL(process.env.SNOWSTEAD_TEST_DATABASE_URL);
	const name = `snowstead_split_${process.pid}_${publications ? "v2" : "legacy"}`;
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
		const vars = { UPSTREAM_CACHES: "", CDN_ZONE_ID: "", PUBLIC_CACHE_ORIGIN: "",
			PUBLICATION_READS: String(publications), STRONG_TOKEN_POLICIES: String(publications) };
		server = createTestHarness({
			root: new URL("../../../", import.meta.url).pathname,
			workers: [
				{ configPath: "wrangler.jsonc" },
				{ configPath: "workers/nix/wrangler.jsonc", vars, secrets },
				{ configPath: "workers/control/wrangler.jsonc", vars, secrets },
				{ configPath: "workers/go/wrangler.jsonc", vars, secrets },
				...(publications ? [
					// Exercise the byte service transport; this does not qualify native caching.
					{ configPath: "wrangler.download.jsonc", vars: { NATIVE_MAX_BYTES: "3145728" }, secrets: { JWT_SECRET: secrets.JWT_SECRET } },
					{ configPath: "wrangler.bytes.jsonc" },
					{ configPath: "wrangler.storage.jsonc" },
				] : []),
			],
		});
		const { url } = await server.listen();
		const call = (path, init) => fetch(new URL(path, url), init);
		const read = publications
			? (path, init) => server.getWorker("snowstead-download").fetch(new URL(path, "https://cache.snowstead.com"), init)
			: call;
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
		assert.equal((await call("/_api/v1/admin/publications/key/initialize", { method: "POST" })).status, 401);
		if (publications) await api("/admin/publications/key/initialize", {});
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
			const path = `/${privateCache && !publications ? "private/" : ""}${cache}/${hash}.narinfo`;
			const headers = { authorization: `Bearer ${token}` };
			const info = await read(path, { headers });
			assert.equal(info.status, 200);
			const narinfo = await info.text();
			assert.ok(narinfo.includes(`Sig: ${publicKey.split(":")[0]}:`));
			const relative = /^URL: (.+)$/m.exec(narinfo)[1];
			const artifactUrl = new URL(relative, new URL(path, url));
			if (publications) {
				assert.match(relative, /^nar\/v2\//);
				assert.match(info.headers.get("cache-control"), /no-store/);
				await api(`/uploads/${sessionId}/publish`, {}, token);
				const repeated = await (await read(path, { headers })).text();
				assert.equal(/^URL: (.+)$/m.exec(repeated)[1], relative);
			}
			for (let pass = 0; pass < 2; pass++) {
				const response = await read(artifactUrl.pathname, { headers });
				assert.equal(response.status, 200);
				assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
			}
			const head = await read(artifactUrl.pathname, { method: "HEAD", headers });
			assert.equal(head.status, 200);
			assert.equal(Number(head.headers.get("content-length")), bytes.length);
			assert.equal((await head.arrayBuffer()).byteLength, 0);
			assert.equal((await read(path)).status, privateCache ? 401 : 200);
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
			if (publications) {
				const range = await read(artifactUrl.pathname, { headers: { ...headers, range: "bytes=7-31" } });
				assert.equal(range.status, 206);
				assert.deepEqual(Buffer.from(await range.arrayBuffer()), bytes.subarray(7, 32));
				const conditional = await read(artifactUrl.pathname, { headers: { ...headers, "if-none-match": head.headers.get("etag") } });
				assert.equal(conditional.status, 304);
			}
			if (privateCache) {
				assert.equal((await read(artifactUrl.pathname)).status, 401);
				await api(`/admin/tokens/${jti}/revoke`, { reason: "worker split regression" });
				// Only the legacy path has an isolate/KV revocation cache.
				if (!publications) await new Promise(resolve => setTimeout(resolve, 31_000));
				assert.equal((await read(path, { headers })).status, 401);
				assert.equal((await read(artifactUrl.pathname, { headers })).status, 401);
			} else if (publications) {
				await api(`/admin/caches/${cache}/paths/delete`, { storePathHashes: [hash] });
				assert.equal((await read(path)).status, 404);
				assert.equal((await read(artifactUrl.pathname)).status, 404);
			}
		}
		if (publications) {
			// Attack the actual deployed-shaped capabilities, not a TS-only wrapper.
			const storage = await server.getWorker("snowstead-storage").getEnv();
			const authorityKey = "authority/v2/tokens/readonly-probe";
			const dataKey = `v2/o/org_probe/c/1/e/${crypto.randomUUID()}/p/${"a".repeat(32)}/r/${crypto.randomUUID()}/nar`;
			await storage.PRIVATE_BUCKET.put(authorityKey, "revoked");
			await storage.PRIVATE_BUCKET.put(dataKey, "private bytes");
			await storage.PUBLIC_BUCKET.put(dataKey, "public bytes");
			for (const name of ["snowstead-download", "snowstead-bytes"]) {
				const edge = await server.getWorker(name).getEnv();
				assert.equal(edge.PRIVATE_BUCKET, undefined);
				assert.equal(edge.PUBLIC_BUCKET, undefined);
				if (name === "snowstead-bytes") assert.equal(edge.AUTHORITY, undefined);
				for (const binding of ["AUTHORITY", "PRIVATE_BYTES", "PUBLIC_BYTES"]) {
					if (!edge[binding]) continue;
					const reader = edge[binding];
					const key = binding === "AUTHORITY" ? authorityKey : dataKey;
					const expected = binding === "AUTHORITY" ? "revoked" : binding === "PRIVATE_BYTES" ? "private bytes" : "public bytes";
					const object = await reader.get(key);
					assert.equal(await new Response(object.body).text(), expected);
					for (const [method, args] of [
						["put", [key, "forged active record"]], ["delete", [key]],
						["createMultipartUpload", [key]], ["resumeMultipartUpload", [key, "upload"]],
						["list", []], ["getEntrypoint", ["AuthorityReader"]],
					]) await assert.rejects(async () => { await reader[method](...args); }, `${name}.${binding}.${method} must be unavailable`);
					await assert.rejects(async () => { await reader.env.PRIVATE_BUCKET.put(key, "forged"); });
					await assert.rejects(async () => { await reader.ctx.exports.AuthorityReader.get(authorityKey); });
					if (binding !== "AUTHORITY") {
						await assert.rejects(async () => { await reader.get(authorityKey); });
						await assert.rejects(async () => { await reader.head(authorityKey); });
						assert.equal((await reader.head(dataKey)).size, expected.length);
						const ranged = await reader.get(dataKey, { range: { offset: 2, length: 5 } });
						assert.equal(ranged.size, expected.length);
						assert.equal(await new Response(ranged.body).text(), expected.slice(2, 7));
					}
				}
			}
			assert.equal(await (await storage.PRIVATE_BUCKET.get(authorityKey)).text(), "revoked");
			assert.equal(await (await storage.PRIVATE_BUCKET.get(dataKey)).text(), "private bytes");
			assert.equal(await (await storage.PUBLIC_BUCKET.get(dataKey)).text(), "public bytes");
			assert.equal((await server.getWorker("snowstead-storage").fetch("https://storage.invalid/authority/v2/tokens/readonly-probe")).status, 404);
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
}
