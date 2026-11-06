import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";
import { Client } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { createTestHarness } from "wrangler";
import gatewayWorker from "../../../workers/gateway/src/index.ts";

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
				{ configPath: "workers/sccache/wrangler.jsonc", vars, secrets },
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
		const { token: smokeToken } = await (await api("/admin/tokens", {
			subject: "streaming-smoke", caches: ["smoke-*"], perms: ["push", "pull"],
		})).json();
		const smoke = await promisify(execFile)("bash", [
			new URL("../../../scripts/smoke-test.sh", import.meta.url).pathname, url.toString(), smokeToken,
		], { env: { ...process.env, ADMIN_SECRET: secrets.ADMIN_SECRET } });
		assert.match(smoke.stdout, /0 failed/);
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
					for (const [path, body] of [[`/caches/${name}/upload-streams/batch`, { paths: [session] }], ["/get-missing-paths", { cache: name, storePathHashes: ["a".repeat(32)] }]]) {
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
			const { sessions: [{ sessionId }] } = await (await api(`/caches/${cache}/upload-streams/batch`, {
				paths: [{ storePath: `/nix/store/${hash}-split`, storePathHash: hash,
					narHash: `sha256:${"1".repeat(52)}`, narSize: bytes.length, compression: "zstd" }],
			}, token)).json();
			assert.match(sessionId, /^s2\./);
			const { parts: [grant] } = await (await api(`/uploads/${sessionId}/parts`, { parts: [{ partNumber: 1, size: bytes.length }] }, token)).json();
			let offset = 0;
			const upload = new ReadableStream({ pull(controller) {
				if (offset === bytes.length) return controller.close();
				const end = Math.min(offset + 16 * 1024, bytes.length);
				controller.enqueue(bytes.subarray(offset, end));
				offset = end;
			} });
			const uploaded = await fetch(new URL(grant.url, url), {
				method: "PUT", headers: grant.headers,
				body: upload, duplex: "half",
			});
			assert.equal(uploaded.status, 200);
			assert.ok(uploaded.headers.get("etag"));
			const item = { sessionId, narHash: `sha256:${"1".repeat(52)}`, narSize: bytes.length, fileHash, fileSize: bytes.length,
				parts: [{ partNumber: 1, etag: uploaded.headers.get("etag").replaceAll('"', "") }] };
			await uploaded.arrayBuffer();
			for (let retry = 0; retry < 2; retry++) {
				const finalized = await (await api("/uploads/finalize", { uploads: [item] }, token)).json();
				assert.equal(finalized.results[0].published, true);
			}
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
		// Real clients, empty local caches and a fresh daemon on each pass: a
		// warm hit must come from the hosted protocol, not process-local state.
		await api("/admin/caches", { name: "compiler", private: true, protocols: ["sccache"] });
		const { token: compilerToken } = await (await api("/admin/tokens", {
			subject: "compiler-test", caches: ["compiler"], perms: ["sccache:read", "sccache:write"],
		})).json();
		const dir = await mkdtemp(join(tmpdir(), "snowstead-sccache-"));
		const exec = promisify(execFile);
		const clientEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("SCCACHE_")));
		Object.assign(clientEnv, {
			SCCACHE_SERVER_UDS: join(dir, "server.sock"), SCCACHE_CONF: join(dir, "config"),
			SCCACHE_WEBDAV_ENDPOINT: new URL("/_api/v1/sccache/default/compiler/", url).href,
			SCCACHE_WEBDAV_TOKEN: compilerToken,
		});
		const run = args => exec("sccache", args, { env: clientEnv, cwd: dir, timeout: 30_000 });
		try {
			await writeFile(join(dir, "config"), "");
			await writeFile(join(dir, "input.cpp"), "int cached(int n) { return n * 7 + 3; }\n");
			await writeFile(join(dir, "input.rs"), "pub fn cached(n: u64) -> u64 { n * 11 + 5 }\n");
			let expected;
			for (let pass = 0; pass < 2; pass++) {
				clientEnv.SCCACHE_DIR = join(dir, `local-${pass}`);
				await run(["--start-server"]);
				const start = performance.now();
				await run(["c++", "-c", "input.cpp", "-o", "cpp.o", "-O2"]);
				await run(["rustc", "--crate-name", "fixture", "--crate-type", "rlib", "--emit=link", "input.rs", "--out-dir", ".", "-O"]);
				const stats = JSON.parse((await run(["--show-stats", "--stats-format", "json"])).stdout).stats;
				const sum = counts => Object.values(counts).reduce((a, b) => a + b, 0);
				assert.equal(sum(stats[pass ? "cache_hits" : "cache_misses"].counts), 2, JSON.stringify(stats));
				assert.equal(stats.cache_write_errors, 0);
				const outputs = await Promise.all(["cpp.o", "libfixture.rlib"].map(name => readFile(join(dir, name))));
				if (expected) assert.deepEqual(outputs, expected);
				expected = outputs;
				console.log(`sccache ${pass ? "warm" : "cold"} Rust+C++: ${(performance.now() - start).toFixed(1)} ms`);
				await run(["--stop-server"]);
				await Promise.all(["cpp.o", "libfixture.rlib"].map(name => rm(join(dir, name))));
			}
		} finally {
			await run(["--stop-server"]).catch(() => {});
			await rm(dir, { recursive: true, force: true });
		}
		// Each service rejects the other service's routes even when called directly.
		assert.equal((await server.getWorker("snowstead-nix").fetch("http://test/_api/v1/admin/caches")).status, 404);
		assert.equal((await server.getWorker("snowstead-control").fetch("http://test/open/nix-cache-info")).status, 404);
		assert.equal((await server.getWorker("snowstead-go").fetch("http://test/_api/v1/admin/caches")).status, 404);
		assert.equal((await server.getWorker("snowstead-sccache").fetch("http://test/_api/v1/admin/caches")).status, 404);
	} catch (error) {
		console.error(JSON.stringify(server?.getLogs(), null, 2));
		throw error;
	} finally {
		await server?.close();
		await admin.query(`DROP DATABASE "${name}" WITH (FORCE)`);
		await admin.end();
	}
});

test("legacy API forwards authenticated binary requests and preserves origin redirects", { timeout: 30_000 }, async () => {
	const origin = createServer(async (request, response) => {
		if (request.url === "/_api/v1/redirect") {
			response.writeHead(307, { location: "/not-an-api-endpoint", "cache-control": "no-store" });
			response.end();
			return;
		}
		const chunks = [];
		for await (const chunk of request) chunks.push(chunk);
		response.writeHead(201, { "content-type": "application/json", "cache-control": "no-store" });
		response.end(JSON.stringify({
			url: request.url, method: request.method, host: request.headers.host,
			authorization: request.headers.authorization,
			contentType: request.headers["content-type"],
			body: Buffer.concat(chunks).toString("base64"),
		}));
	});
	await new Promise(resolve => origin.listen(0, "127.0.0.1", resolve));
	const upstream = `http://127.0.0.1:${origin.address().port}`;
	const gateway = createTestHarness({
		root: new URL("../../../", import.meta.url).pathname,
		workers: [{ configPath: "wrangler.jsonc", env: "production", vars: { API_ORIGIN: upstream } }],
	});
	try {
		const { url } = await gateway.listen();
		const body = randomBytes(257 * 1024);
		for (const method of ["PUT", "POST", "PROPFIND", "MKCOL"]) {
			const path = "/_api/v1/sccache/default/compiler/a/b/c/" + "abc".padEnd(64, "d") + "?cursor=a%2Fb&cursor=c";
			const response = await fetch(new URL(path, url), {
				method, body,
				headers: { authorization: "Bearer forward-fixture", "content-type": "application/octet-stream" },
			});
			assert.equal(response.status, 201);
			assert.equal(response.headers.get("cache-control"), "no-store");
			assert.deepEqual(await response.json(), {
				url: path, method, host: new URL(upstream).host,
				authorization: "Bearer forward-fixture", contentType: "application/octet-stream",
				body: body.toString("base64"),
			});
		}
		// Wrangler's outbound proxy follows redirects despite redirect: manual.
		// Exercise the public handler against the HTTP origin without that proxy.
		const redirect = await gatewayWorker.fetch(new Request(new URL("/_api/v1/redirect", url), {
			headers: { authorization: "Bearer forward-fixture" },
		}), { API_ORIGIN: upstream });
		assert.equal(redirect.status, 307);
		assert.equal(redirect.headers.get("location"), "/not-an-api-endpoint");
		assert.equal(redirect.headers.get("cache-control"), "no-store");
		await redirect.arrayBuffer();
	} finally {
		await gateway.close();
		await new Promise((resolve, reject) => origin.close(error => error ? reject(error) : resolve()));
	}
});
