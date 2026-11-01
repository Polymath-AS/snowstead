import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { stageUpload, finalizeUploads } from "./upload.js";

const NAR = new Uint8Array([9, 8, 7, 6, 5]);

function api(path: string, body: unknown, token = "test-auth-token"): Promise<Response> {
	return SELF.fetch(`http://example.com/_api/v1${path}`, {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

let counter = 0;

/**
 * Uploads and publishes one path through the API; returns its hashes and
 * body. Each body is unique, and its file hash is its real SHA-256: R2
 * checks uploads against it.
 */
async function publish(cache: string): Promise<{ hash: string; fileHash: string; body: Uint8Array }> {
	counter += 1;
	const hash = `${"abcdfghijk"[counter % 10]}${"9".repeat(31)}`;
	const body = new Uint8Array([...NAR, counter]);
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
	const fileHash = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
	const item = await stageUpload(cache, {
		storePath: `/nix/store/${hash}-layout`,
		storePathHash: hash,
		narHash: `sha256:${"1".repeat(52)}`,
		narSize: 64,
		compression: "zstd",
	}, body);
	expect(await finalizeUploads([item])).toMatchObject([{ published: true }]);
	return { hash, fileHash, body };
}

beforeAll(async () => {
	expect((await api("/admin/caches", { name: "open", protocols: ["nix"] }, "test-admin-secret")).status).toBe(201);
	expect((await api("/admin/caches", { name: "closed", private: true, protocols: ["nix"] }, "test-admin-secret")).status).toBe(201);
});

describe("public caches live in the public bucket as Nix requests them", () => {
	it("stores nix-cache-info, narinfo and a shared NAR, all cacheable", async () => {
		const info = await env.PUBLIC_BUCKET.get("open/nix-cache-info");
		expect(await info?.text()).toContain("StoreDir: /nix/store");

		const { hash, fileHash, body } = await publish("open");
		const narinfo = await env.PUBLIC_BUCKET.get(`open/${hash}.narinfo`);
		expect(narinfo?.httpMetadata?.cacheControl).toBe("public, max-age=300");
		expect(await narinfo?.text()).toContain(`URL: ../nar/${fileHash}/zstd.nar`);

		const nar = await env.PUBLIC_BUCKET.get(`nar/${fileHash}/zstd.nar`);
		expect(nar?.httpMetadata?.cacheControl).toBe("public, max-age=31536000, immutable");
		expect(new Uint8Array(await nar!.arrayBuffer())).toEqual(body);

		// The Worker serves the same layout where it fronts every cache.
		const viaWorker = await SELF.fetch(`http://example.com/nar/${fileHash}/zstd.nar`);
		expect(viaWorker.status).toBe(200);
	});
});

describe("private caches never reach the public bucket", () => {
	it("keeps objects private and serves narinfo under /private/ only with a pull token", async () => {
		const { hash, fileHash } = await publish("closed");
		expect(await env.PUBLIC_BUCKET.head(`closed/${hash}.narinfo`)).toBeNull();
		expect(await env.PUBLIC_BUCKET.head(`nar/${fileHash}/zstd.nar`)).toBeNull();
		expect(await env.PUBLIC_BUCKET.head("closed/nix-cache-info")).toBeNull();

		expect(await env.CACHE_BUCKET.head(`narinfo/closed/${hash}.narinfo`)).toBeNull();
		expect(await env.CACHE_BUCKET.head(`nars/sha256/${fileHash}/zstd.nar`)).not.toBeNull();

		const created = await api("/admin/tokens", { subject: "layout", caches: ["closed"], perms: ["pull"] }, "test-admin-secret");
		const { token } = await created.json<{ token: string }>();
		const url = `http://example.com/private/closed/${hash}.narinfo`;
		const read = (method = "GET", headers: Record<string, string> = {}) => SELF.fetch(url, {
			method, headers: { authorization: `Bearer ${token}`, ...headers },
		});
		const head = await read("HEAD");
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
		const res = await read();
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).toContain(`URL: nar/${fileHash}/zstd.nar`);
		expect(res.headers.get("content-length")).toBe(String(new TextEncoder().encode(body).length));
		expect(head.headers.get("etag")).toBe(res.headers.get("etag"));
		expect(res.headers.get("etag")).toBeTruthy();
		expect(res.headers.get("cache-control")).toBe("private, no-cache");
		for (const method of ["GET", "HEAD"]) {
			expect((await read(method, { "if-none-match": res.headers.get("etag")! })).status).toBe(304);
			expect((await read(method, { "if-match": '"wrong"' })).status).toBe(412);
			// An old creation date cannot validate a newly signed representation.
			expect((await read(method, { "if-modified-since": "Thu, 01 Jan 2099 00:00:00 GMT" })).status).toBe(200);
		}
		const { publicKey } = await (await SELF.fetch("http://example.com/_api/v1/admin/caches/closed", {
			headers: { authorization: "Bearer test-admin-secret" },
		})).json<{ publicKey: string }>();
		const [name, material] = publicKey.split(":");
		const signature = body.split("\n").find(line => line.startsWith(`Sig: ${name}:`))!.slice(`Sig: ${name}:`.length);
		const key = await crypto.subtle.importKey("raw", Uint8Array.from(atob(material), c => c.charCodeAt(0)), "Ed25519", false, ["verify"]);
		expect(await crypto.subtle.verify("Ed25519", key, Uint8Array.from(atob(signature), c => c.charCodeAt(0)),
			new TextEncoder().encode(`1;/nix/store/${hash}-layout;sha256:${"1".repeat(52)};64;`))).toBe(true);
		expect((await SELF.fetch(`http://example.com/private/closed/${hash}.narinfo`)).status).toBe(401);
	});

	it("ignores obsolete R2 narinfo and never serves another cache's published path", async () => {
		const own = await publish("closed");
		const foreign = await publish("open");
		const created = await api("/admin/tokens", { subject: "metadata", caches: ["closed"], perms: ["pull"] }, "test-admin-secret");
		const { token } = await created.json<{ token: string }>();
		for (const { hash } of [own, foreign]) {
			await env.CACHE_BUCKET.put(`narinfo/closed/${hash}.narinfo`, "obsolete metadata");
			try {
				const response = await SELF.fetch(`http://obsolete.example/private/closed/${hash}.narinfo`, {
					headers: { authorization: `Bearer ${token}` },
				});
				expect(response.status).toBe(hash === own.hash ? 200 : 404);
				const body = await response.text();
				expect(body).not.toContain("obsolete metadata");
				if (hash === own.hash) expect(body).toContain(`StorePath: /nix/store/${hash}-layout`);
			} finally { await env.CACHE_BUCKET.delete(`narinfo/closed/${hash}.narinfo`); }
		}
	});
});

describe("cache names and visibility", () => {
	it.each(["nar", "private"])("reserves %s", async (name) => {
		expect((await api("/admin/caches", { name, protocols: ["nix"] }, "test-admin-secret")).status).toBe(400);
	});

	it("refuses to change the visibility of a cache with published paths", async () => {
		expect((await api("/admin/caches", { name: "open", private: true }, "test-admin-secret")).status).toBe(409);
		expect(await env.PUBLIC_BUCKET.head("open/nix-cache-info")).not.toBeNull();
	});
});
