import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";

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
	const session = await api(`/caches/${cache}/upload-sessions`, {
		storePath: `/nix/store/${hash}-layout`,
		storePathHash: hash,
		narHash: `sha256:${"1".repeat(52)}`,
		narSize: 64,
		fileHash,
		fileSize: body.byteLength,
		compression: "zstd",
	});
	expect(session.status).toBe(201);
	const { sessionId } = await session.json<{ sessionId: string }>();
	const put = await SELF.fetch(`http://example.com/_api/v1/uploads/${sessionId}/blob`, {
		method: "PUT",
		headers: { authorization: "Bearer test-auth-token" },
		body,
	});
	expect(put.status).toBe(200);
	expect((await api(`/uploads/${sessionId}/complete`, {})).status).toBe(200);
	expect((await api(`/uploads/${sessionId}/publish`, {})).status).toBe(200);
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

		const narinfo = await env.CACHE_BUCKET.get(`narinfo/closed/${hash}.narinfo`);
		expect(await narinfo?.text()).toContain(`URL: nar/${fileHash}/zstd.nar`);
		expect(await env.CACHE_BUCKET.head(`nars/sha256/${fileHash}/zstd.nar`)).not.toBeNull();

		const created = await api("/admin/tokens", { subject: "layout", caches: ["closed"], perms: ["pull"] }, "test-admin-secret");
		const { token } = await created.json<{ token: string }>();
		const res = await SELF.fetch(`http://example.com/private/closed/${hash}.narinfo`, {
			headers: { authorization: `Bearer ${token}` },
		});
		expect(res.status).toBe(200);
		expect(await res.text()).toContain(`URL: nar/${fileHash}/zstd.nar`);
		expect((await SELF.fetch(`http://example.com/private/closed/${hash}.narinfo`)).status).toBe(401);
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
