import { env, createExecutionContext, waitOnExecutionContext, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { testDb } from "./db.js";
import { createCache } from "../src/db/repository.js";
import worker from "./worker.js";

const AUTH_TOKEN = "test-secret-token";
const CACHE_NAME = "auth-test";

function envWithAuth(): typeof env {
	return { ...env, AUTH_TOKEN };
}

function postWithWorker(
	path: string,
	body: unknown,
	headers: Record<string, string> = {},
): Promise<Response> {
	const request = new Request(`http://example.com${path}`, {
		method: "POST",
		headers: { "content-type": "application/json", ...headers },
		body: JSON.stringify(body),
	});
	const ctx = createExecutionContext();
	const response = worker.fetch(request, envWithAuth(), ctx);
	waitOnExecutionContext(ctx);
	return response;
}

const db = testDb();

beforeAll(async () => {
	await createCache(db, CACHE_NAME);
});

describe("write auth", () => {
	it("rejects write requests without authorization header", async () => {
		const res = await postWithWorker(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			{ storePath: `/nix/store/${"a".repeat(32)}-test`, storePathHash: "a".repeat(32), narHash: "sha256:" + "1".repeat(52), narSize: 100, fileHash: "b".repeat(64), fileSize: 100, compression: "zstd" },
		);

		expect(res.status).toBe(401);
		const body = await res.json<{ error: string }>();
		expect(body.error).toBe("Unauthorized");
	});

	it("rejects write requests with wrong bearer token", async () => {
		const res = await postWithWorker(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			{ storePath: `/nix/store/${"a".repeat(32)}-test`, storePathHash: "a".repeat(32), narHash: "sha256:" + "1".repeat(52), narSize: 100, fileHash: "b".repeat(64), fileSize: 100, compression: "zstd" },
			{ authorization: "Bearer wrong-token" },
		);

		expect(res.status).toBe(403);
		const body = await res.json<{ error: string }>();
		expect(body.error).toBe("Forbidden");
	});

	it("accepts write requests with valid bearer token", async () => {
		const res = await postWithWorker(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			{ storePath: `/nix/store/${"c".repeat(32)}-test`, storePathHash: "c".repeat(32), narHash: "sha256:" + "1".repeat(52), narSize: 100, fileHash: "d".repeat(64), fileSize: 100, compression: "zstd" },
			{ authorization: `Bearer ${AUTH_TOKEN}` },
		);

		expect(res.status).toBe(201);
	});

	it("rejects non-bearer auth schemes", async () => {
		const res = await postWithWorker(
			`/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			{ storePath: `/nix/store/${"a".repeat(32)}-test`, storePathHash: "a".repeat(32), narHash: "sha256:" + "1".repeat(52), narSize: 100, fileHash: "b".repeat(64), fileSize: 100, compression: "zstd" },
			{ authorization: `Basic ${AUTH_TOKEN}` },
		);

		expect(res.status).toBe(401);
	});
});

describe("read endpoints remain public", () => {
	it("GET nix-cache-info works without auth even when AUTH_TOKEN is set", async () => {
		const request = new Request(`http://example.com/${CACHE_NAME}/nix-cache-info`);
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, envWithAuth(), ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).toContain("StoreDir: /nix/store");
	});

	it("serves public cache info through SELF without credentials", async () => {
		const res = await SELF.fetch(`http://example.com/${CACHE_NAME}/nix-cache-info`);

		expect(res.status).toBe(200);
		expect(await res.text()).toContain("StoreDir: /nix/store");
	});
});
