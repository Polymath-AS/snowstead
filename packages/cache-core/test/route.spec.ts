import { describe, it, expect } from "vitest";
import { routeOf } from "../src/route.js";

describe("routes", () => {
	it.each([
		["POST", "/_api/v1/get-missing-paths", "POST /_api/v1/get-missing-paths"],
		["POST", "/_api/v1/caches/uzaaft/upload-sessions/batch", "POST /_api/v1/caches/:cache/upload-sessions/batch"],
		["POST", "/_api/v1/uploads/commit", "POST /_api/v1/uploads/commit"],
		["POST", "/_api/v1/uploads/3f9c2c7e-1d8a-4b8e-9f3a-2b6f0c1d2e3f/publish", "POST /_api/v1/uploads/:session/publish"],
		["PUT", "/_api/v1/uploads/3f9c2c7e-1d8a-4b8e-9f3a-2b6f0c1d2e3f/part/7", "PUT /_api/v1/uploads/:session/part/:part"],
		["POST", "/_api/v1/admin/tokens/3f9c2c7e-1d8a-4b8e-9f3a-2b6f0c1d2e3f/revoke", "POST /_api/v1/admin/tokens/:jti/revoke"],
		["GET", "/_api/v1/admin/caches/team", "GET /_api/v1/admin/caches/:cache"],
		["POST", "/_api/v1/admin/caches/team/paths/delete", "POST /_api/v1/admin/caches/:cache/paths/delete"],
		["POST", "/_api/v1/admin/caches/team/purge", "POST /_api/v1/admin/caches/:cache/purge"],
		["PUT", "/_api/v1/orgs/org_01ABC", "PUT /_api/v1/orgs/:org"],
		["GET", "/acme/main/nix-cache-info", "GET /:org/:cache/nix-cache-info"],
		["GET", "/acme/main/0c5a8bvbj6ld1jdk7k1w5p4f5l9jwq8x.narinfo", "GET /:org/:cache/:hash.narinfo"],
		["GET", "/private/acme/main/nar/abc/zstd.nar", "GET /private/:org/:cache/nar/:file"],
		["POST", "/_api/v1/orgs/org_01ABC/keys/abcdefgh12345678/revoke", "POST /_api/v1/orgs/:org/keys/:key/revoke"],
		["POST", "/_api/v1/orgs/org_01ABC/caches/team/paths/delete", "POST /_api/v1/orgs/:org/caches/:cache/paths/delete"],
		["POST", "/_api/v1/orgs/org_01ABC/caches/team/purge", "POST /_api/v1/orgs/:org/caches/:cache/purge"],
		["POST", "/_api/v1/orgs/org_01ABC/tokens/3f9c2c7e-1d8a-4b8e-9f3a-2b6f0c1d2e3f/revoke", "POST /_api/v1/orgs/:org/tokens/:jti/revoke"],
		["GET", "/uzaaft/nix-cache-info", "GET /:cache/nix-cache-info"],
		["HEAD", `/private/team/${"a".repeat(32)}.narinfo`, "HEAD /private/:cache/:hash.narinfo"],
		["GET", `/team/nar/${"f".repeat(64)}/zstd.nar`, "GET /:cache/nar/:file"],
		["GET", `/nar/${"f".repeat(64)}/zstd.nar`, "GET /nar/:file"],
		["GET", "/healthz", "GET /healthz"],
	])("%s %s is %s", (method, path, route) => {
		expect(routeOf(method, path)).toBe(route);
	});

	it.each(["/_api/v1/uploads/x/delete", "/_api/v1/../../etc", "/wp-login.php", "/a/b/c"])(
		"%s is unmatched",
		(path) => {
			expect(routeOf("GET", path)).toBe("unmatched");
		},
	);
});
