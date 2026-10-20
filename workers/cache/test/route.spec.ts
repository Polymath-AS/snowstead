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
