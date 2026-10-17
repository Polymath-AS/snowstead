import { describe, it, expect } from "vitest";
import { createPresignedPut } from "../src/presign.js";

describe("presigned uploads", () => {
	it("sign the checksum and the cache header the CDN serves", async () => {
		const sha256 = "2f9b292e61f1a38cf0581f0b43964c809ab37e78e9b7f183559d279e86d59909";
		const { url, headers } = await createPresignedPut(
			"https://acct.r2.cloudflarestorage.com",
			"key-id",
			"secret",
			"helios-public",
			"nar/abc/zstd.nar",
			sha256,
			3600,
		);
		const parsed = new URL(url);
		expect(parsed.pathname).toBe("/helios-public/nar/abc/zstd.nar");
		expect(parsed.searchParams.get("X-Amz-Expires")).toBe("3600");
		// aws4fetch never signs content-type; Nix does not read it anyway.
		expect(parsed.searchParams.get("X-Amz-SignedHeaders")?.split(";")).toEqual(
			expect.arrayContaining(["host", "x-amz-checksum-sha256", "cache-control"]),
		);
		// The base64 form of the file hash, as R2 checks it.
		expect(headers["x-amz-checksum-sha256"]).toBe("L5spLmHxo4zwWB8LQ5ZMgJqzfnjpt/GDVZ0nnobVmQk=");
		expect(headers["cache-control"]).toContain("immutable");
	});
});
