import { describe, it, expect } from "vitest";
import { createPresignedPartPut, createPresignedPut } from "../src/presign.js";

describe("presigned uploads", () => {
	it.each([true, false])("sign checksum, ownership, and canonical condition (create-only %s)", async (createOnly) => {
		const sha256 = "2f9b292e61f1a38cf0581f0b43964c809ab37e78e9b7f183559d279e86d59909";
		const { url, headers } = await createPresignedPut(
			"https://acct.r2.cloudflarestorage.com",
			"key-id",
			"secret",
			"snowstead-public",
			"nar/abc/zstd.nar",
			sha256,
			3600,
			{ session: "upload-session" },
			createOnly,
		);
		const parsed = new URL(url);
		expect(parsed.pathname).toBe("/snowstead-public/nar/abc/zstd.nar");
		expect(parsed.searchParams.get("X-Amz-Expires")).toBe("3600");
		// aws4fetch never signs content-type; Nix does not read it anyway.
		expect(parsed.searchParams.get("X-Amz-SignedHeaders")?.split(";")).toEqual(
			expect.arrayContaining(["host", "x-amz-checksum-sha256", "cache-control", "x-amz-meta-session"]),
		);
		expect(headers["x-amz-meta-session"]).toBe("upload-session");
		expect(headers["if-none-match"]).toBe(createOnly ? "*" : undefined);
		expect(parsed.searchParams.get("X-Amz-SignedHeaders")?.split(";").includes("if-none-match")).toBe(createOnly);
		// The base64 form of the file hash, as R2 checks it.
		expect(headers["x-amz-checksum-sha256"]).toBe("L5spLmHxo4zwWB8LQ5ZMgJqzfnjpt/GDVZ0nnobVmQk=");
		expect(headers["cache-control"]).toContain("immutable");
	});
});

describe("presigned parts", () => {
	it("name the multipart upload and the part", async () => {
		const url = new URL(await createPresignedPartPut(
			"https://acct.r2.cloudflarestorage.com",
			"key-id",
			"secret",
			"snowstead-private",
			"staging/abc",
			"upload-1",
			3,
			3600,
		));
		expect(url.pathname).toBe("/snowstead-private/staging/abc");
		expect(url.searchParams.get("partNumber")).toBe("3");
		expect(url.searchParams.get("uploadId")).toBe("upload-1");
		expect(url.searchParams.get("X-Amz-Signature")).toBeTruthy();
	});
});
