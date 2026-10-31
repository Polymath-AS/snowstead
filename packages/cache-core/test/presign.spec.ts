import { describe, it, expect } from "vitest";
import { createPresignedPartPut } from "../src/presign.js";

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
			1024,
		));
		expect(url.pathname).toBe("/snowstead-private/staging/abc");
		expect(url.searchParams.get("partNumber")).toBe("3");
		expect(url.searchParams.get("uploadId")).toBe("upload-1");
		expect(url.searchParams.get("X-Amz-SignedHeaders")?.split(";")).toContain("content-length");
		expect(url.searchParams.get("X-Amz-Signature")).toBeTruthy();
	});

	it("binds streaming upload authority to its reserved byte length", async () => {
		const sign = (size: number) => createPresignedPartPut(
			"https://acct.r2.cloudflarestorage.com", "key-id", "secret", "snowstead-private", "staging/bounded", "upload-2", 1, 3600, size,
		);
		const first = new URL(await sign(8388608));
		const second = new URL(await sign(8388609));
		expect(first.searchParams.get("X-Amz-SignedHeaders")?.split(";")).toContain("content-length");
		expect(first.searchParams.get("X-Amz-Signature")).not.toBe(second.searchParams.get("X-Amz-Signature"));
	});
});
