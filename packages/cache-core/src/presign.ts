import { AwsClient } from "aws4fetch";

let cachedClient: AwsClient | undefined;
let cachedCredentials: string | undefined;

function getClient(accessKeyId: string, secretAccessKey: string): AwsClient {
	const key = `${accessKeyId}:${secretAccessKey}`;
	if (cachedClient && cachedCredentials === key) {
		return cachedClient;
	}
	cachedClient = new AwsClient({
		accessKeyId,
		secretAccessKey,
		service: "s3",
		region: "auto",
	});
	cachedCredentials = key;
	return cachedClient;
}

/**
 * A presigned PUT that only accepts the body whose SHA-256 is `sha256Hex`:
 * the checksum header is signed, and R2 rejects a body that does not match
 * it (400 BadDigest), so uploads stay content-addressed though the Worker
 * never sees the bytes. `metadata` is stored with the object as
 * x-amz-meta-* headers, signed like the rest. Canonical writes also sign
 * If-None-Match, so neither concurrent clients nor URL replays can replace
 * another session's ownership metadata.
 */
export async function createPresignedPut(
	endpoint: string,
	accessKeyId: string,
	secretAccessKey: string,
	bucket: string,
	key: string,
	sha256Hex: string,
	expiresIn: number,
	metadata: Readonly<Record<string, string>>,
	createOnly: boolean,
): Promise<{ url: string; headers: Record<string, string> }> {
	const client = getClient(accessKeyId, secretAccessKey);
	const url = new URL(`/${bucket}/${key}`, endpoint);
	url.searchParams.set("X-Amz-Expires", String(expiresIn));
	// cache-control is signed too, so the stored object carries what the CDN
	// serves; aws4fetch never signs content-type, which Nix does not read.
	const headers = {
		"x-amz-checksum-sha256": hexToBase64(sha256Hex),
		"content-type": "application/x-nix-nar",
		"cache-control": "public, max-age=31536000, immutable",
		...(createOnly ? { "if-none-match": "*" } : {}),
		...Object.fromEntries(Object.entries(metadata).map(([k, v]) => [`x-amz-meta-${k}`, v])),
	};
	const signed = await client.sign(new Request(url, { method: "PUT", headers }), {
		aws: { signQuery: true },
	});
	return { url: signed.url, headers };
}

function hexToBase64(hex: string): string {
	let binary = "";
	for (let i = 0; i < hex.length; i += 2) {
		binary += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
	}
	return btoa(binary);
}

/**
 * A presigned PUT for one part of an R2 multipart upload. The parts carry
 * no checksum the server could know in advance; the assembled object is
 * checked against the file hash when it is committed.
 */
export async function createPresignedPartPut(
	endpoint: string,
	accessKeyId: string,
	secretAccessKey: string,
	bucket: string,
	key: string,
	uploadId: string,
	partNumber: number,
	expiresIn: number,
	size?: number,
): Promise<string> {
	const client = getClient(accessKeyId, secretAccessKey);
	const url = new URL(`/${bucket}/${key}`, endpoint);
	url.searchParams.set("partNumber", String(partNumber));
	url.searchParams.set("uploadId", uploadId);
	url.searchParams.set("X-Amz-Expires", String(expiresIn));
	const signed = await client.sign(new Request(url, { method: "PUT", headers: size === undefined ? {} : { "content-length": String(size) } }), {
		aws: { signQuery: true, allHeaders: size !== undefined },
	});
	return signed.url;
}
