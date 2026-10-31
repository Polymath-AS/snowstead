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
	size: number,
): Promise<string> {
	const client = getClient(accessKeyId, secretAccessKey);
	const url = new URL(`/${bucket}/${key}`, endpoint);
	url.searchParams.set("partNumber", String(partNumber));
	url.searchParams.set("uploadId", uploadId);
	url.searchParams.set("X-Amz-Expires", String(expiresIn));
	const signed = await client.sign(new Request(url, { method: "PUT", headers: { "content-length": String(size) } }), {
		aws: { signQuery: true, allHeaders: true },
	});
	return signed.url;
}
