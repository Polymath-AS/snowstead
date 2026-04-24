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

export async function createPresignedUrl(
	endpoint: string,
	accessKeyId: string,
	secretAccessKey: string,
	bucket: string,
	key: string,
	expiresIn: number,
): Promise<string> {
	const client = getClient(accessKeyId, secretAccessKey);
	const url = new URL(`/${bucket}/${key}`, endpoint);
	url.searchParams.set("X-Amz-Expires", String(expiresIn));

	const signed = await client.sign(new Request(url, { method: "GET" }), {
		aws: { signQuery: true },
	});

	return signed.url;
}
