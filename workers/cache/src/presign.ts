import { AwsClient } from "aws4fetch";

export async function createPresignedUrl(
	endpoint: string,
	accessKeyId: string,
	secretAccessKey: string,
	bucket: string,
	key: string,
	expiresIn: number,
): Promise<string> {
	const client = new AwsClient({
		accessKeyId,
		secretAccessKey,
		service: "s3",
		region: "auto",
	});

	const url = new URL(`/${bucket}/${key}`, endpoint);
	url.searchParams.set("X-Amz-Expires", String(expiresIn));

	const signed = await client.sign(new Request(url, { method: "GET" }), {
		aws: { signQuery: true },
	});

	return signed.url;
}
