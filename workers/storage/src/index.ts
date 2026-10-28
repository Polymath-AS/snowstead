import { WorkerEntrypoint } from "cloudflare:workers";
import { PUBLICATION_KEY, type ReadBucket } from "@snowstead/cache-core/read-storage";

interface StorageEnv {
	PRIVATE_BUCKET: R2Bucket;
	PUBLIC_BUCKET: R2Bucket;
}

// Return only copied metadata and a stream, never an R2 capability or an
// RpcTarget with access to one. RPC callers cannot access entrypoint.env.
async function get(bucket: R2Bucket, key: string, options?: Parameters<ReadBucket["get"]>[1]) {
	let range: { offset: number; length: number } | undefined;
	if (options !== undefined) {
		const offset = options?.range?.offset;
		const length = options?.range?.length;
		if (typeof offset !== "number" || !Number.isSafeInteger(offset) || offset < 0 ||
			typeof length !== "number" || !Number.isSafeInteger(length) || length <= 0) throw new Error("Invalid range");
		range = { offset, length };
	}
	const object = await bucket.get(key, range ? { range } : undefined);
	return object ? { size: object.size, body: object.body } : null;
}

function dataKey(key: string): void {
	if (typeof key !== "string" || !PUBLICATION_KEY.test(key)) throw new Error("Invalid publication key");
}

/** Authority is fresh on every call; the byte Worker never gets this entrypoint. */
export class AuthorityReader extends WorkerEntrypoint<StorageEnv> {
	async get(key: string) {
		if (typeof key !== "string" || !key.startsWith("authority/v2/")) throw new Error("Invalid authority key");
		return get(this.env.PRIVATE_BUCKET, key);
	}
}

export class PrivateReader extends WorkerEntrypoint<StorageEnv> implements ReadBucket {
	async get(key: string, options?: Parameters<ReadBucket["get"]>[1]) {
		dataKey(key);
		return get(this.env.PRIVATE_BUCKET, key, options);
	}
	async head(key: string) {
		dataKey(key);
		const object = await this.env.PRIVATE_BUCKET.head(key);
		return object ? { size: object.size } : null;
	}
}

export class PublicReader extends WorkerEntrypoint<StorageEnv> implements ReadBucket {
	async get(key: string, options?: Parameters<ReadBucket["get"]>[1]) {
		dataKey(key);
		return get(this.env.PUBLIC_BUCKET, key, options);
	}
	async head(key: string) {
		dataKey(key);
		const object = await this.env.PUBLIC_BUCKET.head(key);
		return object ? { size: object.size } : null;
	}
}

export default {
	fetch() { return new Response(null, { status: 404 }); },
};
