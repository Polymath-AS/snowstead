import { drizzle } from "drizzle-orm/d1";
import type { DrizzleD1Database } from "drizzle-orm/d1";

export interface WorkerConfig {
	readonly bucket: R2Bucket;
	readonly db: DrizzleD1Database;
	readonly signingKeyName: string;
	readonly signingPrivateKey: string;
	readonly authToken: string;
	readonly r2AccessKeyId: string;
	readonly r2SecretAccessKey: string;
	readonly r2Endpoint: string;
	readonly r2BucketName: string;
	readonly jwtSecret: string;
	readonly adminSecret: string;
	readonly ctx?: ExecutionContext;
}

export function resolveConfig(env: Env): WorkerConfig {
	if (!env.CACHE_BUCKET) {
		throw new Error("Missing required binding: CACHE_BUCKET");
	}
	if (!env.CACHE_DB) {
		throw new Error("Missing required binding: CACHE_DB");
	}
	return {
		bucket: env.CACHE_BUCKET,
		db: drizzle(env.CACHE_DB),
		signingKeyName: env.SIGNING_KEY_NAME || "helios-cache-1",
		signingPrivateKey: env.SIGNING_PRIVATE_KEY || "",
		authToken: env.AUTH_TOKEN || "",
		r2AccessKeyId: env.R2_ACCESS_KEY_ID || "",
		r2SecretAccessKey: env.R2_SECRET_ACCESS_KEY || "",
		r2Endpoint: env.R2_ENDPOINT || "",
		r2BucketName: env.R2_BUCKET_NAME || "helios-cache",
		jwtSecret: env.JWT_SECRET || "",
		adminSecret: env.ADMIN_SECRET || "",
	};
}
