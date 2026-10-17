import { connect } from "./db/connection.js";
import type { Db } from "./db/connection.js";

export interface WorkerConfig {
	/** Private caches, and everything the Worker alone reads. */
	readonly bucket: R2Bucket;
	/** Public caches, served straight from R2 on cache.polmath.no. */
	readonly publicBucket: R2Bucket;
	readonly db: Db;
	/** Database work that may outlive the response. */
	readonly defer: (task: Promise<unknown>) => void;
	/** Waits for deferred work, then releases the request's connections. */
	readonly close: () => Promise<void>;
	readonly signingKeyName: string;
	readonly signingPrivateKey: string;
	readonly authToken: string;
	readonly r2AccessKeyId: string;
	readonly r2SecretAccessKey: string;
	readonly r2Endpoint: string;
	readonly r2BucketName: string;
	readonly r2PublicBucketName: string;
	readonly jwtSecret: string;
	readonly adminSecret: string;
	readonly ctx?: ExecutionContext;
}

export function resolveConfig(env: Env, ctx?: ExecutionContext): WorkerConfig {
	if (!env.CACHE_BUCKET) {
		throw new Error("Missing required binding: CACHE_BUCKET");
	}
	if (!env.PUBLIC_BUCKET) {
		throw new Error("Missing required binding: PUBLIC_BUCKET");
	}
	if (!env.HYPERDRIVE) {
		throw new Error("Missing required binding: HYPERDRIVE");
	}
	const connection = connect(env.HYPERDRIVE.connectionString);
	return {
		bucket: env.CACHE_BUCKET,
		publicBucket: env.PUBLIC_BUCKET,
		// A getter, so the database client is only built for requests that use it.
		get db() {
			return connection.db;
		},
		defer: connection.defer,
		close: connection.close,
		ctx,
		signingKeyName: env.SIGNING_KEY_NAME || "helios-cache-1",
		signingPrivateKey: env.SIGNING_PRIVATE_KEY || "",
		authToken: env.AUTH_TOKEN || "",
		r2AccessKeyId: env.R2_ACCESS_KEY_ID || "",
		r2SecretAccessKey: env.R2_SECRET_ACCESS_KEY || "",
		r2Endpoint: env.R2_ENDPOINT || "",
		r2BucketName: env.R2_BUCKET_NAME || "helios-cache",
		r2PublicBucketName: env.R2_PUBLIC_BUCKET_NAME || "helios-public",
		jwtSecret: env.JWT_SECRET || "",
		adminSecret: env.ADMIN_SECRET || "",
	};
}
