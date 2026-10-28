import { connect } from "./db/connection.js";
import type { Connection, Db } from "./db/connection.js";
import type { CdnConfig } from "./cdn.js";
import type { RateLimiters } from "./rate-limit.js";

export interface WorkerConfig {
	/** Private caches, and everything the Worker alone reads. */
	readonly bucket: R2Bucket;
	/** Public caches, served straight from R2 on cache.snowstead.com. */
	readonly publicBucket: R2Bucket;
	/** Authorization state read per request: token revocations. */
	readonly authKv: KVNamespace;
	readonly db: Db;
	/** Database work that may outlive the response. */
	readonly defer: (task: Promise<unknown>) => void;
	/** Waits for deferred work, then releases the request's connection; nothing to wait for if it never opened one. */
	readonly close: () => Promise<void> | undefined;
	/** Per-caller request limits (rate-limit.ts); none configured is no limit. */
	readonly rateLimiters: RateLimiters;
	readonly signingKeyName: string;
	readonly signingPrivateKey: string;
	/** Seals each cache's own signing key; required for hosted creation and signing. */
	readonly signingMasterKey: () => Promise<string>;
	/** Refuse shared-key and unsigned publication on the hosted service. */
	readonly requireCacheSigningKeys: boolean;
	readonly authToken: string;
	readonly r2AccessKeyId: string;
	readonly r2SecretAccessKey: string;
	readonly r2Endpoint: string;
	readonly r2BucketName: string;
	readonly r2PublicBucketName: string;
	readonly jwtSecret: string;
	readonly adminSecret: string;
	/** Global reader cutover, only after inventory/backfill and ingress isolation. */
	readonly publicationReads?: boolean;
	/** Enable the global positive token perimeter before any cache cutover. */
	readonly strongTokenPolicies?: boolean;
	/** Binary caches whose paths pushes skip, as Nix substituter URLs. */
	readonly upstreams: readonly string[];
	/** The CDN in front of the public bucket, when purges are configured. */
	readonly cdn: CdnConfig | undefined;
	readonly ctx?: ExecutionContext;
}

type Settings = Omit<WorkerConfig, "db" | "defer" | "close" | "ctx">;

/**
 * What a config takes from env, worked out once per env rather than per
 * request: the isolate keeps one env, and reading its bindings and parsing
 * its vars on every request was a twelfth of a cache read's CPU.
 */
const settingsByEnv = new WeakMap<Env, Settings>();

export function resolveConfig(env: Env, ctx?: ExecutionContext): WorkerConfig {
	const settings = settingsByEnv.get(env) ?? readSettings(env);
	settingsByEnv.set(env, settings);
	// Built on first use: most requests (cache hits, nix-cache-info, NARs)
	// never touch the database.
	let connection: Connection | undefined;
	const open = () => (connection ??= connect(env.HYPERDRIVE.connectionString));
	return {
		...settings,
		get db() {
			return open().db;
		},
		defer: (task) => open().defer(task),
		close: () => connection?.close(),
		ctx,
	};
}

function readSettings(env: Env): Settings {
	if (!env.CACHE_BUCKET) {
		throw new Error("Missing required binding: CACHE_BUCKET");
	}
	if (!env.PUBLIC_BUCKET) {
		throw new Error("Missing required binding: PUBLIC_BUCKET");
	}
	if (!env.AUTH_KV) {
		throw new Error("Missing required binding: AUTH_KV");
	}
	if (!env.HYPERDRIVE) {
		throw new Error("Missing required binding: HYPERDRIVE");
	}
	// Resolve only for signing, never on public reads. Cache successful store
	// reads in this isolate, but let a transient store failure be retried.
	let master: Promise<string> | undefined;
	const signingMasterKey = () => master ??= (env.SIGNING_MASTER_KEY_STORE
		? env.SIGNING_MASTER_KEY_STORE.get()
		: Promise.resolve(env.SIGNING_MASTER_KEY || ""))
		.catch(error => { master = undefined; throw error; });
	return {
		bucket: env.CACHE_BUCKET,
		publicBucket: env.PUBLIC_BUCKET,
		authKv: env.AUTH_KV,
		signingKeyName: env.SIGNING_KEY_NAME || "snowstead-1",
		signingPrivateKey: env.SIGNING_PRIVATE_KEY || "",
		signingMasterKey,
		requireCacheSigningKeys: env.REQUIRE_CACHE_SIGNING_KEYS === "true",
		authToken: env.AUTH_TOKEN || "",
		r2AccessKeyId: env.R2_ACCESS_KEY_ID || "",
		r2SecretAccessKey: env.R2_SECRET_ACCESS_KEY || "",
		r2Endpoint: env.R2_ENDPOINT || "",
		r2BucketName: env.R2_BUCKET_NAME || "snowstead-private",
		r2PublicBucketName: env.R2_PUBLIC_BUCKET_NAME || "snowstead-public",
		jwtSecret: env.JWT_SECRET || "",
		adminSecret: env.ADMIN_SECRET || "",
		publicationReads: String(env.PUBLICATION_READS) === "true",
		strongTokenPolicies: String(env.STRONG_TOKEN_POLICIES) === "true" || String(env.PUBLICATION_READS) === "true",
		upstreams: (env.UPSTREAM_CACHES ?? "").split(/\s+/).filter(Boolean).map((u) => u.replace(/\/$/, "")),
		cdn: env.CDN_ZONE_ID && env.CDN_PURGE_TOKEN && env.PUBLIC_CACHE_ORIGIN
			? { zoneId: env.CDN_ZONE_ID, token: env.CDN_PURGE_TOKEN, origin: env.PUBLIC_CACHE_ORIGIN.replace(/\/$/, "") }
			: undefined,
		rateLimiters: { push: env.PUSH_LIMIT, api: env.API_LIMIT, read: env.READ_LIMIT },
	};
}
