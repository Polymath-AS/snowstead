import { pgTable, text, integer, bigint, boolean, timestamp, uniqueIndex, index } from "drizzle-orm/pg-core";

const timestamptz = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });
const createdAt = (name: string) => timestamptz(name).notNull().defaultNow();
// NAR and file sizes pass 2 GiB, beyond Postgres `integer`; JS numbers are
// exact up to 2^53.
const bytes = (name: string) => bigint(name, { mode: "number" });
const id = () => bigint("id", { mode: "number" }).primaryKey().generatedAlwaysAsIdentity();

/**
 * The tenants of a hosted service, each with its caches and a storage limit.
 * Their members and plans live with whatever runs the service. Every cache
 * has one: a self-hosted install's are all the default org's, which has no
 * limit, and so are tokens made without an org.
 */
export const DEFAULT_ORG_ID = "default";

export const orgs = pgTable("orgs", {
	id: text("id").primaryKey(),
	/** Its caches' path in URLs: /<slug>/<cache>. See cache-path.ts. */
	slug: text("slug").notNull().unique(),
	/** Bytes its caches may hold, counted like a cache's size; null for no limit. */
	storageLimit: bytes("storage_limit"),
	createdAt: createdAt("created_at"),
});

export const caches = pgTable("caches", {
	id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
	/** Unique within its org; see cache-path.ts for where it's served. */
	name: text("name").notNull(),
	isPublic: boolean("is_public").notNull().default(true),
	orgId: text("org_id").notNull().default(DEFAULT_ORG_ID).references(() => orgs.id),
	/** Its own signing key (see cache-keys.ts), or null to sign with the service's. */
	signingKeyName: text("signing_key_name"),
	signingPublicKey: text("signing_public_key"),
	signingKeySealed: text("signing_key_sealed"),
	/** Days a path stays after its last push, or null to keep paths until deleted. */
	retentionDays: integer("retention_days"),
	createdAt: createdAt("created_at"),
}, (table) => [
	uniqueIndex("caches_org_name_unique").on(table.orgId, table.name),
]);

export const blobObjects = pgTable("blob_objects", {
	id: id(),
	fileHash: text("file_hash").notNull(),
	fileSize: bytes("file_size").notNull(),
	compression: text("compression").notNull(),
	r2Key: text("r2_key").notNull().unique(),
	createdAt: createdAt("created_at"),
}, (table) => [
	uniqueIndex("blob_objects_file_hash_compression_unique").on(table.fileHash, table.compression),
]);

export const publishedPaths = pgTable("published_paths", {
	id: id(),
	cacheId: integer("cache_id").notNull().references(() => caches.id),
	storePathHash: text("store_path_hash").notNull(),
	storePath: text("store_path").notNull(),
	narHash: text("nar_hash").notNull(),
	narSize: bytes("nar_size").notNull(),
	blobObjectId: bigint("blob_object_id", { mode: "number" }).notNull().references(() => blobObjects.id),
	referencesJson: text("references_json").notNull().default("[]"),
	deriver: text("deriver"),
	system: text("system"),
	signaturesJson: text("signatures_json").notNull().default("[]"),
	createdAt: createdAt("created_at"),
	/**
	 * When a push last included the path, to the day: what retention counts
	 * from. Pulls can't count, since public NARs are served without the Worker.
	 */
	lastPushedAt: timestamptz("last_pushed_at").notNull().defaultNow(),
}, (table) => [
	index("idx_published_paths_cache_pushed").on(table.cacheId, table.lastPushedAt),
	uniqueIndex("published_paths_cache_store_unique").on(table.cacheId, table.storePathHash),
	index("idx_published_paths_blob_object").on(table.blobObjectId),
]);

export const uploadSessions = pgTable("upload_sessions", {
	id: text("id").primaryKey(),
	cacheId: integer("cache_id").notNull().references(() => caches.id),
	storePathHash: text("store_path_hash").notNull(),
	storePath: text("store_path").notNull(),
	narHash: text("nar_hash").notNull(),
	narSize: bytes("nar_size").notNull(),
	fileHash: text("file_hash").notNull(),
	fileSize: bytes("file_size").notNull(),
	compression: text("compression").notNull(),
	referencesJson: text("references_json").notNull().default("[]"),
	deriver: text("deriver"),
	system: text("system"),
	status: text("status").notNull().default("pending"),
	r2UploadKey: text("r2_upload_key"),
	r2UploadId: text("r2_upload_id"),
	createdAt: createdAt("created_at"),
	expiresAt: timestamptz("expires_at").notNull(),
}, (table) => [
	index("idx_upload_sessions_status").on(table.status, table.expiresAt),
]);

export const uploadParts = pgTable("upload_parts", {
	id: id(),
	sessionId: text("session_id").notNull().references(() => uploadSessions.id),
	partNumber: integer("part_number").notNull(),
	etag: text("etag").notNull(),
	size: bytes("size").notNull(),
}, (table) => [
	uniqueIndex("upload_parts_session_part_unique").on(table.sessionId, table.partNumber),
]);

export const gcMarks = pgTable("gc_marks", {
	id: id(),
	targetType: text("target_type").notNull(),
	targetId: text("target_id").notNull(),
	reason: text("reason").notNull(),
	markedAt: createdAt("marked_at"),
}, (table) => [
	uniqueIndex("gc_marks_target_unique").on(table.targetType, table.targetId),
]);

export const apiTokens = pgTable("api_tokens", {
	jti: text("jti").primaryKey(),
	subject: text("subject").notNull(),
	cachesJson: text("caches_json").notNull(),
	permsJson: text("perms_json").notNull(),
	createdAt: createdAt("created_at"),
	expiresAt: timestamptz("expires_at").notNull(),
	createdBy: text("created_by").notNull(),
	revokedAt: timestamptz("revoked_at"),
	revokedBy: text("revoked_by"),
	revocationReason: text("revocation_reason"),
	orgId: text("org_id"),
});

export const auditLogs = pgTable("audit_logs", {
	id: id(),
	timestamp: createdAt("timestamp"),
	actor: text("actor").notNull(),
	action: text("action").notNull(),
	cacheName: text("cache_name"),
	detail: text("detail").notNull().default("{}"),
	ip: text("ip"),
	status: integer("status").notNull(),
	/** The org it happened in, so each org can read its own; null for the operator's. */
	orgId: text("org_id"),
}, (table) => [
	index("idx_audit_logs_org").on(table.orgId, table.id),
	index("idx_audit_logs_actor").on(table.actor),
	index("idx_audit_logs_cache").on(table.cacheName),
	index("idx_audit_logs_time").on(table.timestamp),
]);

/**
 * Paths an upstream cache was found to serve, so pushes skip them without
 * asking it again. Only positive answers: an upstream may build a path
 * later, but does not drop one.
 */
export const upstreamPaths = pgTable("upstream_paths", {
	storePathHash: text("store_path_hash").primaryKey(),
	upstream: text("upstream").notNull(),
	foundAt: createdAt("found_at"),
});

/**
 * Keys an org's own tooling calls the org API with. Only a hash of the key
 * is kept; `id` is the public part of the key, which finds its row.
 */
export const orgApiKeys = pgTable("org_api_keys", {
	id: text("id").primaryKey(),
	orgId: text("org_id").notNull().references(() => orgs.id),
	name: text("name").notNull(),
	secretHash: text("secret_hash").notNull(),
	createdAt: createdAt("created_at"),
	revokedAt: timestamptz("revoked_at"),
}, (table) => [
	index("idx_org_api_keys_org").on(table.orgId),
]);
