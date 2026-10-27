import { sql } from "drizzle-orm";
import { pgTable, text, integer, bigint, boolean, timestamp, date, primaryKey, uniqueIndex, index, check } from "drizzle-orm/pg-core";

const timestamptz = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });
const createdAt = (name: string) => timestamptz(name).notNull().defaultNow();
// NAR and file sizes pass 2 GiB, beyond Postgres `integer`; JS numbers are
// exact up to 2^53.
const bytes = (name: string) => bigint(name, { mode: "number" });
const id = () => bigint("id", { mode: "number" }).primaryKey().generatedAlwaysAsIdentity();

/**
 * The tenants of a hosted service, each with its caches and operator-set limits.
 * Their members live with whatever runs the service. Every cache
 * has one: a self-hosted install's are all the default org's, which has no
 * limit, and so are tokens made without an org.
 */
export const DEFAULT_ORG_ID = "default";

export const orgs = pgTable("orgs", {
	id: text("id").primaryKey(),
	/** Its caches' path in URLs: /<slug>/<cache>. See cache-path.ts. */
	slug: text("slug").notNull().unique(),
	/**
	 * The slug it had before its last change, while its caches' objects still
	 * sit there and move to the new one (slug-move.ts). No other org can take
	 * it until they're moved.
	 */
	movingFrom: text("moving_from").unique(),
	storageLimit: bytes("storage_limit"),
	privateCaches: boolean("private_caches").notNull().default(true),
	customSigningKeys: boolean("custom_signing_keys").notNull().default(false),
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
	/**
	 * Its published paths, and the bytes of the NARs they point at (a NAR
	 * shared with another cache counts in both). Kept by triggers on
	 * published_paths (migration 0001), so usage is read rather than summed
	 * over every path.
	 */
	pathCount: bigint("path_count", { mode: "number" }).notNull().default(0),
	size: bytes("size").notNull().default(0),
	createdAt: createdAt("created_at"),
}, (table) => [
	uniqueIndex("caches_org_name_unique").on(table.orgId, table.name),
]);

export const cacheSigningKeys = pgTable("cache_signing_keys", {
	id: text("id").primaryKey(),
	cacheId: integer("cache_id").notNull().references(() => caches.id, { onDelete: "cascade" }),
	signingKeyName: text("signing_key_name").notNull(),
	signingPublicKey: text("signing_public_key").notNull(),
	/** Public bytes only; imports may intentionally reuse customer key material. */
	managedPublicKey: text("managed_public_key").unique(),
	signingKeySealed: text("signing_key_sealed"),
	state: text("state").notNull().default("staged"),
	createdAt: createdAt("created_at"),
}, (table) => [uniqueIndex("cache_signing_keys_name").on(table.cacheId, table.signingKeyName)]);

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
	// The caches claim's entries, as token_caches now records them. Kept, and
	// still written, for one release, so a Worker from before token_caches
	// still lists tokens; dropped once none runs.
	cachesJson: text("caches_json").notNull().default("[]"),
	permsJson: text("perms_json").notNull(),
	createdAt: createdAt("created_at"),
	expiresAt: timestamptz("expires_at").notNull(),
	createdBy: text("created_by").notNull(),
	revokedAt: timestamptz("revoked_at"),
	revokedBy: text("revoked_by"),
	revocationReason: text("revocation_reason"),
	// The org whose caches the token reaches; null for a token naming no org's.
	orgId: text("org_id").references(() => orgs.id),
}, (table) => [
	// Each org lists its own tokens.
	index("idx_api_tokens_org").on(table.orgId),
]);

/**
 * The caches a token reaches, one row per entry of its caches claim: a
 * cache by id, held to it by a foreign key, or a name or pattern (`main`,
 * `team-*`, `*`), matched against cache names. A pattern has no row to
 * point at: it also reaches caches made after the token. The token carries
 * the same entries; these are their record, for listing and for asking
 * which tokens reach a cache.
 */
export const tokenCaches = pgTable("token_caches", {
	id: id(),
	tokenJti: text("token_jti").notNull().references(() => apiTokens.jti, { onDelete: "cascade" }),
	cacheId: integer("cache_id").references(() => caches.id, { onDelete: "cascade" }),
	pattern: text("pattern"),
}, (table) => [
	check("token_caches_cache_or_pattern", sql`(${table.cacheId} is null) <> (${table.pattern} is null)`),
	uniqueIndex("token_caches_token_cache").on(table.tokenJti, table.cacheId),
	uniqueIndex("token_caches_token_pattern").on(table.tokenJti, table.pattern),
	index("idx_token_caches_cache").on(table.cacheId),
]);

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
 * NAR bytes the Worker served for an org's private caches, by UTC day.
 * Public caches are read from the bucket and CDN directly and aren't counted.
 */
export const bandwidthDaily = pgTable("bandwidth_daily", {
	orgId: text("org_id").notNull().references(() => orgs.id),
	day: date("day", { mode: "string" }).notNull(),
	bytes: bytes("bytes").notNull().default(0),
}, (table) => [primaryKey({ columns: [table.orgId, table.day] })]);

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
