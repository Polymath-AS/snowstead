import { sqliteTable, text, integer, uniqueIndex, index } from "drizzle-orm/sqlite-core";
import { sql } from "drizzle-orm";

const timestamp = (name: string) =>
	text(name).notNull().default(sql`(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`);

export const caches = sqliteTable("caches", {
	id: integer("id").primaryKey({ autoIncrement: true }),
	name: text("name").notNull().unique(),
	isPublic: integer("is_public").notNull().default(1),
	createdAt: timestamp("created_at"),
});

export const blobObjects = sqliteTable("blob_objects", {
	id: integer("id").primaryKey({ autoIncrement: true }),
	fileHash: text("file_hash").notNull(),
	fileSize: integer("file_size").notNull(),
	compression: text("compression").notNull(),
	r2Key: text("r2_key").notNull().unique(),
	createdAt: timestamp("created_at"),
}, (table) => [
	uniqueIndex("blob_objects_file_hash_compression_unique").on(table.fileHash, table.compression),
]);

export const publishedPaths = sqliteTable("published_paths", {
	id: integer("id").primaryKey({ autoIncrement: true }),
	cacheId: integer("cache_id").notNull().references(() => caches.id),
	storePathHash: text("store_path_hash").notNull(),
	storePath: text("store_path").notNull(),
	narHash: text("nar_hash").notNull(),
	narSize: integer("nar_size").notNull(),
	blobObjectId: integer("blob_object_id").notNull().references(() => blobObjects.id),
	referencesJson: text("references_json").notNull().default("[]"),
	deriver: text("deriver"),
	system: text("system"),
	signaturesJson: text("signatures_json").notNull().default("[]"),
	createdAt: timestamp("created_at"),
}, (table) => [
	uniqueIndex("published_paths_cache_store_unique").on(table.cacheId, table.storePathHash),
	index("idx_published_paths_blob_object").on(table.blobObjectId),
]);

export const uploadSessions = sqliteTable("upload_sessions", {
	id: text("id").primaryKey(),
	cacheId: integer("cache_id").notNull().references(() => caches.id),
	storePathHash: text("store_path_hash").notNull(),
	storePath: text("store_path").notNull(),
	narHash: text("nar_hash").notNull(),
	narSize: integer("nar_size").notNull(),
	fileHash: text("file_hash").notNull(),
	fileSize: integer("file_size").notNull(),
	compression: text("compression").notNull(),
	referencesJson: text("references_json").notNull().default("[]"),
	deriver: text("deriver"),
	system: text("system"),
	status: text("status").notNull().default("pending"),
	r2UploadKey: text("r2_upload_key"),
	r2UploadId: text("r2_upload_id"),
	createdAt: timestamp("created_at"),
	expiresAt: text("expires_at").notNull(),
}, (table) => [
	index("idx_upload_sessions_status").on(table.status, table.expiresAt),
]);

export const uploadParts = sqliteTable("upload_parts", {
	id: integer("id").primaryKey({ autoIncrement: true }),
	sessionId: text("session_id").notNull().references(() => uploadSessions.id),
	partNumber: integer("part_number").notNull(),
	etag: text("etag").notNull(),
	size: integer("size").notNull(),
}, (table) => [
	uniqueIndex("upload_parts_session_part_unique").on(table.sessionId, table.partNumber),
]);

export const gcMarks = sqliteTable("gc_marks", {
	id: integer("id").primaryKey({ autoIncrement: true }),
	targetType: text("target_type").notNull(),
	targetId: text("target_id").notNull(),
	reason: text("reason").notNull(),
	markedAt: text("marked_at").notNull().default(sql`(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`),
}, (table) => [
	uniqueIndex("gc_marks_target_unique").on(table.targetType, table.targetId),
]);

export const apiTokens = sqliteTable("api_tokens", {
	jti: text("jti").primaryKey(),
	subject: text("subject").notNull(),
	cachesJson: text("caches_json").notNull(),
	permsJson: text("perms_json").notNull(),
	createdAt: timestamp("created_at"),
	expiresAt: text("expires_at").notNull(),
	createdBy: text("created_by").notNull(),
	revokedAt: text("revoked_at"),
	revokedBy: text("revoked_by"),
	revocationReason: text("revocation_reason"),
});

export const auditLogs = sqliteTable("audit_logs", {
	id: integer("id").primaryKey({ autoIncrement: true }),
	timestamp: timestamp("timestamp"),
	actor: text("actor").notNull(),
	action: text("action").notNull(),
	cacheName: text("cache_name"),
	detail: text("detail").notNull().default("{}"),
	ip: text("ip"),
	status: integer("status").notNull(),
}, (table) => [
	index("idx_audit_logs_actor").on(table.actor),
	index("idx_audit_logs_cache").on(table.cacheName),
	index("idx_audit_logs_time").on(table.timestamp),
]);
