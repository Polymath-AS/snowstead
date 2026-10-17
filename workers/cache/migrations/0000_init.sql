CREATE TABLE "api_tokens" (
	"jti" text PRIMARY KEY NOT NULL,
	"subject" text NOT NULL,
	"caches_json" text NOT NULL,
	"perms_json" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_by" text NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_by" text,
	"revocation_reason" text
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "audit_logs_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"timestamp" timestamp with time zone DEFAULT now() NOT NULL,
	"actor" text NOT NULL,
	"action" text NOT NULL,
	"cache_name" text,
	"detail" text DEFAULT '{}' NOT NULL,
	"ip" text,
	"status" integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE "blob_objects" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "blob_objects_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"file_hash" text NOT NULL,
	"file_size" bigint NOT NULL,
	"compression" text NOT NULL,
	"r2_key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "blob_objects_r2_key_unique" UNIQUE("r2_key")
);
--> statement-breakpoint
CREATE TABLE "caches" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "caches_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"name" text NOT NULL,
	"is_public" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "caches_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "gc_marks" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "gc_marks_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"target_type" text NOT NULL,
	"target_id" text NOT NULL,
	"reason" text NOT NULL,
	"marked_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "published_paths" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "published_paths_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"cache_id" integer NOT NULL,
	"store_path_hash" text NOT NULL,
	"store_path" text NOT NULL,
	"nar_hash" text NOT NULL,
	"nar_size" bigint NOT NULL,
	"blob_object_id" bigint NOT NULL,
	"references_json" text DEFAULT '[]' NOT NULL,
	"deriver" text,
	"system" text,
	"signatures_json" text DEFAULT '[]' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "upload_parts" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "upload_parts_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"session_id" text NOT NULL,
	"part_number" integer NOT NULL,
	"etag" text NOT NULL,
	"size" bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE "upload_sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer NOT NULL,
	"store_path_hash" text NOT NULL,
	"store_path" text NOT NULL,
	"nar_hash" text NOT NULL,
	"nar_size" bigint NOT NULL,
	"file_hash" text NOT NULL,
	"file_size" bigint NOT NULL,
	"compression" text NOT NULL,
	"references_json" text DEFAULT '[]' NOT NULL,
	"deriver" text,
	"system" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"r2_upload_key" text,
	"r2_upload_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "published_paths" ADD CONSTRAINT "published_paths_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "published_paths" ADD CONSTRAINT "published_paths_blob_object_id_blob_objects_id_fk" FOREIGN KEY ("blob_object_id") REFERENCES "public"."blob_objects"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "upload_parts" ADD CONSTRAINT "upload_parts_session_id_upload_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."upload_sessions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "upload_sessions" ADD CONSTRAINT "upload_sessions_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_audit_logs_actor" ON "audit_logs" USING btree ("actor");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_cache" ON "audit_logs" USING btree ("cache_name");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_time" ON "audit_logs" USING btree ("timestamp");--> statement-breakpoint
CREATE UNIQUE INDEX "blob_objects_file_hash_compression_unique" ON "blob_objects" USING btree ("file_hash","compression");--> statement-breakpoint
CREATE UNIQUE INDEX "gc_marks_target_unique" ON "gc_marks" USING btree ("target_type","target_id");--> statement-breakpoint
CREATE UNIQUE INDEX "published_paths_cache_store_unique" ON "published_paths" USING btree ("cache_id","store_path_hash");--> statement-breakpoint
CREATE INDEX "idx_published_paths_blob_object" ON "published_paths" USING btree ("blob_object_id");--> statement-breakpoint
CREATE UNIQUE INDEX "upload_parts_session_part_unique" ON "upload_parts" USING btree ("session_id","part_number");--> statement-breakpoint
CREATE INDEX "idx_upload_sessions_status" ON "upload_sessions" USING btree ("status","expires_at");