CREATE TABLE "api_tokens" (
	"jti" text PRIMARY KEY NOT NULL,
	"subject" text NOT NULL,
	"caches_json" text DEFAULT '[]' NOT NULL,
	"perms_json" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_by" text NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_by" text,
	"revocation_reason" text,
	"org_id" text
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
	"status" integer NOT NULL,
	"org_id" text
);
--> statement-breakpoint
CREATE TABLE "bandwidth_daily" (
	"org_id" text NOT NULL,
	"day" date NOT NULL,
	"bytes" bigint DEFAULT 0 NOT NULL,
	CONSTRAINT "bandwidth_daily_org_id_day_pk" PRIMARY KEY("org_id","day")
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
CREATE TABLE "cache_signing_keys" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer NOT NULL,
	"signing_key_name" text NOT NULL,
	"signing_public_key" text NOT NULL,
	"signing_key_sealed" text,
	"state" text DEFAULT 'staged' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "caches" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "caches_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"name" text NOT NULL,
	"is_public" boolean DEFAULT true NOT NULL,
	"org_id" text DEFAULT 'default' NOT NULL,
	"signing_key_name" text,
	"signing_public_key" text,
	"signing_key_sealed" text,
	"retention_days" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
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
CREATE TABLE "org_api_keys" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"secret_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "orgs" (
	"id" text PRIMARY KEY NOT NULL,
	"slug" text NOT NULL,
	"moving_from" text,
	"storage_limit" bigint,
	"private_caches" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "orgs_slug_unique" UNIQUE("slug"),
	CONSTRAINT "orgs_moving_from_unique" UNIQUE("moving_from")
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
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_pushed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "token_caches" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "token_caches_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"token_jti" text NOT NULL,
	"cache_id" integer,
	"pattern" text,
	CONSTRAINT "token_caches_cache_or_pattern" CHECK (("token_caches"."cache_id" is null) <> ("token_caches"."pattern" is null))
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
CREATE TABLE "upstream_paths" (
	"store_path_hash" text PRIMARY KEY NOT NULL,
	"upstream" text NOT NULL,
	"found_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "api_tokens" ADD CONSTRAINT "api_tokens_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ADD CONSTRAINT "bandwidth_daily_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cache_signing_keys" ADD CONSTRAINT "cache_signing_keys_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "caches" ADD CONSTRAINT "caches_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_api_keys" ADD CONSTRAINT "org_api_keys_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "published_paths" ADD CONSTRAINT "published_paths_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "published_paths" ADD CONSTRAINT "published_paths_blob_object_id_blob_objects_id_fk" FOREIGN KEY ("blob_object_id") REFERENCES "public"."blob_objects"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "token_caches" ADD CONSTRAINT "token_caches_token_jti_api_tokens_jti_fk" FOREIGN KEY ("token_jti") REFERENCES "public"."api_tokens"("jti") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "token_caches" ADD CONSTRAINT "token_caches_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "upload_parts" ADD CONSTRAINT "upload_parts_session_id_upload_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."upload_sessions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "upload_sessions" ADD CONSTRAINT "upload_sessions_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_api_tokens_org" ON "api_tokens" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_org" ON "audit_logs" USING btree ("org_id","id");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_actor" ON "audit_logs" USING btree ("actor");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_cache" ON "audit_logs" USING btree ("cache_name");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_time" ON "audit_logs" USING btree ("timestamp");--> statement-breakpoint
CREATE UNIQUE INDEX "blob_objects_file_hash_compression_unique" ON "blob_objects" USING btree ("file_hash","compression");--> statement-breakpoint
CREATE UNIQUE INDEX "cache_signing_keys_name" ON "cache_signing_keys" USING btree ("cache_id","signing_key_name");--> statement-breakpoint
CREATE UNIQUE INDEX "caches_org_name_unique" ON "caches" USING btree ("org_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "gc_marks_target_unique" ON "gc_marks" USING btree ("target_type","target_id");--> statement-breakpoint
CREATE INDEX "idx_org_api_keys_org" ON "org_api_keys" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_published_paths_cache_pushed" ON "published_paths" USING btree ("cache_id","last_pushed_at");--> statement-breakpoint
CREATE UNIQUE INDEX "published_paths_cache_store_unique" ON "published_paths" USING btree ("cache_id","store_path_hash");--> statement-breakpoint
CREATE INDEX "idx_published_paths_blob_object" ON "published_paths" USING btree ("blob_object_id");--> statement-breakpoint
CREATE UNIQUE INDEX "token_caches_token_cache" ON "token_caches" USING btree ("token_jti","cache_id");--> statement-breakpoint
CREATE UNIQUE INDEX "token_caches_token_pattern" ON "token_caches" USING btree ("token_jti","pattern");--> statement-breakpoint
CREATE INDEX "idx_token_caches_cache" ON "token_caches" USING btree ("cache_id");--> statement-breakpoint
CREATE UNIQUE INDEX "upload_parts_session_part_unique" ON "upload_parts" USING btree ("session_id","part_number");--> statement-breakpoint
CREATE INDEX "idx_upload_sessions_status" ON "upload_sessions" USING btree ("status","expires_at");--> statement-breakpoint
-- Everything without an org is the default org's: a self-hosted install's caches and tokens (see schema.ts).
INSERT INTO "orgs" ("id", "slug") VALUES ('default', 'default') ON CONFLICT ("id") DO NOTHING;
