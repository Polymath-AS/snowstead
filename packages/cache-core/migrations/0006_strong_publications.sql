CREATE TABLE "authority_journal" (
	"operation_id" text PRIMARY KEY NOT NULL,
	"resource_key" text NOT NULL,
	"predecessor_etag" text,
	"payload" text NOT NULL,
	"nonce" text NOT NULL,
	"successor" text NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"fence_nonce" text,
	"fence_successor" text,
	"winning_etag" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "authority_journal_nonce_unique" UNIQUE("nonce"),
	CONSTRAINT "authority_journal_fence_nonce_unique" UNIQUE("fence_nonce"),
	CONSTRAINT "authority_journal_state" CHECK ("authority_journal"."state" in ('pending', 'fencing', 'accepted', 'excluded', 'frozen')),
	CONSTRAINT "authority_journal_fence" CHECK (("authority_journal"."fence_nonce" is null) = ("authority_journal"."fence_successor" is null)),
	CONSTRAINT "authority_journal_outcome" CHECK (("authority_journal"."state" in ('accepted', 'excluded')) = ("authority_journal"."winning_etag" is not null))
);
--> statement-breakpoint
CREATE TABLE "publication_caches" (
	"cache_id" integer PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"path" text NOT NULL,
	"name" text NOT NULL,
	"epoch" text NOT NULL,
	"is_public" boolean NOT NULL,
	"state" text NOT NULL,
	"phase" text,
	"target_epoch" text,
	"target_public" boolean,
	"status_bytes" text,
	"status_etag" text,
	"route_bytes" text,
	"route_etag" text,
	"command_id" text,
	"command_key" text,
	"command_expected" text,
	"command_bytes" text,
	CONSTRAINT "publication_caches_path_unique" UNIQUE("path"),
	CONSTRAINT "publication_caches_state" CHECK ("publication_caches"."state" in ('inactive', 'initializing', 'migrating', 'active', 'changing', 'retiring', 'retired'))
);
--> statement-breakpoint
CREATE TABLE "publication_jobs" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer NOT NULL,
	"epoch" text NOT NULL,
	"store_path_hash" text NOT NULL,
	"kind" text NOT NULL,
	"revision_id" text NOT NULL,
	"path_json" text NOT NULL,
	"blob_json" text NOT NULL,
	"predecessor_etag" text,
	"grant_bytes" text,
	"state" text DEFAULT 'pending' NOT NULL,
	"witness_ready" boolean DEFAULT false NOT NULL,
	CONSTRAINT "publication_job_kind" CHECK ("publication_jobs"."kind" in ('publish', 'backfill', 'withdraw')),
	CONSTRAINT "publication_job_state" CHECK ("publication_jobs"."state" in ('pending', 'done', 'excluded'))
);
--> statement-breakpoint
CREATE TABLE "publication_paths" (
	"cache_id" integer NOT NULL,
	"epoch" text NOT NULL,
	"store_path_hash" text NOT NULL,
	"active_revision" text,
	"pending_job" text,
	"grant_bytes" text,
	"grant_etag" text,
	CONSTRAINT "publication_paths_cache_id_epoch_store_path_hash_pk" PRIMARY KEY("cache_id","epoch","store_path_hash")
);
--> statement-breakpoint
CREATE TABLE "publication_pins" (
	"revision_id" text NOT NULL,
	"kind" text NOT NULL,
	CONSTRAINT "publication_pins_revision_id_kind_pk" PRIMARY KEY("revision_id","kind"),
	CONSTRAINT "publication_pin_kind" CHECK ("publication_pins"."kind" in ('prepared', 'active'))
);
--> statement-breakpoint
CREATE TABLE "publication_revisions" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer NOT NULL,
	"epoch" text NOT NULL,
	"store_path_hash" text NOT NULL,
	"blob_id" bigint NOT NULL,
	"is_public" boolean NOT NULL,
	"nar_key" text NOT NULL,
	"narinfo_key" text NOT NULL,
	"narinfo" text,
	"nar_phase" text DEFAULT 'new' NOT NULL,
	"narinfo_phase" text DEFAULT 'new' NOT NULL,
	"nar_etag" text,
	"narinfo_etag" text,
	"state" text DEFAULT 'prepared' NOT NULL,
	CONSTRAINT "publication_revisions_nar_key_unique" UNIQUE("nar_key"),
	CONSTRAINT "publication_revisions_narinfo_key_unique" UNIQUE("narinfo_key"),
	CONSTRAINT "publication_revision_state" CHECK ("publication_revisions"."state" in ('prepared', 'active', 'retired', 'deleting', 'deleted')),
	CONSTRAINT "publication_revision_uploads" CHECK ("publication_revisions"."nar_phase" in ('new', 'issued', 'complete') and "publication_revisions"."narinfo_phase" in ('new', 'issued', 'complete'))
);
--> statement-breakpoint
ALTER TABLE "publication_jobs" ADD CONSTRAINT "publication_jobs_cache_id_publication_caches_cache_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."publication_caches"("cache_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "publication_jobs" ADD CONSTRAINT "publication_jobs_revision_id_publication_revisions_id_fk" FOREIGN KEY ("revision_id") REFERENCES "public"."publication_revisions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "publication_paths" ADD CONSTRAINT "publication_paths_cache_id_publication_caches_cache_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."publication_caches"("cache_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "publication_paths" ADD CONSTRAINT "publication_paths_active_revision_publication_revisions_id_fk" FOREIGN KEY ("active_revision") REFERENCES "public"."publication_revisions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "publication_paths" ADD CONSTRAINT "publication_paths_pending_job_publication_jobs_id_fk" FOREIGN KEY ("pending_job") REFERENCES "public"."publication_jobs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "publication_pins" ADD CONSTRAINT "publication_pins_revision_id_publication_revisions_id_fk" FOREIGN KEY ("revision_id") REFERENCES "public"."publication_revisions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "publication_revisions" ADD CONSTRAINT "publication_revisions_cache_id_publication_caches_cache_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."publication_caches"("cache_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "authority_journal_unresolved_key" ON "authority_journal" USING btree ("resource_key") WHERE "authority_journal"."state" in ('pending', 'fencing', 'frozen');--> statement-breakpoint
CREATE UNIQUE INDEX "publication_jobs_unresolved_path" ON "publication_jobs" USING btree ("cache_id","epoch","store_path_hash") WHERE "publication_jobs"."state" = 'pending';