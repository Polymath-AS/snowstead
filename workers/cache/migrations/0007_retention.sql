-- Existing paths count as pushed now: turning retention on gives them a full
-- period before they can go, rather than deleting them at once.
ALTER TABLE "caches" ADD COLUMN "retention_days" integer;--> statement-breakpoint
ALTER TABLE "published_paths" ADD COLUMN "last_pushed_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_published_paths_cache_pushed" ON "published_paths" USING btree ("cache_id","last_pushed_at");