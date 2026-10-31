ALTER TABLE "go_entries" ADD COLUMN "last_accessed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "published_paths" ADD COLUMN "last_accessed_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "idx_go_entries_lru" ON "go_entries" USING btree ("cache_id",greatest("uploaded_at", "last_accessed_at"));--> statement-breakpoint
CREATE INDEX "idx_published_paths_lru" ON "published_paths" USING btree ("cache_id",greatest("last_pushed_at", "last_accessed_at"));