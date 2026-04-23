DROP INDEX `idx_published_paths_lookup`;--> statement-breakpoint
CREATE INDEX `idx_published_paths_blob_object` ON `published_paths` (`blob_object_id`);