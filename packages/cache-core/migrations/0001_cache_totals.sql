ALTER TABLE "caches" ADD COLUMN "path_count" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "caches" ADD COLUMN "size" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
-- Each insert or delete of published paths moves its caches' totals, once a
-- statement. Paths never move between caches or blobs, so updates don't.
CREATE FUNCTION "published_paths_totals"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF TG_OP = 'INSERT' THEN
		UPDATE "caches" c SET "path_count" = c."path_count" + d.n, "size" = c."size" + d.bytes
		FROM (SELECT p."cache_id", count(*) AS n, sum(b."file_size") AS bytes
			FROM "added" p JOIN "blob_objects" b ON b."id" = p."blob_object_id" GROUP BY p."cache_id") d
		WHERE c."id" = d."cache_id";
	ELSE
		UPDATE "caches" c SET "path_count" = c."path_count" - d.n, "size" = c."size" - d.bytes
		FROM (SELECT p."cache_id", count(*) AS n, sum(b."file_size") AS bytes
			FROM "removed" p JOIN "blob_objects" b ON b."id" = p."blob_object_id" GROUP BY p."cache_id") d
		WHERE c."id" = d."cache_id";
	END IF;
	RETURN NULL;
END $$;
--> statement-breakpoint
CREATE TRIGGER "published_paths_totals_insert" AFTER INSERT ON "published_paths"
	REFERENCING NEW TABLE AS "added" FOR EACH STATEMENT EXECUTE FUNCTION "published_paths_totals"();
--> statement-breakpoint
CREATE TRIGGER "published_paths_totals_delete" AFTER DELETE ON "published_paths"
	REFERENCING OLD TABLE AS "removed" FOR EACH STATEMENT EXECUTE FUNCTION "published_paths_totals"();
--> statement-breakpoint
-- The paths already published.
UPDATE "caches" c SET "path_count" = t.n, "size" = t.bytes
FROM (SELECT p."cache_id", count(*) AS n, sum(b."file_size") AS bytes
	FROM "published_paths" p JOIN "blob_objects" b ON b."id" = p."blob_object_id" GROUP BY p."cache_id") t
WHERE c."id" = t."cache_id";
