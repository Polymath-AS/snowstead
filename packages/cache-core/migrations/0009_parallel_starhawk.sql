CREATE TABLE "sccache_entries" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer,
	"generation" text NOT NULL,
	"action" text NOT NULL,
	"r2_key" text NOT NULL,
	"size" bigint NOT NULL,
	"uploaded_at" timestamp with time zone,
	"last_accessed_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "sccache_entries_r2_key_unique" UNIQUE("r2_key")
);
--> statement-breakpoint
CREATE TABLE "sccache_usage" (
	"cache_id" integer NOT NULL,
	"generation" text NOT NULL,
	"expires_minute" timestamp with time zone NOT NULL,
	"used" bigint NOT NULL,
	"pending" bigint NOT NULL,
	CONSTRAINT "sccache_usage_cache_id_generation_expires_minute_pk" PRIMARY KEY("cache_id","generation","expires_minute")
);
--> statement-breakpoint
ALTER TABLE "cache_protocols" DROP CONSTRAINT "cache_protocols_protocol_valid";--> statement-breakpoint
ALTER TABLE "caches" ADD COLUMN "sccache_generation" text DEFAULT '0' NOT NULL;--> statement-breakpoint
ALTER TABLE "sccache_entries" ADD CONSTRAINT "sccache_entries_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sccache_usage" ADD CONSTRAINT "sccache_usage_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "sccache_entries_lru" ON "sccache_entries" USING btree ("cache_id","generation",greatest("uploaded_at", "last_accessed_at"),"id") WHERE "sccache_entries"."uploaded_at" is not null;--> statement-breakpoint
CREATE INDEX "sccache_entries_staging" ON "sccache_entries" USING btree ("cache_id","expires_at") WHERE "sccache_entries"."uploaded_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "sccache_entries_action" ON "sccache_entries" USING btree ("cache_id","generation","action");--> statement-breakpoint
CREATE INDEX "sccache_entries_expiry" ON "sccache_entries" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "sccache_entries_quota_expiry" ON "sccache_entries" USING btree ("cache_id","generation","expires_at");--> statement-breakpoint
ALTER TABLE "cache_protocols" ADD CONSTRAINT "cache_protocols_protocol_valid" CHECK ("cache_protocols"."protocol" IN ('nix', 'go', 'sccache'));
--> statement-breakpoint
-- Transition tables aggregate bulk inserts/deletes once per statement. Only
-- changed buckets are locked, in deterministic order, and only during SQL:
-- upload publication updates these totals after the R2 transfer completes.
CREATE FUNCTION "sccache_usage_delta"() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
	source text;
	changed bigint;
BEGIN
	IF TG_OP = 'INSERT' THEN
		IF NOT EXISTS (SELECT FROM added) THEN RETURN NULL; END IF;
		source := 'SELECT cache_id, generation, expires_at, uploaded_at, size FROM added';
	ELSIF TG_OP = 'DELETE' THEN
		IF NOT EXISTS (SELECT FROM removed) THEN RETURN NULL; END IF;
		source := 'SELECT cache_id, generation, expires_at, uploaded_at, -size AS size FROM removed';
	ELSE
		IF NOT EXISTS (SELECT FROM removed) THEN RETURN NULL; END IF;
		source := 'SELECT cache_id, generation, expires_at, uploaded_at, size FROM added
			UNION ALL SELECT cache_id, generation, expires_at, uploaded_at, -size AS size FROM removed';
	END IF;
	-- The parent join skips cascaded SET NULL deltas after cache deletion;
	-- that cache's summary rows are removed by their own ON DELETE CASCADE.
	EXECUTE 'INSERT INTO sccache_usage (cache_id, generation, expires_minute, used, pending)
		SELECT changes.cache_id, changes.generation,
		date_trunc(''minute'', changes.expires_at, ''UTC'') AS minute,
		coalesce(sum(changes.size) FILTER (WHERE uploaded_at IS NOT NULL), 0) AS used_delta,
		coalesce(sum(changes.size) FILTER (WHERE uploaded_at IS NULL), 0) AS pending_delta
		FROM (' || source || ') changes JOIN caches ON caches.id = changes.cache_id
		GROUP BY changes.cache_id, changes.generation, minute
		HAVING coalesce(sum(changes.size) FILTER (WHERE uploaded_at IS NOT NULL), 0) <> 0
			OR coalesce(sum(changes.size) FILTER (WHERE uploaded_at IS NULL), 0) <> 0
		ORDER BY changes.cache_id, changes.generation, minute
		ON CONFLICT (cache_id, generation, expires_minute) DO UPDATE
		SET used = sccache_usage.used + excluded.used, pending = sccache_usage.pending + excluded.pending';
	GET DIAGNOSTICS changed = ROW_COUNT;
	IF changed = 0 THEN RETURN NULL; END IF;
	-- Remove empty touched buckets after the ordered upsert acquired locks.
	EXECUTE 'DELETE FROM sccache_usage u USING (
		SELECT DISTINCT cache_id, generation, date_trunc(''minute'', expires_at, ''UTC'') AS minute
		FROM (' || source || ') changes WHERE cache_id IS NOT NULL
	) touched WHERE u.cache_id = touched.cache_id AND u.generation = touched.generation
		AND u.expires_minute = touched.minute AND u.used = 0 AND u.pending = 0';
	RETURN NULL;
END $$;
--> statement-breakpoint
CREATE TRIGGER "sccache_usage_insert" AFTER INSERT ON "sccache_entries"
	REFERENCING NEW TABLE AS "added" FOR EACH STATEMENT EXECUTE FUNCTION "sccache_usage_delta"();
--> statement-breakpoint
CREATE TRIGGER "sccache_usage_update" AFTER UPDATE ON "sccache_entries"
	REFERENCING OLD TABLE AS "removed" NEW TABLE AS "added" FOR EACH STATEMENT EXECUTE FUNCTION "sccache_usage_delta"();
--> statement-breakpoint
CREATE TRIGGER "sccache_usage_delete" AFTER DELETE ON "sccache_entries"
	REFERENCING OLD TABLE AS "removed" FOR EACH STATEMENT EXECUTE FUNCTION "sccache_usage_delta"();
