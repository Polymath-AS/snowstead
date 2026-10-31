CREATE TABLE "eviction_logs" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "eviction_logs_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"org_id" text NOT NULL,
	"cache_id" integer NOT NULL,
	"cache" text NOT NULL,
	"product" text NOT NULL,
	"key" text NOT NULL,
	"size" bigint NOT NULL,
	"last_accessed_at" timestamp with time zone,
	"evicted_at" timestamp with time zone DEFAULT now() NOT NULL,
	"reason" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "pin_paths" (
	"revision_id" text NOT NULL,
	"cache_id" integer NOT NULL,
	"store_path_hash" text NOT NULL,
	CONSTRAINT "pin_paths_revision_id_store_path_hash_pk" PRIMARY KEY("revision_id","store_path_hash")
);
--> statement-breakpoint
CREATE TABLE "pin_revisions" (
	"id" text PRIMARY KEY NOT NULL,
	"pin_id" text NOT NULL,
	"revision" integer NOT NULL,
	"store_path" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"superseded_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "pins" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer NOT NULL,
	"name" text NOT NULL,
	"keep_kind" text NOT NULL,
	"keep_value" integer,
	"current_revision" integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE "api_tokens" ADD COLUMN "last_used_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "pin_paths" ADD CONSTRAINT "pin_paths_revision_id_pin_revisions_id_fk" FOREIGN KEY ("revision_id") REFERENCES "public"."pin_revisions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pin_paths" ADD CONSTRAINT "pin_paths_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pin_revisions" ADD CONSTRAINT "pin_revisions_pin_id_pins_id_fk" FOREIGN KEY ("pin_id") REFERENCES "public"."pins"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pins" ADD CONSTRAINT "pins_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "eviction_logs_org_page" ON "eviction_logs" USING btree ("org_id","id");--> statement-breakpoint
CREATE INDEX "eviction_logs_expiry" ON "eviction_logs" USING btree ("evicted_at");--> statement-breakpoint
CREATE INDEX "pin_paths_lookup" ON "pin_paths" USING btree ("cache_id","store_path_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "pin_revisions_number" ON "pin_revisions" USING btree ("pin_id","revision");--> statement-breakpoint
CREATE UNIQUE INDEX "pins_cache_name" ON "pins" USING btree ("cache_id","name");
--> statement-breakpoint
CREATE FUNCTION nix_path_pinned(cache integer, hash text, at_time timestamptz) RETURNS boolean
LANGUAGE sql STABLE AS $$
 SELECT EXISTS (
  SELECT 1 FROM pin_paths m JOIN pin_revisions r ON r.id=m.revision_id JOIN pins p ON p.id=r.pin_id
  WHERE m.cache_id=cache AND m.store_path_hash=hash AND (
   r.revision=p.current_revision OR p.keep_kind='forever'
   OR (p.keep_kind='revisions' AND r.revision>p.current_revision-p.keep_value)
   OR (p.keep_kind='days' AND r.superseded_at>at_time-p.keep_value*interval '1 day')
  )
 )
$$;
--> statement-breakpoint
-- Log logical removal in the same transaction, not eventual R2 cleanup.
-- Transition tables keep bulk deletion/reset logging set-based.
CREATE FUNCTION log_nix_evictions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
 SELECT c.org_id,c.id,c.name,'nix',e.store_path,b.file_size,e.last_accessed_at,
  coalesce(nullif(current_setting('snowstead.eviction_reason',true),''),'clear')
 FROM removed e JOIN caches c ON c.id=e.cache_id JOIN blob_objects b ON b.id=e.blob_object_id;
 RETURN NULL;
END $$;
--> statement-breakpoint
CREATE TRIGGER log_nix_evictions AFTER DELETE ON published_paths
 REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION log_nix_evictions();
--> statement-breakpoint
CREATE FUNCTION log_action_evictions() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE product text := TG_ARGV[0]; generation_column text := TG_ARGV[1]; removed_filter text;
BEGIN
 IF TG_OP='UPDATE' THEN
  removed_filter := ' AND EXISTS (SELECT 1 FROM added n WHERE n.id=e.id AND n.cache_id IS NULL)';
 ELSE
  removed_filter := '';
 END IF;
 EXECUTE format('INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
  SELECT c.org_id,c.id,c.name,%L,e.action,e.size,e.last_accessed_at,
   coalesce(nullif(current_setting(''snowstead.eviction_reason'',true),''''),''retention'')
  FROM removed e JOIN caches c ON c.id=e.cache_id
  WHERE e.uploaded_at IS NOT NULL AND e.generation=c.%I %s',product,generation_column,removed_filter);
 RETURN NULL;
END $$;
--> statement-breakpoint
CREATE TRIGGER log_go_removal AFTER DELETE ON go_entries REFERENCING OLD TABLE AS removed
 FOR EACH STATEMENT EXECUTE FUNCTION log_action_evictions('go','go_generation');
--> statement-breakpoint
CREATE TRIGGER log_go_detach AFTER UPDATE ON go_entries REFERENCING OLD TABLE AS removed NEW TABLE AS added
 FOR EACH STATEMENT EXECUTE FUNCTION log_action_evictions('go','go_generation');
--> statement-breakpoint
CREATE TRIGGER log_sccache_removal AFTER DELETE ON sccache_entries REFERENCING OLD TABLE AS removed
 FOR EACH STATEMENT EXECUTE FUNCTION log_action_evictions('sccache','sccache_generation');
--> statement-breakpoint
CREATE TRIGGER log_sccache_detach AFTER UPDATE ON sccache_entries REFERENCING OLD TABLE AS removed NEW TABLE AS added
 FOR EACH STATEMENT EXECUTE FUNCTION log_action_evictions('sccache','sccache_generation');
--> statement-breakpoint
CREATE FUNCTION log_cache_reset() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- Cache -> entry locks match uploads. A concurrent sweep either deletes first
 -- (and disappears from this SELECT) or waits/skips our rows, never double-logs.
 IF NEW.go_generation IS DISTINCT FROM OLD.go_generation THEN
  INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
  SELECT OLD.org_id,OLD.id,OLD.name,'go',action,size,last_accessed_at,
   coalesce(nullif(current_setting('snowstead.eviction_reason',true),''),'clear')
  FROM go_entries WHERE cache_id=OLD.id AND generation=OLD.go_generation AND uploaded_at IS NOT NULL FOR UPDATE;
 END IF;
 IF NEW.sccache_generation IS DISTINCT FROM OLD.sccache_generation THEN
  INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
  SELECT OLD.org_id,OLD.id,OLD.name,'sccache',action,size,last_accessed_at,
   coalesce(nullif(current_setting('snowstead.eviction_reason',true),''),'clear')
  FROM sccache_entries WHERE cache_id=OLD.id AND generation=OLD.sccache_generation AND uploaded_at IS NOT NULL FOR UPDATE;
 END IF;
 RETURN NEW;
END $$;
--> statement-breakpoint
CREATE TRIGGER log_cache_reset BEFORE UPDATE OF go_generation,sccache_generation ON caches
 FOR EACH ROW EXECUTE FUNCTION log_cache_reset();
--> statement-breakpoint
CREATE FUNCTION log_cache_deletion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
 SELECT OLD.org_id,OLD.id,OLD.name,'go',action,size,last_accessed_at,'clear' FROM go_entries
 WHERE cache_id=OLD.id AND generation=OLD.go_generation AND uploaded_at IS NOT NULL FOR UPDATE;
 INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
 SELECT OLD.org_id,OLD.id,OLD.name,'sccache',action,size,last_accessed_at,'clear' FROM sccache_entries
 WHERE cache_id=OLD.id AND generation=OLD.sccache_generation AND uploaded_at IS NOT NULL FOR UPDATE;
 RETURN OLD;
END $$;
--> statement-breakpoint
CREATE TRIGGER log_cache_deletion BEFORE DELETE ON caches FOR EACH ROW EXECUTE FUNCTION log_cache_deletion();
