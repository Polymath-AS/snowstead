-- Current schema baseline, consolidated from migrations 0000 through 0014.
-- Legacy SQLx checksums are frozen in ../migration-history.json.

CREATE TABLE public.api_tokens (
    jti text NOT NULL,
    subject text NOT NULL,
    caches_json text DEFAULT '[]'::text NOT NULL,
    perms_json text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    created_by text NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by text,
    revocation_reason text,
    org_id text,
    last_used_at timestamp with time zone
);

CREATE TABLE public.audit_logs (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    actor text NOT NULL,
    action text NOT NULL,
    cache_name text,
    detail text DEFAULT '{}'::text NOT NULL,
    ip text,
    status integer NOT NULL,
    org_id text
);

ALTER TABLE public.audit_logs ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.audit_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.bandwidth_daily (
    org_id text NOT NULL,
    day date NOT NULL,
    bytes bigint DEFAULT 0 NOT NULL,
    cache_id integer DEFAULT 0 NOT NULL,
    product text NOT NULL,
    public_bytes bigint DEFAULT 0 NOT NULL,
    imported_at timestamp with time zone,
    CONSTRAINT bandwidth_daily_product_valid CHECK ((product = ANY (ARRAY['nix'::text, 'go'::text, 'sccache'::text])))
);

CREATE TABLE public.blob_objects (
    id bigint NOT NULL,
    file_hash text NOT NULL,
    file_size bigint NOT NULL,
    compression text NOT NULL,
    r2_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE public.blob_objects ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.blob_objects_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.cache_protocols (
    cache_id integer NOT NULL,
    protocol text NOT NULL,
    CONSTRAINT cache_protocols_protocol_valid CHECK ((protocol = ANY (ARRAY['nix'::text, 'go'::text, 'sccache'::text])))
);

CREATE TABLE public.cache_signing_keys (
    id text NOT NULL,
    cache_id integer NOT NULL,
    signing_key_name text NOT NULL,
    signing_public_key text NOT NULL,
    signing_key_sealed text,
    state text DEFAULT 'staged'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    managed_public_key text
);

CREATE TABLE public.caches (
    id integer NOT NULL,
    name text NOT NULL,
    is_public boolean DEFAULT true NOT NULL,
    org_id text DEFAULT 'default'::text NOT NULL,
    signing_key_name text,
    signing_public_key text,
    signing_key_sealed text,
    retention_days integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    path_count bigint DEFAULT 0 NOT NULL,
    size bigint DEFAULT 0 NOT NULL,
    go_generation text DEFAULT '0'::text NOT NULL,
    sccache_generation text DEFAULT '0'::text NOT NULL
);

ALTER TABLE public.caches ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.caches_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.eviction_logs (
    id bigint NOT NULL,
    org_id text NOT NULL,
    cache_id integer NOT NULL,
    cache text NOT NULL,
    product text NOT NULL,
    key text NOT NULL,
    size bigint NOT NULL,
    last_accessed_at timestamp with time zone,
    evicted_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text NOT NULL
);

ALTER TABLE public.eviction_logs ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.eviction_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.gc_marks (
    id bigint NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    reason text NOT NULL,
    marked_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE public.gc_marks ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.gc_marks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.go_entries (
    id text NOT NULL,
    cache_id integer,
    generation text NOT NULL,
    action text NOT NULL,
    r2_key text NOT NULL,
    size bigint NOT NULL,
    output text NOT NULL,
    uploaded_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    last_accessed_at timestamp with time zone,
    stored_at timestamp with time zone
);

CREATE TABLE public.nar_installations (
    key text NOT NULL,
    operation_id text NOT NULL,
    source_key text NOT NULL,
    upload_id text,
    file_hash text NOT NULL,
    compression text NOT NULL,
    is_private boolean NOT NULL,
    file_size bigint NOT NULL,
    phase text DEFAULT 'preparing'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.org_api_keys (
    id text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    secret_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone
);

CREATE TABLE public.orgs (
    id text NOT NULL,
    slug text NOT NULL,
    moving_from text,
    storage_limit bigint,
    private_caches boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    custom_signing_keys boolean DEFAULT false NOT NULL
);

CREATE TABLE public.pin_paths (
    revision_id text NOT NULL,
    cache_id integer NOT NULL,
    store_path_hash text NOT NULL
);

CREATE TABLE public.pin_revisions (
    id text NOT NULL,
    pin_id text NOT NULL,
    revision integer NOT NULL,
    store_path text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    superseded_at timestamp with time zone
);

CREATE TABLE public.pins (
    id text NOT NULL,
    cache_id integer NOT NULL,
    name text NOT NULL,
    keep_kind text NOT NULL,
    keep_value integer,
    current_revision integer NOT NULL
);

CREATE TABLE public.published_paths (
    id bigint NOT NULL,
    cache_id integer NOT NULL,
    store_path_hash text NOT NULL,
    store_path text NOT NULL,
    nar_hash text NOT NULL,
    nar_size bigint NOT NULL,
    blob_object_id bigint NOT NULL,
    references_json text DEFAULT '[]'::text NOT NULL,
    deriver text,
    system text,
    signatures_json text DEFAULT '[]'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_pushed_at timestamp with time zone DEFAULT now() NOT NULL,
    last_accessed_at timestamp with time zone
);

ALTER TABLE public.published_paths ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.published_paths_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.sccache_entries (
    id text NOT NULL,
    cache_id integer,
    generation text NOT NULL,
    action text NOT NULL,
    r2_key text NOT NULL,
    size bigint NOT NULL,
    uploaded_at timestamp with time zone,
    last_accessed_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    stored_at timestamp with time zone
);

CREATE TABLE public.sccache_usage (
    cache_id integer NOT NULL,
    generation text NOT NULL,
    expires_minute timestamp with time zone NOT NULL,
    used bigint NOT NULL,
    pending bigint NOT NULL
);

CREATE TABLE public.token_caches (
    id bigint NOT NULL,
    token_jti text NOT NULL,
    cache_id integer,
    pattern text,
    CONSTRAINT token_caches_cache_or_pattern CHECK (((cache_id IS NULL) <> (pattern IS NULL)))
);

ALTER TABLE public.token_caches ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.token_caches_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.upload_parts (
    id bigint NOT NULL,
    session_id text NOT NULL,
    part_number integer NOT NULL,
    etag text,
    size bigint NOT NULL,
    storage_key text
);

ALTER TABLE public.upload_parts ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.upload_parts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.upload_sessions (
    id text NOT NULL,
    cache_id integer NOT NULL,
    store_path_hash text NOT NULL,
    store_path text NOT NULL,
    nar_hash text NOT NULL,
    nar_size bigint NOT NULL,
    file_hash text,
    file_size bigint NOT NULL,
    compression text NOT NULL,
    references_json text DEFAULT '[]'::text NOT NULL,
    deriver text,
    system text,
    status text DEFAULT 'pending'::text NOT NULL,
    r2_upload_key text,
    r2_upload_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    part_size integer,
    staging_capacity bigint
);

CREATE TABLE public.upstream_paths (
    store_path_hash text NOT NULL,
    upstream text NOT NULL,
    found_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE FUNCTION public.log_action_evictions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION public.log_cache_deletion() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
 SELECT OLD.org_id,OLD.id,OLD.name,'go',action,size,last_accessed_at,'clear' FROM go_entries
 WHERE cache_id=OLD.id AND generation=OLD.go_generation AND uploaded_at IS NOT NULL FOR UPDATE;
 INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
 SELECT OLD.org_id,OLD.id,OLD.name,'sccache',action,size,last_accessed_at,'clear' FROM sccache_entries
 WHERE cache_id=OLD.id AND generation=OLD.sccache_generation AND uploaded_at IS NOT NULL FOR UPDATE;
 RETURN OLD;
END $$;

CREATE FUNCTION public.log_cache_reset() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION public.log_nix_evictions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 INSERT INTO eviction_logs (org_id,cache_id,cache,product,key,size,last_accessed_at,reason)
 SELECT c.org_id,c.id,c.name,'nix',e.store_path,b.file_size,e.last_accessed_at,
  coalesce(nullif(current_setting('snowstead.eviction_reason',true),''),'clear')
 FROM removed e JOIN caches c ON c.id=e.cache_id JOIN blob_objects b ON b.id=e.blob_object_id;
 RETURN NULL;
END $$;

CREATE FUNCTION public.nix_path_pinned(cache integer, hash text, at_time timestamp with time zone) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
 SELECT EXISTS (
  SELECT 1 FROM pin_paths m JOIN pin_revisions r ON r.id=m.revision_id JOIN pins p ON p.id=r.pin_id
  WHERE m.cache_id=cache AND m.store_path_hash=hash AND (
   r.revision=p.current_revision OR p.keep_kind='forever'
   OR (p.keep_kind='revisions' AND r.revision>p.current_revision-p.keep_value)
   OR (p.keep_kind='days' AND r.superseded_at>at_time-p.keep_value*interval '1 day')
  )
 )
$$;

CREATE FUNCTION public.published_paths_totals() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION public.sccache_usage_delta() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (jti);

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.bandwidth_daily
    ADD CONSTRAINT bandwidth_daily_org_id_cache_id_product_day_pk PRIMARY KEY (org_id, cache_id, product, day);

ALTER TABLE ONLY public.blob_objects
    ADD CONSTRAINT blob_objects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.blob_objects
    ADD CONSTRAINT blob_objects_r2_key_unique UNIQUE (r2_key);

ALTER TABLE ONLY public.cache_protocols
    ADD CONSTRAINT cache_protocols_cache_id_protocol_pk PRIMARY KEY (cache_id, protocol);

ALTER TABLE ONLY public.cache_signing_keys
    ADD CONSTRAINT cache_signing_keys_managed_public_key_unique UNIQUE (managed_public_key);

ALTER TABLE ONLY public.cache_signing_keys
    ADD CONSTRAINT cache_signing_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.caches
    ADD CONSTRAINT caches_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.eviction_logs
    ADD CONSTRAINT eviction_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.gc_marks
    ADD CONSTRAINT gc_marks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.go_entries
    ADD CONSTRAINT go_entries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.go_entries
    ADD CONSTRAINT go_entries_r2_key_unique UNIQUE (r2_key);

ALTER TABLE ONLY public.nar_installations
    ADD CONSTRAINT nar_installations_pkey PRIMARY KEY (key);

ALTER TABLE ONLY public.org_api_keys
    ADD CONSTRAINT org_api_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.orgs
    ADD CONSTRAINT orgs_moving_from_unique UNIQUE (moving_from);

ALTER TABLE ONLY public.orgs
    ADD CONSTRAINT orgs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.orgs
    ADD CONSTRAINT orgs_slug_unique UNIQUE (slug);

ALTER TABLE ONLY public.pin_paths
    ADD CONSTRAINT pin_paths_revision_id_store_path_hash_pk PRIMARY KEY (revision_id, store_path_hash);

ALTER TABLE ONLY public.pin_revisions
    ADD CONSTRAINT pin_revisions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.pins
    ADD CONSTRAINT pins_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.published_paths
    ADD CONSTRAINT published_paths_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sccache_entries
    ADD CONSTRAINT sccache_entries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sccache_entries
    ADD CONSTRAINT sccache_entries_r2_key_unique UNIQUE (r2_key);

ALTER TABLE ONLY public.sccache_usage
    ADD CONSTRAINT sccache_usage_cache_id_generation_expires_minute_pk PRIMARY KEY (cache_id, generation, expires_minute);

ALTER TABLE ONLY public.token_caches
    ADD CONSTRAINT token_caches_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.upload_parts
    ADD CONSTRAINT upload_parts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.upload_sessions
    ADD CONSTRAINT upload_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.upstream_paths
    ADD CONSTRAINT upstream_paths_pkey PRIMARY KEY (store_path_hash);

CREATE UNIQUE INDEX blob_objects_file_hash_compression_unique ON public.blob_objects USING btree (file_hash, compression);

CREATE UNIQUE INDEX cache_signing_keys_name ON public.cache_signing_keys USING btree (cache_id, signing_key_name);

CREATE UNIQUE INDEX caches_org_name_unique ON public.caches USING btree (org_id, name);

CREATE INDEX eviction_logs_expiry ON public.eviction_logs USING btree (evicted_at);

CREATE INDEX eviction_logs_org_page ON public.eviction_logs USING btree (org_id, id);

CREATE UNIQUE INDEX gc_marks_target_unique ON public.gc_marks USING btree (target_type, target_id);

CREATE UNIQUE INDEX go_entries_action ON public.go_entries USING btree (cache_id, generation, action);

CREATE INDEX go_entries_expiry ON public.go_entries USING btree (expires_at);

CREATE INDEX idx_api_tokens_org ON public.api_tokens USING btree (org_id);

CREATE INDEX idx_audit_logs_actor ON public.audit_logs USING btree (actor);

CREATE INDEX idx_audit_logs_cache ON public.audit_logs USING btree (cache_name);

CREATE INDEX idx_audit_logs_org ON public.audit_logs USING btree (org_id, id);

CREATE INDEX idx_audit_logs_time ON public.audit_logs USING btree ("timestamp");

CREATE INDEX idx_bandwidth_daily_cache ON public.bandwidth_daily USING btree (cache_id, day);

CREATE INDEX idx_go_entries_lru ON public.go_entries USING btree (cache_id, GREATEST(uploaded_at, last_accessed_at));

CREATE INDEX idx_org_api_keys_org ON public.org_api_keys USING btree (org_id);

CREATE INDEX idx_published_paths_blob_object ON public.published_paths USING btree (blob_object_id);

CREATE INDEX idx_published_paths_cache_pushed ON public.published_paths USING btree (cache_id, last_pushed_at);

CREATE INDEX idx_published_paths_lru ON public.published_paths USING btree (cache_id, GREATEST(last_pushed_at, last_accessed_at));

CREATE INDEX idx_token_caches_cache ON public.token_caches USING btree (cache_id);

CREATE INDEX idx_upload_sessions_status ON public.upload_sessions USING btree (status, expires_at);

CREATE INDEX pin_paths_lookup ON public.pin_paths USING btree (cache_id, store_path_hash);

CREATE UNIQUE INDEX pin_revisions_number ON public.pin_revisions USING btree (pin_id, revision);

CREATE UNIQUE INDEX pins_cache_name ON public.pins USING btree (cache_id, name);

CREATE UNIQUE INDEX published_paths_cache_store_unique ON public.published_paths USING btree (cache_id, store_path_hash);

CREATE UNIQUE INDEX sccache_entries_action ON public.sccache_entries USING btree (cache_id, generation, action);

CREATE INDEX sccache_entries_expiry ON public.sccache_entries USING btree (expires_at);

CREATE INDEX sccache_entries_lru ON public.sccache_entries USING btree (cache_id, generation, GREATEST(uploaded_at, last_accessed_at), id) WHERE (uploaded_at IS NOT NULL);

CREATE INDEX sccache_entries_quota_expiry ON public.sccache_entries USING btree (cache_id, generation, expires_at);

CREATE INDEX sccache_entries_staging ON public.sccache_entries USING btree (cache_id, expires_at) WHERE (uploaded_at IS NULL);

CREATE UNIQUE INDEX token_caches_token_cache ON public.token_caches USING btree (token_jti, cache_id);

CREATE UNIQUE INDEX token_caches_token_pattern ON public.token_caches USING btree (token_jti, pattern);

CREATE UNIQUE INDEX upload_parts_session_part_unique ON public.upload_parts USING btree (session_id, part_number);

CREATE TRIGGER log_cache_deletion BEFORE DELETE ON public.caches FOR EACH ROW EXECUTE FUNCTION public.log_cache_deletion();

CREATE TRIGGER log_cache_reset BEFORE UPDATE OF go_generation, sccache_generation ON public.caches FOR EACH ROW EXECUTE FUNCTION public.log_cache_reset();

CREATE TRIGGER log_go_detach AFTER UPDATE ON public.go_entries REFERENCING OLD TABLE AS removed NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.log_action_evictions('go', 'go_generation');

CREATE TRIGGER log_go_removal AFTER DELETE ON public.go_entries REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION public.log_action_evictions('go', 'go_generation');

CREATE TRIGGER log_nix_evictions AFTER DELETE ON public.published_paths REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION public.log_nix_evictions();

CREATE TRIGGER log_sccache_detach AFTER UPDATE ON public.sccache_entries REFERENCING OLD TABLE AS removed NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.log_action_evictions('sccache', 'sccache_generation');

CREATE TRIGGER log_sccache_removal AFTER DELETE ON public.sccache_entries REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION public.log_action_evictions('sccache', 'sccache_generation');

CREATE TRIGGER published_paths_totals_delete AFTER DELETE ON public.published_paths REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION public.published_paths_totals();

CREATE TRIGGER published_paths_totals_insert AFTER INSERT ON public.published_paths REFERENCING NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.published_paths_totals();

CREATE TRIGGER sccache_usage_delete AFTER DELETE ON public.sccache_entries REFERENCING OLD TABLE AS removed FOR EACH STATEMENT EXECUTE FUNCTION public.sccache_usage_delta();

CREATE TRIGGER sccache_usage_insert AFTER INSERT ON public.sccache_entries REFERENCING NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.sccache_usage_delta();

CREATE TRIGGER sccache_usage_update AFTER UPDATE ON public.sccache_entries REFERENCING OLD TABLE AS removed NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.sccache_usage_delta();

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_org_id_orgs_id_fk FOREIGN KEY (org_id) REFERENCES public.orgs(id);

ALTER TABLE ONLY public.bandwidth_daily
    ADD CONSTRAINT bandwidth_daily_org_id_orgs_id_fk FOREIGN KEY (org_id) REFERENCES public.orgs(id);

ALTER TABLE ONLY public.cache_protocols
    ADD CONSTRAINT cache_protocols_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.cache_signing_keys
    ADD CONSTRAINT cache_signing_keys_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.caches
    ADD CONSTRAINT caches_org_id_orgs_id_fk FOREIGN KEY (org_id) REFERENCES public.orgs(id);

ALTER TABLE ONLY public.go_entries
    ADD CONSTRAINT go_entries_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.org_api_keys
    ADD CONSTRAINT org_api_keys_org_id_orgs_id_fk FOREIGN KEY (org_id) REFERENCES public.orgs(id);

ALTER TABLE ONLY public.pin_paths
    ADD CONSTRAINT pin_paths_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.pin_paths
    ADD CONSTRAINT pin_paths_revision_id_pin_revisions_id_fk FOREIGN KEY (revision_id) REFERENCES public.pin_revisions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.pin_revisions
    ADD CONSTRAINT pin_revisions_pin_id_pins_id_fk FOREIGN KEY (pin_id) REFERENCES public.pins(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.pins
    ADD CONSTRAINT pins_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.published_paths
    ADD CONSTRAINT published_paths_blob_object_id_blob_objects_id_fk FOREIGN KEY (blob_object_id) REFERENCES public.blob_objects(id);

ALTER TABLE ONLY public.published_paths
    ADD CONSTRAINT published_paths_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id);

ALTER TABLE ONLY public.sccache_entries
    ADD CONSTRAINT sccache_entries_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.sccache_usage
    ADD CONSTRAINT sccache_usage_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.token_caches
    ADD CONSTRAINT token_caches_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.token_caches
    ADD CONSTRAINT token_caches_token_jti_api_tokens_jti_fk FOREIGN KEY (token_jti) REFERENCES public.api_tokens(jti) ON DELETE CASCADE;

ALTER TABLE ONLY public.upload_parts
    ADD CONSTRAINT upload_parts_session_id_upload_sessions_id_fk FOREIGN KEY (session_id) REFERENCES public.upload_sessions(id);

ALTER TABLE ONLY public.upload_sessions
    ADD CONSTRAINT upload_sessions_cache_id_caches_id_fk FOREIGN KEY (cache_id) REFERENCES public.caches(id);

-- The operator's self-hosted namespace is not a hosted plan.
INSERT INTO public.orgs (id, slug, custom_signing_keys) VALUES ('default', 'default', true);
