-- Logical content identity stays deduplicated. Each bucket points to an
-- immutable physical incarnation; old canonical objects remain readable.
ALTER TABLE blob_objects ADD COLUMN public_key text;
ALTER TABLE blob_objects ADD COLUMN private_key text;

-- Replays return the committed outcome, even after its path is withdrawn.
ALTER TABLE upload_sessions ADD COLUMN publication_result jsonb;

-- NULL ownership/expiry denotes a legacy canonical operation. These records
-- must never expire automatically: provider completion can remain ambiguous.
ALTER TABLE nar_installations ADD COLUMN cache_id integer;
ALTER TABLE nar_installations ADD COLUMN session_id text;
ALTER TABLE nar_installations ADD COLUMN expires_at timestamptz;
CREATE UNIQUE INDEX nar_installation_session ON nar_installations(session_id)
WHERE session_id IS NOT NULL;
CREATE INDEX nar_installation_cache ON nar_installations(cache_id);

CREATE FUNCTION invalidate_deleted_publications() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE nar_installations i SET phase = 'revoked'
    FROM upload_sessions u, removed r
    WHERE i.session_id = u.id AND u.cache_id = r.cache_id
        AND u.store_path_hash = r.store_path_hash;
    UPDATE upload_sessions u SET status = 'aborted'
    FROM removed r WHERE u.cache_id = r.cache_id
        AND u.store_path_hash = r.store_path_hash AND u.status <> 'completed';
    RETURN NULL;
END;
$$;
CREATE TRIGGER invalidate_deleted_publications AFTER DELETE ON published_paths
REFERENCING OLD TABLE AS removed FOR EACH STATEMENT
EXECUTE FUNCTION invalidate_deleted_publications();

-- A key enters this queue only after it can never be adopted again. Keys are
-- never reused. A late provider completion is found by the orphan sweeper.
CREATE TABLE object_cleanup (
    id bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    is_private boolean NOT NULL,
    key text NOT NULL,
    upload_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (is_private, key)
);
