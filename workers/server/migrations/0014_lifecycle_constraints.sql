-- Name the persisted state machines. src/lifecycle.rs documents each state and
-- its transitions, and its tests fail when an enum and its list here differ.
--
-- NOT VALID: existing rows are not scanned, so an unknown value written by a
-- retired release cannot fail this migration. New and updated rows are checked.

-- pending, uploading, and completing were written only by the retired
-- TypeScript service. They stay allowed: its unfinished canonical multipart
-- sessions are never reclaimed automatically, so such rows can still exist.
ALTER TABLE upload_sessions ADD CONSTRAINT upload_sessions_status_valid CHECK (
    status IN (
        'pending', 'uploading', 'completing',
        'streaming', 'finalizing', 'completed', 'aborted', 'expired'
    )
) NOT VALID;

-- copying was written only by the retired TypeScript service, whose canonical
-- installations have no expiry.
ALTER TABLE nar_installations ADD CONSTRAINT nar_installations_phase_valid CHECK (
    phase IN ('preparing', 'ready', 'copying', 'revoked', 'legacy-unresolved')
) NOT VALID;

ALTER TABLE cache_signing_keys ADD CONSTRAINT cache_signing_keys_state_valid CHECK (
    state IN ('staged', 'active', 'retired')
) NOT VALID;

-- A counted policy without a count would pin nothing but the current revision.
ALTER TABLE pins ADD CONSTRAINT pins_keep_valid CHECK (
    (keep_kind = 'forever' AND keep_value IS NULL)
    OR (keep_kind IN ('revisions', 'days') AND keep_value >= 1)
) NOT VALID;

-- Path withdrawal, eviction protection, and the published_paths delete trigger
-- all look sessions up by path. Sessions are removed soon after they expire,
-- so the table stays small enough to build this inside the transaction.
CREATE INDEX IF NOT EXISTS upload_sessions_cache_path
ON upload_sessions (cache_id, store_path_hash);

-- Activation retires the previous key before activating the next, under the
-- cache's row lock, so one active key per cache holds even mid-transaction.
-- A database which already violates that keeps working without the index: it
-- is reported here for repair, not allowed to fail the deployment.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM cache_signing_keys
        WHERE state = 'active'
        GROUP BY cache_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE WARNING 'cache_signing_keys_one_active skipped: a cache has several active signing keys';
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS cache_signing_keys_one_active
        ON cache_signing_keys (cache_id)
        WHERE state = 'active';
    END IF;
END
$$;
