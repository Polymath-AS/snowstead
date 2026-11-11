-- Bound staging admission to each cache's active uploads, including before
-- statistics catch up with a growing history of completed sessions.
CREATE INDEX upload_sessions_staging_cache ON upload_sessions(cache_id)
WHERE status IN ('streaming','finalizing');
