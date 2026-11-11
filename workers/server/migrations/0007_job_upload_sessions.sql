-- Keep the job identity after manifest reclamation: a missing job must never
-- turn a delegated session into an unrestricted legacy upload.
ALTER TABLE upload_sessions ADD COLUMN push_job_id text;
CREATE INDEX upload_session_job ON upload_sessions(push_job_id)
WHERE push_job_id IS NOT NULL;
ALTER TABLE push_job_members ADD COLUMN session_id text
REFERENCES upload_sessions(id) ON DELETE SET NULL;
