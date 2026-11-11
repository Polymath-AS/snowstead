-- Delegated scope is derived from authenticated resume, never client JSON.
ALTER TABLE push_jobs ADD COLUMN authorization_claims jsonb;
ALTER TABLE push_jobs ADD COLUMN work_id text;
ALTER TABLE push_jobs ADD COLUMN work_expires_at timestamptz;
ALTER TABLE push_jobs ADD COLUMN work_at timestamptz NOT NULL DEFAULT NOW();
ALTER TABLE push_jobs ADD COLUMN work_failures integer NOT NULL DEFAULT 0;
ALTER TABLE push_jobs ADD COLUMN work_blocked boolean NOT NULL DEFAULT false;
CREATE INDEX push_job_work ON push_jobs(work_at,id)
WHERE state='sealed' AND NOT work_blocked;
