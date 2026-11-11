ALTER TABLE push_jobs DROP CONSTRAINT push_jobs_state_check;
ALTER TABLE push_jobs ADD CONSTRAINT push_jobs_state_check CHECK (state IN ('building','sealed','cancelled'));
ALTER TABLE push_jobs ADD COLUMN authorization_jti text REFERENCES api_tokens(jti) ON DELETE SET NULL;
ALTER TABLE push_jobs ADD COLUMN authorization_expires_at timestamptz;
ALTER TABLE push_jobs ADD COLUMN grant_generation bigint NOT NULL DEFAULT 0;
CREATE INDEX push_job_authorization ON push_jobs(authorization_jti) WHERE authorization_jti IS NOT NULL;
