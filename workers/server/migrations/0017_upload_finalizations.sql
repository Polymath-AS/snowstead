-- SQL owns admitted work; process-local tasks are only consumers.
CREATE TABLE upload_finalization_batches (
    id text PRIMARY KEY,
    org_id text NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor text NOT NULL,
    token_jti text REFERENCES api_tokens(jti) ON DELETE SET NULL,
    shared_generation text,
    job_id text,
    grant_generation bigint,
    prepare_only boolean NOT NULL,
    admitted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    expires_at timestamptz NOT NULL,
    work_id text,
    lease_expires_at timestamptz,
    work_at timestamptz NOT NULL DEFAULT NOW(),
    failures integer NOT NULL DEFAULT 0
);
CREATE TABLE upload_finalizations (
    session_id text PRIMARY KEY REFERENCES upload_sessions(id) ON DELETE CASCADE,
    batch_id text NOT NULL REFERENCES upload_finalization_batches(id) ON DELETE CASCADE,
    ordinal integer NOT NULL,
    receipt jsonb NOT NULL,
    result jsonb
);
CREATE INDEX upload_finalization_batch_members ON upload_finalizations(batch_id,ordinal);
CREATE INDEX upload_finalization_work ON upload_finalization_batches(work_at,org_id);
