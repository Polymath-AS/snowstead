CREATE TABLE push_jobs (
    id text PRIMARY KEY,
    cache_id integer NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
    creator text NOT NULL,
    idempotency_key text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('closure','selected')),
    roots jsonb NOT NULL,
    state text NOT NULL DEFAULT 'building' CHECK (state IN ('building','sealed')),
    revision integer NOT NULL DEFAULT 0,
    manifest_digest text,
    manifest_bytes integer NOT NULL,
    input_members integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    idle_expires_at timestamptz NOT NULL DEFAULT NOW() + INTERVAL '30 minutes',
    hard_expires_at timestamptz NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    UNIQUE(cache_id,creator,idempotency_key)
);
CREATE INDEX push_job_expiry ON push_jobs(idle_expires_at);
CREATE INDEX push_job_hard_expiry ON push_jobs(hard_expires_at);
CREATE TABLE push_manifest_chunks (
    job_id text NOT NULL REFERENCES push_jobs(id) ON DELETE CASCADE,
    ordinal integer NOT NULL CHECK (ordinal>=0),
    members jsonb NOT NULL,
    PRIMARY KEY(job_id,ordinal)
);
CREATE TABLE push_job_members (
    job_id text NOT NULL REFERENCES push_jobs(id) ON DELETE CASCADE,
    store_path_hash text NOT NULL,
    metadata jsonb NOT NULL,
    PRIMARY KEY(job_id,store_path_hash)
);
