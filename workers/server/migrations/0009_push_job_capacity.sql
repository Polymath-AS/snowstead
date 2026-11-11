ALTER TABLE push_jobs ADD COLUMN work_members integer NOT NULL DEFAULT 16
CHECK (work_members BETWEEN 1 AND 16);
-- Resume changes the authorization generation, making blocked members eligible
-- again without rewriting an entire manifest under the organization fence.
ALTER TABLE push_job_members ADD COLUMN blocked_generation bigint;
ALTER TABLE push_job_members ADD COLUMN publication_error text;
