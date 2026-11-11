-- Scheduling hints only. Publication revalidates dependencies under its fences.
ALTER TABLE push_job_members ADD COLUMN publication_order integer NOT NULL DEFAULT 0;
ALTER TABLE upload_sessions ADD COLUMN publication_order integer NOT NULL DEFAULT 0;
CREATE INDEX upload_sessions_job_publication_order
    ON upload_sessions(push_job_id, publication_order, id)
    WHERE status='finalizing';
