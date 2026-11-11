-- Unprepared manifests must not add one candidate probe per member to every
-- worker poll. Only linked sessions can have a ready installation.
CREATE INDEX push_job_member_session ON push_job_members(job_id,session_id)
WHERE session_id IS NOT NULL;
