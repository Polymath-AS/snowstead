-- Execution expires independently of the client's upload session. Ready
-- candidates and legacy canonical operations do not need execution leases.
ALTER TABLE nar_installations ADD COLUMN lease_expires_at timestamptz;
UPDATE nar_installations
SET lease_expires_at = LEAST(expires_at, NOW() + INTERVAL '60 seconds')
WHERE session_id IS NOT NULL AND phase = 'preparing';
