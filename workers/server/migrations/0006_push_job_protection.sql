CREATE INDEX push_job_protection ON push_jobs(cache_id,id)
WHERE state='sealed' AND authorization_jti IS NOT NULL;

-- Temporary protection is not a permanent pin. Explicit withdrawal bypasses
-- this function and cancels affected jobs under the organization fence.
CREATE FUNCTION nix_job_protected_paths(org text, at_time timestamptz)
RETURNS TABLE(cache_id integer, store_path_hash text) LANGUAGE sql STABLE AS $$
  SELECT p.cache_id,p.store_path_hash FROM caches c
  JOIN push_jobs j ON j.cache_id=c.id
  JOIN push_job_members m ON m.job_id=j.id
  JOIN api_tokens t ON t.jti=j.authorization_jti
  JOIN published_paths p ON p.cache_id=j.cache_id AND p.store_path_hash=m.store_path_hash
  WHERE c.org_id=org
   AND j.state='sealed' AND j.authorization_jti IS NOT NULL
   AND j.idle_expires_at>at_time AND j.hard_expires_at>at_time
   AND j.authorization_expires_at>at_time AND t.revoked_at IS NULL
   AND m.metadata->>'storePath'=p.store_path
   AND m.metadata->>'narHash'=p.nar_hash
   AND (m.metadata->>'narSize')::bigint=p.nar_size
   AND (m.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver
   AND p.references_json::jsonb @> (m.metadata->'references')
   AND (m.metadata->'references') @> p.references_json::jsonb
$$;
