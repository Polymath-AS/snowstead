-- Publication never writes SQL. Maintenance records approximate usage separately.
ALTER TABLE cache_protocols DROP CONSTRAINT cache_protocols_protocol_valid;
ALTER TABLE cache_protocols ADD CONSTRAINT cache_protocols_protocol_valid
    CHECK (protocol IN ('nix', 'go', 'sccache', 'bazel'));
ALTER TABLE token_permissions DROP CONSTRAINT token_permissions_permission_check;
ALTER TABLE token_permissions ADD CONSTRAINT token_permissions_permission_check
    CHECK (permission IN ('pull', 'push', 'go:read', 'go:write',
        'sccache:read', 'sccache:write', 'bazel:read', 'bazel:write'));

CREATE TABLE bazel_caches (
    cache_id integer PRIMARY KEY REFERENCES caches(id) ON DELETE CASCADE,
    generation text NOT NULL UNIQUE,
    capacity bigint NOT NULL CHECK (capacity >= 0)
);

CREATE TABLE bazel_usage (
    cache_id integer PRIMARY KEY REFERENCES caches(id) ON DELETE CASCADE,
    generation text NOT NULL,
    entries bigint NOT NULL,
    size bigint NOT NULL,
    physical_size bigint NOT NULL,
    staging_size bigint NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Bazel shares the storage left by the existing products. These are soft
-- targets, recomputed at collection time, including after a tier downgrade.
CREATE VIEW bazel_retention AS
WITH usage AS (
    SELECT org_id, SUM(size)::bigint AS size FROM (
        SELECT org_id, size FROM caches
        UNION ALL
        SELECT c.org_id, e.size FROM go_entries e JOIN caches c ON c.id=e.cache_id
            WHERE e.generation=c.go_generation AND e.uploaded_at IS NOT NULL AND e.expires_at>NOW()
        UNION ALL
        SELECT c.org_id, e.size FROM sccache_entries e JOIN caches c ON c.id=e.cache_id
            WHERE e.generation=c.sccache_generation AND e.uploaded_at IS NOT NULL AND e.expires_at>NOW()
    ) entries GROUP BY org_id
)
SELECT b.cache_id, b.generation, b.capacity,
    LEAST(b.capacity, CASE WHEN o.storage_limit IS NULL THEN b.capacity
        ELSE GREATEST(0, o.storage_limit - COALESCE(u.size, 0)) /
            COUNT(*) OVER (PARTITION BY o.id) END)::bigint AS target
FROM bazel_caches b JOIN caches c ON c.id=b.cache_id
JOIN orgs o ON o.id=c.org_id LEFT JOIN usage u ON u.org_id=o.id;
