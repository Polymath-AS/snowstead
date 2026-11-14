-- Narinfo and nix-cache-info are rendered from SQL. The earlier service wrote
-- them to storage, and those objects were retired one path at a time whenever
-- a publication was withdrawn. Queue every key a current publication or cache
-- could still own, once, so withdrawals stop doing per-path cleanup. Queued
-- keys that never existed are deleted harmlessly.
WITH routes AS (
    SELECT c.id AS cache_id,
        CASE WHEN s.slug = 'default' THEN c.name ELSE s.slug || '/' || c.name END AS path
    FROM caches c
    JOIN orgs o ON o.id = c.org_id
    CROSS JOIN LATERAL (
        SELECT DISTINCT slug FROM unnest(ARRAY[o.slug, o.moving_from]) AS slug WHERE slug IS NOT NULL
    ) s
)
INSERT INTO object_cleanup (is_private, key)
SELECT placement.is_private, placement.prefix || r.path || '/' || p.store_path_hash || '.narinfo'
FROM published_paths p
JOIN routes r ON r.cache_id = p.cache_id
CROSS JOIN (VALUES (FALSE, ''), (TRUE, 'narinfo/')) AS placement(is_private, prefix)
UNION ALL
SELECT FALSE, r.path || '/nix-cache-info' FROM routes r
ON CONFLICT DO NOTHING;
