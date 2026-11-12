-- Database-backed API token scope. Each token's permissions and cache grants
-- live only in token_permissions and token_caches; authentication reads them
-- on every request. New tokens are opaque (snowstead_tok_<jti>_<secret>) and
-- store only a SHA-256 hex digest of their secret. Rows from the JWT era keep
-- secret_hash NULL: such a JWT is accepted only while its row is listed and
-- unrevoked, and its signed claims no longer grant anything.
--
-- Additive: the previous release keeps working against this schema, so apply
-- it before deploying the server that reads it. caches_json and perms_json
-- are no longer written or read; drop them once no release that reads them
-- can be rolled back to.

ALTER TABLE api_tokens ADD COLUMN secret_hash text;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_secret_hash_valid
    CHECK (secret_hash IS NULL OR secret_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE api_tokens ALTER COLUMN perms_json SET DEFAULT '[]';

CREATE TABLE token_permissions (
    token_jti text NOT NULL REFERENCES api_tokens(jti) ON DELETE CASCADE,
    permission text NOT NULL CHECK (
        permission IN ('pull', 'push', 'go:read', 'go:write', 'sccache:read', 'sccache:write')
    ),
    -- The order the token was created with, for listings.
    position integer NOT NULL,
    PRIMARY KEY (token_jti, permission)
);

-- A row whose JSON is invalid or not an array backfills nothing, so that
-- token is denied rather than widened. docs.md lists the query that finds
-- live JWT-era tokens left without permissions or caches.
CREATE FUNCTION pg_temp.json_array_or_empty(value text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    parsed jsonb;
BEGIN
    parsed := value::jsonb;
    RETURN CASE WHEN jsonb_typeof(parsed) = 'array' THEN parsed ELSE '[]'::jsonb END;
EXCEPTION WHEN others THEN
    RETURN '[]'::jsonb;
END
$$;

-- Backfill from the claims each JWT-era row recorded when it was issued.
-- Unknown permissions were never accepted by the verifier and are skipped.
INSERT INTO token_permissions (token_jti, permission, position)
SELECT t.jti, p.permission, MIN(p.position)
FROM api_tokens t
CROSS JOIN LATERAL jsonb_array_elements_text(pg_temp.json_array_or_empty(t.perms_json)) WITH ORDINALITY AS p(permission, position)
WHERE p.permission IN ('pull', 'push', 'go:read', 'go:write', 'sccache:read', 'sccache:write')
GROUP BY t.jti, p.permission;

-- token_caches has been written alongside every token the Rust service
-- issued. Older rows that have none get theirs from caches_json: "id:<n>" is
-- a grant of that cache, anything else a name pattern, as the verifier read
-- them. Grants of caches that no longer exist grant nothing and are skipped.
INSERT INTO token_caches (token_jti, cache_id, pattern)
SELECT g.jti, g.cache_id, g.pattern
FROM (
    SELECT
        t.jti,
        e.position,
        CASE WHEN e.entry ~ '^id:[0-9]{1,9}$' THEN substr(e.entry, 4)::integer END AS cache_id,
        CASE WHEN e.entry !~ '^id:[0-9]{1,9}$' THEN e.entry END AS pattern
    FROM api_tokens t
    CROSS JOIN LATERAL jsonb_array_elements_text(pg_temp.json_array_or_empty(t.caches_json)) WITH ORDINALITY AS e(entry, position)
    WHERE e.entry <> ''
        AND NOT EXISTS (SELECT 1 FROM token_caches tc WHERE tc.token_jti = t.jti)
) g
WHERE g.cache_id IS NULL OR EXISTS (SELECT 1 FROM caches c WHERE c.id = g.cache_id)
ORDER BY g.jti, g.position
ON CONFLICT DO NOTHING;
