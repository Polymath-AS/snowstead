//! Retained capacity is logical, across all three products. Callers hold the
//! org transaction lock through admission and publication. Physical orphan
//! reclamation is separate; SQL publication controls public narinfo visibility.
use std::collections::HashSet;

use crate::db::Transaction;
use axum::http::StatusCode;

use crate::error::ApiError;

struct Victim {
    kind: String,
    id: String,
    size: i64,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn admit(
    tx: &mut Transaction,
    org: &str,
    limit: i64,
    incoming_bytes: i64,
    protect: &[(i32, String)],
) -> Result<(), ApiError> {
    let caches: Vec<_> = protect.iter().map(|p| p.0).collect();
    let hashes: Vec<_> = protect.iter().map(|p| p.1.clone()).collect();
    let used = sqlx::query_scalar!(
        r#"
        SELECT COALESCE(SUM(n), 0)::bigint AS "used!"
        FROM (
            SELECT c.size AS n
            FROM caches c
            WHERE c.org_id = $1
            UNION ALL
            SELECT e.size
            FROM go_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.go_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
            UNION ALL
            SELECT e.size
            FROM sccache_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.sccache_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
        ) usage
        "#,
        org,
    )
    .fetch_one(&mut **tx)
    .await?;
    let total = used.saturating_add(incoming_bytes);
    if total <= limit {
        return Ok(());
    }
    let protected = sqlx::query_scalar!(
        r#"
        SELECT COALESCE(SUM(n), 0)::bigint AS "protected!"
        FROM (
            SELECT b.file_size AS n
            FROM published_paths e
            JOIN caches c ON c.id = e.cache_id
            JOIN blob_objects b ON b.id = e.blob_object_id
            WHERE c.org_id = $1
                AND EXISTS (
                    SELECT 1
                    FROM UNNEST($2::int[], $3::text[]) p(cache, hash)
                    WHERE p.cache = e.cache_id
                        AND p.hash = e.store_path_hash
                )
            UNION ALL
            SELECT e.size
            FROM go_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.go_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
                AND EXISTS (
                    SELECT 1
                    FROM UNNEST($2::int[], $3::text[]) p(cache, hash)
                    WHERE p.cache = e.cache_id
                        AND p.hash = 'go:' || e.id
                )
            UNION ALL
            SELECT e.size
            FROM sccache_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.sccache_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
                AND EXISTS (
                    SELECT 1
                    FROM UNNEST($2::int[], $3::text[]) p(cache, hash)
                    WHERE p.cache = e.cache_id
                        AND p.hash = 'sccache:' || e.id
                )
        ) protected
        "#,
        org,
        &caches,
        &hashes,
    )
    .fetch_one(&mut **tx)
    .await?;
    if protected.saturating_add(incoming_bytes) > limit {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Incoming objects exceed retained capacity",
        ));
    }
    // A bounded LRU candidate list, then three batched row-lock statements.
    // SKIP LOCKED excludes work being moved by another product's transfer.
    let candidates = sqlx::query_as!(
        Victim,
        r#"
        WITH active AS MATERIALIZED (
            SELECT
                u.cache_id,
                u.store_path_hash
            FROM upload_sessions u
            JOIN caches c ON c.id = u.cache_id
            WHERE c.org_id = $1
                AND (
                    u.status = 'finalizing'
                    OR (u.status IN ('pending', 'uploading', 'streaming') AND u.expires_at > NOW())
                )
        )
        SELECT
            kind AS "kind!",
            id AS "id!",
            size AS "size!"
        FROM (
            SELECT
                'nix' AS kind,
                e.id::text AS id,
                b.file_size AS size,
                GREATEST(e.last_pushed_at, e.last_accessed_at) AS used
            FROM published_paths e
            JOIN caches c ON c.id = e.cache_id
            JOIN blob_objects b ON b.id = e.blob_object_id
            WHERE c.org_id = $1
                AND NOT nix_path_pinned(e.cache_id, e.store_path_hash, NOW())
                AND NOT EXISTS (
                    SELECT 1 FROM nix_job_protected_paths($1, NOW()) j
                    WHERE j.cache_id=e.cache_id AND j.store_path_hash=e.store_path_hash
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM UNNEST($2::int[], $3::text[]) p(cache, hash)
                    WHERE p.cache = e.cache_id
                        AND p.hash = e.store_path_hash
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM active a
                    WHERE a.cache_id = e.cache_id
                        AND a.store_path_hash = e.store_path_hash
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM nar_installations i
                    WHERE i.file_hash = b.file_hash
                        AND i.compression = b.compression
                )
            UNION ALL
            SELECT
                'go',
                e.id,
                e.size,
                GREATEST(e.uploaded_at, e.last_accessed_at)
            FROM go_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.go_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
                AND NOT EXISTS (
                    SELECT 1
                    FROM UNNEST($2::int[], $3::text[]) p(cache, hash)
                    WHERE p.cache = e.cache_id
                        AND p.hash = 'go:' || e.id
                )
            UNION ALL
            SELECT
                'sccache',
                e.id,
                e.size,
                GREATEST(e.uploaded_at, e.last_accessed_at)
            FROM sccache_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.sccache_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
                AND NOT EXISTS (
                    SELECT 1
                    FROM UNNEST($2::int[], $3::text[]) p(cache, hash)
                    WHERE p.cache = e.cache_id
                        AND p.hash = 'sccache:' || e.id
                )
        ) victims
        ORDER BY used, kind, id
        LIMIT 256
        "#,
        org,
        &caches,
        &hashes,
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut available = HashSet::new();
    let nix: Vec<i64> = candidates
        .iter()
        .filter(|v| v.kind == "nix")
        .map(|v| v.id.parse().expect("database bigint"))
        .collect();
    if !nix.is_empty() {
        let locked = sqlx::query_scalar!(
            r#"
            SELECT e.id
            FROM published_paths e
            JOIN caches c ON c.id = e.cache_id
            JOIN blob_objects b ON b.id = e.blob_object_id
            WHERE e.id = ANY($1)
                AND c.org_id = $2
                AND NOT nix_path_pinned(e.cache_id, e.store_path_hash, NOW())
                AND NOT EXISTS (
                    SELECT 1 FROM nix_job_protected_paths($2, NOW()) j
                    WHERE j.cache_id=e.cache_id AND j.store_path_hash=e.store_path_hash
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM upload_sessions u
                    WHERE u.cache_id = e.cache_id
                        AND u.store_path_hash = e.store_path_hash
                        AND (
                            u.status = 'finalizing'
                            OR (u.status IN ('pending', 'uploading', 'streaming') AND u.expires_at > NOW())
                        )
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM nar_installations i
                    WHERE i.file_hash = b.file_hash
                        AND i.compression = b.compression
                )
            ORDER BY e.id
            FOR UPDATE OF e SKIP LOCKED
            "#,
            &nix,
            org,
        )
        .fetch_all(&mut **tx)
        .await?;
        for id in locked {
            available.insert(("nix".to_owned(), id.to_string()));
        }
    }
    for kind in ["go", "sccache"] {
        let ids: Vec<_> = candidates
            .iter()
            .filter(|v| v.kind == kind)
            .map(|v| v.id.clone())
            .collect();
        if ids.is_empty() {
            continue;
        }
        let locked = if kind == "go" {
            sqlx::query_scalar!(
                r#"
                SELECT e.id
                FROM go_entries e
                JOIN caches c ON c.id = e.cache_id
                WHERE e.id = ANY($1)
                    AND c.org_id = $2
                    AND e.generation = c.go_generation
                    AND e.uploaded_at IS NOT NULL
                    AND e.expires_at > NOW()
                ORDER BY e.id
                FOR UPDATE OF e SKIP LOCKED
                "#,
                &ids,
                org,
            )
            .fetch_all(&mut **tx)
            .await?
        } else {
            sqlx::query_scalar!(
                r#"
                SELECT e.id
                FROM sccache_entries e
                JOIN caches c ON c.id = e.cache_id
                WHERE e.id = ANY($1)
                    AND c.org_id = $2
                    AND e.generation = c.sccache_generation
                    AND e.uploaded_at IS NOT NULL
                    AND e.expires_at > NOW()
                ORDER BY e.id
                FOR UPDATE OF e SKIP LOCKED
                "#,
                &ids,
                org,
            )
            .fetch_all(&mut **tx)
            .await?
        };
        for id in locked {
            available.insert((kind.to_owned(), id));
        }
    }
    let mut victims = Vec::new();
    let mut freed = 0i64;
    let busy = candidates
        .iter()
        .any(|v| !available.contains(&(v.kind.clone(), v.id.clone())));
    for v in candidates {
        if !available.contains(&(v.kind.clone(), v.id.clone())) {
            continue;
        }
        freed = freed.saturating_add(v.size);
        victims.push(v);
        if total.saturating_sub(freed) <= limit {
            break;
        }
    }
    if total.saturating_sub(freed) > limit {
        return Err(ApiError::new(
            if busy {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::PAYLOAD_TOO_LARGE
            },
            if busy {
                "Capacity victims are busy; retry"
            } else {
                "Insufficient evictable capacity within the 256-object budget; delete retained paths first"
            },
        ));
    }
    sqlx::query!(
        r#"
        SELECT SET_CONFIG('snowstead.eviction_reason', 'capacity', TRUE)
        "#
    )
    .fetch_one(&mut **tx)
    .await?;
    let ids: Vec<i64> = victims
        .iter()
        .filter(|v| v.kind == "nix")
        .map(|v| v.id.parse().expect("database bigint"))
        .collect();
    if !ids.is_empty() {
        let metadata = sqlx::query!(
            r#"
            SELECT
                o.slug,
                o.moving_from,
                c.name,
                p.store_path_hash,
                c.is_public
            FROM published_paths p
            JOIN caches c ON c.id = p.cache_id
            JOIN orgs o ON o.id = c.org_id
            WHERE p.id = ANY($1)
            "#,
            &ids,
        )
        .fetch_all(&mut **tx)
        .await?;
        for row in metadata {
            let (slug, moving_from, name, hash, public) = (
                row.slug,
                row.moving_from,
                row.name,
                row.store_path_hash,
                row.is_public,
            );
            for slug in std::iter::once(slug).chain(moving_from) {
                let path = if slug == "default" {
                    name.clone()
                } else {
                    format!("{slug}/{name}")
                };
                let key = if public {
                    format!("{path}/{hash}.narinfo")
                } else {
                    format!("narinfo/{path}/{hash}.narinfo")
                };
                sqlx::query(
                    "INSERT INTO object_cleanup (is_private, key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(!public)
                .bind(key)
                .execute(&mut **tx)
                .await?;
            }
        }
        sqlx::query!(
            r#"
            DELETE FROM published_paths
            WHERE id = ANY($1)
            "#,
            &ids,
        )
        .execute(&mut **tx)
        .await?;
    }
    for kind in ["go", "sccache"] {
        let ids: Vec<_> = victims
            .iter()
            .filter(|v| v.kind == kind)
            .map(|v| v.id.clone())
            .collect();
        if ids.is_empty() {
            continue;
        }
        if kind == "go" {
            sqlx::query!(
                r#"
                UPDATE go_entries
                SET cache_id = NULL
                WHERE id = ANY($1)
                "#,
                &ids,
            )
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query!(
                r#"
                UPDATE sccache_entries
                SET cache_id = NULL
                WHERE id = ANY($1)
                "#,
                &ids,
            )
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}
