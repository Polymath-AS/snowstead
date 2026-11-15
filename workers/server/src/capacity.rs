//! Retained capacity is logical, across all three products, and eventually
//! consistent. Publication never checks or evicts: it commits and wakes the
//! evictor, which brings an organization back under its limit in its own
//! bounded transactions. A brief overshoot is expected. New uploads are refused
//! once usage reaches 110% of the limit, or reaches the limit while protected
//! paths alone already fill it. Physical orphan reclamation is separate.
use std::{
    collections::{BTreeSet, HashSet},
    sync::Mutex,
    time::Duration,
};

use axum::http::StatusCode;
use sqlx::PgConnection;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::{
    AppState,
    db::{self, Transaction},
    error::ApiError,
};

/// Organizations waiting for the evictor. Requests coalesce per organization
/// and never block: without a running worker they only occupy this set.
#[derive(Default)]
pub(crate) struct Wakes {
    pending: Mutex<BTreeSet<String>>,
    notify: Notify,
}

impl Wakes {
    /// Call after a commit which may have raised retained usage.
    pub(crate) fn request(&self, org: &str) {
        let mut pending = self.pending.lock().unwrap();
        if !pending.contains(org) {
            pending.insert(org.to_owned());
        }
        drop(pending);
        // A stored permit wakes a worker that is busy or has not started yet.
        self.notify.notify_one();
    }

    fn take(&self) -> BTreeSet<String> {
        std::mem::take(&mut *self.pending.lock().unwrap())
    }
}

/// Evict woken organizations promptly, and every `period` those a wake missed:
/// a limit lowered by management, another instance's publication, or a pass
/// that failed. Shutdown interrupts between passes, never inside a transaction.
pub async fn run(state: AppState, stopped: CancellationToken, period: Duration) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stopped.cancelled() => break,
            _ = state.evictions.notify.notified() => {}
            _ = interval.tick() => {
                match over_limit(&state.pool, None).await {
                    Ok(orgs) => state.evictions.pending.lock().unwrap().extend(orgs),
                    Err(_) => tracing::warn!("Capacity scan failed; retried on the next tick"),
                }
            }
        }
        for org in state.evictions.take() {
            if stopped.is_cancelled() {
                break;
            }
            if evict_until(&state, &org, &stopped).await.is_err() {
                tracing::warn!("Capacity eviction failed; retried on the next wake or tick");
            }
        }
    }
}

/// Organizations whose retained usage exceeds their limit, or only `org`.
/// Unfenced and therefore a hint: each eviction pass recomputes under the
/// organization fence.
async fn over_limit(pool: &sqlx::PgPool, org: Option<&str>) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT o.id
        FROM orgs o
        WHERE o.storage_limit IS NOT NULL
            AND ($1::text IS NULL OR o.id = $1)
            AND o.storage_limit < (
                SELECT COALESCE(SUM(n), 0)
                FROM (
                    SELECT c.size AS n
                    FROM caches c
                    WHERE c.org_id = o.id
                    UNION ALL
                    SELECT e.size
                    FROM go_entries e
                    JOIN caches c ON c.id = e.cache_id
                    WHERE c.org_id = o.id
                        AND e.generation = c.go_generation
                        AND e.uploaded_at IS NOT NULL
                        AND e.expires_at > NOW()
                    UNION ALL
                    SELECT e.size
                    FROM sccache_entries e
                    JOIN caches c ON c.id = e.cache_id
                    WHERE c.org_id = o.id
                        AND e.generation = c.sccache_generation
                        AND e.uploaded_at IS NOT NULL
                        AND e.expires_at > NOW()
                ) usage
            )
        ORDER BY o.id
        "#,
        org,
    )
    .fetch_all(pool)
    .await
}

/// Committed retained bytes: published Nix paths plus live compiler entries.
async fn usage(tx: &mut PgConnection, org: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
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
    .fetch_one(tx)
    .await
}

/// Refuse a new upload for an organization that is too far over its limit to
/// wait for eviction, or over it with nothing left to evict. The read is not
/// exact: concurrent publications may still overshoot, and the evictor
/// recovers. `over` is the caller's message for the 110% refusal.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub(crate) async fn admit_upload(
    tx: &mut Transaction,
    org: &str,
    limit: i64,
    over: &'static str,
) -> Result<(), ApiError> {
    let used = usage(tx, org).await?;
    if used < limit {
        return Ok(());
    }
    // used >= limit * 1.1, exactly and without overflow.
    if i128::from(used) * 10 >= i128::from(limit) * 11 {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, over));
    }
    // Only an organization already at its limit pays for this. Driven from the
    // pin and job tables, not one `nix_path_pinned` call per published path.
    let protected = sqlx::query_scalar!(
        r#"
        SELECT COALESCE(SUM(b.file_size), 0)::bigint AS "protected!"
        FROM (
            SELECT
                m.cache_id,
                m.store_path_hash
            FROM pin_paths m
            JOIN pin_revisions r ON r.id = m.revision_id
            JOIN pins p ON p.id = r.pin_id
            JOIN caches c ON c.id = m.cache_id
            WHERE c.org_id = $1
                AND (
                    r.revision = p.current_revision
                    OR p.keep_kind = 'forever'
                    OR (p.keep_kind = 'revisions' AND r.revision > p.current_revision - p.keep_value)
                    OR (p.keep_kind = 'days' AND r.superseded_at > NOW() - p.keep_value * INTERVAL '1 day')
                )
            UNION
            SELECT
                j.cache_id,
                j.store_path_hash
            FROM nix_job_protected_paths($1, NOW()) j
        ) kept
        JOIN published_paths e ON e.cache_id = kept.cache_id
            AND e.store_path_hash = kept.store_path_hash
        JOIN blob_objects b ON b.id = e.blob_object_id
        "#,
        org,
    )
    .fetch_one(&mut **tx)
    .await?;
    if protected >= limit {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Insufficient evictable capacity; delete retained paths first",
        ));
    }
    Ok(())
}

struct Victim {
    kind: String,
    id: String,
    size: i64,
}

struct Pass {
    removed: usize,
    freed: i64,
    over: bool,
}

/// Bring `org` back to its limit, least recently used first, and return the
/// bytes freed. Each pass is its own transaction under the organization fence
/// and removes at most 256 entries; passes repeat while the organization is
/// still over and the last one removed something. Ending over the limit is not
/// an error: whatever remains is pinned, job-protected, being uploaded, or
/// locked by another writer, and the next wake or tick tries again.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn evict(state: &AppState, org: &str) -> anyhow::Result<u64> {
    evict_until(state, org, &CancellationToken::new()).await
}

async fn evict_until(
    state: &AppState,
    org: &str,
    stopped: &CancellationToken,
) -> anyhow::Result<u64> {
    // Most wakes find nothing to do. Decide that without the fence.
    if over_limit(&state.pool, Some(org)).await?.is_empty() {
        return Ok(0);
    }
    let mut freed = 0u64;
    loop {
        let pass = pass(state, org).await?;
        freed = freed.saturating_add(pass.freed.max(0) as u64);
        if pass.removed == 0 || !pass.over || stopped.is_cancelled() {
            return Ok(freed);
        }
    }
}

async fn pass(state: &AppState, org: &str) -> Result<Pass, ApiError> {
    let idle = |over| Pass {
        removed: 0,
        freed: 0,
        over,
    };
    let mut tx = db::begin(state, org).await?;
    db::advisory_lock(&mut tx, &format!("org:{org}")).await?;
    let limit = sqlx::query_scalar!(
        r#"
        SELECT storage_limit
        FROM orgs
        WHERE id = $1
        "#,
        org,
    )
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    let Some(limit) = limit else {
        tx.rollback().await?;
        return Ok(idle(false));
    };
    let used = usage(&mut tx, org).await?;
    if used <= limit {
        tx.rollback().await?;
        return Ok(idle(false));
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
        ) victims
        ORDER BY used, kind, id
        LIMIT 256
        "#,
        org,
    )
    .fetch_all(&mut *tx)
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
        .fetch_all(&mut *tx)
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
            .fetch_all(&mut *tx)
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
            .fetch_all(&mut *tx)
            .await?
        };
        for id in locked {
            available.insert((kind.to_owned(), id));
        }
    }
    // Stop at the limit: LRU order, skipping whatever another writer holds.
    let mut victims = Vec::new();
    let mut remaining = used;
    for v in candidates {
        if remaining <= limit {
            break;
        }
        if !available.contains(&(v.kind.clone(), v.id.clone())) {
            continue;
        }
        remaining = remaining.saturating_sub(v.size);
        victims.push(v);
    }
    if victims.is_empty() {
        tx.rollback().await?;
        return Ok(idle(true));
    }
    sqlx::query!(
        r#"
        SELECT SET_CONFIG('snowstead.eviction_reason', 'capacity', TRUE)
        "#
    )
    .fetch_one(&mut *tx)
    .await?;
    let ids: Vec<i64> = victims
        .iter()
        .filter(|v| v.kind == "nix")
        .map(|v| v.id.parse().expect("database bigint"))
        .collect();
    if !ids.is_empty() {
        sqlx::query!(
            r#"
            DELETE FROM published_paths
            WHERE id = ANY($1)
            "#,
            &ids,
        )
        .execute(&mut *tx)
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
            .execute(&mut *tx)
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
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(Pass {
        removed: victims.len(),
        freed: used.saturating_sub(remaining),
        over: remaining > limit,
    })
}
