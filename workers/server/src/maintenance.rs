//! Bounded, retryable control-plane maintenance over the existing R2 objects.
//!
//! SQL withdrawal records exact keys in a durable cleanup queue. Storage I/O
//! never holds a transaction. Legacy canonical installations do not expire.
use std::collections::BTreeSet;

use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Mutex;

use crate::{AppState, auth::JWT_CLOCK_SKEW_SECONDS, management_policy::MetadataTarget};

const BATCH: i64 = 500;
const BATCHES: usize = 20;
// At most 400 distinct sessions per sweep, each with one 500-receipt page and
// one 500-object listing. Do not let one huge or broken upload spend the run.
const SESSION_PAGE: usize = 20;
const SESSION_PAGES: usize = 20;
// Retain revocations beyond the verifier's entire acceptance window, with
// a small margin for clock/precision differences between SQL and the server.
const TOKEN_EXPIRY_MARGIN_SECONDS: i64 = 5;
static RUNNING: Mutex<()> = Mutex::const_new(());

#[derive(Default, Debug)]
/// Counts from fully successful stages; a failed stage may have made partial
/// progress in independently committed batches before retaining its retry work.
pub(crate) struct Counts {
    pub compiler_entries: u64,
    pub orphan_objects: u64,
    pub sessions: u64,
    pub paths: u64,
    pub blobs: u64,
    pub tokens: u64,
    pub audit_logs: u64,
    pub eviction_logs: u64,
    pub failed_stages: u64,
}

/// Called by the lifecycle owner every six hours. Failure of one stage must
/// not suppress discovery in another; only static stage names reach logs.
#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(target = "snowstead_observability", skip_all, name = "maintenance.run")
)]
pub(crate) async fn run(state: &AppState) -> anyhow::Result<Counts> {
    let Ok(_running) = RUNNING.try_lock() else {
        return Ok(Counts::default());
    };
    let mut counts = Counts::default();
    record(
        &mut counts.orphan_objects,
        &mut counts.failed_stages,
        "publication reservations",
        expire_installations(state).await,
    );
    for kind in ["go", "sccache"] {
        record(
            &mut counts.compiler_entries,
            &mut counts.failed_stages,
            kind,
            compiler_entries(state, kind).await,
        );
        record(
            &mut counts.orphan_objects,
            &mut counts.failed_stages,
            "compiler attempts",
            orphan_page(state, &format!("{kind}-attempt/"), Some(kind)).await,
        );
    }
    record(
        &mut counts.sessions,
        &mut counts.failed_stages,
        "upload sessions",
        sessions(state).await,
    );
    // Also finds unadmitted parts, assembled sources, and transfers that finish
    // after their expired session was removed. The cursor wraps on every pass.
    record(
        &mut counts.orphan_objects,
        &mut counts.failed_stages,
        "staging objects",
        orphan_page(state, "staging/", None).await,
    );
    record(
        &mut counts.paths,
        &mut counts.failed_stages,
        "retention",
        retention(state).await,
    );
    record(
        &mut counts.blobs,
        &mut counts.failed_stages,
        "canonical blobs",
        blobs(state).await,
    );
    for (private, prefix) in [(false, "nar/objects/"), (true, "nars/objects/")] {
        record(
            &mut counts.orphan_objects,
            &mut counts.failed_stages,
            "NAR attempts",
            orphan_nars(state, private, prefix).await,
        );
    }
    record(
        &mut counts.orphan_objects,
        &mut counts.failed_stages,
        "object cleanup",
        cleanup_objects(state).await,
    );
    for (table, destination) in [
        ("api_tokens", &mut counts.tokens),
        ("audit_logs", &mut counts.audit_logs),
        ("eviction_logs", &mut counts.eviction_logs),
    ] {
        record(
            destination,
            &mut counts.failed_stages,
            table,
            expire_rows(&state.pool, table).await,
        );
    }
    Ok(counts)
}

fn record(count: &mut u64, failures: &mut u64, stage: &'static str, result: anyhow::Result<u64>) {
    match result {
        Ok(n) => *count += n,
        Err(_) => {
            *failures += 1;
            tracing::warn!(
                stage,
                "Maintenance stage failed; durable records retained for retry"
            );
        }
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn begin(pool: &PgPool) -> anyhow::Result<Transaction<'static, Postgres>> {
    let mut tx = crate::profile_future!(pool.begin(), label = "maintenance.pool_begin").await?;
    sqlx::query!(
        r#"
        SET LOCAL lock_timeout = '1ms'
        "#
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        r#"
        SET LOCAL statement_timeout = '30s'
        "#
    )
    .execute(&mut *tx)
    .await?;
    Ok(tx)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn lock(tx: &mut Transaction<'_, Postgres>, key: &str) -> anyhow::Result<()> {
    crate::profile_future!(
        crate::db::advisory_lock(tx, key),
        label = "maintenance.advisory_lock_wait"
    )
    .await?;
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "maintenance.expire_rows"
    )
)]
async fn expire_rows(pool: &PgPool, table: &'static str) -> anyhow::Result<u64> {
    let result = match table {
        "api_tokens" => {
            sqlx::query!(
                r#"
                DELETE FROM api_tokens
                WHERE jti IN (
                    SELECT jti
                    FROM api_tokens
                    WHERE expires_at < now() - $1 * INTERVAL '1 second'
                    ORDER BY jti
                    LIMIT $2
                    FOR UPDATE SKIP LOCKED
                )
                "#,
                (JWT_CLOCK_SKEW_SECONDS + TOKEN_EXPIRY_MARGIN_SECONDS) as f64,
                BATCH
            )
            .execute(pool)
            .await?
        }
        "audit_logs" => {
            sqlx::query!(
                r#"
                DELETE FROM audit_logs
                WHERE id IN (
                    SELECT id
                    FROM audit_logs
                    WHERE timestamp < now() - INTERVAL '30 days'
                    ORDER BY id
                    LIMIT $1
                    FOR UPDATE SKIP LOCKED
                )
                "#,
                BATCH
            )
            .execute(pool)
            .await?
        }
        "eviction_logs" => {
            sqlx::query!(
                r#"
                DELETE FROM eviction_logs
                WHERE id IN (
                    SELECT id
                    FROM eviction_logs
                    WHERE evicted_at < now() - INTERVAL '30 days'
                    ORDER BY id
                    LIMIT $1
                    FOR UPDATE SKIP LOCKED
                )
                "#,
                BATCH
            )
            .execute(pool)
            .await?
        }
        _ => unreachable!("fixed maintenance table"),
    };
    Ok(result.rows_affected())
}

struct CompilerEntry {
    id: String,
    org_id: Option<String>,
    cache_id: Option<i32>,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "maintenance.compiler_entries"
    )
)]
async fn compiler_entries(state: &AppState, kind: &'static str) -> anyhow::Result<u64> {
    let candidates = match kind {
        "go" => {
            sqlx::query_as!(
                CompilerEntry,
                r#"
                SELECT
                    e.id,
                    c.org_id,
                    e.cache_id
                FROM go_entries e
                LEFT JOIN caches c ON c.id = e.cache_id
                WHERE e.expires_at <= now()
                    OR e.cache_id IS NULL
                    OR e.generation <> c.go_generation
                ORDER BY e.expires_at, e.id
                LIMIT $1
                "#,
                BATCH
            )
            .fetch_all(&state.pool)
            .await?
        }
        "sccache" => {
            sqlx::query_as!(
                CompilerEntry,
                r#"
                SELECT
                    e.id,
                    c.org_id,
                    e.cache_id
                FROM sccache_entries e
                LEFT JOIN caches c ON c.id = e.cache_id
                WHERE e.expires_at <= now()
                    OR e.cache_id IS NULL
                    OR e.generation <> c.sccache_generation
                ORDER BY e.expires_at, e.id
                LIMIT $1
                "#,
                BATCH
            )
            .fetch_all(&state.pool)
            .await?
        }
        _ => unreachable!("fixed compiler product"),
    };
    let mut count = 0;
    let mut failed = false;
    for CompilerEntry {
        id,
        org_id: org,
        cache_id: cache,
    } in candidates
    {
        let result: anyhow::Result<bool> = async {
            let mut tx = begin(&state.pool).await?;
            if let Some(org) = org {
                lock(&mut tx, &format!("org:{org}")).await?;
                sqlx::query!(
                    r#"
                    SELECT id
                    FROM caches
                    WHERE id = $1
                    FOR SHARE
                    "#,
                    cache
                )
                .fetch_all(&mut *tx)
                .await?;
            }
            let key = match kind {
                "go" => {
                    sqlx::query_scalar!(
                        r#"
                        SELECT e.r2_key
                        FROM go_entries e
                        LEFT JOIN caches c ON c.id = e.cache_id
                        WHERE e.id = $1
                            AND (
                                e.expires_at <= now()
                                OR e.cache_id IS NULL
                                OR e.generation <> c.go_generation
                            )
                        FOR UPDATE OF e SKIP LOCKED
                        "#,
                        &id
                    )
                    .fetch_optional(&mut *tx)
                    .await?
                }
                "sccache" => {
                    sqlx::query_scalar!(
                        r#"
                        SELECT e.r2_key
                        FROM sccache_entries e
                        LEFT JOIN caches c ON c.id = e.cache_id
                        WHERE e.id = $1
                            AND (
                                e.expires_at <= now()
                                OR e.cache_id IS NULL
                                OR e.generation <> c.sccache_generation
                            )
                        FOR UPDATE OF e SKIP LOCKED
                        "#,
                        &id
                    )
                    .fetch_optional(&mut *tx)
                    .await?
                }
                _ => unreachable!("fixed compiler product"),
            };
            let Some(key) = key else { return Ok(false) };
            sqlx::query(
                "INSERT INTO object_cleanup(is_private,key) VALUES(TRUE,$1) ON CONFLICT DO NOTHING",
            )
            .bind(&key)
            .execute(&mut *tx)
            .await?;
            match kind {
                "go" => {
                    sqlx::query!(
                        r#"
                        DELETE FROM go_entries
                        WHERE id = $1
                        "#,
                        &id
                    )
                    .execute(&mut *tx)
                    .await?
                }
                "sccache" => {
                    sqlx::query!(
                        r#"
                        DELETE FROM sccache_entries
                        WHERE id = $1
                        "#,
                        &id
                    )
                    .execute(&mut *tx)
                    .await?
                }
                _ => unreachable!("fixed compiler product"),
            };
            tx.commit().await?;
            Ok(true)
        }
        .await;
        match result {
            Ok(true) => count += 1,
            Ok(false) => (),
            Err(_) => failed = true,
        }
    }
    // Keep processing unrelated entries even when a particular key is broken.
    if failed {
        anyhow::bail!("Compiler cleanup incomplete")
    }
    Ok(count)
}

/// Persist cursors in the existing generic GC bookkeeping, not process memory.
/// A failed page does not advance, including failure to save its next cursor.
#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "maintenance.orphan_page"
    )
)]
async fn orphan_page(
    state: &AppState,
    prefix: &str,
    product: Option<&'static str>,
) -> anyhow::Result<u64> {
    let cursor: Option<String> = sqlx::query_scalar!(
        r#"
        SELECT reason
        FROM gc_marks
        WHERE target_type = 'server-gc-cursor'
            AND target_id = $1
        "#,
        prefix
    )
    .fetch_optional(&state.pool)
    .await?;
    let keys = state
        .storage
        .list(
            true,
            prefix.trim_end_matches('/'),
            cursor.as_deref(),
            BATCH as usize,
        )
        .await?;
    let mut count = 0;
    for key in &keys {
        let Some(owner) = key.strip_prefix(prefix).and_then(|s| s.split('/').next()) else {
            continue;
        };
        let mut tx = begin(&state.pool).await?;
        // These owner IDs are never reused. An absent session/reservation can
        // never adopt this key later, even if a provider write completes late.
        let live = match product {
            Some("go") => {
                sqlx::query_scalar!(
                    r#"
                    SELECT EXISTS(
                        SELECT 1
                        FROM go_entries
                        WHERE id = $1
                    ) AS "live!"
                    "#,
                    owner
                )
                .fetch_one(&mut *tx)
                .await?
            }
            Some("sccache") => {
                sqlx::query_scalar!(
                    r#"
                    SELECT EXISTS(
                        SELECT 1
                        FROM sccache_entries
                        WHERE id = $1
                    ) AS "live!"
                    "#,
                    owner
                )
                .fetch_one(&mut *tx)
                .await?
            }
            None => {
                sqlx::query_scalar!(
                    r#"
                    SELECT EXISTS(
                        SELECT 1
                        FROM upload_sessions
                        WHERE id = $1
                    ) OR EXISTS(
                        SELECT 1
                        FROM nar_installations
                        WHERE source_key = $2
                    ) AS "live!"
                    "#,
                    owner,
                    key
                )
                .fetch_one(&mut *tx)
                .await?
            }
            Some(_) => unreachable!("fixed compiler product"),
        };
        // Reservation IDs are never reused. While a reservation exists, keep
        // *all* attempts, even a transfer not yet adopted by SQL.
        if !live {
            count += sqlx::query(
                "INSERT INTO object_cleanup(is_private,key) VALUES(TRUE,$1) ON CONFLICT DO NOTHING",
            )
            .bind(key)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }
        tx.commit().await?;
    }
    if keys.len() == BATCH as usize {
        sqlx::query!(
            r#"
            INSERT INTO gc_marks (target_type, target_id, reason)
            VALUES ('server-gc-cursor', $1, $2)
            ON CONFLICT (target_type, target_id) DO UPDATE
            SET
                reason = excluded.reason,
                marked_at = now()
            "#,
            prefix,
            keys.last().unwrap()
        )
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query!(
            r#"
            DELETE FROM gc_marks
            WHERE target_type = 'server-gc-cursor'
                AND target_id = $1
            "#,
            prefix
        )
        .execute(&state.pool)
        .await?;
    }
    Ok(count)
}

struct Session {
    id: String,
    file_hash: Option<String>,
    file_size: i64,
    compression: String,
    status: String,
    r2_upload_key: Option<String>,
    r2_upload_id: Option<String>,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "maintenance.sessions"
    )
)]
async fn sessions(state: &AppState) -> anyhow::Result<u64> {
    // IDs are immutable. Persist a keyset cursor even for partial/failed work
    // so those oldest records cannot monopolize successive bounded sweeps.
    let mut cursor: Option<String> = sqlx::query_scalar!(
        r#"
        SELECT reason
        FROM gc_marks
        WHERE target_type = 'server-gc-cursor'
            AND target_id = 'upload sessions'
        "#
    )
    .fetch_optional(&state.pool)
    .await?;
    let mut count = 0;
    let mut failed = false;
    for page in 0..SESSION_PAGES {
        let candidates = sqlx::query!(
            r#"
            SELECT
                u.id,
                c.org_id
            FROM upload_sessions u
            JOIN caches c ON c.id = u.cache_id
            WHERE ($1::text IS NULL OR u.id > $1)
                AND u.expires_at <= now()
                AND NOT EXISTS(
                    SELECT 1
                    FROM nar_installations i
                    WHERE i.source_key = u.r2_upload_key
                        OR starts_with(i.source_key, 'staging/' || u.id || '/')
                )
                AND NOT (
                    u.status <> 'completed'
                    AND u.r2_upload_id IS NOT NULL
                    AND u.r2_upload_key IS NOT NULL
                    AND NOT starts_with(u.r2_upload_key, 'staging/')
                )
            ORDER BY u.id
            LIMIT $2
            "#,
            cursor.as_deref(),
            SESSION_PAGE as i64
        )
        .fetch_all(&state.pool)
        .await?;
        let next = candidates.last().map(|row| row.id.clone());
        let exhausted = candidates.len() < SESSION_PAGE;
        for candidate in candidates {
            match expire_session(state, &candidate.id, &candidate.org_id).await {
                Ok(true) => count += 1,
                Ok(false) => (),
                Err(_) => failed = true,
            }
        }
        if exhausted {
            sqlx::query!(
                r#"
                DELETE FROM gc_marks
                WHERE target_type = 'server-gc-cursor'
                    AND target_id = 'upload sessions'
                "#
            )
            .execute(&state.pool)
            .await?;
            // A cursor at the end must not waste an entire six-hour pass.
            // Otherwise wrap next run: never retry a failure twice this run.
            if next.is_none() && cursor.is_some() && page == 0 {
                cursor = None;
                continue;
            }
            break;
        }
        sqlx::query!(
            r#"
            INSERT INTO gc_marks (target_type, target_id, reason)
            VALUES ('server-gc-cursor', 'upload sessions', $1)
            ON CONFLICT (target_type, target_id) DO UPDATE
            SET
                reason = excluded.reason,
                marked_at = now()
            "#,
            next.as_deref()
        )
        .execute(&state.pool)
        .await?;
        cursor = next;
    }
    if failed {
        anyhow::bail!("Session cleanup incomplete")
    }
    Ok(count)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn expire_session(state: &AppState, id: &str, org: &str) -> anyhow::Result<bool> {
    let mut tx = begin(&state.pool).await?;
    lock(&mut tx, &format!("org:{org}")).await?;
    lock(&mut tx, &format!("upload:{id}")).await?;
    sqlx::query!(
        r#"
        LOCK TABLE upload_sessions IN SHARE ROW EXCLUSIVE MODE NOWAIT
        "#
    )
    .execute(&mut *tx)
    .await?;
    let session = sqlx::query_as!(
        Session,
        r#"
        SELECT
            u.id,
            u.file_hash,
            u.file_size,
            u.compression,
            u.status,
            u.r2_upload_key,
            u.r2_upload_id
        FROM upload_sessions u
        WHERE u.id = $1
            AND u.expires_at <= now()
            AND NOT EXISTS(
                SELECT 1
                FROM nar_installations i
                WHERE i.source_key = u.r2_upload_key
                    OR starts_with(i.source_key, 'staging/' || u.id || '/')
            )
        FOR UPDATE OF u NOWAIT
        "#,
        id
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(s) = session else { return Ok(false) };
    if let Some(key) = &s.r2_upload_key {
        if !key.starts_with("staging/") {
            // Old canonical MPUs may still complete after an abort. An expired
            // SQL lease does not prove their bytes are safe to reclaim.
            if s.r2_upload_id.is_some() && s.status != "completed" {
                return Ok(false);
            }
            if let Some(hash) = &s.file_hash {
                lock(&mut tx, &format!("nar:{hash}:{}", s.compression)).await?;
                sqlx::query!(
                    r#"
                    INSERT INTO blob_objects (file_hash, file_size, compression, r2_key)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (file_hash, compression) DO NOTHING
                    "#,
                    hash,
                    s.file_size,
                    &s.compression,
                    key
                )
                .execute(&mut *tx)
                .await?;
            } else {
                // No content identity means we cannot safely adopt or delete.
                anyhow::bail!("Legacy canonical source has no identity")
            }
        } else {
            // Rust stores immutable part objects; its upload ID equals the
            // session ID and is not an R2 MPU. TS rows carry real provider IDs.
            let upload = s
                .r2_upload_id
                .as_ref()
                .filter(|upload| *upload != &s.id && s.status != "completed");
            sqlx::query("INSERT INTO object_cleanup(is_private,key,upload_id) VALUES(TRUE,$1,$2) \
                ON CONFLICT(is_private,key) DO UPDATE SET upload_id=COALESCE(object_cleanup.upload_id,EXCLUDED.upload_id)")
                .bind(key).bind(upload).execute(&mut *tx).await?;
        }
    }
    sqlx::query!(
        r#"
        UPDATE upload_sessions
        SET status = 'expired'
        WHERE id = $1
            AND status <> 'completed'
        "#,
        id
    )
    .execute(&mut *tx)
    .await?;
    // Bound receipt retirement. The cleanup queue owns these immutable keys
    // after SQL deletion; a crash cannot lose the remaining physical work.
    let parts = sqlx::query!(
        r#"
        SELECT
            id,
            storage_key
        FROM upload_parts
        WHERE session_id = $1
        ORDER BY id
        LIMIT $2
        "#,
        id,
        BATCH
    )
    .fetch_all(&mut *tx)
    .await?;
    for key in parts.iter().filter_map(|part| part.storage_key.as_ref()) {
        sqlx::query(
            "INSERT INTO object_cleanup(is_private,key) VALUES(TRUE,$1) ON CONFLICT DO NOTHING",
        )
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    let part_ids: Vec<i64> = parts.iter().map(|p| p.id).collect();
    sqlx::query!(
        r#"
        DELETE FROM upload_parts
        WHERE id = ANY($1)
        "#,
        &part_ids
    )
    .execute(&mut *tx)
    .await?;
    // Unreceipted parts and late writes are discovered by orphan_page after
    // their session is gone. Listing them does not belong in this transaction.
    let remaining: bool = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM upload_parts
            WHERE session_id = $1
        ) AS "remaining!"
        "#,
        id
    )
    .fetch_one(&mut *tx)
    .await?;
    let removed = !remaining;
    if removed {
        sqlx::query!(
            r#"
            DELETE FROM upload_sessions
            WHERE id = $1
            "#,
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(removed)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "maintenance.retention"
    )
)]
async fn retention(state: &AppState) -> anyhow::Result<u64> {
    // Bound discovery too. Only select caches that actually have work; a cache
    // with retained pins alone cannot starve later caches of the global budget.
    let caches = sqlx::query!(
        r#"
        SELECT
            c.id,
            c.org_id
        FROM caches c
        WHERE c.retention_days IS NOT NULL
            AND EXISTS(
                SELECT 1
                FROM published_paths p
                WHERE p.cache_id = c.id
                    AND p.last_pushed_at < now() - c.retention_days * INTERVAL '1 day'
                    AND NOT nix_path_pinned(p.cache_id, p.store_path_hash, now())
            )
        ORDER BY c.id
        LIMIT $1
        "#,
        BATCHES as i64
    )
    .fetch_all(&state.pool)
    .await?;
    let mut count = 0;
    let mut budget = BATCHES;
    let mut failed = false;
    for cache in caches {
        while budget > 0 {
            budget -= 1;
            match retention_batch(state, cache.id, &cache.org_id).await {
                Ok(n) => {
                    count += n;
                    if n < BATCH as u64 {
                        break;
                    }
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
    }
    if failed {
        anyhow::bail!("Retention incomplete")
    }
    Ok(count)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn retention_batch(state: &AppState, cache: i32, org: &str) -> anyhow::Result<u64> {
    let mut tx = begin(&state.pool).await?;
    lock(&mut tx, &format!("org:{org}")).await?;
    let metadata = sqlx::query!(
        r#"
        SELECT
            c.is_public,
            o.slug,
            o.moving_from,
            c.name
        FROM caches c
        JOIN orgs o ON o.id = c.org_id
        WHERE c.id = $1
            AND c.org_id = $2
            AND c.retention_days IS NOT NULL
        FOR UPDATE OF c NOWAIT
        "#,
        cache,
        org
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(metadata) = metadata else {
        return Ok(0);
    };
    sqlx::query!(
        r#"
        SELECT set_config('snowstead.eviction_reason', 'retention', TRUE)
        "#
    )
    .fetch_all(&mut *tx)
    .await?;
    // The database pin function is the same policy used by management and
    // capacity eviction. Last push, not original publication, controls TTL.
    let hashes = sqlx::query_scalar!(
        r#"
        DELETE FROM published_paths
        WHERE id IN (
            SELECT p.id
            FROM published_paths p
            JOIN caches c ON c.id = p.cache_id
            WHERE c.id = $1
                AND p.last_pushed_at < now() - c.retention_days * INTERVAL '1 day'
                AND NOT nix_path_pinned(p.cache_id, p.store_path_hash, now())
            ORDER BY p.last_pushed_at, p.id
            LIMIT $2
        )
        RETURNING store_path_hash
        "#,
        cache,
        BATCH
    )
    .fetch_all(&mut *tx)
    .await?;
    MetadataTarget::new(
        metadata.is_public,
        &metadata.slug,
        metadata.moving_from.as_deref(),
        &metadata.name,
    )
    .withdraw(&mut tx, &hashes)
    .await
    .map_err(|_| anyhow::anyhow!("Metadata withdrawal failed"))?;
    tx.commit().await?;
    Ok(hashes.len() as u64)
}

struct Blob {
    id: i64,
    file_hash: String,
    compression: String,
    r2_key: String,
    public_key: Option<String>,
    private_key: Option<String>,
}

// Keep expired *canonical* MPUs as reservations too, unlike expiring staged
// uploads. Their completion may be in flight indefinitely. Publications and
// source leases are independent references; one cache cannot free another's NAR.
#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "maintenance.blobs"
    )
)]
async fn blobs(state: &AppState) -> anyhow::Result<u64> {
    let mut count = 0;
    for _ in 0..BATCHES {
        let n = blob_batch(state).await?;
        count += n;
        if n < BATCH as u64 {
            break;
        }
    }
    Ok(count)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn blob_batch(state: &AppState) -> anyhow::Result<u64> {
    let mut tx = begin(&state.pool).await?;
    // Match upload publication and the TS repository's canonical deletion
    // fence, before taking any per-blob locks. Never acquire org locks here.
    sqlx::query!(
        r#"
        LOCK TABLE upload_sessions IN SHARE MODE NOWAIT
        "#
    )
    .execute(&mut *tx)
    .await?;
    let candidates = sqlx::query_as!(
        Blob,
        r#"
        SELECT
            b.id,
            b.file_hash,
            b.compression,
            b.r2_key,
            b.public_key,
            b.private_key
        FROM blob_objects b
        WHERE NOT EXISTS(
            SELECT 1
            FROM published_paths p
            WHERE p.blob_object_id = b.id
        )
            AND NOT EXISTS(
                SELECT 1
                FROM nar_installations i
                WHERE i.file_hash = b.file_hash
                    AND i.compression = b.compression
            )
            AND NOT EXISTS(
                SELECT 1
                FROM upload_sessions u
                WHERE (
                    (
                        u.file_hash = b.file_hash
                        AND u.compression = b.compression
                    )
                    OR u.r2_upload_key = b.r2_key
                    OR u.r2_upload_key = 'nar/' || b.file_hash || '/' || b.compression || '.nar'
                    OR u.r2_upload_key = 'nars/sha256/' || b.file_hash || '/' || b.compression || '.nar'
                )
                    AND (
                        u.expires_at > now()
                        OR (
                            u.status <> 'completed'
                            AND u.r2_upload_id IS NOT NULL
                            AND u.r2_upload_key IS NOT NULL
                            AND NOT starts_with(u.r2_upload_key, 'staging/')
                        )
                    )
            )
        ORDER BY b.file_hash, b.compression
        LIMIT $1
        "#,
        BATCH
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut count = 0;
    for b in candidates {
        lock(&mut tx, &format!("nar:{}:{}", b.file_hash, b.compression)).await?;
        let eligible = sqlx::query_scalar!(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM blob_objects b
                WHERE b.id = $1
                    AND NOT EXISTS(
                        SELECT 1
                        FROM published_paths p
                        WHERE p.blob_object_id = b.id
                    )
                    AND NOT EXISTS(
                        SELECT 1
                        FROM nar_installations i
                        WHERE i.file_hash = b.file_hash
                            AND i.compression = b.compression
                    )
                    AND NOT EXISTS(
                        SELECT 1
                        FROM upload_sessions u
                        WHERE (
                            (
                                u.file_hash = b.file_hash
                                AND u.compression = b.compression
                            )
                            OR u.r2_upload_key = b.r2_key
                            OR u.r2_upload_key = 'nar/' || b.file_hash || '/' || b.compression || '.nar'
                            OR u.r2_upload_key = 'nars/sha256/' || b.file_hash || '/' || b.compression || '.nar'
                        )
                            AND (
                                u.expires_at > now()
                                OR (
                                    u.status <> 'completed'
                                    AND u.r2_upload_id IS NOT NULL
                                    AND u.r2_upload_key IS NOT NULL
                                    AND NOT starts_with(u.r2_upload_key, 'staging/')
                                )
                            )
                    )
            ) AS "eligible!"
            "#,
            b.id
        )
        .fetch_one(&mut *tx)
        .await?;
        if !eligible {
            continue;
        }
        let mut keys = BTreeSet::from([
            (
                true,
                format!("nars/sha256/{}/{}.nar", b.file_hash, b.compression),
            ),
            (false, format!("nar/{}/{}.nar", b.file_hash, b.compression)),
            (!b.r2_key.starts_with("nar/"), b.r2_key),
        ]);
        keys.extend(b.public_key.map(|key| (false, key)));
        keys.extend(b.private_key.map(|key| (true, key)));
        // Retire the SQL identity before I/O. New uploads create a new physical
        // incarnation, never one of these queued keys.
        for (private, key) in keys {
            sqlx::query(
                "INSERT INTO object_cleanup(is_private,key) VALUES($1,$2) ON CONFLICT DO NOTHING",
            )
            .bind(private)
            .bind(key)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query!(
            r#"
            DELETE FROM blob_objects
            WHERE id = $1
            "#,
            b.id
        )
        .execute(&mut *tx)
        .await?;
        count += 1;
    }
    tx.commit().await?;
    Ok(count)
}

/// Expiry revokes adoption, not provider execution. Late writes use unique keys
/// and are rediscovered by orphan_nars. Legacy canonical work has no expiry.
async fn expire_installations(state: &AppState) -> anyhow::Result<u64> {
    let mut tx = begin(&state.pool).await?;
    let result = sqlx::query(
        r#"
        WITH retired AS (
            DELETE FROM nar_installations WHERE key IN (
                SELECT i.key FROM nar_installations i
                LEFT JOIN upload_sessions u ON u.id=i.session_id
                LEFT JOIN caches c ON c.id=i.cache_id
                WHERE i.expires_at IS NOT NULL AND (
                    i.expires_at<=NOW() OR i.phase='revoked'
                    OR (i.session_id IS NOT NULL AND (u.id IS NULL
                        OR u.status NOT IN ('finalizing','completed') OR u.expires_at<=NOW()))
                    OR c.id IS NULL
                )
                ORDER BY i.key LIMIT $1 FOR UPDATE OF i SKIP LOCKED
            ) RETURNING key,is_private
        ) INSERT INTO object_cleanup(is_private,key)
        SELECT is_private,key FROM retired ON CONFLICT DO NOTHING
        "#,
    )
    .bind(BATCH)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected())
}

/// The database owns every adoptable immutable key before its first write.
/// Publication swaps the reservation for a pointer in one SQL transaction.
async fn orphan_nars(state: &AppState, private: bool, prefix: &str) -> anyhow::Result<u64> {
    let cursor: Option<String> = sqlx::query_scalar(
        "SELECT reason FROM gc_marks WHERE target_type='server-gc-cursor' AND target_id=$1",
    )
    .bind(prefix)
    .fetch_optional(&state.pool)
    .await?;
    let keys = state
        .storage
        .list(
            private,
            prefix.trim_end_matches('/'),
            cursor.as_deref(),
            BATCH as usize,
        )
        .await?;
    let mut count = 0;
    for key in &keys {
        let mut tx = begin(&state.pool).await?;
        let live: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM nar_installations WHERE key=$1) \
             OR EXISTS(SELECT 1 FROM blob_objects WHERE r2_key=$1 OR public_key=$1 OR private_key=$1)",
        ).bind(key).fetch_one(&mut *tx).await?;
        if !live {
            sqlx::query(
                "INSERT INTO object_cleanup(is_private,key) VALUES($1,$2) ON CONFLICT DO NOTHING",
            )
            .bind(private)
            .bind(key)
            .execute(&mut *tx)
            .await?;
            count += 1;
        }
        tx.commit().await?;
    }
    if keys.len() == BATCH as usize {
        sqlx::query("INSERT INTO gc_marks(target_type,target_id,reason) VALUES('server-gc-cursor',$1,$2) \
            ON CONFLICT(target_type,target_id) DO UPDATE SET reason=EXCLUDED.reason,marked_at=NOW()")
            .bind(prefix).bind(keys.last().unwrap()).execute(&state.pool).await?;
    } else {
        sqlx::query("DELETE FROM gc_marks WHERE target_type='server-gc-cursor' AND target_id=$1")
            .bind(prefix)
            .execute(&state.pool)
            .await?;
    }
    Ok(count)
}

/// Retired keys are never adopted again. Duplicate deletion after a crash is
/// safe, so no database transaction or worker lease spans storage I/O.
async fn cleanup_objects(state: &AppState) -> anyhow::Result<u64> {
    let mut count = 0;
    let mut failed = false;
    let mut after = 0i64;
    for _ in 0..BATCHES {
        let jobs: Vec<(i64, bool, String, Option<String>)> = sqlx::query_as(
            "SELECT id,is_private,key,upload_id FROM object_cleanup WHERE id>$1 ORDER BY id LIMIT $2",
        ).bind(after).bind(BATCH).fetch_all(&state.pool).await?;
        if jobs.is_empty() {
            break;
        }
        // Advance past failures too, so one broken key cannot starve others.
        after = jobs.last().unwrap().0;
        for (id, private, key, upload) in jobs {
            let result: anyhow::Result<()> = async {
                if let Some(upload) = upload {
                    state
                        .storage
                        .abort_multipart(private, &key, &upload)
                        .await?;
                }
                state.storage.delete(private, &key).await?;
                sqlx::query("DELETE FROM object_cleanup WHERE id=$1")
                    .bind(id)
                    .execute(&state.pool)
                    .await?;
                Ok(())
            }
            .await;
            match result {
                Ok(()) => count += 1,
                Err(_) => failed = true,
            }
        }
    }
    if failed {
        anyhow::bail!("Object cleanup incomplete")
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use object_store::memory::InMemory;
    use sha2::Sha256;
    use tower::ServiceExt;

    use super::*;
    use crate::{config::Config, storage::Storage};

    // Independent test databases still share the process-wide sweep admission.
    static RUN_TESTS: Mutex<()> = Mutex::const_new(());

    async fn request(app: &Router, method: &str, path: &str, token: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    async fn fixture(pool: PgPool) -> (AppState, i32) {
        sqlx::query(
            "INSERT INTO orgs(id,slug,moving_from) VALUES('maintenance','current','previous')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let cache = sqlx::query_scalar(
            "INSERT INTO caches(org_id,name,is_public,retention_days)
            VALUES('maintenance','cache',true,1) RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let state = AppState::new(
            pool,
            Config::default(),
            Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new())),
            reqwest::Client::new(),
        )
        .unwrap();
        (state, cache)
    }

    async fn blob(state: &AppState, hash: &str) -> i64 {
        let id = sqlx::query_scalar(
            "INSERT INTO blob_objects(file_hash,file_size,compression,r2_key)
            VALUES($1,4,'zstd','nar/'||$1||'/zstd.nar') RETURNING id",
        )
        .bind(hash)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        for (private, key) in [
            (false, format!("nar/{hash}/zstd.nar")),
            (true, format!("nars/sha256/{hash}/zstd.nar")),
        ] {
            state.storage.put(private, &key, b"data").await.unwrap();
        }
        id
    }

    async fn path(state: &AppState, cache: i32, blob: i64, hash: &str) {
        sqlx::query("INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,last_pushed_at)
            VALUES($1,$2,'/nix/store/'||$2,'sha256:test',4,$3,now()-interval '2 days')")
            .bind(cache).bind(hash).bind(blob).execute(&state.pool).await.unwrap();
        for slug in ["current", "previous"] {
            state
                .storage
                .put(false, &format!("{slug}/cache/{hash}.narinfo"), b"metadata")
                .await
                .unwrap();
        }
    }

    async fn session(state: &AppState, cache: i32, id: &str, hash: &str, key: &str, status: &str) {
        sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,status,r2_upload_key,expires_at)
            VALUES($1,$2,$1,'/nix/store/'||$1,'sha256:test',4,$3,4,'zstd',$5,$4,now()-interval '1 day')")
            .bind(id).bind(cache).bind(hash).bind(key).bind(status).execute(&state.pool).await.unwrap();
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn session_pages_reclaim_unrelated_work_and_eventually_retry_partial_and_failed_uploads(
        pool: PgPool,
    ) {
        let _run = RUN_TESTS.lock().await;
        let (state, cache) = fixture(pool).await;
        // Both troublesome records precede more than a full run's budget.
        for id in ["a-failing", "b-partial"] {
            let key = format!("staging/{id}/source");
            session(&state, cache, id, id, &key, "streaming").await;
            state.storage.put(true, &key, b"data").await.unwrap();
        }
        sqlx::raw_sql(
            "CREATE FUNCTION reject_session_delete() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN IF OLD.id='a-failing' THEN RAISE EXCEPTION 'retry'; END IF; RETURN OLD; END $$;
             CREATE TRIGGER reject_session_delete BEFORE DELETE ON upload_sessions
             FOR EACH ROW EXECUTE FUNCTION reject_session_delete();",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upload_parts(session_id,part_number,etag,size,storage_key)
             SELECT 'b-partial',n,'etag',4,'staging/b-partial/part-'||n
             FROM generate_series(1,1001) n",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        for n in 1..=1001 {
            state
                .storage
                .put(true, &format!("staging/b-partial/part-{n}"), b"data")
                .await
                .unwrap();
        }
        for n in 0..421 {
            let id = format!("healthy-{n:04}");
            let key = format!("staging/{id}/source");
            session(&state, cache, &id, &id, &key, "streaming").await;
            state.storage.put(true, &key, b"data").await.unwrap();
        }

        let counts = run(&state).await.unwrap();
        assert_eq!(counts.failed_stages, 1);
        let healthy: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM upload_sessions WHERE starts_with(id,'healthy-')",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            healthy, 23,
            "398 healthy sessions advance despite failure and partial work"
        );
        assert!(
            state
                .storage
                .head(true, "staging/healthy-0397/source")
                .await
                .is_err()
        );
        assert!(
            state
                .storage
                .head(true, "staging/healthy-0398/source")
                .await
                .is_ok()
        );
        let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_parts")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(
            receipts, 501,
            "one bounded receipt page, not repeated oldest-session work"
        );

        let counts = run(&state).await.unwrap();
        assert_eq!(
            counts.failed_stages, 0,
            "cursor advances past the failed record"
        );
        assert_eq!(counts.sessions, 23);
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT id FROM upload_sessions ORDER BY id")
                .fetch_all(&state.pool)
                .await
                .unwrap();
        assert_eq!(remaining, ["a-failing", "b-partial"]);
        assert!(
            state
                .storage
                .head(true, "staging/healthy-0420/source")
                .await
                .is_err()
        );

        assert_eq!(run(&state).await.unwrap().failed_stages, 1);
        let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_parts")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(
            receipts, 1,
            "partial sessions make durable progress on revisit"
        );
        sqlx::query("DROP TRIGGER reject_session_delete ON upload_sessions")
            .execute(&state.pool)
            .await
            .unwrap();
        let counts = run(&state).await.unwrap();
        assert_eq!(counts.failed_stages, 0);
        assert_eq!(counts.sessions, 2);
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_sessions")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
        let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_parts")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(receipts, 0);
        assert!(
            state
                .storage
                .list(true, "staging", None, 2000)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn token_cleanup_preserves_revocations_through_jwt_tolerance(pool: PgPool) {
        let _run = RUN_TESTS.lock().await;
        let (state, cache) = fixture(pool).await;
        sqlx::query("UPDATE caches SET is_public=false WHERE id=$1")
            .bind(cache)
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) VALUES($1,'nix')")
            .bind(cache)
            .execute(&state.pool)
            .await
            .unwrap();
        let state = AppState::new(
            state.pool.clone(),
            Config {
                jwt_secret: "maintenance-secret".into(),
                ..Default::default()
            },
            state.storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut tokens = Vec::new();
        for (jti, exp, revoked) in [
            ("recent-revoked", now - 15, true),
            ("old-revoked", now - 86400, true),
            ("recent-valid", now - 15, false),
        ] {
            let payload = serde_json::json!({
                "jti":jti,"sub":"cli","iss":"snowstead","aud":"snowstead",
                "org":"maintenance","caches":[format!("id:{cache}")],
                "perms":["pull"],"iat":now-172800,"exp":exp
            });
            let input = format!(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
            );
            let mut mac = Hmac::<Sha256>::new_from_slice(b"maintenance-secret").unwrap();
            mac.update(input.as_bytes());
            tokens.push(format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            ));
            sqlx::query("INSERT INTO api_tokens(jti,subject,perms_json,created_by,org_id,expires_at,revoked_at)
                VALUES($1,'cli','[\"pull\"]','test','maintenance',to_timestamp($2),CASE WHEN $3 THEN now() END)")
                .bind(jti).bind(exp as f64).bind(revoked).execute(&state.pool).await.unwrap();
        }
        let app = crate::router(state.clone());
        for after_cleanup in [false, true] {
            if after_cleanup {
                let counts = run(&state).await.unwrap();
                assert_eq!(counts.failed_stages, 0);
                assert_eq!(counts.tokens, 1, "only the safely old token is eligible");
                let remaining: Vec<String> =
                    sqlx::query_scalar("SELECT jti FROM api_tokens ORDER BY jti")
                        .fetch_all(&state.pool)
                        .await
                        .unwrap();
                assert_eq!(remaining, ["recent-revoked", "recent-valid"]);
            }
            for (token, expected) in tokens.iter().zip([
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::OK,
            ]) {
                assert_eq!(
                    request(&app, "GET", "/current/cache/nix-cache-info", token).await,
                    expected,
                    "after_cleanup={after_cleanup}"
                );
            }
        }
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn retention_withdraws_both_slug_aliases_and_keeps_pinned_shared_nars(pool: PgPool) {
        let (state, cache) = fixture(pool).await;
        let shared = blob(&state, "shared").await;
        path(&state, cache, shared, "removed").await;
        path(&state, cache, shared, "pinned").await;
        let other: i32 = sqlx::query_scalar(
            "INSERT INTO caches(org_id,name,is_public)
            VALUES('maintenance','other',false) RETURNING id",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            VALUES($1,'shared','/nix/store/shared','sha256:test',4,$2)")
            .bind(other).bind(shared).execute(&state.pool).await.unwrap();
        sqlx::query(
            "INSERT INTO pins(id,cache_id,name,keep_kind,current_revision)
            VALUES('pin',$1,'release','forever',1)",
        )
        .bind(cache)
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO pin_revisions(id,pin_id,revision,store_path) VALUES('revision','pin',1,'/nix/store/pinned')")
            .execute(&state.pool).await.unwrap();
        sqlx::query("INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) VALUES('revision',$1,'pinned')")
            .bind(cache).execute(&state.pool).await.unwrap();
        assert_eq!(retention(&state).await.unwrap(), 1);
        assert_eq!(blobs(&state).await.unwrap(), 0);
        cleanup_objects(&state).await.unwrap();
        let hashes: Vec<String> =
            sqlx::query_scalar("SELECT store_path_hash FROM published_paths WHERE cache_id=$1")
                .bind(cache)
                .fetch_all(&state.pool)
                .await
                .unwrap();
        assert_eq!(hashes, ["pinned"]);
        for slug in ["current", "previous"] {
            assert!(
                state
                    .storage
                    .head(false, &format!("{slug}/cache/removed.narinfo"))
                    .await
                    .is_err()
            );
            assert!(
                state
                    .storage
                    .head(false, &format!("{slug}/cache/pinned.narinfo"))
                    .await
                    .is_ok()
            );
        }
        assert!(
            state
                .storage
                .head(false, "nar/shared/zstd.nar")
                .await
                .is_ok()
        );
        assert!(
            state
                .storage
                .head(true, "nars/sha256/shared/zstd.nar")
                .await
                .is_ok()
        );
        let reasons: Vec<String> = sqlx::query_scalar("SELECT reason FROM eviction_logs")
            .fetch_all(&state.pool)
            .await
            .unwrap();
        assert_eq!(reasons, ["retention"]);
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn failed_sql_commit_keeps_blob_and_rolls_back_cleanup_jobs(pool: PgPool) {
        let _run = RUN_TESTS.lock().await;
        let (state, _) = fixture(pool).await;
        blob(&state, "orphan").await;
        sqlx::raw_sql(
            "CREATE FUNCTION reject_gc_delete() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'injected'; END $$;
            CREATE TRIGGER reject_gc_delete BEFORE DELETE ON blob_objects
            FOR EACH ROW EXECUTE FUNCTION reject_gc_delete();",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        assert!(blob_batch(&state).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM blob_objects")
                .fetch_one(&state.pool)
                .await
                .unwrap(),
            1
        );
        // A failed retirement cannot delete bytes or leave a cleanup job.
        assert_eq!(cleanup_objects(&state).await.unwrap(), 0);
        assert!(
            state
                .storage
                .head(false, "nar/orphan/zstd.nar")
                .await
                .is_ok()
        );
        assert!(
            state
                .storage
                .head(true, "nars/sha256/orphan/zstd.nar")
                .await
                .is_ok()
        );
        sqlx::query(
            "INSERT INTO api_tokens(jti,subject,perms_json,created_by,expires_at)
            VALUES('expired','test','[]','test',now()-interval '1 day')",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        let counts = run(&state).await.unwrap();
        assert_eq!(counts.failed_stages, 1);
        assert_eq!(
            counts.tokens, 1,
            "Blob failure must not suppress token cleanup"
        );
        sqlx::query("DROP TRIGGER reject_gc_delete ON blob_objects")
            .execute(&state.pool)
            .await
            .unwrap();
        assert_eq!(blob_batch(&state).await.unwrap(), 1);
        assert_eq!(blob_batch(&state).await.unwrap(), 0);
        assert_eq!(cleanup_objects(&state).await.unwrap(), 2);
        assert!(
            state
                .storage
                .head(false, "nar/orphan/zstd.nar")
                .await
                .is_err()
        );
        assert!(
            state
                .storage
                .head(true, "nars/sha256/orphan/zstd.nar")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn retired_incarnation_cleanup_survives_republication_and_late_provider_completion(
        pool: PgPool,
    ) {
        let (state, cache) = fixture(pool).await;
        let old = "nar/objects/old/hash/zstd.nar";
        let new = "nar/objects/new/hash/zstd.nar";
        sqlx::query(
            "INSERT INTO blob_objects(file_hash,file_size,compression,r2_key,public_key)
            VALUES('hash',4,'zstd',$1,$1)",
        )
        .bind(old)
        .execute(&state.pool)
        .await
        .unwrap();
        state.storage.put(false, old, b"old!").await.unwrap();
        assert_eq!(blob_batch(&state).await.unwrap(), 1);
        // Retirement committed without touching storage. A crash here leaves
        // durable cleanup, while the same content can get a new incarnation.
        assert!(state.storage.head(false, old).await.is_ok());
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO blob_objects(file_hash,file_size,compression,r2_key,public_key)
            VALUES('hash',4,'zstd',$1,$1) RETURNING id",
        )
        .bind(new)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        path(&state, cache, id, "republished").await;
        state.storage.put(false, new, b"new!").await.unwrap();
        let restarted = AppState::new(
            state.pool.clone(),
            Config::default(),
            state.storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap();
        assert_eq!(cleanup_objects(&restarted).await.unwrap(), 3);
        assert!(state.storage.head(false, old).await.is_err());
        assert!(state.storage.head(false, new).await.is_ok());
        assert_eq!(blob_batch(&restarted).await.unwrap(), 0);
        // A provider operation can finish even after cleanup. Discovery must
        // retry that exact old key, without reclaiming the new publication.
        state.storage.put(false, old, b"late").await.unwrap();
        assert_eq!(
            orphan_nars(&restarted, false, "nar/objects/")
                .await
                .unwrap(),
            1
        );
        assert_eq!(cleanup_objects(&restarted).await.unwrap(), 1);
        assert_eq!(cleanup_objects(&restarted).await.unwrap(), 0);
        assert!(state.storage.head(false, old).await.is_err());
        let mut object = state.storage.open(false, new).await.unwrap();
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut object.reader, &mut bytes)
            .await
            .unwrap();
        assert_eq!(bytes, b"new!");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT blob_object_id FROM published_paths WHERE cache_id=$1"
            )
            .bind(cache)
            .fetch_one(&state.pool)
            .await
            .unwrap(),
            id
        );
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn legacy_sessions_adopt_canonical_bytes_but_preserve_mpu_reservations_and_sources(
        pool: PgPool,
    ) {
        let (state, cache) = fixture(pool).await;
        let state = AppState::new(
            state.pool.clone(),
            Config {
                admin_secret: "maintenance-admin".into(),
                ..Default::default()
            },
            state.storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap();
        session(
            &state,
            cache,
            "completed",
            "abandoned",
            "nar/abandoned/zstd.nar",
            "completed",
        )
        .await;
        state
            .storage
            .put(false, "nar/abandoned/zstd.nar", b"data")
            .await
            .unwrap();
        session(
            &state,
            cache,
            "canonical-mpu",
            "reserved",
            "nar/reserved/zstd.nar",
            "finalizing",
        )
        .await;
        sqlx::query(
            "UPDATE upload_sessions SET r2_upload_id='provider-id' WHERE id IN ('completed','canonical-mpu')",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        blob(&state, "reserved").await;
        session(
            &state,
            cache,
            "staged",
            "stage-hash",
            "staging/staged",
            "completed",
        )
        .await;
        state
            .storage
            .put(true, "staging/staged/assembled", b"data")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO upload_parts(session_id,part_number,etag,size,storage_key)
            VALUES('staged',1,'etag',4,'staging/staged/part')",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        state
            .storage
            .put(true, "staging/staged/part", b"data")
            .await
            .unwrap();
        session(
            &state,
            cache,
            "pinned",
            "source-hash",
            "staging/pinned",
            "completed",
        )
        .await;
        state
            .storage
            .put(true, "staging/pinned", b"data")
            .await
            .unwrap();
        sqlx::query("INSERT INTO nar_installations(key,operation_id,source_key,file_hash,compression,is_private,file_size)
            VALUES('nar/source-hash/zstd.nar','operation','staging/pinned','source-hash','zstd',false,4)")
            .execute(&state.pool).await.unwrap();
        // Start with live sessions so eviction, not their original age, must
        // expire them without erasing proof that the canonical MPU completed.
        sqlx::query("UPDATE upload_sessions SET expires_at=now()+interval '1 day'")
            .execute(&state.pool)
            .await
            .unwrap();
        assert_eq!(sessions(&state).await.unwrap(), 0);
        let app = crate::router(state.clone());
        assert_eq!(
            request(
                &app,
                "POST",
                "/_api/v1/orgs/maintenance/caches/cache/evict",
                "maintenance-admin"
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(sessions(&state).await.unwrap(), 2);
        orphan_page(&state, "staging/", None).await.unwrap();
        cleanup_objects(&state).await.unwrap();
        assert!(
            state
                .storage
                .head(true, "staging/staged/assembled")
                .await
                .is_err()
        );
        assert!(
            state
                .storage
                .head(true, "staging/staged/part")
                .await
                .is_err()
        );
        assert!(state.storage.head(true, "staging/pinned").await.is_ok());
        assert_eq!(blobs(&state).await.unwrap(), 1);
        cleanup_objects(&state).await.unwrap();
        assert!(
            state
                .storage
                .head(false, "nar/abandoned/zstd.nar")
                .await
                .is_err()
        );
        assert!(
            state
                .storage
                .head(false, "nar/reserved/zstd.nar")
                .await
                .is_ok()
        );
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT id FROM upload_sessions ORDER BY id")
                .fetch_all(&state.pool)
                .await
                .unwrap();
        assert_eq!(remaining, ["canonical-mpu", "pinned"]);
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
    async fn legacy_staging_multipart_cleanup_retains_original_provider_id(pool: PgPool) {
        use axum::body::Bytes;
        use object_store::{aws::AmazonS3Builder, multipart::MultipartStore, path::Path};

        let config = Config::from_env();
        let endpoint = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
        assert_eq!(config.r2_endpoint, endpoint);
        assert!(endpoint.starts_with("http://127.0.0.1:"));
        let provider = AmazonS3Builder::new()
            .with_region("auto")
            .with_endpoint(&endpoint)
            .with_bucket_name(&config.r2_bucket_name)
            .with_access_key_id(&config.r2_access_key_id)
            .with_secret_access_key(&config.r2_secret_access_key)
            .with_allow_http(true)
            .with_virtual_hosted_style_request(false)
            .build()
            .unwrap();
        let cache: i32 =
            sqlx::query_scalar("INSERT INTO caches(name) VALUES ('legacy') RETURNING id")
                .fetch_one(&pool)
                .await
                .unwrap();
        let storage = Storage::new(&config).unwrap();
        let state = AppState::new(
            pool.clone(),
            Config::default(),
            storage,
            reqwest::Client::new(),
        )
        .unwrap();
        for already_aborted in [false, true] {
            let id = uuid::Uuid::now_v7().to_string();
            let key = format!("staging/{id}/legacy");
            let path = Path::from(key.clone());
            let upload = provider.create_multipart(&path).await.unwrap();
            let part = provider
                .put_part(&path, &upload, 0, Bytes::from_static(b"data").into())
                .await
                .unwrap();
            session(&state, cache, &id, "legacy-hash", &key, "streaming").await;
            sqlx::query("UPDATE upload_sessions SET r2_upload_id=$2 WHERE id=$1")
                .bind(&id)
                .bind(&upload)
                .execute(&pool)
                .await
                .unwrap();
            if already_aborted {
                provider.abort_multipart(&path, &upload).await.unwrap();
            }
            assert!(expire_session(&state, &id, "default").await.unwrap());
            let retained: Option<String> =
                sqlx::query_scalar("SELECT upload_id FROM object_cleanup WHERE key=$1")
                    .bind(&key)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(retained.as_deref(), Some(upload.as_str()));
            cleanup_objects(&state).await.unwrap();
            assert!(
                provider
                    .complete_multipart(&path, &upload, vec![part])
                    .await
                    .is_err(),
                "cleanup must abort the original upload, not just delete its key"
            );
            let remaining: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM upload_sessions WHERE id=$1)")
                    .bind(&id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert!(!remaining);
        }
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn compiler_sweep_and_attempt_discovery_preserve_live_reservations(pool: PgPool) {
        let (state, cache) = fixture(pool).await;
        for kind in ["go", "sccache"] {
            for (id, generation) in [("obsolete", "old"), ("live", "0")] {
                let key = format!("{kind}-attempt/{id}/adopted");
                let (column, value) = if kind == "go" {
                    (",output", ",'checksum'")
                } else {
                    ("", "")
                };
                sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {kind}_entries(id,cache_id,generation,action,r2_key,size,expires_at{column})
                    VALUES($1,$2,$3,$1,$4,4,now()+interval '1 day'{value})")))
                    .bind(id).bind(cache).bind(generation).bind(&key).execute(&state.pool).await.unwrap();
                state.storage.put(true, &key, b"data").await.unwrap();
                state
                    .storage
                    .put(true, &format!("{kind}-attempt/{id}/loser"), b"data")
                    .await
                    .unwrap();
            }
            assert_eq!(compiler_entries(&state, kind).await.unwrap(), 1);
            assert_eq!(
                orphan_page(&state, &format!("{kind}-attempt/"), Some(kind))
                    .await
                    .unwrap(),
                1
            );
            cleanup_objects(&state).await.unwrap();
            assert!(
                state
                    .storage
                    .head(true, &format!("{kind}-attempt/obsolete/adopted"))
                    .await
                    .is_err()
            );
            assert!(
                state
                    .storage
                    .head(true, &format!("{kind}-attempt/obsolete/loser"))
                    .await
                    .is_err()
            );
            assert!(
                state
                    .storage
                    .head(true, &format!("{kind}-attempt/live/loser"))
                    .await
                    .is_ok()
            );
        }
    }
}
