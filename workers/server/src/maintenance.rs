//! Bounded, retryable control-plane maintenance over the existing R2 objects.
//!
//! SQL withdrawal records exact keys in a durable cleanup queue. Storage I/O
//! never holds a transaction. Uploads that predate staging are not handled
//! here: the deploy check refuses to start while any remain.
use std::time::Duration;

use futures_util::{StreamExt, stream};
use snowstead_cache_types::Compiler;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::{sync::Mutex, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{AppState, auth::JWT_CLOCK_SKEW_SECONDS, lifecycle::UploadStatus};

const BATCH: i64 = 500;
const BATCHES: usize = 20;
const CLEANUP_CONCURRENCY: usize = 8;
// Each session costs one transaction, which retires all of its receipts. Do
// not let one broken upload spend the run: the cursor moves past it.
const SESSION_PAGE: usize = 20;
// Row expiry and the session sweep run until drained, since each can gain far
// more than one batch between runs. Both stay bounded: the deadline is checked
// between statements (batch size and statement timeouts are unchanged), and
// the iteration caps hold even if the clock does not.
const SESSION_PAGES: usize = 5_000;
const SESSION_BUDGET: Duration = Duration::from_secs(300);
const ROW_BATCHES: usize = 2_000;
const ROW_BUDGET: Duration = Duration::from_secs(60);
/// The pause between drain passes while there is work, as it has always been.
const BUSY: Duration = Duration::from_secs(1);
// Retain revocations beyond the verifier's entire acceptance window, with
// a small margin for clock/precision differences between SQL and the server.
const TOKEN_EXPIRY_MARGIN_SECONDS: i64 = 5;
static RUNNING: Mutex<()> = Mutex::const_new(());

#[derive(Default)]
struct CleanupCursor {
    after: i64,
    through: i64,
}

/// Drain durable retirement work independently of the slow discovery sweep.
/// Each pass finishes one bounded page before shutdown. The cursor passes
/// failed entries and wraps, so neither retries nor new arrivals can starve.
///
/// Nobody waits on this, and its queues fill from many writers and triggers,
/// so nothing wakes it. A pass that retired something, or left cleanup pages
/// of its frozen range unread, is followed a second later by the next: the
/// pace it always had, so a backlog drains as before and a stage that keeps
/// reporting progress cannot spin. A pass that found nothing waits out the
/// idle period, which is how late an expiry here can now run. A pass
/// that only failed backs off instead.
pub(crate) async fn drain(state: AppState, stopped: CancellationToken) {
    let mut cursor = CleanupCursor::default();
    let mut failures = crate::wake::Backoff::default();
    while !stopped.is_cancelled() {
        let mut counts = Counts::default();
        record(
            &mut counts.push_jobs,
            &mut counts.failed_stages,
            "push manifests",
            expire_manifests(&state).await,
        );
        record(
            &mut counts.sessions,
            &mut counts.failed_stages,
            "finalization batches",
            crate::uploads::expire_finalizations(&state).await,
        );
        record(
            &mut counts.orphan_objects,
            &mut counts.failed_stages,
            "publication reservations",
            expire_installations(&state).await,
        );
        record(
            &mut counts.orphan_objects,
            &mut counts.failed_stages,
            "object cleanup",
            cleanup_objects(&state, &mut cursor).await,
        );
        let retired = counts.push_jobs + counts.sessions + counts.orphan_objects > 0;
        let pause = if retired {
            failures.reset();
            BUSY
        } else if counts.failed_stages > 0 {
            failures.next()
        } else if cursor.after < cursor.through {
            BUSY
        } else {
            failures.reset();
            state.idle_period
        };
        tokio::select! {
            _ = stopped.cancelled() => break,
            _ = tokio::time::sleep(pause) => {}
        }
    }
}

#[derive(Default, Debug)]
/// Counts from fully successful stages; a failed stage may have made partial
/// progress in independently committed batches before retaining its retry work.
pub(crate) struct Counts {
    pub compiler_entries: u64,
    pub orphan_objects: u64,
    pub sessions: u64,
    pub push_jobs: u64,
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
    run_bounded(state, SESSION_PAGES).await
}

async fn run_bounded(state: &AppState, session_pages: usize) -> anyhow::Result<Counts> {
    let Ok(_running) = RUNNING.try_lock() else {
        return Ok(Counts::default());
    };
    let mut counts = Counts::default();
    record(
        &mut counts.push_jobs,
        &mut counts.failed_stages,
        "push manifests",
        expire_manifests(state).await,
    );
    record(
        &mut counts.orphan_objects,
        &mut counts.failed_stages,
        "publication reservations",
        expire_installations(state).await,
    );
    for compiler in Compiler::ALL {
        let kind = compiler.as_str();
        record(
            &mut counts.compiler_entries,
            &mut counts.failed_stages,
            kind,
            compiler_entries(state, compiler).await,
        );
        record(
            &mut counts.orphan_objects,
            &mut counts.failed_stages,
            "compiler attempts",
            orphan_page(state, &format!("{kind}-attempt/"), Some(compiler)).await,
        );
    }
    record(
        &mut counts.sessions,
        &mut counts.failed_stages,
        "upload sessions",
        sessions(state, session_pages).await,
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
        "blobs",
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
        async {
            let mut cursor = CleanupCursor::default();
            let mut count = 0;
            let mut failed = false;
            for _ in 0..BATCHES {
                match cleanup_objects(state, &mut cursor).await {
                    Ok(n) => count += n,
                    Err(_) => failed = true,
                }
                if cursor.after >= cursor.through {
                    break;
                }
            }
            anyhow::ensure!(!failed, "Object cleanup incomplete");
            Ok(count)
        }
        .await,
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

/// Sweeps give way to request writers at once and bound every statement.
/// The settings travel with BEGIN in one round trip; see `db::start`.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn begin(pool: &PgPool) -> anyhow::Result<Transaction<'static, Postgres>> {
    Ok(crate::profile_future!(
        crate::db::start(
            pool,
            "SET LOCAL lock_timeout = '1ms'; SET LOCAL statement_timeout = '30s'; BEGIN",
        ),
        label = "maintenance.pool_begin"
    )
    .await?)
}

/// For sweeps that order themselves against request writers on a row lock:
/// the same wait budget those writers have, instead of giving up at once.
async fn begin_patient(pool: &PgPool) -> anyhow::Result<Transaction<'static, Postgres>> {
    Ok(crate::db::start(
        pool,
        "SET LOCAL lock_timeout = '100ms'; SET LOCAL statement_timeout = '30s'; BEGIN",
    )
    .await?)
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
    let deadline = Instant::now() + ROW_BUDGET;
    let mut count = 0;
    // One short autocommit statement per batch: other writers interleave.
    for _ in 0..ROW_BATCHES {
        let n = expire_row_batch(pool, table).await?;
        count += n;
        if n < BATCH as u64 || Instant::now() >= deadline {
            break;
        }
    }
    Ok(count)
}

async fn expire_row_batch(pool: &PgPool, table: &'static str) -> anyhow::Result<u64> {
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
async fn compiler_entries(state: &AppState, compiler: Compiler) -> anyhow::Result<u64> {
    let candidates = match compiler {
        Compiler::Go => {
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
        Compiler::Sccache => {
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
            let mut tx = begin_patient(&state.pool).await?;
            if org.is_some() {
                // Hold the generation the predicate below compares against.
                // A reset takes this row FOR UPDATE.
                sqlx::query!(
                    r#"
                    SELECT id
                    FROM caches
                    WHERE id = $1
                    FOR KEY SHARE
                    "#,
                    cache
                )
                .fetch_all(&mut *tx)
                .await?;
            }
            let key = match compiler {
                Compiler::Go => {
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
                Compiler::Sccache => {
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
            };
            let Some(key) = key else { return Ok(false) };
            sqlx::query(
                "INSERT INTO object_cleanup(is_private,key) VALUES(TRUE,$1) ON CONFLICT DO NOTHING",
            )
            .bind(&key)
            .execute(&mut *tx)
            .await?;
            match compiler {
                Compiler::Go => {
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
                Compiler::Sccache => {
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
    product: Option<Compiler>,
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
            Some(Compiler::Go) => {
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
            Some(Compiler::Sccache) => {
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

#[derive(sqlx::FromRow)]
struct Session {
    id: String,
    status: UploadStatus,
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
async fn sessions(state: &AppState, pages: usize) -> anyhow::Result<u64> {
    let deadline = Instant::now() + SESSION_BUDGET;
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
    for page in 0..pages {
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
            match expire_session(state, &candidate.id).await {
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
        // The saved cursor resumes here next run.
        if Instant::now() >= deadline {
            break;
        }
    }
    if failed {
        anyhow::bail!("Session cleanup incomplete")
    }
    Ok(count)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn expire_session(state: &AppState, id: &str) -> anyhow::Result<bool> {
    let mut tx = begin_patient(&state.pool).await?;
    // Candidate allocation takes the same upload lock before it leases this
    // session's staged bytes, so the lease check below cannot go stale.
    lock(&mut tx, &format!("upload:{id}")).await?;
    let session = sqlx::query_as::<_, Session>(
        "SELECT u.id, u.status, u.r2_upload_key, u.r2_upload_id
        FROM upload_sessions u
        WHERE u.id = $1
            AND u.expires_at <= now()
            AND NOT EXISTS(
                SELECT 1
                FROM nar_installations i
                WHERE i.source_key = u.r2_upload_key
                    OR starts_with(i.source_key, 'staging/' || u.id || '/')
            )
        FOR UPDATE OF u NOWAIT",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(s) = session else { return Ok(false) };
    if let Some(key) = &s.r2_upload_key {
        // Every upload stages under its own prefix. Anything else predates
        // staging and is not ours to reclaim: the deploy check refuses it.
        if !key.starts_with("staging/") {
            return Ok(false);
        }
        // The session ID marks a multipart upload not yet initialized.
        // All other upload IDs belong to the provider and need aborting.
        let upload = s
            .r2_upload_id
            .as_ref()
            .filter(|upload| *upload != &s.id && s.status != UploadStatus::Completed);
        sqlx::query("INSERT INTO object_cleanup(is_private,key,upload_id) VALUES(TRUE,$1,$2) \
            ON CONFLICT(is_private,key) DO UPDATE SET upload_id=COALESCE(object_cleanup.upload_id,EXCLUDED.upload_id)")
            .bind(key).bind(upload).execute(&mut *tx).await?;
    }
    // The cleanup queue owns these immutable keys after SQL deletion; a crash
    // cannot lose the remaining physical work. Unreceipted parts and late
    // writes are discovered by orphan_page after their session is gone.
    sqlx::query(
        "WITH gone AS (DELETE FROM upload_parts WHERE session_id = $1 RETURNING storage_key)
        INSERT INTO object_cleanup(is_private, key)
        SELECT DISTINCT TRUE, storage_key FROM gone WHERE storage_key IS NOT NULL
        ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
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
                    AND NOT EXISTS (
                        SELECT 1 FROM nix_job_protected_paths(c.org_id, now()) j
                        WHERE j.cache_id=p.cache_id AND j.store_path_hash=p.store_path_hash
                    )
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
    let mut tx = begin_patient(&state.pool).await?;
    // The cache row, for its path totals: this pass reads its retention
    // policy and deletes its paths. Publication, eviction, pins, and
    // withdrawal in this cache each run wholly before or after it. Uploads
    // in flight hold the row FOR KEY SHARE, which this does not wait for.
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
        FOR NO KEY UPDATE OF c
        "#,
        cache,
        org
    )
    .fetch_optional(&mut *tx)
    .await?;
    if metadata.is_none() {
        return Ok(0);
    }
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
                AND NOT EXISTS (
                    SELECT 1 FROM nix_job_protected_paths(c.org_id, now()) j
                    WHERE j.cache_id=p.cache_id AND j.store_path_hash=p.store_path_hash
                )
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
    tx.commit().await?;
    Ok(hashes.len() as u64)
}

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
    // A batch can come back short when publication holds some candidates, so
    // only an empty batch ends the sweep.
    for _ in 0..BATCHES {
        let n = blob_batch(state).await?;
        count += n;
        if n == 0 {
            break;
        }
    }
    Ok(count)
}

// A blob is collectable once no publication points at it and no publication
// attempt is preparing the same bytes. Upload sessions hold no claim: each
// one stages its own bytes and publishes a key of its own.
const UNREFERENCED: &str = "NOT EXISTS (SELECT 1 FROM published_paths p WHERE p.blob_object_id = b.id) \
    AND NOT EXISTS (SELECT 1 FROM nar_installations i \
        WHERE i.file_hash = b.file_hash AND i.compression = b.compression)";

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn blob_batch(state: &AppState) -> anyhow::Result<u64> {
    let mut tx = begin(&state.pool).await?;
    // Publication takes these row locks to adopt a blob, so skipping locked
    // rows never waits and never collects a blob that is being adopted.
    let ids: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT b.id FROM blob_objects b WHERE {UNREFERENCED} \
         ORDER BY b.id LIMIT $1 FOR UPDATE OF b SKIP LOCKED"
    )))
    .bind(BATCH)
    .fetch_all(&mut *tx)
    .await?;
    if ids.is_empty() {
        return Ok(0);
    }
    // A publication that committed after the first snapshot is visible to
    // this statement, and none can adopt these rows while they are locked.
    // Retire the SQL identity before I/O. New uploads create a new physical
    // incarnation, never one of these queued keys.
    let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "WITH gone AS (
            DELETE FROM blob_objects b WHERE b.id = ANY($1) AND {UNREFERENCED}
            RETURNING b.file_hash, b.compression, b.r2_key, b.public_key, b.private_key
        ), queued AS (
            INSERT INTO object_cleanup(is_private, key)
            SELECT DISTINCT k.is_private, k.key FROM gone g CROSS JOIN LATERAL (VALUES
                (TRUE, 'nars/sha256/' || g.file_hash || '/' || g.compression || '.nar'),
                (FALSE, 'nar/' || g.file_hash || '/' || g.compression || '.nar'),
                (NOT starts_with(g.r2_key, 'nar/'), g.r2_key),
                (FALSE, g.public_key),
                (TRUE, g.private_key)
            ) AS k(is_private, key)
            WHERE k.key IS NOT NULL
            ON CONFLICT DO NOTHING
        )
        SELECT count(*) FROM gone"
    )))
    .bind(&ids)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count as u64)
}

/// Reclaim at most twenty bounded manifests per sweep. Keep expired identities
/// until 24 hours after their hard deadline so delayed retries cannot reopen
/// a builder. Each job's row is locked first, as manifest writes lock it.
async fn expire_manifests(state: &AppState) -> anyhow::Result<u64> {
    let jobs: Vec<(String, String)> = sqlx::query_as(
        "SELECT j.id,c.org_id FROM push_jobs j JOIN caches c ON c.id=j.cache_id \
         WHERE (j.manifest_bytes>0 AND (j.idle_expires_at<=NOW() OR j.hard_expires_at<=NOW())) \
            OR j.hard_expires_at<=NOW()-INTERVAL '24 hours' ORDER BY j.idle_expires_at,j.id LIMIT 20",
    ).fetch_all(&state.pool).await?;
    let mut count = 0;
    for (id, _) in jobs {
        let mut tx = crate::db::begin(state).await?;
        let cleared: i64 = sqlx::query_scalar(
            "WITH expired AS (UPDATE push_jobs SET manifest_bytes=0 WHERE id=$1 AND manifest_bytes>0 \
                AND (idle_expires_at<=NOW() OR hard_expires_at<=NOW()) RETURNING id), \
             chunks AS (DELETE FROM push_manifest_chunks WHERE job_id IN (SELECT id FROM expired)), \
             members AS (DELETE FROM push_job_members WHERE job_id IN (SELECT id FROM expired)), \
             sessions AS (UPDATE upload_sessions SET status='aborted',expires_at=LEAST(expires_at,NOW()) \
                WHERE push_job_id IN (SELECT id FROM expired) AND status IN ('streaming','finalizing')) \
             SELECT count(*) FROM expired",
        ).bind(&id).fetch_one(&mut *tx).await?;
        let removed = sqlx::query(
            "DELETE FROM push_jobs WHERE id=$1 AND hard_expires_at<=NOW()-INTERVAL '24 hours'",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        count += u64::from(cleared > 0 || removed.rows_affected() > 0);
    }
    Ok(count)
}

/// Expiry revokes adoption, not provider execution. Late writes use unique keys
/// and are rediscovered by orphan_nars. A row without an expiry predates
/// staged uploads and is left alone; the deploy check refuses those.
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
                    OR (i.phase='preparing' AND i.lease_expires_at<=NOW())
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
async fn cleanup_objects(state: &AppState, cursor: &mut CleanupCursor) -> anyhow::Result<u64> {
    if cursor.after >= cursor.through {
        // Freeze this pass's endpoint so continuous arrivals cannot postpone
        // retries forever. A restart can safely begin another pass at zero.
        cursor.through = sqlx::query_scalar("SELECT coalesce(max(id),0) FROM object_cleanup")
            .fetch_one(&state.pool)
            .await?;
        cursor.after = 0;
    }
    let jobs: Vec<(i64, bool, String, Option<String>)> = sqlx::query_as(
        "SELECT id,is_private,key,upload_id FROM object_cleanup WHERE id>$1 AND id<=$2 ORDER BY id LIMIT $3",
    ).bind(cursor.after).bind(cursor.through).bind(BATCH).fetch_all(&state.pool).await?;
    let Some(last) = jobs.last() else {
        cursor.after = cursor.through;
        return Ok(0);
    };
    cursor.after = last.0;
    let results = stream::iter(jobs)
        .map(|(id, private, key, upload)| async move {
            let result: anyhow::Result<()> = async {
                if let Some(upload) = upload.as_deref() {
                    state.storage.abort_multipart(private, &key, upload).await?;
                }
                state.storage.delete(private, &key).await?;
                Ok(())
            }
            .await;
            (id, upload, result)
        })
        .buffer_unordered(CLEANUP_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut ids = Vec::new();
    let mut uploads = Vec::new();
    let mut failed = false;
    for (id, upload, result) in results {
        if result.is_ok() {
            ids.push(id);
            uploads.push(upload);
        } else {
            failed = true;
        }
    }
    // A crash before acknowledgement merely repeats safe deletions. Do not
    // acknowledge a multipart upload that changed while storage was in flight.
    let count = sqlx::query(
        "DELETE FROM object_cleanup q USING unnest($1::bigint[],$2::text[]) AS done(id,upload_id) \
         WHERE q.id=done.id AND q.upload_id IS NOT DISTINCT FROM done.upload_id",
    )
    .bind(&ids)
    .bind(&uploads)
    .execute(&state.pool)
    .await?
    .rows_affected();
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

    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn sweep_transactions_start_in_one_round_trip_with_their_settings(observer: PgPool) {
        async fn show(tx: &mut Transaction<'_, Postgres>, setting: &'static str) -> String {
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SHOW {setting}")))
                .fetch_one(&mut **tx)
                .await
                .unwrap()
        }
        let (pool, ready) = crate::db::counted(&observer).await;
        let count = || ready.load(std::sync::atomic::Ordering::SeqCst);

        let before = count();
        let mut tx = begin(&pool).await.unwrap();
        assert_eq!(count() - before, 1);
        assert_eq!(show(&mut tx, "lock_timeout").await, "1ms");
        assert_eq!(show(&mut tx, "statement_timeout").await, "30s");
        // Dropped, as a sweep that fails leaves it.
        drop(tx);
        crate::db::settle(&pool).await;

        let before = count();
        let mut tx = begin_patient(&pool).await.unwrap();
        assert_eq!(count() - before, 1);
        assert_eq!(show(&mut tx, "lock_timeout").await, "100ms");
        assert_eq!(show(&mut tx, "statement_timeout").await, "30s");
        tx.commit().await.unwrap();
        crate::db::settle(&pool).await;

        // The one connection kept neither setting past its transactions.
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(show(&mut tx, "lock_timeout").await, "0");
        assert_eq!(show(&mut tx, "statement_timeout").await, "0");
        tx.commit().await.unwrap();
        pool.close().await;
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

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn cleanup_passes_failures_bounds_arrivals_and_retries_after_wrap(pool: PgPool) {
        let (state, _) = fixture(pool).await;
        // This store cannot abort persisted multipart uploads. A whole failed
        // page must not prevent later public/private objects being deleted.
        sqlx::query(
            "INSERT INTO object_cleanup(is_private,key,upload_id) \
            SELECT false,'failed/'||n,'unsupported' FROM generate_series(1,500) n",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        state
            .storage
            .put(false, "retired/public", b"public")
            .await
            .unwrap();
        sqlx::query("INSERT INTO object_cleanup(is_private,key) VALUES(false,'retired/public')")
            .execute(&state.pool)
            .await
            .unwrap();
        let mut cursor = CleanupCursor::default();
        assert!(cleanup_objects(&state, &mut cursor).await.is_err());
        state
            .storage
            .put(true, "retired/private", b"private")
            .await
            .unwrap();
        sqlx::query("INSERT INTO object_cleanup(is_private,key) VALUES(true,'retired/private')")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE object_cleanup SET upload_id=NULL WHERE upload_id IS NOT NULL")
            .execute(&state.pool)
            .await
            .unwrap();
        assert_eq!(cleanup_objects(&state, &mut cursor).await.unwrap(), 1);
        assert!(state.storage.head(false, "retired/public").await.is_err());
        assert!(
            state.storage.head(true, "retired/private").await.is_ok(),
            "arrivals belong to the next pass, so retries cannot starve"
        );
        assert_eq!(cleanup_objects(&state, &mut cursor).await.unwrap(), 500);
        assert_eq!(cleanup_objects(&state, &mut cursor).await.unwrap(), 1);
        assert!(state.storage.head(true, "retired/private").await.is_err());

        // Exercise the lifecycle worker, not just manual sweeps: newly queued
        // retirement must drain without waiting for the six-hour discovery.
        state
            .storage
            .put(false, "retired/background", b"background")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO object_cleanup(is_private,key) VALUES(false,'retired/background')",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        let stopped = CancellationToken::new();
        let worker = tokio::spawn(drain(state.clone(), stopped.clone()));
        let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM object_cleanup")
                    .fetch_one(&state.pool)
                    .await
                    .unwrap();
                if queued == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        stopped.cancel();
        worker.await.unwrap();
        drained.unwrap();
        assert!(
            state
                .storage
                .head(false, "retired/background")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn manifest_expiry_is_bounded_and_retains_retry_identities(pool: PgPool) {
        let _run = RUN_TESTS.lock().await;
        let (state, cache) = fixture(pool).await;
        sqlx::query("INSERT INTO push_jobs(id,cache_id,creator,idempotency_key,mode,roots,manifest_bytes,idle_expires_at) \
            SELECT 'expired-'||n,$1,'actor',n::text,'closure','[]',32,NOW()-INTERVAL '1 hour' FROM generate_series(1,23) n")
            .bind(cache).execute(&state.pool).await.unwrap();
        sqlx::query("INSERT INTO push_jobs(id,cache_id,creator,idempotency_key,mode,roots,manifest_bytes,idle_expires_at,hard_expires_at) \
            VALUES('old',$1,'actor','old','closure','[]',32,NOW()-INTERVAL '26 hours',NOW()-INTERVAL '25 hours'), \
            ('active',$1,'actor','active','closure','[]',32,NOW()+INTERVAL '1 hour',NOW()+INTERVAL '2 hours')")
            .bind(cache).execute(&state.pool).await.unwrap();
        sqlx::raw_sql(
            "INSERT INTO push_manifest_chunks SELECT id,0,'[]' FROM push_jobs; \
            INSERT INTO push_job_members SELECT id,'member','{}' FROM push_jobs;",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE push_jobs SET state='completed',completed_at=NOW()-INTERVAL '2 hours', \
            protection_expires_at=NOW()-INTERVAL '1 hour' WHERE id='expired-1'",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        for status in ["streaming", "finalizing", "completed"] {
            let id = format!("expired-{status}");
            session(
                &state,
                cache,
                &id,
                &id,
                &format!("staging/{id}/source"),
                status,
            )
            .await;
            sqlx::query("UPDATE upload_sessions SET push_job_id='expired-1',expires_at=NOW()+INTERVAL '1 hour' WHERE id=$1")
                .bind(id).execute(&state.pool).await.unwrap();
        }
        assert_eq!(expire_manifests(&state).await.unwrap(), 20);
        let sessions: Vec<(String, bool)> =
            sqlx::query_as("SELECT status,expires_at<=NOW() FROM upload_sessions ORDER BY id")
                .fetch_all(&state.pool)
                .await
                .unwrap();
        assert_eq!(
            sessions,
            vec![
                ("completed".into(), false),
                ("aborted".into(), true),
                ("aborted".into(), true)
            ],
            "expiry releases unfinished work without destroying completed receipts"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM push_manifest_chunks")
                .fetch_one(&state.pool)
                .await
                .unwrap(),
            5
        );
        let second = run(&state).await.unwrap();
        assert_eq!(second.failed_stages, 0);
        assert_eq!(second.push_jobs, 4);
        let chunks: Vec<String> = sqlx::query_scalar("SELECT job_id FROM push_manifest_chunks")
            .fetch_all(&state.pool)
            .await
            .unwrap();
        let members: Vec<String> = sqlx::query_scalar("SELECT job_id FROM push_job_members")
            .fetch_all(&state.pool)
            .await
            .unwrap();
        assert_eq!(chunks, vec!["active"]);
        assert_eq!(members, vec!["active"]);
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT state='completed' AND completed_at IS NOT NULL \
            FROM push_jobs WHERE id='expired-1'"
            )
            .fetch_one(&state.pool)
            .await
            .unwrap(),
            "manifest reclamation must preserve the historical completion receipt"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM push_jobs WHERE id LIKE 'expired-%' AND manifest_bytes=0"
            )
            .fetch_one(&state.pool)
            .await
            .unwrap(),
            23
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM push_jobs WHERE id='old'")
                .fetch_one(&state.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(run(&state).await.unwrap().push_jobs, 0);
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
    async fn session_pages_reclaim_unrelated_work_and_eventually_retry_failed_uploads(
        pool: PgPool,
    ) {
        let _run = RUN_TESTS.lock().await;
        let (state, cache) = fixture(pool).await;
        // A run stops at its page budget here, as a production run does at its
        // deadline: the cursor rules are the same.
        const PAGES: usize = 20;
        // The failing record and one with more receipts than a batch precede
        // more than a full run's budget.
        for id in ["a-failing", "b-large"] {
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
             SELECT 'b-large',n,'etag',4,'staging/b-large/part-'||n
             FROM generate_series(1,1001) n",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        for n in 1..=1001 {
            state
                .storage
                .put(true, &format!("staging/b-large/part-{n}"), b"data")
                .await
                .unwrap();
        }
        for n in 0..421 {
            let id = format!("healthy-{n:04}");
            let key = format!("staging/{id}/source");
            session(&state, cache, &id, &id, &key, "streaming").await;
            state.storage.put(true, &key, b"data").await.unwrap();
        }

        let counts = run_bounded(&state, PAGES).await.unwrap();
        assert_eq!(counts.failed_stages, 1);
        let healthy: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM upload_sessions WHERE starts_with(id,'healthy-')",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            healthy, 23,
            "398 healthy sessions advance despite the failure"
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
        assert_eq!(receipts, 0, "a session's receipts retire in one pass");
        assert!(
            state
                .storage
                .list(true, "staging/b-large", None, 2000)
                .await
                .unwrap()
                .is_empty(),
            "every receipt key was queued and cleaned"
        );

        let counts = run_bounded(&state, PAGES).await.unwrap();
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
        assert_eq!(remaining, ["a-failing"]);
        assert!(
            state
                .storage
                .head(true, "staging/healthy-0420/source")
                .await
                .is_err()
        );

        assert_eq!(run_bounded(&state, PAGES).await.unwrap().failed_stages, 1);
        sqlx::query("DROP TRIGGER reject_session_delete ON upload_sessions")
            .execute(&state.pool)
            .await
            .unwrap();
        let counts = run_bounded(&state, PAGES).await.unwrap();
        assert_eq!(counts.failed_stages, 0);
        assert_eq!(counts.sessions, 1);
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
    async fn one_run_drains_backlogs_larger_than_a_batch(pool: PgPool) {
        let _run = RUN_TESTS.lock().await;
        let (state, cache) = fixture(pool).await;
        // More than one 500-row batch per table and more than twenty session
        // pages: what a single run used to leave behind for six hours.
        sqlx::raw_sql(
            "INSERT INTO audit_logs(actor,action,status,timestamp)
             SELECT 'ci','push',200,now()-interval '31 days' FROM generate_series(1,1201);
             INSERT INTO audit_logs(actor,action,status) VALUES('ci','push',200);
             INSERT INTO eviction_logs(org_id,cache_id,cache,product,key,size,reason,evicted_at)
             SELECT 'maintenance',0,'cache','nix',n::text,1,'capacity',now()-interval '31 days'
             FROM generate_series(1,501) n;",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_size,compression,status,expires_at)
             SELECT 'expired-'||n,$1,n::text,'/nix/store/'||n,'sha256:test',4,4,'zstd','streaming',now()-interval '1 day'
             FROM generate_series(1,450) n",
        )
        .bind(cache)
        .execute(&state.pool)
        .await
        .unwrap();

        let counts = run(&state).await.unwrap();
        assert_eq!(counts.failed_stages, 0);
        assert_eq!(counts.audit_logs, 1201);
        assert_eq!(counts.eviction_logs, 501);
        assert_eq!(counts.sessions, 450);
        let remaining: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM audit_logs), (SELECT count(*) FROM eviction_logs),
                (SELECT count(*) FROM upload_sessions)",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(remaining, (1, 0, 0), "only the unexpired audit row remains");
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
            // The row, not the claims, grants what the token may do.
            sqlx::query(
                "INSERT INTO token_permissions(token_jti,permission,position) VALUES($1,'pull',1)",
            )
            .bind(jti)
            .execute(&state.pool)
            .await
            .unwrap();
            sqlx::query("INSERT INTO token_caches(token_jti,cache_id) VALUES($1,$2)")
                .bind(jti)
                .bind(cache)
                .execute(&state.pool)
                .await
                .unwrap();
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
    async fn retention_withdraws_sql_publication_without_queuing_narinfo_and_keeps_pinned_shared_nars(
        pool: PgPool,
    ) {
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
        // Narinfo is rendered from SQL: retention queues no metadata object.
        let queued: i64 =
            sqlx::query_scalar("SELECT count(*) FROM object_cleanup WHERE key LIKE '%.narinfo'")
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(queued, 0);
        assert_eq!(blobs(&state).await.unwrap(), 0);
        cleanup_objects(&state, &mut CleanupCursor::default())
            .await
            .unwrap();
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
                    .is_ok()
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
    async fn retention_honors_job_protection_until_its_deadline(pool: PgPool) {
        let (state, cache) = fixture(pool).await;
        let shared = blob(&state, "job-shared").await;
        path(&state, cache, shared, "protected").await;
        path(&state, cache, shared, "ordinary").await;
        sqlx::query("INSERT INTO api_tokens(jti,subject,perms_json,created_by,org_id) VALUES('job-token','test','[\"push\"]','test','maintenance')")
            .execute(&state.pool).await.unwrap();
        sqlx::query("INSERT INTO push_jobs(id,cache_id,creator,idempotency_key,mode,roots,state,manifest_bytes,authorization_jti,authorization_expires_at)
            VALUES('job',$1,'job-token','job','selected','[]','sealed',1,'job-token',now()+interval '30 minutes')")
            .bind(cache).execute(&state.pool).await.unwrap();
        sqlx::query("INSERT INTO push_job_members(job_id,store_path_hash,metadata)
            SELECT 'job',store_path_hash,jsonb_build_object('storePath',store_path,'narHash',nar_hash,'narSize',nar_size,'references',references_json::jsonb,'deriver',deriver)
            FROM published_paths WHERE store_path_hash='protected'").execute(&state.pool).await.unwrap();
        assert_eq!(retention(&state).await.unwrap(), 1);
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT store_path_hash FROM published_paths")
                .fetch_all(&state.pool)
                .await
                .unwrap();
        assert_eq!(remaining, ["protected"]);
        sqlx::query("UPDATE push_jobs SET idle_expires_at=now()-interval '1 second'")
            .execute(&state.pool)
            .await
            .unwrap();
        assert_eq!(retention(&state).await.unwrap(), 1);
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
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
        assert_eq!(
            cleanup_objects(&state, &mut CleanupCursor::default())
                .await
                .unwrap(),
            0
        );
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
        assert_eq!(
            cleanup_objects(&state, &mut CleanupCursor::default())
                .await
                .unwrap(),
            2
        );
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

    async fn blob_ids(state: &AppState) -> Vec<i64> {
        sqlx::query_scalar("SELECT id FROM blob_objects ORDER BY id")
            .fetch_all(&state.pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn blob_collection_skips_locked_rows_and_keeps_blobs_adopted_meanwhile(pool: PgPool) {
        let (state, cache) = fixture(pool).await;
        let idle = blob(&state, "idle").await;
        let adopted = blob(&state, "adopted").await;
        blob(&state, "free").await;
        // Publication locks the blob rows it adopts until it commits.
        let mut publication = state.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM blob_objects WHERE id=ANY($1) FOR UPDATE")
            .bind(vec![idle, adopted])
            .fetch_all(&mut *publication)
            .await
            .unwrap();
        // Collection neither waits for those rows nor fails on them.
        assert_eq!(blob_batch(&state).await.unwrap(), 1);
        assert_eq!(blob_ids(&state).await, [idle, adopted]);
        sqlx::query("INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            VALUES($1,'adopted','/nix/store/adopted','sha256:test',4,$2)")
            .bind(cache).bind(adopted).execute(&mut *publication).await.unwrap();
        assert_eq!(blob_batch(&state).await.unwrap(), 0);
        publication.commit().await.unwrap();
        // Once unlocked, the still unreferenced blob goes and the adopted one stays.
        assert_eq!(blob_batch(&state).await.unwrap(), 1);
        assert_eq!(blob_ids(&state).await, [adopted]);
        let queued: Vec<(bool, String)> =
            sqlx::query_as("SELECT is_private,key FROM object_cleanup ORDER BY key")
                .fetch_all(&state.pool)
                .await
                .unwrap();
        assert_eq!(
            queued,
            [
                (false, "nar/free/zstd.nar".to_owned()),
                (false, "nar/idle/zstd.nar".to_owned()),
                (true, "nars/sha256/free/zstd.nar".to_owned()),
                (true, "nars/sha256/idle/zstd.nar".to_owned()),
            ]
        );
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn blob_collection_rechecks_a_selected_blob_that_was_published_before_its_lock(
        pool: PgPool,
    ) {
        use std::time::Duration;

        let (state, cache) = fixture(pool).await;
        let raced = blob(&state, "raced").await;
        // Pause the selecting statement after it has taken its snapshot and
        // before it locks the row: the predicate reads installations through
        // a view which waits on a barrier, then reports no installation.
        sqlx::raw_sql(
            "ALTER TABLE nar_installations RENAME TO held_installations;
            CREATE TABLE gate_calls(n integer);
            CREATE FUNCTION gate() RETURNS boolean LANGUAGE plpgsql AS $$
            BEGIN
                PERFORM set_config('lock_timeout','0',true);
                PERFORM pg_advisory_xact_lock_shared(78432::bigint);
                INSERT INTO gate_calls VALUES(1);
                RETURN false;
            END $$;
            CREATE VIEW nar_installations AS SELECT * FROM held_installations WHERE gate();
            INSERT INTO held_installations(key,operation_id,source_key,file_hash,compression,is_private,file_size)
            VALUES('gate','gate','staging/gate/source','raced','zstd',false,4);",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        let mut barrier = state.pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(78432::bigint)")
            .execute(&mut *barrier)
            .await
            .unwrap();
        let collection = tokio::spawn({
            let state = state.clone();
            async move { blob_batch(&state).await }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT FROM pg_locks
                WHERE locktype='advisory' AND classid=0 AND objid=78432 AND NOT granted)",
            )
            .fetch_one(&state.pool)
            .await
            .unwrap()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("collection must reach the barrier");
        // A publication commits in that window. The paused statement's
        // snapshot cannot see it, so it still selects and locks the blob.
        sqlx::query("INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            VALUES($1,'raced','/nix/store/raced','sha256:test',4,$2)")
            .bind(cache).bind(raced).execute(&state.pool).await.unwrap();
        barrier.rollback().await.unwrap();
        assert_eq!(collection.await.unwrap().unwrap(), 0);
        // Only a committed collection keeps the gate's records: the blob was
        // selected, and the deleting statement then saw the publication.
        let calls: i64 = sqlx::query_scalar("SELECT count(*) FROM gate_calls")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert!(calls > 0, "the blob must have been selected");
        assert_eq!(blob_ids(&state).await, [raced]);
        let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM object_cleanup")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(queued, 0);
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn collection_and_expiry_proceed_while_another_session_row_is_being_written(
        pool: PgPool,
    ) {
        let (state, cache) = fixture(pool).await;
        blob(&state, "shared").await;
        // A live session for the same content holds no claim on the blob.
        session(
            &state,
            cache,
            "writing",
            "shared",
            "staging/writing/source",
            "streaming",
        )
        .await;
        sqlx::query("UPDATE upload_sessions SET expires_at=now()+interval '1 day'")
            .execute(&state.pool)
            .await
            .unwrap();
        session(
            &state,
            cache,
            "lapsed",
            "other",
            "staging/lapsed/source",
            "streaming",
        )
        .await;
        let mut writer = state.pool.begin().await.unwrap();
        sqlx::query("UPDATE upload_sessions SET file_size=file_size+1 WHERE id='writing'")
            .execute(&mut *writer)
            .await
            .unwrap();
        // Neither stage takes a table lock, so an open row write elsewhere in
        // the table does not fail them.
        assert_eq!(blob_batch(&state).await.unwrap(), 1);
        assert!(blob_ids(&state).await.is_empty());
        assert!(expire_session(&state, "lapsed").await.unwrap());
        writer.commit().await.unwrap();
        let remaining: Vec<String> = sqlx::query_scalar("SELECT id FROM upload_sessions")
            .fetch_all(&state.pool)
            .await
            .unwrap();
        assert_eq!(remaining, ["writing"]);
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn expiry_removes_a_session_with_more_receipts_than_a_batch_in_one_pass(pool: PgPool) {
        let (state, cache) = fixture(pool).await;
        session(
            &state,
            cache,
            "large",
            "large",
            "staging/large/source",
            "streaming",
        )
        .await;
        // One receipt was reserved but never stored: it has no key to queue.
        sqlx::query(
            "INSERT INTO upload_parts(session_id,part_number,etag,size,storage_key)
             SELECT 'large',n,'etag',4,CASE WHEN n<=1001 THEN 'staging/large/part-'||n END
             FROM generate_series(1,1002) n",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        assert!(expire_session(&state, "large").await.unwrap());
        let remaining: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM upload_sessions),(SELECT count(*) FROM upload_parts)",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(remaining, (0, 0));
        let queued: (i64, i64, i64) = sqlx::query_as(
            "SELECT count(*),count(*) FILTER (WHERE starts_with(key,'staging/large/part-')),
                count(*) FILTER (WHERE key='staging/large/source')
             FROM object_cleanup WHERE is_private AND upload_id IS NULL",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(queued, (1002, 1001, 1));
        // The session is gone: a later sweep finds nothing left to do.
        assert!(!expire_session(&state, "large").await.unwrap());
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
        assert_eq!(
            cleanup_objects(&restarted, &mut CleanupCursor::default())
                .await
                .unwrap(),
            3
        );
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
        assert_eq!(
            cleanup_objects(&restarted, &mut CleanupCursor::default())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            cleanup_objects(&restarted, &mut CleanupCursor::default())
                .await
                .unwrap(),
            0
        );
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
    async fn eviction_expires_staged_sessions_but_keeps_leased_sources_and_unstaged_sessions(
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
        // An upload written straight to a final key predates staging. Expiry
        // must not touch it: neither its row nor its bytes are ours to reclaim.
        session(
            &state,
            cache,
            "unstaged",
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
        // expire them.
        sqlx::query("UPDATE upload_sessions SET expires_at=now()+interval '1 day'")
            .execute(&state.pool)
            .await
            .unwrap();
        assert_eq!(sessions(&state, SESSION_PAGES).await.unwrap(), 0);
        let app = crate::router(state.clone());
        // Org routes take the org's own credentials, not the operator's.
        sqlx::query("INSERT INTO org_api_keys(id,org_id,name,secret_hash) VALUES('0123456789abcdef','maintenance','test',$1)")
            .bind(crate::auth::secret_hash("key-secret"))
            .execute(&state.pool)
            .await
            .unwrap();
        assert_eq!(
            request(
                &app,
                "POST",
                "/_api/v1/orgs/maintenance/caches/cache/evict",
                "snowstead_key_0123456789abcdef_key-secret"
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(sessions(&state, SESSION_PAGES).await.unwrap(), 1);
        orphan_page(&state, "staging/", None).await.unwrap();
        cleanup_objects(&state, &mut CleanupCursor::default())
            .await
            .unwrap();
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
        // The unstaged upload was not adopted as a blob, so nothing can
        // collect its bytes.
        assert_eq!(blobs(&state).await.unwrap(), 0);
        cleanup_objects(&state, &mut CleanupCursor::default())
            .await
            .unwrap();
        assert!(
            state
                .storage
                .head(false, "nar/abandoned/zstd.nar")
                .await
                .is_ok()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM blob_objects")
                .fetch_one(&state.pool)
                .await
                .unwrap(),
            0
        );
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT id FROM upload_sessions ORDER BY id")
                .fetch_all(&state.pool)
                .await
                .unwrap();
        assert_eq!(remaining, ["pinned", "unstaged"]);
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
            assert!(expire_session(&state, &id).await.unwrap());
            let retained: Option<String> =
                sqlx::query_scalar("SELECT upload_id FROM object_cleanup WHERE key=$1")
                    .bind(&key)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(retained.as_deref(), Some(upload.as_str()));
            cleanup_objects(&state, &mut CleanupCursor::default())
                .await
                .unwrap();
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
        for compiler in Compiler::ALL {
            let kind = compiler.as_str();
            for (id, generation) in [("obsolete", "old"), ("live", "0")] {
                let key = format!("{kind}-attempt/{id}/adopted");
                let (column, value) = match compiler {
                    Compiler::Go => (",output", ",'checksum'"),
                    Compiler::Sccache => ("", ""),
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
            assert_eq!(compiler_entries(&state, compiler).await.unwrap(), 1);
            assert_eq!(
                orphan_page(&state, &format!("{kind}-attempt/"), Some(compiler))
                    .await
                    .unwrap(),
                1
            );
            cleanup_objects(&state, &mut CleanupCursor::default())
                .await
                .unwrap();
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
