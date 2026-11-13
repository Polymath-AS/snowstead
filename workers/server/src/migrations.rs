//! One schema baseline; existing deployments require an explicit ledger rebaseline.
use anyhow::{Result, ensure};
use serde::Deserialize;
use sqlx::{Connection, Executor, PgConnection, PgPool, migrate::Migrate};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Deserialize)]
struct LegacyMigration {
    version: i64,
    description: String,
    checksum: String,
}

struct AppliedMigration {
    version: i64,
    success: bool,
    checksum: Vec<u8>,
}

/// Run fresh or already-rebaselined installations; never infer an existing schema.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn run(pool: &PgPool) -> Result<()> {
    migrate(pool, false).await
}

/// Refuse a transport cutover while an old relay session owns uploaded bytes.
/// This check is read-only: operators must drain or cancel those pushes first.
pub async fn check_upload_cutover(pool: &PgPool) -> Result<()> {
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM upload_sessions u WHERE u.r2_upload_id=u.id \
         AND u.status IN ('streaming','finalizing') AND u.expires_at>NOW() \
         AND EXISTS (SELECT 1 FROM upload_parts p WHERE p.session_id=u.id AND p.etag IS NOT NULL)",
    )
    .fetch_one(pool)
    .await?;
    ensure!(
        active == 0,
        "{active} active relayed upload sessions contain uploaded parts; drain or cancel their pushes before deploying presigned uploads"
    );
    Ok(())
}

/// Replace only the exact, fully applied legacy SQLx ledger. Schema and application
/// data are untouched; the old ledger is retained as `_sqlx_migrations_legacy`.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn rebaseline(pool: &PgPool) -> Result<()> {
    migrate(pool, true).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn migrate(pool: &PgPool, rebaseline: bool) -> Result<()> {
    // Session locks require a pinned connection. Close it even on cancellation,
    // rather than returning a possibly locked session to the pool.
    let mut conn =
        crate::profile_future!(pool.acquire(), label = "migrations.pool_acquire").await?;
    conn.close_on_drop();
    let result = async {
        crate::profile_future!(conn.lock(), label = "migrations.advisory_lock_wait").await?;
        if rebaseline {
            baseline(&mut conn).await?;
        }
        conn.ensure_migrations_table(&MIGRATOR.table_name).await?;
        let applied = validate_sqlx(&mut conn).await?;
        ensure!(
            !drizzle_exists(&mut conn).await? || applied > 0,
            "Drizzle ledger found without a SQLx baseline; upgrade with the pre-baseline release first"
        );
        for migration in MIGRATOR.iter().skip(applied) {
            conn.apply(&MIGRATOR.table_name, migration).await?;
        }
        Ok(())
    }
    .await;
    let unlock = conn.unlock().await;
    let close = conn.close().await;
    result?;
    unlock?;
    close?;
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn drizzle_exists(conn: &mut PgConnection) -> Result<bool> {
    Ok(sqlx::query_scalar!(
        r#"
        SELECT TO_REGCLASS('drizzle.__drizzle_migrations') IS NOT NULL AS "exists!"
        "#,
    )
    .fetch_one(conn)
    .await?)
}

async fn applied(conn: &mut PgConnection) -> Result<Vec<AppliedMigration>> {
    Ok(sqlx::query_as!(
        AppliedMigration,
        r#"
        SELECT
            version,
            success,
            checksum
        FROM _sqlx_migrations
        ORDER BY version
        "#,
    )
    .fetch_all(conn)
    .await?)
}

/// Require a clean, known prefix, not merely a subset of known versions.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn validate_sqlx(conn: &mut PgConnection) -> Result<usize> {
    let rows = applied(conn).await?;
    ensure!(
        rows.len() <= MIGRATOR.iter().len(),
        "legacy or unknown SQLx history; the deployed 15-migration history requires migrate --rebaseline"
    );
    for (row, expected) in rows.iter().zip(MIGRATOR.iter()) {
        ensure!(row.success, "dirty SQLx migration {}", row.version);
        ensure!(
            row.version == expected.version,
            "SQLx history has a gap or unknown version {}",
            row.version
        );
        ensure!(
            row.checksum.as_slice() == expected.checksum.as_ref(),
            "SQLx checksum conflict at {}",
            row.version
        );
    }
    Ok(rows.len())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn baseline(conn: &mut PgConnection) -> Result<()> {
    let history: Vec<LegacyMigration> =
        serde_json::from_str(include_str!("../migration-history.json"))?;
    let mut tx = conn.begin().await?;
    tx.execute("LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE")
        .await?;
    let rows = applied(&mut tx).await?;
    // A repeated operator command is safe, including after later migrations.
    if validate_sqlx(&mut tx).await.is_ok() && !rows.is_empty() {
        tx.commit().await?;
        return Ok(());
    }
    ensure!(
        rows.len() == history.len(),
        "rebaseline requires the complete legacy migration history"
    );
    for (row, expected) in rows.iter().zip(history) {
        ensure!(
            row.success
                && row.version == expected.version
                && hex::encode(&row.checksum) == expected.checksum,
            "legacy SQLx ledger mismatch at {} ({})",
            expected.version,
            expected.description
        );
    }
    // Retain the original ledger and install the baseline receipt atomically.
    // If a backup already exists or any statement fails, everything rolls back.
    tx.execute("ALTER TABLE _sqlx_migrations RENAME TO _sqlx_migrations_legacy")
        .await?;
    tx.ensure_migrations_table(&MIGRATOR.table_name).await?;
    let migration = MIGRATOR.iter().next().expect("schema baseline exists");
    sqlx::query!(
        r#"
        INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
        VALUES ($1, $2, TRUE, $3, 0)
        "#,
        migration.version,
        migration.description.as_ref(),
        migration.checksum.as_ref(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
