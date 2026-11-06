//! Run with: scripts/with-postgres.sh cargo test -p snowstead-server --test migrations
use anyhow::{Context, Result};
use futures_util::FutureExt;
use snowstead_server::migrations;
use sqlx::{
    Connection, Executor, PgConnection, PgPool, migrate::Migrate, postgres::PgConnectOptions,
};
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

async fn isolated<F, Fut>(test: F) -> Result<()>
where
    F: FnOnce(PgPool) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let url = std::env::var("SNOWSTEAD_TEST_DATABASE_URL")
        .context("run via scripts/with-postgres.sh; tests require a disposable Postgres server")?;
    let options = PgConnectOptions::from_str(&url)?;
    let mut admin = PgConnection::connect_with(&options).await?;
    let name = format!(
        "snowstead_migrations_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    admin
        .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .await?;
    let pool = PgPool::connect_with(options.database(&name)).await?;
    let outcome = AssertUnwindSafe(test(pool.clone())).catch_unwind().await;
    pool.close().await;
    admin
        .execute(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .await?;
    admin.close().await?;
    match outcome {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn legacy(pool: &PgPool) -> Result<()> {
    // The schema baseline is independently checked against the historical chain.
    // This fixture installs that schema with the frozen, deployed ledger.
    sqlx::raw_sql(include_str!("../migrations/0000_baseline.sql"))
        .execute(pool)
        .await?;
    let mut conn = pool.acquire().await?;
    conn.ensure_migrations_table(&migrations::MIGRATOR.table_name)
        .await?;
    drop(conn);
    let history: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../migration-history.json"))?;
    for migration in history {
        sqlx::query("INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES ($1, $2, true, $3, 17)")
            .bind(migration["version"].as_i64().unwrap())
            .bind(migration["description"].as_str().unwrap())
            .bind(hex::decode(migration["checksum"].as_str().unwrap())?)
            .execute(pool).await?;
    }
    pool.execute("CREATE SCHEMA drizzle; CREATE TABLE drizzle.__drizzle_migrations (id serial PRIMARY KEY, hash text NOT NULL, created_at bigint); INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ('preserved', 123)").await?;
    Ok(())
}

async fn count(pool: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await?)
}

async fn ledger(pool: &PgPool) -> Result<serde_json::Value> {
    Ok(sqlx::query_scalar("SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY version), '[]'::jsonb) FROM _sqlx_migrations m")
        .fetch_one(pool).await?)
}

#[tokio::test]
async fn fresh_and_idempotent() -> Result<()> {
    isolated(|pool| async move {
        migrations::run(&pool).await?;
        assert_eq!(count(&pool).await?, 1);
        let custom_keys: bool =
            sqlx::query_scalar("SELECT custom_signing_keys FROM orgs WHERE id = 'default'")
                .fetch_one(&pool)
                .await?;
        assert!(custom_keys);
        pool.execute("INSERT INTO caches (name) VALUES ('preserved')")
            .await?;
        migrations::run(&pool).await?;
        migrations::rebaseline(&pool).await?;
        assert_eq!(count(&pool).await?, 1);
        let names: Vec<String> = sqlx::query_scalar("SELECT name FROM caches")
            .fetch_all(&pool)
            .await?;
        assert_eq!(names, ["preserved"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rebaseline_preserves_data_and_both_legacy_ledgers() -> Result<()> {
    isolated(|pool| async move {
        legacy(&pool).await?;
        pool.execute("INSERT INTO caches (name, signing_key_name, signing_public_key, signing_key_sealed) VALUES ('existing', 'cache-1', 'public-key', 'sealed-key'); INSERT INTO bandwidth_daily (org_id, cache_id, product, day, bytes) VALUES ('default', 0, 'nix', '2026-10-01', 123)").await?;
        let before = ledger(&pool).await?;
        let caches: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(c)) FROM caches c").fetch_one(&pool).await?;
        assert!(migrations::run(&pool).await.is_err(), "must not auto-rebaseline");
        migrations::rebaseline(&pool).await?;
        assert_eq!(count(&pool).await?, 1);
        let retained: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM _sqlx_migrations_legacy m").fetch_one(&pool).await?;
        assert_eq!(retained, before);
        let after: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(c)) FROM caches c").fetch_one(&pool).await?;
        assert_eq!(after, caches);
        let bytes: i64 = sqlx::query_scalar("SELECT bytes FROM bandwidth_daily").fetch_one(&pool).await?;
        assert_eq!(bytes, 123);
        let drizzle: (String, i64) = sqlx::query_as("SELECT hash, created_at FROM drizzle.__drizzle_migrations").fetch_one(&pool).await?;
        assert_eq!(drizzle, ("preserved".into(), 123));
        let baseline = ledger(&pool).await?;
        migrations::rebaseline(&pool).await?;
        migrations::run(&pool).await?;
        assert_eq!(ledger(&pool).await?, baseline);
        Ok(())
    }).await
}

#[tokio::test]
async fn invalid_legacy_history_is_rejected_without_changes() -> Result<()> {
    for tamper in [
        "UPDATE _sqlx_migrations SET success = false WHERE version = 14",
        "UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') WHERE version = 0",
        "DELETE FROM _sqlx_migrations WHERE version = 7",
        "UPDATE _sqlx_migrations SET version = 999 WHERE version = 14",
        "INSERT INTO _sqlx_migrations SELECT 999, description, installed_on, success, checksum, execution_time FROM _sqlx_migrations WHERE version = 0",
        "TRUNCATE _sqlx_migrations",
    ] {
        isolated(|pool| async move {
            legacy(&pool).await?;
            pool.execute(tamper).await?;
            let before = ledger(&pool).await?;
            assert!(migrations::rebaseline(&pool).await.is_err());
            assert_eq!(ledger(&pool).await?, before);
            let absent: bool =
                sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations_legacy') IS NULL")
                    .fetch_one(&pool)
                    .await?;
            assert!(absent);
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn failed_rebaseline_rolls_back_and_allows_retry() -> Result<()> {
    isolated(|pool| async move {
        legacy(&pool).await?;
        let before = ledger(&pool).await?;
        pool.execute("CREATE TABLE _sqlx_migrations_legacy (sentinel integer)")
            .await?;
        assert!(migrations::rebaseline(&pool).await.is_err());
        assert_eq!(ledger(&pool).await?, before);
        pool.execute("DROP TABLE _sqlx_migrations_legacy").await?;
        // Fail after the old ledger has been renamed, while creating the new
        // one. This must roll back the rename too, not only receipt insertion.
        pool.execute(
            r#"
            CREATE FUNCTION reject_new_ledger() RETURNS event_trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF to_regclass('_sqlx_migrations_legacy') IS NOT NULL THEN
                    RAISE EXCEPTION 'injected baseline installation failure';
                END IF;
            END $$;
            CREATE EVENT TRIGGER reject_new_ledger ON ddl_command_end
                WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION reject_new_ledger();
        "#,
        )
        .await?;
        assert!(migrations::rebaseline(&pool).await.is_err());
        assert_eq!(ledger(&pool).await?, before);
        let absent: bool =
            sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations_legacy') IS NULL")
                .fetch_one(&pool)
                .await?;
        assert!(absent);
        pool.execute("DROP EVENT TRIGGER reject_new_ledger; DROP FUNCTION reject_new_ledger()")
            .await?;
        migrations::rebaseline(&pool).await?;
        assert_eq!(count(&pool).await?, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn drizzle_only_requires_the_pre_baseline_release() -> Result<()> {
    isolated(|pool| async move {
        pool.execute(
            "CREATE SCHEMA drizzle; CREATE TABLE drizzle.__drizzle_migrations (id integer)",
        )
        .await?;
        assert!(migrations::run(&pool).await.is_err());
        assert!(migrations::rebaseline(&pool).await.is_err());
        let absent: bool = sqlx::query_scalar("SELECT to_regclass('caches') IS NULL")
            .fetch_one(&pool)
            .await?;
        assert!(absent);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancellation_closes_the_locked_dedicated_session() -> Result<()> {
    isolated(|pool| async move {
        legacy(&pool).await?;
        let mut blocker = pool.begin().await?;
        blocker.execute("LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE").await?;
        let migration_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .connect_with(pool.connect_options().as_ref().clone().application_name("migration-budget-test"))
            .await?;
        let task_pool = migration_pool.clone();
        let task = tokio::spawn(async move { migrations::rebaseline(&task_pool).await });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let held: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))")
                    .fetch_one(&pool).await?;
                if held { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok::<(), anyhow::Error>(())
        }).await??;
        let connections: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND application_name = 'migration-budget-test'")
            .fetch_one(&pool).await?;
        assert_eq!(connections, 1, "migrations must stay within the pool's connection budget");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        migration_pool.close().await;
        blocker.rollback().await?;
        tokio::time::timeout(std::time::Duration::from_secs(10), migrations::rebaseline(&pool)).await??;
        assert_eq!(count(&pool).await?, 1);
        Ok(())
    }).await
}

#[tokio::test]
async fn concurrent_runners_use_the_sqlx_lock() -> Result<()> {
    isolated(|pool| async move {
        let (first, second) = tokio::join!(migrations::run(&pool), migrations::run(&pool));
        first?;
        second?;
        assert_eq!(count(&pool).await?, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn concurrent_rebaselines_are_idempotent() -> Result<()> {
    isolated(|pool| async move {
        legacy(&pool).await?;
        let (first, second) =
            tokio::join!(migrations::rebaseline(&pool), migrations::rebaseline(&pool));
        first?;
        second?;
        assert_eq!(count(&pool).await?, 1);
        Ok(())
    })
    .await
}
