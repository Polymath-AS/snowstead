use sqlx::{Postgres, Transaction};

/// Acquire a transaction-scoped fence using the service's shared key namespace.
/// Callers own key construction, lock ordering, and wait profiling.
pub(crate) async fn advisory_lock(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            SELECT pg_advisory_xact_lock(hashtextextended($1, 0)) AS "lock!: ()"
            "#,
        key
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}
