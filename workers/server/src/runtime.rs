//! Shared startup validation for standalone and composed API hosts.
use crate::{
    AppState,
    config::{Config, connect_pool},
    migrations,
    storage::Storage,
};
use sqlx::PgPool;

/// Build the cache state from the host's primary pool and environment.
/// Migrations remain an explicit operator action, not a startup side effect.
pub async fn application_state(pool: PgPool) -> anyhow::Result<AppState> {
    migrations::check_upload_cutover(&pool).await?;
    let config = Config::from_env();
    config.validate_auth()?;
    if config.allow_legacy_web_admin {
        tracing::warn!(
            "ALLOW_LEGACY_WEB_ADMIN=true: org routes accept ADMIN_SECRET with an unverified actor; turn it off once the dashboard signs assertions"
        );
    }
    if config.jwt_secret.is_empty() {
        let live: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM api_tokens WHERE secret_hash IS NULL \
             AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()))",
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| anyhow::anyhow!("Reading API tokens failed; run migrations first"))?;
        anyhow::ensure!(
            !live,
            "JWT_SECRET is required while unrevoked JWT-era API tokens exist"
        );
    }
    let storage = Storage::new(&config)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let mut state = AppState::new(pool, config, storage, http)?;
    match std::env::var("DATABASE_READ_URL") {
        Ok(url) => {
            let max_connections: u32 = std::env::var("DATABASE_READ_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "8".to_owned())
                .parse()?;
            anyhow::ensure!(
                max_connections > 0,
                "DATABASE_READ_MAX_CONNECTIONS must be positive"
            );
            state.read_pool = connect_pool(&url, max_connections, 5)
                .await
                .map_err(|_| anyhow::anyhow!("Read database connection failed"))?;
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(_) => anyhow::bail!("DATABASE_READ_URL must be valid Unicode"),
    }
    Ok(state)
}
