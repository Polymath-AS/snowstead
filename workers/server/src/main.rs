use snowstead_server::{
    AppState,
    config::{Config, connect_pool, listen_address},
    migrations, serve,
    storage::Storage,
};

#[cfg(not(feature = "profiling"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

#[cfg(feature = "profiling")]
fn main() -> anyhow::Result<()> {
    let _profile = hotpath::HotpathGuardBuilder::new("snowstead-server")
        .percentiles(&[50.0, 95.0, 99.0])
        .limit(0)
        .sections(vec![
            hotpath::Section::FunctionsTiming,
            hotpath::Section::Futures,
            hotpath::Section::Streams,
        ])
        .build();
    // SAFETY: one session, outside the runtime: dropping the runtime also waits
    // for cancelled requests' spawn_blocking verifiers before snitch finishes.
    let _native = unsafe { snowstead_server::NativeProfile::start() };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        // Instrumented handler futures exceed Tokio's default 2 MiB stack.
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn run() -> anyhow::Result<()> {
    #[cfg(feature = "observability")]
    let telemetry = snowstead_server::observability::init().await;
    #[cfg(not(feature = "observability"))]
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let result = run_server().await;
    #[cfg(feature = "observability")]
    if let Some(telemetry) = telemetry {
        telemetry.shutdown().await;
    }
    result
}

async fn run_server() -> anyhow::Result<()> {
    let url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
    let max_connections: u32 = std::env::var("DATABASE_MAX_CONNECTIONS")
        .unwrap_or_else(|_| "8".to_owned())
        .parse()?;
    anyhow::ensure!(
        max_connections > 0,
        "DATABASE_MAX_CONNECTIONS must be positive"
    );
    let pool = connect_pool(&url, max_connections)
        .await
        .map_err(|_| anyhow::anyhow!("Database connection failed"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => {}
        ["migrate"] => {
            migrations::run(&pool).await?;
            pool.close().await;
            return Ok(());
        }
        ["migrate", "--rebaseline"] => {
            migrations::rebaseline(&pool).await?;
            pool.close().await;
            return Ok(());
        }
        _ => anyhow::bail!("Usage: snowstead-server [migrate [--rebaseline]]"),
    }
    let config = Config::from_env();
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
            state.read_pool = connect_pool(&url, max_connections)
                .await
                .map_err(|_| anyhow::anyhow!("Read database connection failed"))?;
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(_) => anyhow::bail!("DATABASE_READ_URL must be valid Unicode"),
    }
    let listener = tokio::net::TcpListener::bind(listen_address()?).await?;
    tracing::info!(address = %listener.local_addr()?, "Snowstead listening");
    serve(listener, state, shutdown()).await?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Draining requests before shutdown");
}
