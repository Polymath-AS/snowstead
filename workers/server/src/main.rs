use snowstead_server::{
    config::{connect_pool, listen_address},
    migrations,
    runtime::application_state,
    serve,
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
    let pool = connect_pool(&url, max_connections, 2)
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
        ["check-upload-cutover"] => {
            migrations::check_upload_cutover(&pool).await?;
            pool.close().await;
            println!("Upload cutover ready: no active relayed parts");
            return Ok(());
        }
        _ => {
            anyhow::bail!("Usage: snowstead-server [migrate [--rebaseline] | check-upload-cutover]")
        }
    }
    let state = application_state(pool).await?;
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
