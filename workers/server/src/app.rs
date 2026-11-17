use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::any,
    serve::ListenerExt,
};
use serde_json::json;
use sqlx::PgPool;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    cdn,
    config::Config,
    error::{ApiError, json_response},
    maintenance, management, protocol_policy, storage,
};

#[derive(Clone)]
pub struct AppState {
    pub(crate) pool: PgPool,
    /// Pool for explicitly stale-tolerant reads; shares the primary by default.
    pub read_pool: PgPool,
    pub(crate) config: Arc<Config>,
    pub(crate) http: reqwest::Client,
    pub(crate) tasks: TaskTracker,
    finalization_stop: CancellationToken,
    finalization_started: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) storage: storage::Storage,
    pub(crate) upstream_slots: Arc<Semaphore>,
    pub(crate) management_limits: Arc<management::ApiLimits>,
    pub(crate) protocol_limits: Arc<protocol_policy::ProtocolLimits>,
    pub(crate) verification_slots: Arc<Semaphore>,
    pub(crate) preparation_slots: Arc<Semaphore>,
    pub(crate) manifest_slots: Arc<Semaphore>,
    /// Organizations whose retained usage may have grown since eviction.
    pub(crate) evictions: Arc<crate::capacity::Wakes>,
    /// Sent after a commit that makes a finalization batch runnable.
    pub(crate) finalizations: Arc<crate::wake::Wake>,
    /// Sent after a commit that leaves a push job a candidate to publish.
    pub(crate) publications: Arc<crate::wake::Wake>,
    /// Bazel generations whose objects or targets may have changed since
    /// they were swept.
    pub(crate) bazel: Arc<crate::bazel::Sweeps>,
    /// How long an idle worker sleeps before it looks without being woken.
    pub(crate) idle_period: Duration,
    pub(crate) cdn: Option<Arc<dyn cdn::PurgeTransport>>,
    proxy_ips: Arc<[IpAddr]>,
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl AppState {
    /// Validate configuration once and own the supplied shared services.
    pub fn new(
        pool: PgPool,
        config: Config,
        mut storage: storage::Storage,
        http: reqwest::Client,
    ) -> anyhow::Result<Self> {
        config.resources.validate()?;
        config.push_jobs.validate()?;
        storage.configure_limits(&config.resources);
        cdn::validate_config(&config)?;
        crate::cache_host::validate_config(&config)?;
        let proxy_ips = config
            .trusted_proxy_ips
            .split_whitespace()
            .map(str::parse::<IpAddr>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                anyhow::anyhow!(
                    "TRUSTED_PROXY_IPS must contain IP addresses separated by whitespace"
                )
            })?;
        Ok(Self {
            cdn: None,
            read_pool: pool.clone(),
            evictions: Arc::default(),
            finalizations: Arc::default(),
            publications: Arc::default(),
            bazel: Arc::default(),
            idle_period: crate::wake::FALLBACK,
            pool,
            storage,
            verification_slots: Arc::new(Semaphore::new(config.resources.verifications)),
            // Bound preparations and part transfers waiting to record receipts.
            // Allow one eight-member batch per verifier across both stages.
            preparation_slots: Arc::new(Semaphore::new(config.resources.verifications * 8)),
            // Manifest parsing must not consume upload or verifier admission.
            manifest_slots: Arc::new(Semaphore::new(4)),
            config: Arc::new(config),
            http,
            tasks: TaskTracker::new(),
            finalization_stop: CancellationToken::new(),
            finalization_started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            upstream_slots: Arc::new(Semaphore::new(4)),
            management_limits: Arc::default(),
            protocol_limits: Arc::default(),
            proxy_ips: proxy_ips.into(),
        })
    }

    /// Attach an invalidation provider before starting requests or workers.
    /// Core owns the durable queue and drains it before shutdown.
    pub fn with_cdn(mut self, transport: Arc<dyn cdn::PurgeTransport>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !self.config.public_cache_origin.is_empty(),
            "CDN purging requires a public cache origin"
        );
        self.cdn = Some(transport);
        Ok(self)
    }

    /// Change, before starting workers, how long an idle one sleeps before it
    /// looks for work nothing in this process announced. Thirty seconds by
    /// default. Work this process commits is picked up without it.
    pub fn with_idle_period(mut self, period: Duration) -> Self {
        self.idle_period = period;
        self
    }

    /// Change, before starting workers or requests, how soon one Bazel sweep
    /// pass may follow another, and how often every generation is swept
    /// unasked. A minute and an hour by default.
    pub fn with_bazel_sweep_periods(mut self, settle: Duration, fallback: Duration) -> Self {
        self.bazel = Arc::new(crate::bazel::Sweeps::new(settle, fallback));
        self
    }

    /// Start the durable multipart consumers once. Tower hosts and tests use
    /// this same lifecycle as serve(), rather than a request-local shortcut.
    pub fn start_upload_finalizers(&self) -> CancellationToken {
        if self
            .finalization_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return self.finalization_stop.clone();
        }
        for _ in 0..self.config.resources.verifications.clamp(1, 4) {
            self.tasks.spawn(crate::uploads::run_finalizations(
                self.clone(),
                self.finalization_stop.clone(),
            ));
        }
        self.finalization_stop.clone()
    }

    /// Stop discovery, then finish tracked work without closing shared SQL.
    pub async fn finish_background(&self) {
        self.finalization_stop.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}

/// Serve until shutdown, then drain requests and background work before SQL.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let routes = router(state.clone());
    serve_router(listener, state, routes, shutdown).await
}

/// Host composed routers with the cache's workers and graceful shutdown.
/// The routes must contain `router(state.clone())` and use this same state.
pub async fn serve_router(
    listener: tokio::net::TcpListener,
    state: AppState,
    routes: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let retry_stop = CancellationToken::new();
    state
        .tasks
        .spawn(maintenance::drain(state.clone(), retry_stop.clone()));
    state
        .tasks
        .spawn(crate::bazel::maintain(state.clone(), retry_stop.clone()));
    state.start_upload_finalizers();
    state.tasks.spawn(crate::capacity::run(
        state.clone(),
        retry_stop.clone(),
        Duration::from_secs(10 * 60),
    ));
    for _ in 0..state.config.push_jobs.publication_workers {
        let worker_state = state.clone();
        let stopped = retry_stop.clone();
        state
            .tasks
            .spawn(crate::push_job_worker::run(worker_state, stopped));
    }
    if state.cdn.is_some() {
        let retry_state = state.clone();
        let stopped = retry_stop.clone();
        state.tasks.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    _ = interval.tick() => {
                        tokio::select! {
                            _ = stopped.cancelled() => break,
                            result = cdn::retry(&retry_state) => {
                                if result.is_err() { tracing::warn!("CDN purge backlog retained for retry"); }
                            }
                        }
                    }
                }
            }
        });
    }
    let maintenance_state = state.clone();
    let stopped = retry_stop.clone();
    state.tasks.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stopped.cancelled() => break,
                _ = interval.tick() => {
                    // Finish in-flight cleanup before releasing its fences or
                    // closing SQL. Shutdown only interrupts between full runs.
                    if maintenance::run(&maintenance_state).await.is_err() {
                        tracing::warn!("Maintenance failed; durable cleanup remains for retry");
                    }
                }
            }
        }
    });
    let served = axum::serve(
        listener.tap_io(|stream| {
            // Streamed response chunks must not wait for delayed ACKs.
            if let Err(error) = stream.set_nodelay(true) {
                tracing::warn!(%error, "Setting TCP_NODELAY failed");
            }
        }),
        routes.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await;
    retry_stop.cancel();
    state.finish_background().await;
    state.read_pool.close().await;
    state.pool.close().await;
    served
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub fn router(state: AppState) -> Router {
    let router = Router::new()
        .route(
            "/",
            any(|| async {
                json_response(
                    StatusCode::OK,
                    json!({ "service": "snowstead", "status": "ok" }),
                )
            }),
        )
        .route("/healthz", any(health))
        .route(
            snowstead_protocol::routes::PROTOCOL,
            axum::routing::get(crate::wire::info),
        )
        .route(
            snowstead_protocol::routes::AUTH_STATUS,
            axum::routing::get(crate::auth::status),
        )
        .merge(crate::nix::router(state.clone()))
        .merge(crate::go::router())
        .merge(crate::sccache::router())
        .merge(crate::bazel::router(state.clone()))
        .merge(crate::cache_host::product_routes(state.clone()))
        .merge(management::router(state.clone()))
        .route("/_api/v1", any(api_not_found))
        .route("/_api/v1/{*unmatched}", any(api_not_found))
        .fallback(crate::reads::handle)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::cache_host::ingress,
        ))
        .layer(middleware::from_fn(head_response));
    #[cfg(feature = "observability")]
    let router = router.layer(middleware::from_fn(observe_request));
    router.with_state(state)
}

#[cfg(feature = "observability")]
async fn observe_request(request: Request, next: Next) -> Response {
    let observation = crate::observability::RequestObservation::new(&request);
    let response =
        tracing::Instrument::instrument(next.run(request), observation.span.clone()).await;
    observation.response(response)
}

async fn api_not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not Found")
}

async fn head_response(request: Request, next: Next) -> Response {
    let head = request.method() == Method::HEAD;
    let mut response = next.run(request).await;
    // Keep 304's unknown-size empty body so Axum doesn't synthesize a zero
    // Content-Length for a nonempty representation. Other HEADs are bodyless.
    if head && response.status() != StatusCode::NOT_MODIFIED {
        *response.body_mut() = axum::body::Body::empty();
    }
    response
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn health(State(state): State<AppState>) -> Response {
    let ok = crate::profile_future!(
        sqlx::query_scalar!(
            r#"
            SELECT id
            FROM orgs
            WHERE id = 'default'
            "#
        )
        .fetch_optional(&state.pool),
        label = "app.health_sql"
    )
    .await
    .is_ok();
    json_response(
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        json!({ "ok": ok, "service": "snowstead" }),
    )
}

/// Forwarded addresses are authoritative only from explicitly trusted peers.
pub(crate) fn client_ip(state: &AppState, request: &Request) -> Option<String> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()?
        .0
        .ip();
    if state.proxy_ips.contains(&peer) {
        // The authenticated ingress must replace these, not append arbitrary
        // client headers. Reject chains rather than guessing which hop to use.
        for name in ["cf-connecting-ip", "x-forwarded-for"] {
            if let Some(ip) = request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<IpAddr>().ok())
            {
                return Some(ip.to_string());
            }
        }
    }
    Some(peer.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use object_store::memory::InMemory;
    use tower::ServiceExt;

    fn state() -> AppState {
        AppState::new(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/unused")
                .unwrap(),
            Config {
                admin_secret: "test-admin-secret".into(),
                ..Default::default()
            },
            storage::Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new())),
            reqwest::Client::new(),
        )
        .unwrap()
    }

    fn request(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn outstanding_responses_do_not_reject_other_requests() {
        let app = router(state());
        let mut responses = Vec::new();
        // Exceed the former default cap while retaining every response body.
        for _ in 0..1025 {
            let response = app.clone().oneshot(request("/")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            responses.push(response);
        }
        assert_eq!(
            app.oneshot(request("/_api/v1/admin/caches"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn protocol_versions_are_advertised_and_checked_before_authentication() {
        use snowstead_protocol::{PROTOCOL_VERSION_HEADER, ProtocolInfo};
        let app = router(state());
        let response = app
            .clone()
            .oneshot(request(snowstead_protocol::routes::PROTOCOL))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<ProtocolInfo>(&body).unwrap(),
            ProtocolInfo::current()
        );
        let send = |version: Option<&str>| {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(snowstead_protocol::routes::MISSING_PATHS);
            if let Some(version) = version {
                request = request.header(PROTOCOL_VERSION_HEADER, version);
            }
            app.clone().oneshot(request.body(Body::empty()).unwrap())
        };
        // Only current clients reach authentication. Old and missing versions
        // are rejected before credentials or request bodies are considered.
        for version in [Some("2")] {
            let response = send(version).await.unwrap();
            assert!(
                matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "{}",
                response.status()
            );
            assert_eq!(response.headers()[PROTOCOL_VERSION_HEADER], "2");
        }
        for version in [None, Some("1")] {
            assert_eq!(
                send(version).await.unwrap().status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            send(Some("99")).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
}
