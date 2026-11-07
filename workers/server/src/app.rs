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
    bandwidth, cdn,
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
    pub(crate) storage: storage::Storage,
    pub(crate) upstream_slots: Arc<Semaphore>,
    pub(crate) management_limits: Arc<management::ApiLimits>,
    pub(crate) protocol_limits: Arc<protocol_policy::ProtocolLimits>,
    pub(crate) verification_slots: Arc<Semaphore>,
    pub(crate) sql_waiters: Arc<Semaphore>,
    pub(crate) sql_writers: Arc<crate::db::Writers>,
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
        storage.configure_limits(&config.resources);
        cdn::validate_config(&config)?;
        crate::cache_host::validate_config(&config)?;
        anyhow::ensure!(
            config.analytics_token.is_empty()
                || !config.cdn_zone_id.is_empty() && !config.public_cache_origin.is_empty(),
            "Analytics requires a CDN zone and public cache origin"
        );
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
            read_pool: pool.clone(),
            sql_waiters: Arc::new(Semaphore::new(pool.options().get_max_connections() as usize)),
            sql_writers: Arc::default(),
            pool,
            storage,
            verification_slots: Arc::new(Semaphore::new(config.resources.verifications)),
            config: Arc::new(config),
            http,
            tasks: TaskTracker::new(),
            upstream_slots: Arc::new(Semaphore::new(4)),
            management_limits: Arc::default(),
            protocol_limits: Arc::default(),
            proxy_ips: proxy_ips.into(),
        })
    }

    /// Finish tracked work without closing the caller's shared database pool.
    pub async fn finish_background(&self) {
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
    let retry_stop = CancellationToken::new();
    if !state.config.cdn_zone_id.is_empty() {
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
                    bandwidth::run(&maintenance_state).await;
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
        router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
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
        .merge(crate::nix::router(state.clone()))
        .merge(crate::go::router())
        .merge(crate::sccache::router())
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
}
