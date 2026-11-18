//! Direct organization ingress. Host is authoritative, or the request URI's authority (`:authority` on HTTP/2) when no Host is sent; never forwarded headers.
use axum::{
    Router,
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{Extensions, StatusCode, header, uri::Authority},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::any,
};
use std::net::SocketAddr;
use tower::ServiceExt;

use crate::{AppState, cache, config::Config};

#[derive(Clone)]
pub(crate) struct OrganizationHost(pub String);

/// Products served at `/<cache>/<product>` on an organization host.
pub(crate) const PRODUCTS: &[&str] = &["go", "sccache", "bazel"];

/// The path the client used on an organization host, before dispatch
/// rewrote it to the protocol's canonical route.
#[derive(Clone)]
pub(crate) struct PublicPath(pub String);

/// Fixed gRPC service paths. On an organization host they run directly, and
/// the instance names only the cache.
const GRPC_PREFIXES: &[&str] = &[
    "/build.bazel.remote.execution.v2.",
    "/google.bytestream.ByteStream/",
];

/// `/<cache>/<product>/…`. A product only on an organization host; on any
/// other host this shape is a path-based Nix read.
pub(crate) fn product_routes(state: AppState) -> Router<AppState> {
    // Protocol routers only: an organization host must never reach
    // management, upload, or operator routes.
    let protocols: Router = Router::new()
        .merge(crate::go::router())
        .merge(crate::sccache::router())
        .merge(crate::bazel::http_router())
        .fallback(|| async { cache::not_found() })
        .with_state(state);
    let mut routes = Router::new();
    for &product in PRODUCTS {
        for tail in ["", "/", "/{*rest}"] {
            let protocols = protocols.clone();
            routes = routes.route(
                &format!("/{{cache}}/{product}{tail}"),
                any(move |State(state): State<AppState>, request: Request| {
                    dispatch(protocols.clone(), product, state, request)
                }),
            );
        }
    }
    routes
}

async fn dispatch(
    protocols: Router,
    product: &'static str,
    state: AppState,
    request: Request,
) -> Response {
    let Some(owner) = request
        .extensions()
        .get::<OrganizationHost>()
        .map(|host| host.0.clone())
    else {
        return match crate::reads::handle(State(state), request).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        };
    };
    let public = request.uri().path().to_owned();
    let target = public
        .strip_prefix('/')
        .and_then(|path| path.split_once('/'))
        .and_then(|(name, rest)| {
            // The route matched `/<cache>/<product>` followed by `/` or nothing.
            let tail = rest
                .strip_prefix(product)
                .filter(|tail| tail.is_empty() || tail.starts_with('/'))?;
            let query = request
                .uri()
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            Some(format!("/_api/v1/{product}/{owner}/{name}{tail}{query}"))
        })
        .and_then(|target| target.parse::<axum::http::Uri>().ok());
    let Some(target) = target else {
        return cache::not_found().into_response();
    };
    // Rebuild the extensions: axum appends inner captures after the outer
    // `{cache}` capture, which breaks the protocol handlers' `Path` extractors.
    // Go, sccache, and Bazel over HTTP read no request extensions; the peer
    // address is carried for handlers that audit by IP.
    let (mut parts, body) = request.into_parts();
    let mut extensions = Extensions::new();
    if let Some(peer) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
        extensions.insert(*peer);
    }
    extensions.insert(PublicPath(public));
    parts.extensions = extensions;
    parts.uri = target;
    match protocols.oneshot(Request::from_parts(parts, body)).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// Names that conflict with the core's path-based protocol namespace.
pub(crate) const PROTOCOL_NAMES: &[&str] = &["default", "nar", "private", "_api", "healthz"];

pub(crate) fn reserved_name(config: &Config, name: &str) -> bool {
    PROTOCOL_NAMES.contains(&name)
        || config
            .cache_reserved_names
            .split_whitespace()
            .any(|v| v == name)
}

pub(crate) fn validate_config(config: &Config) -> anyhow::Result<()> {
    let suffix = &config.cache_host_suffix;
    anyhow::ensure!(
        suffix.is_empty()
            || (suffix.len() <= 253 && suffix.split('.').all(|label| cache::valid_name(label, 63))),
        "CACHE_HOST_SUFFIX must be a bare lowercase DNS name without a leading dot or port"
    );
    anyhow::ensure!(
        config.cache_canonical_hosts.split_whitespace().all(|host| {
            host.len() <= 253 && host.split('.').all(|label| cache::valid_name(label, 63))
        }),
        "CACHE_CANONICAL_HOSTS must contain bare lowercase DNS names separated by whitespace"
    );
    anyhow::ensure!(
        config.cache_reserved_hosts.split_whitespace().all(|host| {
            host.len() <= 253 && host.split('.').all(|label| cache::valid_name(label, 63))
        }),
        "CACHE_RESERVED_HOSTS must contain bare lowercase DNS names separated by whitespace"
    );
    anyhow::ensure!(
        config
            .cache_reserved_names
            .split_whitespace()
            .all(|name| cache::valid_name(name, cache::SLUG_MAX)),
        "CACHE_RESERVED_NAMES must contain lowercase organization names separated by whitespace"
    );
    Ok(())
}

pub(crate) async fn ingress(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let suffix = &state.config.cache_host_suffix;
    if suffix.is_empty() {
        return next.run(request).await;
    }
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Authority>().ok())
        // HTTP/2 names the host in `:authority`, which hyper puts on the URI.
        .or_else(|| {
            (!request.headers().contains_key(header::HOST))
                .then(|| request.uri().authority().cloned())
                .flatten()
        })
        .filter(|v| !v.host().ends_with(".."))
        .map(|v| v.host().trim_end_matches('.').to_ascii_lowercase());
    if request.headers().get_all(header::HOST).iter().count() > 1
        || ((request.headers().contains_key(header::HOST) || request.uri().authority().is_some())
            && host.is_none())
    {
        return (
            StatusCode::BAD_REQUEST,
            [("cache-control", "no-store")],
            "Invalid Host",
        )
            .into_response();
    }
    if host.as_deref().is_some_and(|host| {
        state
            .config
            .cache_reserved_hosts
            .split_whitespace()
            .any(|v| v == host)
    }) {
        return (
            StatusCode::NOT_FOUND,
            [
                ("cache-control", "no-store"),
                ("cloudflare-cdn-cache-control", "no-store"),
            ],
            "Not Found",
        )
            .into_response();
    }
    if host.as_deref().is_some_and(|host| {
        state
            .config
            .cache_canonical_hosts
            .split_whitespace()
            .any(|v| v == host)
    }) {
        return next.run(request).await;
    }
    if host.as_deref() == Some(suffix.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            [("cache-control", "no-store")],
            "Not Found",
        )
            .into_response();
    }
    let Some(owner) = host
        .as_deref()
        .and_then(|host| host.strip_suffix(suffix))
        .and_then(|prefix| prefix.strip_suffix('.'))
    else {
        return next.run(request).await;
    };
    let mut response =
        if reserved_name(&state.config, owner) || !cache::valid_name(owner, cache::SLUG_MAX) {
            (
                StatusCode::NOT_FOUND,
                [("cache-control", "no-store")],
                "Not Found",
            )
                .into_response()
        } else {
            request
                .extensions_mut()
                .insert(OrganizationHost(owner.to_owned()));
            // Product routes are the only ones registered under `/{cache}/`.
            // The cache router must be merged, not nested: a nest would prefix
            // the matched path, so product requests would miss this check and
            // fall back to Nix reads. gRPC services run directly as well: they
            // read the organization from this extension, since their instance
            // names carry no owner segment on an organization host.
            let direct = request
                .extensions()
                .get::<MatchedPath>()
                .is_some_and(|path| {
                    let path = path.as_str();
                    path.starts_with("/{cache}/")
                        || GRPC_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
                });
            if direct {
                next.run(request).await
            } else {
                match crate::reads::handle(State(state), request).await {
                    Ok(response) => response,
                    Err(error) => error.into_response(),
                }
            }
        };
    // Every alias hit must observe current SQL policy, even with a warm CDN.
    response
        .headers_mut()
        .insert("cloudflare-cdn-cache-control", "no-store".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_protocol_names_and_explicit_host_policy_are_reserved() {
        let mut config = Config::default();
        assert!(validate_config(&config).is_ok());
        assert!(!reserved_name(&config, "docs"));
        assert!(!reserved_name(&config, "admin"));
        for name in PROTOCOL_NAMES {
            assert!(reserved_name(&config, name));
        }
        config.cache_reserved_names = "docs custom".into();
        config.cache_reserved_hosts = "blocked.example.test".into();
        assert!(validate_config(&config).is_ok());
        assert!(reserved_name(&config, "docs"));
        assert!(reserved_name(&config, "custom"));
        assert!(!reserved_name(&config, "admin"));
        for invalid in ["Mixed", "a.b", "-bad", "bad_", ""] {
            config.cache_reserved_names = invalid.into();
            assert_eq!(validate_config(&config).is_ok(), invalid.is_empty());
        }
        config.cache_reserved_names.clear();
        for invalid in [
            "https://blocked.example.test",
            "UPPER.example.test",
            "a..b",
            "a:443",
            ".example.test",
        ] {
            config.cache_reserved_hosts = invalid.into();
            assert!(validate_config(&config).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn explicit_reserved_host_precedes_canonical_ingress_without_database() {
        let config = Config {
            cache_host_suffix: "example.test".into(),
            cache_canonical_hosts: "blocked.example.test".into(),
            cache_reserved_hosts: "blocked.example.test".into(),
            ..Default::default()
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let storage = crate::storage::Storage::from_stores(
            std::sync::Arc::new(object_store::memory::InMemory::new()),
            std::sync::Arc::new(object_store::memory::InMemory::new()),
        );
        let state = AppState::new(pool, config, storage, reqwest::Client::new()).unwrap();
        let app = axum::Router::new()
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn_with_state(state, ingress));
        use tower::ServiceExt;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header("host", "BLOCKED.EXAMPLE.TEST.:443")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["cloudflare-cdn-cache-control"],
            "no-store"
        );
    }

    #[tokio::test]
    async fn http2_authority_names_the_host_when_no_host_header_is_sent() {
        let config = Config {
            cache_host_suffix: "example.test".into(),
            cache_canonical_hosts: "api.example.test".into(),
            cache_reserved_hosts: "blocked.example.test".into(),
            ..Default::default()
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let storage = crate::storage::Storage::from_stores(
            std::sync::Arc::new(object_store::memory::InMemory::new()),
            std::sync::Arc::new(object_store::memory::InMemory::new()),
        );
        let state = AppState::new(pool, config, storage, reqwest::Client::new()).unwrap();
        let app = axum::Router::new()
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn_with_state(state, ingress));
        use tower::ServiceExt;
        let send = |host: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut request = Request::builder().uri("http://blocked.example.test/healthz");
                if let Some(host) = host {
                    request = request.header("host", host);
                }
                app.oneshot(request.body(axum::body::Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status()
            }
        };
        // Without a Host header, the `:authority` names a reserved host.
        assert_eq!(send(None).await, StatusCode::NOT_FOUND);
        // A malformed authority is refused as an invalid Host, as a Host header would be.
        let malformed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("http://blocked.example.test../healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        // A Host header wins over the authority: the canonical host passes through.
        assert_eq!(send(Some("api.example.test")).await, StatusCode::NO_CONTENT);
    }
}
