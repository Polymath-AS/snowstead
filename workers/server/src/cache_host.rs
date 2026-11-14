//! Direct organization ingress. Only Host is authoritative, never forwarded headers.
use axum::{
    extract::{Request, State},
    http::{StatusCode, header, uri::Authority},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{AppState, cache, config::Config};

#[derive(Clone)]
pub(crate) struct OrganizationHost(pub String);

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
        .filter(|v| !v.host().ends_with(".."))
        .map(|v| v.host().trim_end_matches('.').to_ascii_lowercase());
    if request.headers().get_all(header::HOST).iter().count() > 1
        || (request.headers().contains_key(header::HOST) && host.is_none())
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
            match crate::reads::handle(State(state), request).await {
                Ok(response) => response,
                Err(error) => error.into_response(),
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
}
