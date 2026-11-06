//! Direct organization ingress. Only Host is authoritative, never forwarded headers.
use axum::{
    extract::{Request, State},
    http::{StatusCode, header, uri::Authority},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{AppState, config::Config};

#[derive(Clone)]
pub(crate) struct OrganizationHost(pub String);

// Keep in sync with the web service's cache-host.ts registration policy.
const RESERVED: &[&str] = &[
    "www",
    "admin",
    "docs",
    "cache",
    "cache-staging",
    "api",
    "auth",
    "staging",
    "status",
    "mail",
    "orgs",
    "invitations",
    "default",
    "nar",
    "private",
    "_api",
    "healthz",
    "origin",
];

pub(crate) fn validate_config(config: &Config) -> anyhow::Result<()> {
    let suffix = &config.cache_host_suffix;
    anyhow::ensure!(
        suffix.is_empty()
            || (suffix.len() <= 253
                && suffix
                    .split('.')
                    .all(|label| crate::reads::valid_name(label, 63))),
        "CACHE_HOST_SUFFIX must be a bare lowercase DNS name without a leading dot or port"
    );
    anyhow::ensure!(
        config.cache_canonical_hosts.split_whitespace().all(|host| {
            host.len() <= 253
                && host
                    .split('.')
                    .all(|label| crate::reads::valid_name(label, 63))
        }),
        "CACHE_CANONICAL_HOSTS must contain bare lowercase DNS names separated by whitespace"
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
    let mut response = if RESERVED.contains(&owner) || !crate::reads::valid_name(owner, 39) {
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
