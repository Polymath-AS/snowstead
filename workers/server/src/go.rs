//! Go's build-cache actions. Each action commits to one output ID.
use crate::{
    AppState,
    artifacts::{self, Access, Product},
    cache,
    error::ApiError,
};
use axum::{
    Router,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{Method, StatusCode, request::Parts},
    response::Response,
    routing::get,
};

const ALLOW: &str = "GET, HEAD, PUT";

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/_api/v1/go/{slug}/{cache}/v1/actions/{action}",
        get(read).head(read).put(upload).fallback(unsupported),
    )
}

type ActionPath = Result<Path<(String, String, String)>, PathRejection>;

/// The wire grammar: literal names and a SHA-256 action.
fn parse(path: ActionPath, pathname: &str) -> Result<(String, String, String), ApiError> {
    let Path((slug, name, action)) = path.map_err(|_| cache::not_found())?;
    if !artifacts::literal(pathname, &slug, &name) || !cache::sha256_hex(&action) {
        return Err(cache::not_found());
    }
    Ok((slug, name, action))
}

async fn open(
    state: &AppState,
    path: ActionPath,
    request: &Parts,
    write: bool,
) -> Result<Access, ApiError> {
    let (slug, name, action) = parse(path, request.uri.path())?;
    artifacts::open(
        state,
        Product::Go,
        &slug,
        &name,
        &action,
        &request.headers,
        write,
    )
    .await
}

// Unsupported methods validate the grammar, but do not look up/auth the cache.
async fn unsupported(path: ActionPath, request: Request) -> Result<Response, ApiError> {
    parse(path, request.uri().path())?;
    Err(cache::method_not_allowed(ALLOW))
}

async fn read(
    State(state): State<AppState>,
    path: ActionPath,
    method: Method,
    request: Request,
) -> Result<Response, ApiError> {
    let (request, _) = request.into_parts();
    let access = open(&state, path, &request, false).await?;
    access.download(&state, method == Method::HEAD).await
}

async fn upload(
    State(state): State<AppState>,
    path: ActionPath,
    request: Request,
) -> Result<Response, ApiError> {
    let (request, body) = request.into_parts();
    let access = open(&state, path, &request, true).await?;
    let output = request
        .headers
        .get("x-snowstead-output-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| cache::sha256_hex(v))
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Output ID is required"))?
        .to_owned();
    let size = cache::content_length(&request.headers, artifacts::MAX_BYTES)?;
    access.upload(&state, size, Some(&output), body).await
}
