use crate::{
    AppState,
    artifacts::{self, Product},
    error::ApiError,
};
use axum::{
    Router,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::get,
};

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/_api/v1/go/{slug}/{cache}/v1/actions/{action}",
        get(download).head(head).put(upload).fallback(unsupported),
    )
}

type ActionPath = Result<Path<(String, String, String)>, PathRejection>;

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not Found")
}

fn name_valid(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn hash_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

async fn target(
    state: &AppState,
    path: ActionPath,
    pathname: &str,
) -> Result<(String, String, artifacts::Target), ApiError> {
    let Path((slug, name, action)) = path.map_err(|_| not_found())?;
    // Path decodes captures; the wire protocol only accepts literal names/hashes.
    if pathname.contains('%') || !name_valid(&slug) || !name_valid(&name) || !hash_valid(&action) {
        return Err(not_found());
    }
    let target = artifacts::target(state, &slug, &name, Product::Go, &action)
        .await?
        .ok_or_else(not_found)?;
    Ok((name, action, target))
}

async fn unsupported(
    State(state): State<AppState>,
    path: ActionPath,
    request: Request,
) -> Result<Response, ApiError> {
    // Missing caches and malformed paths remain 404 even for unsupported methods.
    target(&state, path, request.uri().path()).await?;
    Err(
        ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
            .header(header::ALLOW, HeaderValue::from_static("GET, HEAD, PUT")),
    )
}

async fn download(
    State(state): State<AppState>,
    path: ActionPath,
    request: Request,
) -> Result<Response, ApiError> {
    read(state, path, request, false).await
}

async fn head(
    State(state): State<AppState>,
    path: ActionPath,
    request: Request,
) -> Result<Response, ApiError> {
    read(state, path, request, true).await
}

async fn read(
    state: AppState,
    path: ActionPath,
    request: Request,
    head: bool,
) -> Result<Response, ApiError> {
    let (name, _, target) = target(&state, path, request.uri().path()).await?;
    artifacts::authorize(
        &state,
        request.headers(),
        &target,
        &name,
        Product::Go,
        false,
    )
    .await?;
    artifacts::download(&state, &target, head, Product::Go).await
}

async fn upload(
    State(state): State<AppState>,
    path: ActionPath,
    request: Request,
) -> Result<Response, ApiError> {
    let (name, action, target) = target(&state, path, request.uri().path()).await?;
    artifacts::authorize(&state, request.headers(), &target, &name, Product::Go, true).await?;
    let output = request
        .headers()
        .get("x-snowstead-output-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !hash_valid(&output) || length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Output ID and content length are required",
        ));
    }
    let size = length
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= 64 * 1024 * 1024)
        .ok_or_else(|| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "Artifact is too large"))?;
    artifacts::upload(
        &state,
        &target,
        Product::Go,
        &action,
        size,
        Some(&output),
        request.into_body(),
    )
    .await
}
