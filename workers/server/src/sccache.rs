//! sccache's WebDAV subset. Directories and the write probe are virtual.
use axum::{
    Router,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;

use crate::{
    AppState,
    artifacts::{self, Product},
    error::ApiError,
    protocol_policy::Admission,
};

const MAX_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn router() -> Router<AppState> {
    let methods = get(download).head(head).put(upload).fallback(webdav_method);
    Router::new()
        // The endpoint without a trailing slash is not a WebDAV directory.
        .route(
            "/_api/v1/sccache/{slug}/{cache}",
            axum::routing::any(missing),
        )
        .route("/_api/v1/sccache/{slug}/{cache}/", methods.clone())
        .route("/_api/v1/sccache/{slug}/{cache}/{*path}", methods)
}

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not Found")
}

async fn missing() -> ApiError {
    not_found()
}

fn method_not_allowed() -> ApiError {
    ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

#[derive(Deserialize)]
struct CachePath {
    slug: String,
    cache: String,
    #[serde(default)]
    path: String,
}

type DavPath = Result<Path<CachePath>, PathRejection>;

enum Resource {
    Directory,
    Probe,
    Artifact(String),
}

impl Resource {
    fn action(&self) -> &str {
        match self {
            Self::Artifact(action) => action,
            _ => "",
        }
    }
}

// Only the WebDAV grammar remains protocol-specific; Axum captures the endpoint.
async fn parse(
    state: &AppState,
    path: DavPath,
    pathname: &str,
    write: bool,
) -> Result<(CachePath, Resource, Admission), ApiError> {
    let Path(path) = path.map_err(|_| not_found())?;
    // Preserve literal-path validation rather than accepting percent-encoded hex.
    if pathname.contains('%') || !name_valid(&path.slug) || !name_valid(&path.cache) {
        return Err(not_found());
    }
    // Bound both lanes before metadata SQL; callers retain this through streaming
    // uploads/probe consumption, but not through a returned download body.
    let admission = state
        .protocol_limits
        .admit_sccache(&path.slug, write)
        .await?;
    // OpenDAL can append a slash to an endpoint that already ends in one.
    let rest = path.path.trim_start_matches('/');
    let directory = rest.len() <= 6
        && rest.len() % 2 == 0
        && rest
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .all(|part| hex(part[0]) && part[1] == b'/');
    let resource = if directory {
        Resource::Directory
    } else if rest == ".sccache_check" {
        Resource::Probe
    } else if rest.len() == 70 {
        let bytes = rest.as_bytes();
        if bytes[1] != b'/'
            || bytes[3] != b'/'
            || bytes[5] != b'/'
            || !bytes[6..].iter().copied().all(hex)
            || bytes[0] != bytes[6]
            || bytes[2] != bytes[7]
            || bytes[4] != bytes[8]
        {
            return Err(not_found());
        }
        Resource::Artifact(rest[6..].to_owned())
    } else {
        return Err(not_found());
    };
    Ok((path, resource, admission))
}

async fn prepare(
    state: &AppState,
    path: DavPath,
    pathname: &str,
    headers: &HeaderMap,
    write: bool,
) -> Result<(Resource, artifacts::Target, Admission), ApiError> {
    let (path, resource, admission) = parse(state, path, pathname, write).await?;
    let target = artifacts::target(
        state,
        &path.slug,
        &path.cache,
        Product::Sccache,
        resource.action(),
    )
    .await?
    .ok_or_else(not_found)?;
    artifacts::authorize(
        state,
        headers,
        &target,
        &path.cache,
        Product::Sccache,
        write,
    )
    .await?;
    Ok((resource, target, admission))
}

// Axum 0.8's MethodFilter only supports standard methods. Keep its fallback
// limited to WebDAV extension methods; GET/HEAD/PUT use native method routing.
async fn webdav_method(
    State(state): State<AppState>,
    path: DavPath,
    method: Method,
    request: Request,
) -> Result<Response, ApiError> {
    match method.as_str() {
        "PROPFIND" => return propfind(State(state), path, request).await,
        "MKCOL" => return mkcol(State(state), path, request).await,
        _ => {}
    }
    // Unsupported methods validate the grammar, but do not look up/auth the cache.
    let _parsed = parse(&state, path, request.uri().path(), false).await?;
    Err(method_not_allowed().header(
        header::ALLOW,
        HeaderValue::from_static("GET, HEAD, PUT, PROPFIND, MKCOL"),
    ))
}

async fn propfind(
    State(state): State<AppState>,
    path: DavPath,
    request: Request,
) -> Result<Response, ApiError> {
    let (resource, target, _admission) =
        prepare(&state, path, request.uri().path(), request.headers(), false).await?;
    if !matches!(resource, Resource::Directory) {
        return Err(method_not_allowed());
    }
    let modified = httpdate::fmt_http_date(target.created_at.into());
    let pathname = request.uri().path();
    let xml = format!(
        "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>{pathname}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getlastmodified>{modified}</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    );
    Ok((
        StatusCode::MULTI_STATUS,
        [
            (header::CONTENT_TYPE, "application/xml"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        xml,
    )
        .into_response())
}

async fn mkcol(
    State(state): State<AppState>,
    path: DavPath,
    request: Request,
) -> Result<Response, ApiError> {
    let (resource, _, _admission) =
        prepare(&state, path, request.uri().path(), request.headers(), true).await?;
    if !matches!(resource, Resource::Directory) {
        return Err(method_not_allowed());
    }
    Ok(StatusCode::CREATED.into_response())
}

async fn download(
    State(state): State<AppState>,
    path: DavPath,
    request: Request,
) -> Result<Response, ApiError> {
    read(state, path, request, false).await
}

async fn head(
    State(state): State<AppState>,
    path: DavPath,
    request: Request,
) -> Result<Response, ApiError> {
    read(state, path, request, true).await
}

async fn read(
    state: AppState,
    path: DavPath,
    request: Request,
    head: bool,
) -> Result<Response, ApiError> {
    let (resource, target, _admission) =
        prepare(&state, path, request.uri().path(), request.headers(), false).await?;
    if matches!(resource, Resource::Directory) {
        return Err(method_not_allowed());
    }
    artifacts::download(&state, &target, head, Product::Sccache).await
}

async fn upload(
    State(state): State<AppState>,
    path: DavPath,
    request: Request,
) -> Result<Response, ApiError> {
    let (resource, target, _admission) =
        prepare(&state, path, request.uri().path(), request.headers(), true).await?;
    if matches!(resource, Resource::Directory) {
        return Err(method_not_allowed());
    }
    let probe = matches!(resource, Resource::Probe);
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| ApiError::new(StatusCode::LENGTH_REQUIRED, "Content-Length required"))?;
    let size = length
        .parse::<u64>()
        .ok()
        .filter(|size| *size <= if probe { 1024 } else { MAX_BYTES })
        .ok_or_else(|| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "Artifact is too large"))?;
    if probe {
        artifacts::consume(request.into_body(), size).await?;
        return Ok((
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response());
    }
    artifacts::upload(
        &state,
        &target,
        Product::Sccache,
        resource.action(),
        size,
        None,
        request.into_body(),
    )
    .await
}
