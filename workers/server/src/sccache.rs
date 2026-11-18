//! sccache's WebDAV subset. Directories and the write probe are virtual.
use axum::{
    Router,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;

use crate::{
    AppState,
    artifacts::{self, Access, Product},
    cache,
    error::ApiError,
};

const ALLOW: &str = "GET, HEAD, PUT, PROPFIND, MKCOL";
const PROBE_MAX_BYTES: u64 = 1024;

pub(crate) fn router() -> Router<AppState> {
    let methods = get(read).head(read).put(upload).fallback(webdav_method);
    Router::new()
        // The endpoint without a trailing slash is not a WebDAV directory.
        .route(
            "/_api/v1/sccache/{slug}/{cache}",
            axum::routing::any(|| async { cache::not_found() }),
        )
        .route("/_api/v1/sccache/{slug}/{cache}/", methods.clone())
        .route("/_api/v1/sccache/{slug}/{cache}/{*path}", methods)
}

fn method_not_allowed() -> ApiError {
    cache::method_not_allowed(ALLOW)
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

/// The wire grammar: literal names, then a fan-out directory, the write
/// probe, or `a/b/c/<sha256>` whose directories repeat the digest's prefix.
fn parse(path: DavPath, pathname: &str) -> Result<(CachePath, Resource), ApiError> {
    let Path(path) = path.map_err(|_| cache::not_found())?;
    if !artifacts::literal(pathname, &path.slug, &path.cache) {
        return Err(cache::not_found());
    }
    // OpenDAL can append a slash to an endpoint that already ends in one.
    let rest = path.path.trim_start_matches('/');
    let bytes = rest.as_bytes();
    let directory = rest.len() <= 6
        && rest.len() % 2 == 0
        && bytes
            .as_chunks::<2>()
            .0
            .iter()
            .all(|part| cache::lower_hex(part[0]) && part[1] == b'/');
    let resource = if directory {
        Resource::Directory
    } else if rest == ".sccache_check" {
        Resource::Probe
    } else if rest.len() == 70
        && [1, 3, 5].iter().all(|i| bytes[*i] == b'/')
        && cache::sha256_hex(&rest[6..])
        && bytes[0] == bytes[6]
        && bytes[2] == bytes[7]
        && bytes[4] == bytes[8]
    {
        Resource::Artifact(rest[6..].to_owned())
    } else {
        return Err(cache::not_found());
    };
    Ok((path, resource))
}

async fn open(
    state: &AppState,
    path: DavPath,
    request: &Parts,
    write: bool,
) -> Result<(Resource, Access), ApiError> {
    let (path, resource) = parse(path, request.uri.path())?;
    let access = artifacts::open(
        state,
        Product::Sccache,
        &path.slug,
        &path.cache,
        resource.action(),
        &request.headers,
        write,
    )
    .await?;
    Ok((resource, access))
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
        "PROPFIND" => propfind(state, path, request).await,
        "MKCOL" => mkcol(state, path, request).await,
        // Unsupported methods validate the grammar, but do not look up/auth the cache.
        _ => {
            parse(path, request.uri().path())?;
            Err(method_not_allowed())
        }
    }
}

async fn propfind(state: AppState, path: DavPath, request: Request) -> Result<Response, ApiError> {
    let (request, _) = request.into_parts();
    let (resource, access) = open(&state, path, &request, false).await?;
    if !matches!(resource, Resource::Directory) {
        return Err(method_not_allowed());
    }
    let modified = httpdate::fmt_http_date(access.target.created_at.into());
    let pathname = request
        .extensions
        .get::<crate::cache_host::PublicPath>()
        .map_or(request.uri.path(), |path| path.0.as_str());
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

async fn mkcol(state: AppState, path: DavPath, request: Request) -> Result<Response, ApiError> {
    let (request, _) = request.into_parts();
    let (resource, _access) = open(&state, path, &request, true).await?;
    if !matches!(resource, Resource::Directory) {
        return Err(method_not_allowed());
    }
    Ok(StatusCode::CREATED.into_response())
}

async fn read(
    State(state): State<AppState>,
    path: DavPath,
    method: Method,
    request: Request,
) -> Result<Response, ApiError> {
    let (request, _) = request.into_parts();
    let (resource, access) = open(&state, path, &request, false).await?;
    if matches!(resource, Resource::Directory) {
        return Err(method_not_allowed());
    }
    access.download(&state, method == Method::HEAD).await
}

async fn upload(
    State(state): State<AppState>,
    path: DavPath,
    request: Request,
) -> Result<Response, ApiError> {
    let (request, body) = request.into_parts();
    let (resource, access) = open(&state, path, &request, true).await?;
    let max = match resource {
        Resource::Directory => return Err(method_not_allowed()),
        Resource::Probe => PROBE_MAX_BYTES,
        Resource::Artifact(_) => artifacts::MAX_BYTES,
    };
    let size = cache::content_length(&request.headers, max)?;
    if matches!(resource, Resource::Probe) {
        artifacts::consume(body, size).await?;
        return Ok((
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response());
    }
    access.upload(&state, size, None, body).await
}
