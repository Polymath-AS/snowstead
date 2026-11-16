mod grpc;
pub mod proto;
pub mod store;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use prost::Message;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::{
    AppState,
    authz::{self, Action, Resource},
    cache,
    error::ApiError,
    protocol_policy::CallerLimit,
};
use proto::build::bazel::remote::execution::v2::{ActionResult, Digest, Tree};

const MAX_METADATA: usize = 4 * 1024 * 1024;

pub(crate) async fn maintain(state: AppState, stopped: tokio_util::sync::CancellationToken) {
    let period = std::time::Duration::from_secs(60);
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stopped.cancelled() => break,
            _ = interval.tick() => {
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    result = collect(&state) => {
                        if result.is_err() { tracing::warn!("Bazel retention sweep failed; retrying next minute"); }
                    }
                }
            }
        }
    }
}

pub(crate) async fn collect(state: &AppState) -> anyhow::Result<u64> {
    use futures_util::{StreamExt, TryStreamExt, stream};
    let active: Vec<(String, i64)> =
        sqlx::query_as("SELECT generation, target FROM bazel_retention")
            .fetch_all(&state.pool)
            .await?;
    let mut generations: std::collections::HashMap<String, bool> = active
        .iter()
        .map(|(generation, _)| (generation.clone(), true))
        .collect();
    let mut deleted = 0;
    let mut sweeps = stream::iter(active.into_iter().map(|(generation, capacity)| async move {
        let started = chrono::Utc::now();
        let store = store::Store::new(state.storage.clone(), &generation, capacity as u64);
        let deleted = store.collect().await?;
        let (entries, size) = store.usage().await?;
        let (physical, staging) = store.physical_usage().await?;
        // Background observations only. A reset cannot inherit the old generation's
        // totals, and a slow collector cannot replace a more recent observation.
        sqlx::query("INSERT INTO bazel_usage(cache_id,generation,entries,size,physical_size,staging_size,updated_at)
            SELECT cache_id,generation,$2,$3,$4,$5,$6 FROM bazel_caches WHERE generation=$1
            ON CONFLICT(cache_id) DO UPDATE SET generation=EXCLUDED.generation,entries=EXCLUDED.entries,
                size=EXCLUDED.size,physical_size=EXCLUDED.physical_size,staging_size=EXCLUDED.staging_size,
                updated_at=EXCLUDED.updated_at WHERE bazel_usage.updated_at < EXCLUDED.updated_at")
            .bind(generation).bind(entries as i64).bind(size as i64).bind(physical as i64)
            .bind(staging as i64).bind(started).execute(&state.pool).await?;
        Ok::<_, anyhow::Error>(deleted)
    })).buffer_unordered(4);
    while let Some(sweep) = sweeps.next().await {
        match sweep {
            Ok(count) => deleted += count,
            Err(_) => {
                tracing::warn!("Bazel cache sweep failed; retaining its previous usage snapshot")
            }
        }
    }
    let metadata = state.storage.private_store();
    let prefix = object_store::path::Path::from("bazel/");
    let mut objects = metadata.list(Some(&prefix));
    while let Some(object) = objects.try_next().await? {
        if object.last_modified.timestamp() + 7200 >= chrono::Utc::now().timestamp() {
            continue;
        }
        let Some(generation) = object.location.as_ref().split('/').nth(1) else {
            continue;
        };
        // Generations are globally unique and never reactivated. Read primary
        // state immediately before retiring an old generation's objects.
        let active = if let Some(active) = generations.get(generation) {
            *active
        } else {
            let active: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM bazel_caches WHERE generation=$1)")
                    .bind(generation)
                    .fetch_one(&state.pool)
                    .await?;
            generations.insert(generation.to_owned(), active);
            active
        };
        if !active {
            state.storage.delete(true, object.location.as_ref()).await?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

pub(crate) fn router(state: AppState) -> Router<AppState> {
    grpc::router(state).route(
        "/_api/v1/bazel/{slug}/{cache}/{kind}/{digest}",
        get(http).head(http).put(http),
    )
}

#[derive(sqlx::FromRow)]
struct Target {
    id: i32,
    org: String,
    public: bool,
    private_caches: bool,
    generation: String,
    capacity: i64,
}

async fn open(
    state: &AppState,
    instance: &str,
    headers: &HeaderMap,
    write: bool,
) -> Result<(store::Store, bool), ApiError> {
    let (slug, name) = instance.split_once('/').ok_or_else(cache::not_found)?;
    if !cache::valid_name(slug, cache::SLUG_MAX) || !cache::valid_name(name, cache::NAME_MAX) {
        return Err(cache::not_found());
    }
    let target: Target = sqlx::query_as(
        "SELECT c.id, c.org_id AS org, c.is_public AS public, o.private_caches,
            b.generation, b.capacity FROM caches c JOIN orgs o ON o.id=c.org_id
            JOIN bazel_caches b ON b.cache_id=c.id
            WHERE o.slug=$1 AND c.name=$2 AND EXISTS
            (SELECT 1 FROM cache_protocols p WHERE p.cache_id=c.id AND p.protocol='bazel')",
    )
    .bind(slug)
    .bind(name)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(cache::not_found)?;
    if write || !target.public {
        let principal = cache::caller(
            state,
            headers,
            if write {
                CallerLimit::Push
            } else {
                CallerLimit::Read
            },
        )
        .await?;
        authz::authorize(
            &principal,
            if write {
                Action::BazelWrite
            } else {
                Action::BazelRead
            },
            &Resource::cache(&target.org, target.id, name),
        )?;
    }
    if write && !target.public && !target.private_caches {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Private cache uploads are disabled",
        ));
    }
    Ok((
        store::Store::new(
            state.storage.clone(),
            &target.generation,
            target.capacity as u64,
        ),
        target.public,
    ))
}

fn failure(error: std::io::Error) -> ApiError {
    let status = match error.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
            StatusCode::BAD_REQUEST
        }
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::BAD_GATEWAY,
    };
    ApiError::new(status, "Bazel storage request failed")
}

fn valid_digest(digest: &Digest) -> bool {
    digest.size_bytes >= 0 && cache::sha256_hex(&digest.hash)
}

async fn blob(store: &store::Store, digest: &Digest) -> Result<Option<Vec<u8>>, ApiError> {
    if !valid_digest(digest) || digest.size_bytes > MAX_METADATA as i64 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid metadata digest",
        ));
    }
    let Some(mut object) = store.read("cas", &digest.hash).await.map_err(failure)? else {
        return Ok(None);
    };
    if object.metadata.size != digest.size_bytes as u64 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    object
        .reader
        .read_to_end(&mut bytes)
        .await
        .map_err(failure)?;
    Ok(Some(bytes))
}

async fn complete(store: &store::Store, result: &ActionResult) -> Result<bool, ApiError> {
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    let matches = |digest: &Digest, bytes: &[u8]| {
        valid_digest(digest)
            && digest.size_bytes as usize == bytes.len()
            && digest.hash == hex::encode(Sha256::digest(bytes))
    };
    // Bound expanded work, not just the wire size of each individual Tree.
    // A legal action may reuse a Tree at many different output paths.
    let exhausted = || {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Action validation budget exceeded",
        )
    };
    let mut remaining_nodes = 100_000usize;
    remaining_nodes = remaining_nodes
        .checked_sub(result.output_files.len() + result.output_directories.len())
        .ok_or_else(exhausted)?;
    let mut remaining_tree_bytes = 16 * 1024 * 1024u64;
    let mut trees = BTreeSet::new();
    let mut references = BTreeSet::new();
    for file in &result.output_files {
        let Some(digest) = &file.digest else {
            return Ok(false);
        };
        if file.contents.is_empty() {
            references.insert((digest.hash.clone(), digest.size_bytes));
        } else if !matches(digest, &file.contents) {
            return Ok(false);
        }
    }
    for (digest, raw) in [
        (&result.stdout_digest, &result.stdout_raw),
        (&result.stderr_digest, &result.stderr_raw),
    ] {
        if let Some(digest) = digest {
            if raw.is_empty() {
                references.insert((digest.hash.clone(), digest.size_bytes));
            } else if !matches(digest, raw) {
                return Ok(false);
            }
        }
    }
    for output in &result.output_directories {
        let Some(digest) = &output.tree_digest else {
            return Ok(false);
        };
        if !valid_digest(digest) {
            return Ok(false);
        }
        if !trees.insert((digest.hash.clone(), digest.size_bytes)) {
            continue;
        }
        remaining_tree_bytes = remaining_tree_bytes
            .checked_sub(digest.size_bytes as u64)
            .ok_or_else(exhausted)?;
        let Some(bytes) = blob(store, digest).await? else {
            return Ok(false);
        };
        let tree = Tree::decode(bytes.as_slice())
            .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid output tree"))?;
        let Some(root) = tree.root else {
            return Ok(false);
        };
        let children: BTreeMap<_, _> = tree
            .children
            .into_iter()
            .map(|directory| {
                let encoded = directory.encode_to_vec();
                (
                    hex::encode(Sha256::digest(&encoded)),
                    (encoded.len(), directory),
                )
            })
            .collect();
        let mut pending = vec![&root];
        let mut seen = BTreeSet::new();
        while let Some(directory) = pending.pop() {
            remaining_nodes = remaining_nodes
                .checked_sub(
                    1 + directory.files.len()
                        + directory.directories.len()
                        + directory.symlinks.len(),
                )
                .ok_or_else(exhausted)?;
            for file in &directory.files {
                let Some(digest) = &file.digest else {
                    return Ok(false);
                };
                references.insert((digest.hash.clone(), digest.size_bytes));
            }
            for child in &directory.directories {
                let Some(digest) = &child.digest else {
                    return Ok(false);
                };
                if !valid_digest(digest) {
                    return Ok(false);
                }
                let Some((length, directory)) = children.get(&digest.hash) else {
                    return Ok(false);
                };
                if *length != digest.size_bytes as usize {
                    return Ok(false);
                }
                if seen.insert(digest.hash.clone()) {
                    pending.push(directory)
                }
            }
        }
    }
    use futures_util::{StreamExt, TryStreamExt, stream};
    let mut checks = stream::iter(references.into_iter().map(|(hash, size_bytes)| async move {
        let digest = Digest { hash, size_bytes };
        if !valid_digest(&digest) {
            return Ok(false);
        }
        Ok::<_, ApiError>(
            store
                .stat("cas", &digest.hash)
                .await
                .map_err(failure)?
                .is_some_and(|object| object.size == digest.size_bytes as u64),
        )
    }))
    .buffer_unordered(32);
    while let Some(present) = checks.try_next().await? {
        if !present {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn http(
    State(state): State<AppState>,
    Path((slug, name, kind, digest)): Path<(String, String, String, String)>,
    method: Method,
    request: Request,
) -> Result<Response, ApiError> {
    if !crate::artifacts::literal(request.uri().path(), &slug, &name)
        || !matches!(kind.as_str(), "cas" | "ac")
        || !cache::sha256_hex(&digest)
    {
        return Err(cache::not_found());
    }
    let (parts, body) = request.into_parts();
    let (store, public) = open(
        &state,
        &format!("{slug}/{name}"),
        &parts.headers,
        method == Method::PUT,
    )
    .await?;
    if method == Method::PUT {
        let size = cache::content_length(&parts.headers, store.max_blob_size())?;
        let body = if kind == "ac" {
            let bytes = to_bytes(body, MAX_METADATA).await.map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Action result exceeds metadata limit",
                )
            })?;
            if bytes.len() as u64 != size {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Content length mismatch",
                ));
            }
            let result = ActionResult::decode(bytes.clone())
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid action result"))?;
            if !complete(&store, &result).await? {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Action result references missing blobs",
                ));
            }
            Body::from(bytes)
        } else {
            body
        };
        store
            .write(&kind, &digest, size, body)
            .await
            .map_err(failure)?;
        return Ok((StatusCode::NO_CONTENT, [("cache-control", "no-store")]).into_response());
    }
    let cache_control = if public && kind == "cas" {
        // CDN bytes may be reused only after origin authorization and existence
        // revalidation. A visibility change therefore needs no purge race.
        "public, no-cache, must-revalidate, no-transform"
    } else {
        "no-store"
    };
    let etag = format!("\"{digest}\"");
    if kind == "cas" && (method == Method::HEAD || parts.headers.get("if-none-match").is_some()) {
        let metadata = store
            .stat(&kind, &digest)
            .await
            .map_err(failure)?
            .ok_or_else(cache::not_found)?;
        let matches = parts
            .headers
            .get("if-none-match")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(',').map(str::trim).any(|value| {
                    value == etag || value == "*" || value.strip_prefix("W/") == Some(etag.as_str())
                })
            });
        if matches || method == Method::HEAD {
            return Ok((
                if matches {
                    StatusCode::NOT_MODIFIED
                } else {
                    StatusCode::OK
                },
                [
                    ("etag", etag.as_str()),
                    ("cache-control", cache_control),
                    ("cloudflare-cdn-cache-control", cache_control),
                    ("content-length", &metadata.size.to_string()),
                    ("content-type", "application/octet-stream"),
                ],
            )
                .into_response());
        }
    }
    let mut object = store
        .read(&kind, &digest)
        .await
        .map_err(failure)?
        .ok_or_else(cache::not_found)?;
    let size = object.metadata.size;
    let body = if kind == "ac" {
        if size > MAX_METADATA as u64 {
            return Err(cache::not_found());
        }
        let mut bytes = Vec::new();
        object
            .reader
            .read_to_end(&mut bytes)
            .await
            .map_err(failure)?;
        let result = ActionResult::decode(bytes.as_slice()).map_err(|_| cache::not_found())?;
        if !complete(&store, &result).await? {
            return Err(cache::not_found());
        }
        if method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(bytes)
        }
    } else if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::with_capacity(object.reader, 256 * 1024))
    };
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("content-length", &size.to_string()),
            ("etag", etag.as_str()),
            ("cache-control", cache_control),
            ("cloudflare-cdn-cache-control", cache_control),
        ],
        body,
    )
        .into_response())
}
