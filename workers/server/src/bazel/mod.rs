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
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::{
    AppState,
    authz::{self, Access, Action, Protocol, Resource},
    cache,
    error::ApiError,
    protocol_policy::CallerLimit,
    wake::{Pace, Turn, Wake},
};
use proto::build::bazel::remote::execution::v2::{ActionResult, Digest, Tree};

const MAX_METADATA: usize = 4 * 1024 * 1024;

/// The soonest one sweep pass may follow another. A build's writes are swept
/// together, at most this often, as the former fixed interval swept them.
const SETTLE: Duration = Duration::from_secs(60);
/// How often every generation is swept whether or not anything announced it.
const FALLBACK: Duration = Duration::from_secs(60 * 60);

/// What the collector has been told may have changed. A sweep reads object
/// storage in proportion to a generation's size, so a generation is swept
/// when a sweep could find something new, and otherwise costs nothing: no
/// storage request and no statement.
///
/// A generation is marked by every `Store` operation that writes its objects
/// (`write`, `write_buffered`, `append`, `write_stream`, `finish_upload`),
/// over HTTP and gRPC alike, as the operation ends, however it ends. The
/// collector marks it again when a sweep fails or leaves it above its target.
/// Targets are reread when management creates a Bazel cache or changes a
/// capacity or an organization's limit; a generation is then swept only if
/// its target fell below the size last observed.
///
/// Access markers mark nothing. A sweep leaves a generation within its
/// target, so a marker alone evicts nothing and changes no usage; the sweep
/// that next evicts reads the markers then.
///
/// The fallback sweeps every generation for what this process never saw:
/// another instance's writes, a manual change, and targets moved by the other
/// products' usage. It is also the timer for everything a sweep removes by
/// age (uploads never published, staging chunks, access markers, and the
/// objects of retired generations): two hours is their minimum age, not a
/// deadline, so no sweep is scheduled for it.
pub(crate) struct Sweeps {
    wake: Wake,
    pending: Mutex<Pending>,
    settle: Duration,
    fallback: Duration,
}

#[derive(Default)]
struct Pending {
    generations: HashSet<String>,
    targets: bool,
}

impl Default for Sweeps {
    fn default() -> Self {
        Self::new(SETTLE, FALLBACK)
    }
}

impl Sweeps {
    pub(crate) fn new(settle: Duration, fallback: Duration) -> Self {
        Self {
            wake: Wake::default(),
            pending: Mutex::default(),
            settle,
            fallback,
        }
    }

    /// Call after the change, never before: a sweep that looks first records
    /// the old state and nothing asks for another.
    pub(crate) fn mark(&self, generation: &str) {
        let mut pending = self.pending.lock().unwrap();
        let added = !pending.generations.contains(generation)
            && pending.generations.insert(generation.to_owned());
        drop(pending);
        // Later marks of a waiting generation join the pass already owed.
        if added {
            self.wake.wake();
        }
    }

    /// Call after a commit that may have lowered a retention target.
    pub(crate) fn retarget(&self) {
        self.pending.lock().unwrap().targets = true;
        self.wake.wake();
    }
}

/// The collector's own record between passes.
struct Collector {
    /// No pass starts before this.
    next: Instant,
    /// The next pass at or after this sweeps everything.
    full: Instant,
    /// Retained bytes each generation was last observed to hold.
    sizes: HashMap<String, u64>,
}

pub(crate) async fn maintain(state: AppState, stopped: tokio_util::sync::CancellationToken) {
    let sweeps = state.bazel.clone();
    let mut pace = Pace::new(&sweeps.wake, &stopped, sweeps.fallback);
    // The first pass sweeps everything: nothing before this start was seen.
    let start = Instant::now() + sweeps.settle;
    let mut collector = Collector {
        next: start,
        full: start,
        sizes: HashMap::new(),
    };
    while pace.running() {
        let turn = tokio::select! {
            _ = stopped.cancelled() => break,
            turn = collector.turn(&state) => turn,
        };
        if turn.is_err() {
            tracing::warn!("Bazel retention sweep failed; retrying after the settle period");
        }
        pace.after(turn).await;
    }
}

impl Collector {
    async fn turn(&mut self, state: &AppState) -> anyhow::Result<Turn> {
        let sweeps = &state.bazel;
        let now = Instant::now();
        if now < self.next {
            // A wake inside the settle period waits it out. Its marks stay.
            return Ok(Turn::Idle(Some(self.next - now)));
        }
        let full = now >= self.full;
        // Take the marks before reading anything, so a change that lands
        // during this pass asks for the next one.
        let pending = std::mem::take(&mut *sweeps.pending.lock().unwrap());
        if !full && !pending.targets && pending.generations.is_empty() {
            return Ok(Turn::Idle(Some(self.full - now)));
        }
        self.next = now + sweeps.settle;
        match collect(state, &mut self.sizes, full, &pending).await {
            Ok(_) => {
                if full {
                    self.full = now + sweeps.fallback;
                }
                Ok(Turn::Worked)
            }
            Err(error) => {
                let mut again = sweeps.pending.lock().unwrap();
                again.generations.extend(pending.generations);
                again.targets |= pending.targets;
                Err(error)
            }
        }
    }
}

/// Sweep every generation and retire unknown ones, or with `full` unset only
/// the marked generations and, after a retargeting, those above their target.
async fn collect(
    state: &AppState,
    sizes: &mut HashMap<String, u64>,
    full: bool,
    pending: &Pending,
) -> anyhow::Result<u64> {
    use futures_util::{StreamExt, TryStreamExt, stream};
    let mut active: Vec<(String, i64)> = if full || pending.targets {
        sqlx::query!(
            r#"SELECT generation AS "generation!", target AS "target!" FROM bazel_retention"#
        )
        .map(|row| (row.generation, row.target))
        .fetch_all(&state.pool)
        .await?
    } else {
        let marked: Vec<String> = pending.generations.iter().cloned().collect();
        sqlx::query!(
            r#"SELECT generation AS "generation!", target AS "target!"
            FROM bazel_retention WHERE generation = ANY($1)"#,
            &marked,
        )
        .map(|row| (row.generation, row.target))
        .fetch_all(&state.pool)
        .await?
    };
    let mut generations: HashMap<String, bool> = active
        .iter()
        .map(|(generation, _)| (generation.clone(), true))
        .collect();
    if full {
        sizes.retain(|generation, _| generations.contains_key(generation));
    }
    active.retain(|(generation, target)| {
        full || pending.generations.contains(generation)
            // Never observed, or observed above what it may now retain.
            || sizes.get(generation).is_none_or(|size| *size > *target as u64)
    });
    let mut deleted = 0;
    let mut sweeps = stream::iter(active.into_iter().map(|(generation, capacity)| async move {
        let started = chrono::Utc::now();
        let store = store::Store::new(state.storage.clone(), &generation, capacity as u64);
        let swept = async {
            let deleted = store.collect().await?;
            let (entries, size) = store.usage().await?;
            let (physical, staging) = store.physical_usage().await?;
            // Background observations only. A reset cannot inherit the old generation's
            // totals, and a slow collector cannot replace a more recent observation.
            sqlx::query!("INSERT INTO bazel_usage(cache_id,generation,entries,size,physical_size,staging_size,updated_at)
                SELECT cache_id,generation,$2,$3,$4,$5,$6 FROM bazel_caches WHERE generation=$1
                ON CONFLICT(cache_id) DO UPDATE SET generation=EXCLUDED.generation,entries=EXCLUDED.entries,
                    size=EXCLUDED.size,physical_size=EXCLUDED.physical_size,staging_size=EXCLUDED.staging_size,
                    updated_at=EXCLUDED.updated_at WHERE bazel_usage.updated_at < EXCLUDED.updated_at",
                generation, entries as i64, size as i64, physical as i64, staging as i64, started)
                .execute(&state.pool).await?;
            Ok::<_, anyhow::Error>((deleted, size))
        }
        .await;
        (generation, capacity as u64, swept)
    }))
    .buffer_unordered(4);
    while let Some((generation, capacity, swept)) = sweeps.next().await {
        match swept {
            Ok((count, size)) => {
                deleted += count;
                // Candidates are bounded and a racing collector may win an
                // entry: a large excess drains over successive passes.
                if size > capacity {
                    state.bazel.mark(&generation);
                }
                sizes.insert(generation, size);
            }
            Err(_) => {
                tracing::warn!("Bazel cache sweep failed; retaining its previous usage snapshot");
                state.bazel.mark(&generation);
            }
        }
    }
    if !full {
        return Ok(deleted);
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
    grpc::router(state).merge(http_router())
}

/// Bazel over HTTP alone, without gRPC. Organization hosts route to this
/// router so that the gRPC service never sees their requests.
pub(crate) fn http_router() -> Router<AppState> {
    Router::new().route(
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
    owner: Option<&str>,
    instance: &str,
    headers: &HeaderMap,
    write: bool,
) -> Result<(store::Store, bool), ApiError> {
    let (slug, name) = match owner {
        // On an organization host the host names the organization and the
        // instance names only the cache.
        Some(owner) => (owner, instance),
        None => instance.split_once('/').ok_or_else(cache::not_found)?,
    };
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
            Action::Use(Protocol::Bazel.permission(Access::of(write))),
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
        )
        .announcing(state.bazel.clone()),
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
    // The HTTP organization path is already rewritten to the canonical route.
    let (store, public) = open(
        &state,
        None,
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
