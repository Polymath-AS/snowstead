//! PostgreSQL owns grants, immutable receipts, seals, and abort exclusion.
//! No connection is held during HTTP bodies, verification, or storage I/O.
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io::Read,
    time::Duration,
};

use crate::db::{self, Transaction};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::{Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::Response,
    routing::post,
};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_protocol::{
    self as protocol, Aborted, CreateSessions, CreatedSessions, FinalizeBatch, InlineEntry,
    InlineManifest, JobSession, PartGrant, PartGrants, PartRequest, Receipt, ReceiptPart,
    ReservationResult, ReservationResults, ReservePartsBatch, SessionStatus, UploadResult,
    UploadResults, UploadSession, UploadStage, UploadStatusRequest, limits, routes,
};
use sqlx::Acquire;

mod finalization;
pub(crate) use finalization::expire as expire_finalizations;
pub(crate) use finalization::run as run_finalizations;
use finalization::{enqueue_finalizations, status};

use crate::{
    AppState,
    authz::{Action, Principal as Identity, Resource, authorize as decide},
    error::ApiError,
    lifecycle::UploadStatus,
    native, signing,
    wire::respond,
};

const MIB: i64 = 1024 * 1024;
/// Inline sessions' part size, and the bound on their NAR and file sizes.
const INLINE: i64 = limits::INLINE_MAX_BYTES as i64;
const MAX_INLINE_MANIFEST: usize = limits::INLINE_MANIFEST_MAX_BYTES;
const MAX_INLINE_FRAME: usize =
    4 + MAX_INLINE_MANIFEST + limits::INLINE_BATCH_MAX * limits::INLINE_MAX_BYTES as usize;
const MAX_OBJECT: i64 = 5 * 1024 * 1024 * 1024 * 1024;
const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const PRIVATE_CACHES_REFUSED: &str = "this org does not allow private caches: its private caches keep serving their paths, but take no pushes, and no new ones can be made";

pub(crate) fn router(state: AppState) -> Router<AppState> {
    // Method layers leave Axum's 405/Allow response outside authentication.
    let write = middleware::from_fn_with_state(state, crate::nix::write_access);
    Router::new()
        .route(
            routes::UPLOAD_STREAMS_ROUTE,
            post(create).route_layer(write.clone()),
        )
        .route(
            routes::UPLOAD_PARTS,
            post(reserve_parts_batch).route_layer(write.clone()),
        )
        .route(routes::FINALIZE, post(finalize).route_layer(write.clone()))
        .route(
            routes::UPLOAD_STATUS,
            post(status).route_layer(write.clone()),
        )
        .route(
            routes::SESSION_PARTS_ROUTE,
            post(reserve_parts).route_layer(write.clone()),
        )
        .route(
            routes::INLINE_BATCH,
            post(inline_batch).route_layer(write.clone()),
        )
        .route(
            routes::INLINE_ROUTE,
            post(inline).route_layer(write.clone()),
        )
        .route(routes::ABORT_ROUTE, post(abort).route_layer(write))
}

fn configured_origin(value: &str) -> Result<String, ApiError> {
    let url = reqwest::Url::parse(value).map_err(|_| error(500, "Invalid PUBLIC_URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(error(500, "Invalid PUBLIC_URL"));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn error(code: u16, message: &str) -> ApiError {
    ApiError::new(StatusCode::from_u16(code).unwrap(), message)
}
fn io_error(failure: std::io::Error) -> ApiError {
    match failure.kind() {
        std::io::ErrorKind::FileTooLarge => error(413, "Object exceeds upload buffer limit"),
        std::io::ErrorKind::WouldBlock => error(503, "Upload capacity exhausted"),
        _ => error(500, "Storage operation failed"),
    }
}
fn hash_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn store_hash(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| NIX32.contains(c))
}
pub(crate) fn basename(s: &str) -> bool {
    let Some((hash, name)) = s.split_once('-') else {
        return false;
    };
    store_hash(hash)
        && !name.is_empty()
        && name.len() <= 211
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-._?=".contains(&b))
}
fn canonical_hash(s: &str) -> Result<String, ApiError> {
    signing::parse_nar_hash(s)
        .map(|h| format!("sha256:{}", signing::nix32(&h)))
        .ok_or_else(|| error(400, "Invalid NAR hash"))
}
fn part_size(size: i64) -> i64 {
    let bound = size
        + size / 256
        + if size < 128 * 1024 {
            (128 * 1024 - size) / 2048
        } else {
            0
        };
    let parts = i64::from(limits::MAX_PARTS);
    ((bound + parts * MIB - 1) / (parts * MIB) * MIB).clamp(8 * MIB, 1024 * MIB)
}
fn bounded(size: i64) -> bool {
    (1..=MAX_OBJECT).contains(&size)
}
fn batch<T>(items: &[T]) -> Result<(), ApiError> {
    if items.is_empty() || items.len() > limits::BATCH_MAX {
        return Err(error(400, "Batch must contain 1 to 100 entries"));
    }
    Ok(())
}
fn distinct<'a>(mut ids: impl Iterator<Item = &'a str>) -> Result<(), ApiError> {
    let mut seen = HashSet::new();
    if ids.all(|id| seen.insert(id)) {
        Ok(())
    } else {
        Err(error(400, "Duplicate sessions"))
    }
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn json_body<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    let bytes = to_bytes(request.into_body(), 4 * 1024 * 1024)
        .await
        .map_err(|_| error(400, "Invalid JSON in request body"))?;
    serde_json::from_slice(&bytes).map_err(|_| error(400, "Invalid JSON in request body"))
}

#[derive(Clone, Serialize)]
struct Session {
    id: String,
    cache_id: i32,
    store_path_hash: String,
    store_path: String,
    nar_hash: String,
    nar_size: i64,
    file_hash: Option<String>,
    file_size: i64,
    references_json: String,
    deriver: Option<String>,
    system: Option<String>,
    status: UploadStatus,
    r2_upload_id: Option<String>,
    r2_upload_key: Option<String>,
    part_size: Option<i32>,
    staging_capacity: Option<i64>,
    org_id: String,
    name: String,
    slug: String,
    is_public: bool,
    private_caches: bool,
    publication_result: Option<Value>,
    #[serde(skip)]
    job_authorized: bool,
    #[serde(skip)]
    push_job_id: Option<String>,
}
struct ReservationSession {
    id: String,
    cache_id: i32,
    org_id: String,
    name: String,
    r2_upload_id: Option<String>,
    job_authorized: bool,
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn load(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    identity: &Identity,
) -> Result<Session, ApiError> {
    load_sessions(executor, &[id.to_owned()], identity)
        .await?
        .pop()
        .ok_or_else(|| error(404, "Not found"))
}

async fn load_sessions(
    executor: impl sqlx::PgExecutor<'_>,
    ids: &[String],
    identity: &Identity,
) -> Result<Vec<Session>, ApiError> {
    let sessions = load_session_rows(executor, ids, identity).await?;
    for session in &sessions {
        authorize_session(
            identity,
            &session.org_id,
            session.cache_id,
            &session.name,
            session.job_authorized,
        )?;
    }
    Ok(sessions)
}

fn authorize_session(
    identity: &Identity,
    org: &str,
    cache_id: i32,
    name: &str,
    job_authorized: bool,
) -> Result<(), ApiError> {
    decide(
        identity,
        Action::NixPush,
        &Resource::cache(org, cache_id, name),
    )
    .map_err(|_| error(403, "Forbidden"))?;
    if !job_authorized {
        return Err(error(
            409,
            "Push job authorization is inactive; resume the job",
        ));
    }
    Ok(())
}

async fn load_session_rows(
    executor: impl sqlx::PgExecutor<'_>,
    ids: &[String],
    identity: &Identity,
) -> Result<Vec<Session>, ApiError> {
    let sessions = sqlx::query_as!(
        Session,
        r#"
        SELECT
            u.id,
            u.cache_id,
            u.store_path_hash,
            u.store_path,
            u.nar_hash,
            u.nar_size,
            u.file_hash,
            u.file_size,
            u.references_json,
            u.deriver,
            u.system,
            u.status AS "status: UploadStatus",
            u.r2_upload_id,
            u.r2_upload_key,
            u.part_size,
            u.staging_capacity,
            c.org_id,
            c.name,
            c.is_public,
            o.slug,
            o.private_caches,
            u.publication_result,
            u.push_job_id,
            (u.push_job_id IS NULL OR EXISTS (
                SELECT 1 FROM push_jobs j JOIN api_tokens t ON t.jti=j.authorization_jti
                WHERE j.id=u.push_job_id AND j.cache_id=u.cache_id AND j.creator=$2 AND $3
                    AND (j.state='sealed' OR (j.state='completed' AND u.status='completed'))
                    AND j.idle_expires_at>NOW()
                    AND j.hard_expires_at>NOW() AND j.authorization_expires_at>NOW()
                    AND t.revoked_at IS NULL
            )) AS "job_authorized!"
        FROM upload_sessions u
        JOIN caches c ON c.id = u.cache_id
        JOIN orgs o ON o.id = c.org_id
        WHERE u.id = ANY($1)
            AND u.expires_at > NOW()
            AND EXISTS (
                SELECT 1
                FROM cache_protocols p
                WHERE p.cache_id = c.id
                    AND p.protocol = 'nix'
            )
        "#,
        ids,
        identity.actor(),
        matches!(identity, Identity::ApiToken(_)),
    )
    .fetch_all(executor)
    .await?;
    Ok(sessions)
}

async fn load_reservation_rows(
    executor: impl sqlx::PgExecutor<'_>,
    ids: &[String],
    identity: &Identity,
) -> Result<Vec<ReservationSession>, ApiError> {
    let sessions = sqlx::query_as!(
        ReservationSession,
        r#"
        SELECT
            u.id,
            u.cache_id,
            c.org_id,
            c.name,
            u.r2_upload_id,
            (u.push_job_id IS NULL OR EXISTS (
                SELECT 1 FROM push_jobs j JOIN api_tokens t ON t.jti=j.authorization_jti
                WHERE j.id=u.push_job_id AND j.cache_id=u.cache_id AND j.creator=$2 AND $3
                    AND (j.state='sealed' OR (j.state='completed' AND u.status='completed'))
                    AND j.idle_expires_at>NOW()
                    AND j.hard_expires_at>NOW() AND j.authorization_expires_at>NOW()
                    AND t.revoked_at IS NULL
            )) AS "job_authorized!"
        FROM upload_sessions u
        JOIN caches c ON c.id = u.cache_id
        JOIN orgs o ON o.id = c.org_id
        WHERE u.id = ANY($1)
            AND u.expires_at > NOW()
            AND EXISTS (
                SELECT 1
                FROM cache_protocols p
                WHERE p.cache_id = c.id
                    AND p.protocol = 'nix'
            )
        "#,
        ids,
        identity.actor(),
        matches!(identity, Identity::ApiToken(_)),
    )
    .fetch_all(executor)
    .await?;
    Ok(sessions)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn locked(
    state: &AppState,
    s: &Session,
    identity: &Identity,
) -> Result<(Transaction, Session), ApiError> {
    let tx = crate::profile_future!(
        crate::db::begin(state),
        label = "uploads.session_pool_begin"
    )
    .await?;
    lock_session(tx, s, identity).await
}

/// One writer per session. The advisory lock orders requests for the session
/// against each other and against publication, without waiting. The row lock
/// orders them against writers that take no advisory lock: bulk aborts wait
/// for this transaction, and a cache deletion cannot remove the session from
/// under the parts, receipt, or candidate this transaction adds.
async fn lock_session(
    mut tx: Transaction,
    s: &Session,
    identity: &Identity,
) -> Result<(Transaction, Session), ApiError> {
    let held = crate::profile_future!(
        lock_sessions(&mut tx, std::slice::from_ref(&s.id)),
        label = "uploads.advisory_lock_wait"
    )
    .await?;
    if !held {
        return Err(error(503, "Concurrent write; retry")
            .header(header::RETRY_AFTER, HeaderValue::from_static("1")));
    }
    // Re-read and reauthorize after the locks, using the same query as preflight.
    let current = load(&mut *tx, &s.id, identity).await?;
    Ok((tx, current))
}

/// Try every session's `upload:<session>` advisory lock, in sorted order, and
/// only if all were free lock the session rows as `lock_rows` does. It is one
/// statement, in that order: the row locks read the outcome of the advisory
/// locks, so none is requested before every advisory lock has been tried, and
/// none at all when one was held. Returns whether the locks were taken.
async fn lock_sessions(tx: &mut Transaction, ids: &[String]) -> Result<bool, ApiError> {
    let (held, _): (bool, i64) = sqlx::query_as(
        "SELECT held.ok,(SELECT count(*) FROM (SELECT FROM upload_sessions \
         WHERE held.ok AND id=ANY($1) ORDER BY id FOR NO KEY UPDATE) locked) \
         FROM (SELECT COALESCE(bool_and(pg_try_advisory_xact_lock(hashtextextended(key,0))),TRUE) AS ok \
         FROM (SELECT DISTINCT 'upload:'||id AS key FROM UNNEST($1::text[]) AS id \
         ORDER BY key OFFSET 0) ordered) held",
    )
    .bind(ids)
    .fetch_one(&mut **tx)
    .await?;
    Ok(held)
}

/// Lock session rows in ID order, so two multi-session writers cannot wait on
/// each other. Status changes and deletion wait for the holder.
async fn lock_rows(tx: &mut Transaction, ids: &[String]) -> Result<(), ApiError> {
    sqlx::query("SELECT FROM upload_sessions WHERE id=ANY($1) ORDER BY id FOR NO KEY UPDATE")
        .bind(ids)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) use protocol::PathInput;

/// Wire sizes are unsigned; SQL stores `bigint`. Saturating is safe: every
/// size is checked with [`bounded`], which rejects anything near `i64::MAX`.
fn signed(size: u64) -> i64 {
    i64::try_from(size).unwrap_or(i64::MAX)
}
/// Stored sizes are positive; a corrupt negative one fails [`bounded`].
fn unsigned(size: i64) -> u64 {
    u64::try_from(size).unwrap_or_default()
}

pub(crate) trait PathInputExt {
    fn normalize(&mut self) -> Result<(), ApiError>;
    fn validate(&self) -> Result<String, ApiError>;
}

impl PathInputExt for PathInput {
    fn normalize(&mut self) -> Result<(), ApiError> {
        self.inline = false;
        self.nar_hash = self.validate()?;
        let references = self.references.get_or_insert_default();
        references.sort();
        references.dedup();
        Ok(())
    }

    fn validate(&self) -> Result<String, ApiError> {
        if !store_hash(&self.store_path_hash)
            || !self
                .store_path
                .starts_with(&format!("/nix/store/{}-", self.store_path_hash))
            || !basename(self.store_path.strip_prefix("/nix/store/").unwrap_or(""))
            || !bounded(signed(self.nar_size))
            || self.compression != protocol::COMPRESSION_ZSTD
            || (self.inline && signed(self.nar_size) > INLINE)
            || self
                .references
                .as_ref()
                .is_some_and(|r| r.iter().any(|s| !basename(s)))
            || self
                .deriver
                .as_ref()
                .is_some_and(|s| s.is_empty() || !s.bytes().all(|b| (33..=126).contains(&b)))
        {
            return Err(error(400, "Invalid stream metadata"));
        }
        canonical_hash(&self.nar_hash)
    }
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn create(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(cache): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let body: CreateSessions = json_body(request).await?;
    let state = &state;
    let identity = &identity;
    let cache = cache.as_str();
    batch(&body.paths)?;
    let mut members = Vec::new();
    if body.job_id.is_some() {
        distinct(body.paths.iter().map(|p| p.store_path_hash.as_str()))?;
        members = body.paths.clone();
        for member in &mut members {
            member.validate()?;
            member.normalize()?;
        }
    }
    let mut tx =
        crate::profile_future!(crate::db::begin(state), label = "uploads.create_pool_begin")
            .await?;
    // Hold the policy this decision reads until the sessions commit. A key
    // share lock on the cache excludes a policy change or deletion, which
    // take the row FOR UPDATE, but not a publication's update of its totals.
    struct CachePolicy {
        id: i32,
        is_public: bool,
        private_caches: bool,
        storage_limit: Option<i64>,
    }
    let CachePolicy {
        id: cache_id,
        is_public,
        private_caches: allowed,
        storage_limit: capacity,
    } = sqlx::query_as!(
        CachePolicy,
        r#"
        SELECT
            c.id,
            c.is_public,
            o.private_caches,
            o.storage_limit
        FROM caches c
        JOIN orgs o ON o.id = c.org_id
        WHERE c.org_id = $1
            AND c.name = $2
            AND EXISTS (
                SELECT 1
                FROM cache_protocols p
                WHERE p.cache_id = c.id
                    AND p.protocol = 'nix'
            )
        FOR KEY SHARE OF c NOWAIT
        FOR SHARE OF o NOWAIT
        "#,
        identity.org(),
        cache,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| error(404, "Cache not found"))?;
    decide(
        identity,
        Action::NixPush,
        &Resource::cache(identity.org(), cache_id, cache),
    )
    .map_err(|_| error(403, "Forbidden"))?;
    if !is_public && !allowed {
        return Err(error(403, PRIVATE_CACHES_REFUSED));
    }
    let mut reused = if let Some(job) = &body.job_id {
        crate::push_jobs::upload_members(&mut tx, identity, cache_id, job, &members).await?
    } else {
        HashMap::new()
    };
    // A soft limit: concurrent requests each count before either inserts.
    let active = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) AS "count!"
        FROM upload_sessions u
        JOIN caches c ON c.id = u.cache_id
        WHERE c.org_id = $1
            AND u.expires_at > NOW()
            AND u.status IN ('streaming', 'finalizing')
        "#,
        identity.org(),
    )
    .fetch_one(&mut *tx)
    .await?;
    if active + (body.paths.len() - reused.len()) as i64 > 8192 {
        return Err(error(
            429,
            "Too many active upload sessions; finish or abort existing uploads",
        ));
    }
    let mut sessions = Vec::with_capacity(body.paths.len());
    let mut rows = Vec::with_capacity(body.paths.len());
    for p in body.paths {
        let hash = p.validate()?;
        if let Some(session) = reused.remove(&p.store_path_hash) {
            sessions.push(session);
            continue;
        }
        let id = format!("s2.{}.{}", identity.org(), uuid::Uuid::now_v7());
        let size = if p.inline {
            INLINE
        } else {
            part_size(signed(p.nar_size))
        };
        sessions.push(UploadSession {
            session_id: id.clone(),
            part_size: unsigned(size),
            inline: p.inline,
            job: body.job_id.as_ref().map(|_| JobSession {
                status: SessionStatus::Streaming,
                publication_result: None,
                retained: None,
            }),
        });
        rows.push((id, p, hash, size));
    }
    let ids: Vec<_> = rows.iter().map(|(id, _, _, _)| id.clone()).collect();
    let hashes: Vec<_> = rows
        .iter()
        .map(|(_, p, _, _)| p.store_path_hash.clone())
        .collect();
    let paths: Vec<_> = rows
        .iter()
        .map(|(_, p, _, _)| p.store_path.clone())
        .collect();
    let nar_hashes: Vec<_> = rows.iter().map(|(_, _, hash, _)| hash.clone()).collect();
    let nar_sizes: Vec<_> = rows.iter().map(|(_, p, _, _)| signed(p.nar_size)).collect();
    let references: Vec<_> = rows
        .iter()
        .map(|(_, p, _, _)| {
            serde_json::to_string(&p.references.as_deref().unwrap_or_default()).unwrap()
        })
        .collect();
    let derivers: Vec<_> = rows.iter().map(|(_, p, _, _)| p.deriver.clone()).collect();
    let keys: Vec<_> = ids.iter().map(|id| format!("staging/{id}")).collect();
    let upload_ids: Vec<_> = rows
        .iter()
        .map(|(id, p, _, _)| if p.inline { None } else { Some(id.clone()) })
        .collect();
    let sizes: Vec<_> = rows.iter().map(|(_, _, _, size)| *size as i32).collect();
    if !rows.is_empty() {
        // Replaying sessions a job already owns starts no new upload.
        if let Some(limit) = capacity {
            crate::capacity::admit_upload(state, &mut tx, identity.org(), limit).await?;
        }
        sqlx::query!(
            r#"
        INSERT INTO upload_sessions (
            id, cache_id, store_path_hash, store_path, nar_hash, nar_size,
            file_size, compression, references_json, deriver, status,
            r2_upload_key, r2_upload_id, part_size, expires_at, staging_capacity, push_job_id
        )
        SELECT
            incoming.id,
            $1,
            incoming.store_path_hash,
            incoming.store_path,
            incoming.nar_hash,
            incoming.nar_size,
            0,
            'zstd',
            incoming.references_json,
            incoming.deriver,
            'streaming',
            incoming.r2_upload_key,
            incoming.r2_upload_id,
            incoming.part_size,
            NOW() + INTERVAL '1 hour',
            $2,
            $13
        FROM UNNEST(
            $3::text[], $4::text[], $5::text[], $6::text[], $7::bigint[],
            $8::text[], $9::text[], $10::text[], $11::text[], $12::integer[]
        ) AS incoming(
            id, store_path_hash, store_path, nar_hash, nar_size,
            references_json, deriver, r2_upload_key, r2_upload_id, part_size
        )
        "#,
            cache_id,
            capacity,
            &ids,
            &hashes,
            &paths,
            &nar_hashes,
            &nar_sizes,
            &references,
            &derivers as &[Option<String>],
            &keys,
            &upload_ids as &[Option<String>],
            &sizes,
            body.job_id.as_deref(),
        )
        .execute(&mut *tx)
        .await?;
    }
    if body.job_id.is_some() && !ids.is_empty() {
        sqlx::query(
            "WITH linked AS (UPDATE push_job_members m SET session_id=u.id FROM upload_sessions u \
            WHERE u.id=ANY($1) AND m.job_id=u.push_job_id AND m.store_path_hash=u.store_path_hash \
            RETURNING u.id,m.publication_order) \
            UPDATE upload_sessions u SET publication_order=m.publication_order FROM linked m WHERE u.id=m.id",
        )
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(respond(StatusCode::CREATED, &CreatedSessions { sessions }))
}

/// A part reservation in SQL widths.
#[derive(Clone)]
struct Reservation {
    part_number: i32,
    size: i64,
}
impl Reservation {
    fn read(value: Value) -> Result<Vec<Self>, ApiError> {
        serde_json::from_value::<Vec<PartRequest>>(value)
            .ok()
            .and_then(|parts| {
                parts
                    .into_iter()
                    .map(|p| {
                        Some(Self {
                            part_number: i32::try_from(p.part_number).ok()?,
                            size: i64::try_from(p.size).ok()?,
                        })
                    })
                    .collect()
            })
            .ok_or_else(|| error(400, "Invalid part reservations"))
    }
}
/// The single-session endpoint's body; its parts parse like a batch row's.
#[derive(Deserialize)]
struct Reservations {
    parts: Value,
}
#[derive(Clone)]
struct Part {
    part_number: i32,
    size: i64,
    etag: Option<String>,
    storage_key: Option<String>,
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn parts(tx: &mut Transaction, id: &str) -> Result<Vec<Part>, ApiError> {
    Ok(sqlx::query_as!(
        Part,
        r#"
        SELECT
            part_number,
            size,
            etag,
            storage_key
        FROM upload_parts
        WHERE session_id = $1
        ORDER BY part_number
        "#,
        id,
    )
    .fetch_all(&mut **tx)
    .await?)
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve_tx(
    tx: &mut Transaction,
    s: &Session,
    requested: &[Reservation],
) -> Result<(), ApiError> {
    reserve_group(tx, &[(s, requested)]).await?.remove(0)
}

/// The callers' session locks protect every accepted size update. The staging
/// total is a soft limit: concurrent reservations each read it before either
/// adds to it. Validation failures exclude only their own session; SQL
/// failures abort the group.
async fn reserve_group(
    tx: &mut Transaction,
    requests: &[(&Session, &[Reservation])],
) -> Result<Vec<Result<(), ApiError>>, ApiError> {
    let ids: Vec<_> = requests
        .iter()
        .flat_map(|(s, parts)| parts.iter().map(|_| s.id.clone()))
        .collect();
    let numbers: Vec<_> = requests
        .iter()
        .flat_map(|(_, parts)| parts.iter().map(|p| p.part_number))
        .collect();
    // The staging total, on every row, beside the parts already reserved.
    // The callers' session locks hold those parts still, so reading both in
    // one snapshot sees what reading them one after the other did.
    #[derive(sqlx::FromRow)]
    struct Reserved {
        staged: i64,
        session_id: Option<String>,
        part_number: Option<i32>,
        size: Option<i64>,
    }
    let previous: Vec<Reserved> = sqlx::query_as(
        "SELECT s.staged,p.session_id,p.part_number,p.size FROM \
         (SELECT COALESCE(SUM(u.file_size),0)::bigint AS staged FROM upload_sessions u \
         JOIN caches c ON c.id=u.cache_id WHERE c.org_id=$3 AND u.expires_at>NOW() \
         AND u.status IN ('streaming','finalizing')) s \
         LEFT JOIN (SELECT p.session_id,p.part_number,p.size FROM upload_parts p \
         JOIN UNNEST($1::text[],$2::integer[]) r(session_id,part_number) \
         USING(session_id,part_number)) p ON TRUE",
    )
    .bind(&ids)
    .bind(&numbers)
    .bind(&requests[0].0.org_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut staged = previous[0].staged;
    let previous: HashMap<_, _> = previous
        .into_iter()
        .filter_map(|p| Some(((p.session_id?, p.part_number?), p.size?)))
        .collect();
    let mut ids = Vec::new();
    let mut numbers = Vec::new();
    let mut sizes = Vec::new();
    let mut sessions = Vec::new();
    let mut additions = Vec::new();
    let mut results = Vec::with_capacity(requests.len());
    for (s, requested) in requests {
        let result = reservation_added(s, requested, &previous, staged);
        match result {
            Ok(added) => {
                staged += added;
                sessions.push(s.id.clone());
                additions.push(added);
                for part in *requested {
                    ids.push(s.id.clone());
                    numbers.push(part.part_number);
                    sizes.push(part.size);
                }
                results.push(Ok(()));
            }
            Err(error) => results.push(Err(error)),
        }
    }
    if !sessions.is_empty() {
        // Neither write reads what the other changes.
        sqlx::query(
            "WITH reserved AS (INSERT INTO upload_parts(session_id,part_number,size) \
             SELECT * FROM UNNEST($1::text[],$2::integer[],$3::bigint[]) \
             ON CONFLICT(session_id,part_number) DO NOTHING) \
             UPDATE upload_sessions u SET file_size=u.file_size+r.added \
             FROM UNNEST($4::text[],$5::bigint[]) r(id,added) WHERE u.id=r.id",
        )
        .bind(&ids)
        .bind(&numbers)
        .bind(&sizes)
        .bind(&sessions)
        .bind(&additions)
        .execute(&mut **tx)
        .await?;
    }
    Ok(results)
}

fn reservation_added(
    s: &Session,
    requested: &[Reservation],
    previous: &HashMap<(String, i32), i64>,
    staged: i64,
) -> Result<i64, ApiError> {
    if s.status != UploadStatus::Streaming {
        return Err(error(409, "Conflict"));
    }
    batch(requested)?;
    let mut seen = HashSet::new();
    if requested.iter().any(|p| {
        !(1..=limits::MAX_PARTS as i32).contains(&p.part_number)
            || p.size < 1
            || p.size > i64::from(s.part_size.unwrap_or(0))
            || !seen.insert(p.part_number)
    }) {
        return Err(error(400, "Invalid part reservations"));
    }
    let added = requested.iter().try_fold(0, |added, p| {
        match previous.get(&(s.id.clone(), p.part_number)) {
            Some(size) if *size != p.size => Err(error(409, "Part size cannot change")),
            Some(_) => Ok(added),
            None => Ok(added + p.size),
        }
    })?;
    if s.file_size + added > MAX_OBJECT {
        return Err(error(400, "NAR exceeds the multipart object limit"));
    }
    if s.staging_capacity.is_some_and(|n| s.file_size + added > n) {
        return Err(error(413, "Object exceeds cache capacity"));
    }
    let budget = s
        .staging_capacity
        .unwrap_or(256 * 1024 * MIB)
        .saturating_mul(2)
        .clamp(512 * MIB, MAX_OBJECT);
    if staged + added > budget {
        return Err(error(429, "Upload staging is busy; retry"));
    }
    Ok(added)
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve(
    state: &AppState,
    identity: &Identity,
    id: &str,
    value: Value,
) -> Result<PartGrants, ApiError> {
    reserve_batch(
        state,
        identity,
        vec![protocol::SessionParts {
            session_id: id.to_owned(),
            parts: value,
        }],
    )
    .await?
    .remove(0)
}

async fn reserve_batch(
    state: &AppState,
    identity: &Identity,
    uploads: Vec<protocol::SessionParts<Value>>,
) -> Result<Vec<Result<PartGrants, ApiError>>, ApiError> {
    let ids: Vec<_> = uploads.iter().map(|u| u.session_id.clone()).collect();
    let mut sessions: HashMap<_, _> = load_reservation_rows(&state.pool, &ids, identity)
        .await?
        .into_iter()
        .map(|s| (s.id.clone(), s))
        .collect();
    let mut pending: Vec<_> = uploads
        .into_iter()
        .map(|u| {
            let s = sessions
                .remove(&u.session_id)
                .ok_or_else(|| error(404, "Not found"))?;
            authorize_session(identity, &s.org_id, s.cache_id, &s.name, s.job_authorized)?;
            if s.r2_upload_id.is_none() {
                return Err(error(409, "Not a multipart upload"));
            }
            Ok((s, Reservation::read(u.parts)?))
        })
        .collect::<Vec<Result<_, ApiError>>>();
    let mut reserved: Vec<Option<Session>> = (0..pending.len()).map(|_| None).collect();
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (index, row) in pending.iter().enumerate() {
        if let Ok((s, _)) = row {
            match groups.iter_mut().find(|(org, _)| org == &s.org_id) {
                Some((_, indices)) => indices.push(index),
                None => groups.push((s.org_id.clone(), vec![index])),
            }
        }
    }
    // One transaction per organization: each reads that organization's
    // staging total once.
    for (_, indices) in groups {
        let requests: Vec<_> = indices
            .iter()
            .map(|i| {
                let (s, parts) = pending[*i].as_ref().unwrap();
                (s.id.clone(), parts.as_slice())
            })
            .collect();
        let outcomes = reserve_org(state, identity, &requests).await;
        match outcomes {
            Ok(outcomes) => {
                for (index, outcome) in indices.into_iter().zip(outcomes) {
                    match outcome {
                        Ok(session) => reserved[index] = Some(session),
                        Err(error) => pending[index] = Err(error),
                    }
                }
            }
            Err(error) => {
                for index in indices {
                    pending[index] = Err(ApiError {
                        status: error.status,
                        message: error.message.clone(),
                        headers: error.headers.clone(),
                    });
                }
            }
        }
    }
    // The sessions are distinct, and each adopts its provider upload in its
    // own transaction. Start first reservations' uploads a few at a time.
    let initialized = stream::iter(pending.into_iter().zip(reserved).map(
        |(row, session)| async move {
            let (_, parts) = row?;
            let session = session.ok_or_else(|| error(500, "Internal server error"))?;
            let session = initialize_multipart(state, identity, session).await?;
            grants(state, &session, &parts).await
        },
    ))
    .buffered(4);
    Ok(initialized.collect().await)
}

async fn reserve_org(
    state: &AppState,
    identity: &Identity,
    requests: &[(String, &[Reservation])],
) -> Result<Vec<Result<Session, ApiError>>, ApiError> {
    let mut tx = crate::db::begin(state).await?;
    let ids: Vec<_> = requests.iter().map(|(id, _)| id.clone()).collect();
    if !lock_sessions(&mut tx, &ids).await? {
        return Err(error(503, "Concurrent write; retry"));
    }
    let mut sessions: HashMap<_, _> = load_session_rows(&mut *tx, &ids, identity)
        .await?
        .into_iter()
        .map(|s| (s.id.clone(), s))
        .collect();
    let mut results: Vec<_> = requests
        .iter()
        .map(|(id, _)| {
            let s = sessions.remove(id).ok_or_else(|| error(404, "Not found"))?;
            authorize_session(identity, &s.org_id, s.cache_id, &s.name, s.job_authorized)?;
            Ok(s)
        })
        .collect::<Vec<Result<_, ApiError>>>();
    let accepted: Vec<_> = results
        .iter()
        .zip(requests)
        .filter_map(|(s, (_, parts))| s.as_ref().ok().map(|s| (s, *parts)))
        .collect();
    if !accepted.is_empty() {
        let reserved = reserve_group(&mut tx, &accepted).await?;
        let mut reserved = reserved.into_iter();
        for result in &mut results {
            if result.is_ok()
                && let Err(error) = reserved.next().unwrap()
            {
                *result = Err(error);
            }
        }
    }
    tx.commit().await?;
    Ok(results)
}

async fn grants(
    state: &AppState,
    s: &Session,
    requested: &[Reservation],
) -> Result<PartGrants, ApiError> {
    let key = s
        .r2_upload_key
        .as_deref()
        .ok_or_else(|| error(409, "Missing staging upload"))?;
    let mut parts = Vec::with_capacity(requested.len());
    for part in requested {
        parts.push(PartGrant {
            part_number: part.part_number.unsigned_abs(),
            url: state
                .storage
                .sign_part(
                    key,
                    s.r2_upload_id.as_deref().unwrap(),
                    part.part_number,
                    part.size,
                )
                .await
                .map_err(io_error)?,
            headers: std::collections::BTreeMap::from([(
                "content-length".to_owned(),
                part.size.to_string(),
            )]),
        });
    }
    Ok(PartGrants { parts })
}

/// Initialize outside SQL locks, then adopt exactly one provider upload. A
/// disconnected caller cannot abandon a provider upload between create and adopt.
async fn initialize_multipart(
    state: &AppState,
    identity: &Identity,
    s: Session,
) -> Result<Session, ApiError> {
    if s.r2_upload_id.as_deref() != Some(s.id.as_str()) {
        return Ok(s);
    }
    let owned = state.clone();
    let identity = identity.clone();
    state.tasks.spawn(async move {
        let key = format!("staging/{}/{}", s.id, uuid::Uuid::now_v7());
        let upload = owned.storage.create_multipart(&key).await.map_err(io_error)?;
        let mut commit_attempted = false;
        let adopted = async {
            let (mut tx, mut current) = locked(&owned, &s, &identity).await?;
            if current.status != UploadStatus::Streaming {
                return Err(error(409, "Conflict"));
            }
            if current.r2_upload_id.as_deref() == Some(s.id.as_str()) {
                // Adopt only into the session this transaction read: still
                // streaming and still without a provider upload. The row lock
                // already holds that; the predicate keeps it true by itself.
                let set = sqlx::query(
                    "UPDATE upload_sessions SET r2_upload_id=$2,r2_upload_key=$3 \
                     WHERE id=$1 AND status='streaming' AND r2_upload_id=$1",
                )
                .bind(&s.id).bind(&upload).bind(&key).execute(&mut *tx).await?
                .rows_affected();
                if set != 1 {
                    return Err(error(409, "Conflict"));
                }
                current.r2_upload_id = Some(upload.clone());
                current.r2_upload_key = Some(key.clone());
            }
            commit_attempted = true;
            tx.commit().await?;
            Ok(current)
        }.await;
        // Never abort an ambiguously committed upload. Session expiry cleans up
        // adopted uploads; the provider lifecycle reclaims unadopted uploads.
        if matches!(&adopted, Ok(current) if current.r2_upload_id.as_deref() != Some(upload.as_str()))
            || (adopted.is_err() && !commit_attempted)
        {
            sqlx::query("INSERT INTO object_cleanup(is_private,key,upload_id) VALUES(TRUE,$1,$2) ON CONFLICT DO NOTHING")
                .bind(&key).bind(&upload).execute(&owned.pool).await?;
        }
        adopted
    }).await.map_err(|_| error(500, "Multipart initialization failed"))?
}

trait ReceiptExt {
    fn validate(&self) -> Result<String, ApiError>;
}
impl ReceiptExt for Receipt {
    fn validate(&self) -> Result<String, ApiError> {
        if !bounded(signed(self.file_size))
            || !bounded(signed(self.nar_size))
            || !hash_valid(&self.file_hash)
            || self.parts.is_empty()
            || self.parts.len() > limits::MAX_PARTS as usize
        {
            return Err(error(400, "Invalid stream receipt"));
        }
        canonical_hash(&self.nar_hash)
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Finalization {
    #[serde(default)]
    prepare_only: bool,
}

impl Finalization {
    fn validate(&self, session: &Session) -> Result<(), ApiError> {
        if self.prepare_only && session.push_job_id.is_none() {
            return Err(error(409, "Preparation-only uploads require a push job"));
        }
        Ok(())
    }
}

fn shared_generation(state: &AppState) -> Option<String> {
    state.config.shared_auth_token.as_ref().map(|secret| {
        let mut hash = Sha256::new();
        hash.update(b"snowstead-finalization-delegation-v1\0");
        hash.update(secret.as_bytes());
        hex::encode(hash.finalize())
    })
}

/// Call inside the caller's write transaction. The share lock on the token row
/// orders revocation against it: a revocation in flight is waited for and then
/// seen, and a later one waits for this transaction. Never store the bearer
/// credential, and never trust middleware's old token snapshot.
async fn finalization_authority(
    state: &AppState,
    tx: &mut Transaction,
    identity: &Identity,
    session: &Session,
    delegated: bool,
) -> Result<(), ApiError> {
    use crate::authz::{ApiToken, CacheGrant, Permission};
    match identity {
        Identity::ApiToken(token) => {
            #[derive(sqlx::FromRow)]
            struct Grant {
                org: String,
                expires_at: Option<chrono::DateTime<chrono::Utc>>,
                permissions: Vec<String>,
                caches: Vec<i32>,
                patterns: Vec<String>,
            }
            let grant: Grant = sqlx::query_as(
                "SELECT COALESCE(t.org_id,'default') AS org,t.expires_at, \
                 ARRAY(SELECT permission FROM token_permissions WHERE token_jti=t.jti) AS permissions, \
                 ARRAY(SELECT cache_id FROM token_caches WHERE token_jti=t.jti AND cache_id IS NOT NULL) AS caches, \
                 ARRAY(SELECT pattern FROM token_caches WHERE token_jti=t.jti AND pattern IS NOT NULL) AS patterns \
                 FROM api_tokens t WHERE t.jti=$1 AND t.revoked_at IS NULL \
                 AND (t.expires_at IS NULL OR t.expires_at>NOW()) FOR SHARE OF t",
            ).bind(&token.id).fetch_optional(&mut **tx).await?
                .ok_or_else(|| error(401, "Token revoked or expired"))?;
            let current = Identity::ApiToken(ApiToken {
                id: token.id.clone(),
                org: grant.org,
                expires_at: grant.expires_at,
                permissions: grant
                    .permissions
                    .iter()
                    .filter_map(|p| Permission::parse(p))
                    .collect(),
                caches: grant
                    .caches
                    .into_iter()
                    .map(CacheGrant::Id)
                    .chain(grant.patterns.into_iter().map(CacheGrant::Pattern))
                    .collect(),
            });
            decide(
                &current,
                Action::NixPush,
                &Resource::cache(&session.org_id, session.cache_id, &session.name),
            )
            .map_err(|_| error(403, "Forbidden"))?;
        }
        Identity::SharedToken if shared_generation(state).is_some() => {}
        _ => return Err(error(403, "Forbidden")),
    }
    if delegated && session.status != UploadStatus::Completed {
        // The share lock on the batch holds what this reads until the caller
        // commits: a consumer's claim, a settlement, and a job resume all take
        // the batch exclusively, so each runs wholly before or after it.
        let active: Option<bool> = sqlx::query_scalar(
            "SELECT COALESCE(b.expires_at>clock_timestamp() AND b.actor=$2 AND \
             (b.job_id IS NULL OR b.grant_generation=(SELECT grant_generation FROM push_jobs WHERE id=b.job_id)) AND \
             (f.result IS NULL OR COALESCE((f.result->>'prepared')::boolean,false)) AND \
             ((b.token_jti=$2 AND b.shared_generation IS NULL) OR b.shared_generation=$3),false) \
             FROM upload_finalizations f JOIN upload_finalization_batches b ON b.id=f.batch_id \
             WHERE f.session_id=$1 FOR SHARE OF b",
        )
        .bind(&session.id)
        .bind(identity.actor())
        .bind(shared_generation(state))
        .fetch_optional(&mut **tx)
        .await?;
        if active == Some(false) {
            return Err(error(401, "Finalization authorization expired or replaced"));
        }
    }
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn seal(
    state: &AppState,
    identity: &Identity,
    session: &Session,
    receipt: &Receipt,
    bytes: Option<axum::body::Bytes>,
    admission: Option<(&str, usize, bool)>,
) -> Result<Prepared, ApiError> {
    let inline = bytes.is_some();
    let nar_hash = receipt.validate()?;
    let (mut tx, mut s) = locked(state, session, identity).await?;
    finalization_authority(state, &mut tx, identity, &s, admission.is_none()).await?;
    if let Some((batch, _, prepare_only)) = admission {
        let existing: Option<bool> = sqlx::query_scalar(
            "SELECT b.prepare_only FROM upload_finalizations f JOIN upload_finalization_batches b \
             ON b.id=f.batch_id WHERE f.session_id=$1",
        )
        .bind(&s.id)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.is_some_and(|saved| saved != prepare_only) {
            return Err(error(409, "Finalization intent cannot change"));
        }
        if existing.is_none() {
            // Never strand a late member in settled work. The share lock holds
            // admission open until this append commits: a consumer's claim
            // fails its NOWAIT and retries, and a close that got there first
            // is waited for and then seen.
            let open: Option<bool> = sqlx::query_scalar(
                "SELECT TRUE FROM upload_finalization_batches WHERE id=$1 AND NOT admitted FOR SHARE",
            )
            .bind(batch)
            .fetch_optional(&mut *tx)
            .await?;
            if open.is_none() {
                return Err(error(503, "Finalization admission closed; retry"));
            }
        }
    }
    if (s.r2_upload_id.is_none()) != inline {
        return Err(error(409, "Conflict"));
    }
    if !matches!(
        s.status,
        UploadStatus::Streaming | UploadStatus::Finalizing | UploadStatus::Completed
    ) {
        return Err(error(409, "Conflict"));
    }
    if inline
        && (s.nar_size > INLINE
            || signed(receipt.file_size) > INLINE
            || s.part_size != Some(INLINE as i32))
    {
        return Err(error(409, "Not an inline upload"));
    }
    if s.nar_hash != nar_hash || s.nar_size != signed(receipt.nar_size) {
        return Err(error(
            400,
            "Stream metadata or parts do not match reservations",
        ));
    }
    if inline && s.status == UploadStatus::Streaming {
        reserve_tx(
            &mut tx,
            &s,
            &[Reservation {
                part_number: 1,
                size: signed(receipt.file_size),
            }],
        )
        .await?;
        sqlx::query!(
            r#"
            UPDATE upload_parts
            SET etag = $2
            WHERE session_id = $1
                AND part_number = 1
            "#,
            &s.id,
            &receipt.file_hash,
        )
        .execute(&mut *tx)
        .await?;
        s.file_size = signed(receipt.file_size);
    }
    let mut stored = parts(&mut tx, &s.id).await?;
    let mut input = receipt.parts.clone();
    input.sort_by_key(|p| p.part_number);
    if s.file_size != signed(receipt.file_size)
        || stored.len() != input.len()
        || stored.is_empty()
        || stored.iter().enumerate().any(|(i, p)| {
            p.part_number != i as i32 + 1
                || i64::from(input[i].part_number) != i64::from(p.part_number)
                || input[i].etag.is_empty()
                || (i + 1 < stored.len() && p.size != i64::from(s.part_size.unwrap_or(0)))
        })
    {
        return Err(error(
            400,
            "Stream metadata or parts do not match reservations",
        ));
    }
    if s.status != UploadStatus::Streaming && s.file_hash.as_deref() != Some(&receipt.file_hash) {
        return Err(error(409, "Sealed stream cannot change"));
    }
    if !inline && s.status == UploadStatus::Streaming {
        if s.r2_upload_id.as_deref() == Some(s.id.as_str()) {
            return Err(error(400, "Upload incomplete"));
        }
        let numbers: Vec<_> = stored.iter().map(|p| p.part_number).collect();
        let etags: Vec<_> = input.iter().map(|p| p.etag.clone()).collect();
        sqlx::query("UPDATE upload_parts p SET etag=i.etag,storage_key=$4 FROM UNNEST($2::integer[],$3::text[]) AS i(number,etag) WHERE p.session_id=$1 AND p.part_number=i.number")
            .bind(&s.id).bind(&numbers).bind(&etags).bind(&s.r2_upload_key)
            .execute(&mut *tx).await?;
        for (part, receipt) in stored.iter_mut().zip(&input) {
            part.etag = Some(receipt.etag.clone());
            part.storage_key = s.r2_upload_key.clone();
        }
    }
    if stored.iter().zip(&input).any(|(p, i)| {
        p.etag.as_deref() != Some(i.etag.as_str()) || (!inline && p.storage_key.is_none())
    }) {
        return Err(error(
            if s.status == UploadStatus::Streaming {
                400
            } else {
                409
            },
            "Part receipts do not match uploaded bytes",
        ));
    }
    if s.status == UploadStatus::Streaming {
        // Deletion, cancellation, and expiry abort sessions in bulk. Sealing
        // must lose to them on its own, not resurrect an aborted session.
        let sealed = sqlx::query!(
            r#"
            UPDATE upload_sessions
            SET status = 'finalizing', file_hash = $2
            WHERE id = $1
                AND status = 'streaming'
            "#,
            &s.id,
            &receipt.file_hash,
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if sealed != 1 {
            return Err(error(409, "Conflict"));
        }
        s.file_hash = Some(receipt.file_hash.clone());
        s.status = UploadStatus::Finalizing;
    }
    if let Some((batch, ordinal, _)) = admission {
        sqlx::query(
            "INSERT INTO upload_finalizations(session_id,batch_id,ordinal,receipt) \
            VALUES($1,$2,$3,$4) ON CONFLICT(session_id) DO NOTHING",
        )
        .bind(&s.id)
        .bind(batch)
        .bind(ordinal as i32)
        .bind(sqlx::types::Json(receipt))
        .execute(&mut *tx)
        .await?;
        // An explicit retry may reconsider changed capacity. It cannot renew
        // a deadline, replace the actor, or change immutable verification.
        sqlx::query(
            "WITH retried AS (UPDATE upload_finalizations f SET result=NULL \
             FROM upload_finalization_batches b WHERE f.session_id=$1 AND b.id=f.batch_id \
             AND b.actor=$2 AND b.expires_at>clock_timestamp() \
             AND (f.result->>'status')::integer IN (413,507) RETURNING f.batch_id) \
             UPDATE upload_finalization_batches SET work_at=NOW(),failures=0 WHERE id IN (SELECT batch_id FROM retried)",
        ).bind(&s.id).bind(identity.actor()).execute(&mut *tx).await?;
    }
    let prepared = prepare_sealed(&mut tx, s, stored, bytes).await?;
    tx.commit().await?;
    Ok(prepared)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn verify(
    state: &AppState,
    s: &Session,
    file: impl Future<Output = Result<Box<dyn Read + Send>, ApiError>>,
    output: Option<(
        tokio::sync::mpsc::Sender<axum::body::Bytes>,
        tokio::sync::oneshot::Sender<()>,
    )>,
) -> Result<(), ApiError> {
    // Preparation already owns a bounded admission. Wait here rather than
    // rejecting admitted work when all native verifiers are occupied.
    let permit = crate::profile_future!(
        state.verification_slots.clone().acquire_owned(),
        label = "uploads.verification_slot_wait"
    )
    .await
    .map_err(|_| error(503, "Verification unavailable"))?;
    // Open the source only after admission. An R2 response has a running
    // body deadline even while another verifier keeps us queued.
    let mut file = file.await?;
    let expected_file = s
        .file_hash
        .clone()
        .ok_or_else(|| error(409, "Unsealed upload"))?;
    let expected_nar =
        signing::parse_nar_hash(&s.nar_hash).ok_or_else(|| error(400, "Invalid NAR hash"))?;
    let file_size = s.file_size as u64;
    let nar_size = s.nar_size as u64;
    #[cfg(feature = "observability")]
    let span = tracing::info_span!(target: "snowstead_observability", "uploads.verify");
    tokio::task::spawn_blocking(move || {
        #[cfg(feature = "observability")]
        let _entered = span.enter();
        // Blocking work survives request cancellation; keep its verification slot
        // until the native decompressor and its buffers have actually finished.
        let _permit = permit;
        let result = (|| {
            let mut verifier = native::Verifier::new_bounded(native::Compression::Zstd, nar_size)
                .map_err(|_| error(400, "Invalid NAR"))?;
            let mut buffer = [0; 64 * 1024];
            loop {
                let n = crate::profile_block!("uploads.verification_read", file.read(&mut buffer))
                    .map_err(io_error)?;
                if n == 0 {
                    break;
                }
                verifier
                    .update(&buffer[..n])
                    .map_err(|_| error(400, "Invalid NAR"))?;
                if let Some((output, _)) = &output {
                    crate::profile_block!(
                        "uploads.destination_backpressure",
                        output.blocking_send(axum::body::Bytes::copy_from_slice(&buffer[..n]))
                    )
                    .map_err(|_| error(500, "Destination upload failed"))?;
                }
            }
            let digest = verifier.finish().map_err(|_| error(400, "Invalid NAR"))?;
            if digest.file_size != file_size || hex::encode(digest.file_hash) != expected_file {
                return Err(error(400, "File hash or size mismatch"));
            }
            if digest.nar_size != nar_size || digest.nar_hash != expected_nar {
                return Err(error(400, "NAR hash or size mismatch"));
            }
            Ok(())
        })();
        if result.is_ok()
            && let Some((_, complete)) = output
        {
            // Closing the byte pipe is not proof of success: a panic also
            // closes it. Only this explicit verdict permits destination EOF.
            let _ = complete.send(());
        }
        result
    })
    .await
    .map_err(|_| error(500, "Verification failed"))?
}

fn cache_path(s: &Session) -> String {
    if s.slug == "default" {
        s.name.clone()
    } else {
        format!("{}/{}", s.slug, s.name)
    }
}
fn nar(s: &Session) -> Result<signing::Narinfo, ApiError> {
    Ok(signing::Narinfo {
        store_path: s.store_path.clone(),
        store_path_hash: s.store_path_hash.clone(),
        nar_hash: s.nar_hash.clone(),
        nar_size: s.nar_size,
        references: serde_json::from_str(&s.references_json)
            .map_err(|_| error(500, "Invalid stored references"))?,
        deriver: s.deriver.clone(),
        system: s.system.clone(),
        signatures: vec![],
        file_hash: s
            .file_hash
            .clone()
            .ok_or_else(|| error(409, "Unsealed upload"))?,
        file_size: s.file_size,
        compression: "zstd".into(),
    })
}

/// Own an immutable destination before I/O. This neither admits retained bytes
/// nor evicts anything: upload start refuses, and the evictor follows publication.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn allocate_candidate(
    state: &AppState,
    tx: Transaction,
    identity: &Identity,
    s: &Session,
) -> Result<(String, String), ApiError> {
    let (mut tx, current) = lock_session(tx, s, identity).await?;
    finalization_authority(state, &mut tx, identity, &current, true).await?;
    if current.status == UploadStatus::Completed {
        return Err(error(503, "Publication completed; retry for its result"));
    }
    if current.status != UploadStatus::Finalizing || current.file_hash != s.file_hash {
        return Err(error(409, "Conflict"));
    }
    if !current.is_public && !current.private_caches {
        return Err(error(403, PRIVATE_CACHES_REFUSED));
    }
    if current.is_public != s.is_public {
        return Err(error(503, "Cache policy changed; retry"));
    }
    let candidate = claim_candidate(&mut tx, &current).await?;
    tx.commit().await?;
    Ok(candidate)
}

/// The caller holds the session's advisory and row locks and has validated
/// the seal, so the session stays finalizing until this candidate commits.
async fn claim_candidate(tx: &mut Transaction, s: &Session) -> Result<(String, String), ApiError> {
    if !s.is_public && !s.private_caches {
        return Err(error(403, PRIVATE_CACHES_REFUSED));
    }
    let hash = s.file_hash.as_deref().unwrap();
    let operation = uuid::Uuid::now_v7().to_string();
    let key = if s.is_public {
        format!("nar/objects/{operation}/{hash}/zstd.nar")
    } else {
        format!("nars/objects/{operation}/{hash}/zstd.nar")
    };
    let claimed = sqlx::query(
        r#"
        INSERT INTO nar_installations (
            key, operation_id, file_hash, compression, is_private, file_size,
            cache_id, session_id, expires_at, lease_expires_at
        )
        SELECT $1, $2, $3, 'zstd', $4, $5, cache_id, id, expires_at,
            LEAST(expires_at, NOW() + INTERVAL '60 seconds')
        FROM upload_sessions WHERE id=$6
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(&key)
    .bind(&operation)
    .bind(hash)
    .bind(!s.is_public)
    .bind(s.file_size)
    .bind(&s.id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Err(error(503, "NAR installation busy; retry"));
    }
    Ok((key, operation))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn publish(
    state: &AppState,
    identity: &Identity,
    ready: &Prepared,
) -> Result<UploadResult, ApiError> {
    Ok(publish_group(state, identity, &[ready], None)
        .await?
        .remove(0))
}

/// Lock ordering is independent of request order, which decides path winners.
async fn lock_set(tx: &mut Transaction, keys: Vec<String>) -> Result<(), ApiError> {
    let acquired: Vec<bool> = sqlx::query_scalar(
        "SELECT pg_try_advisory_xact_lock(hashtextextended(key,0)) FROM \
         (SELECT DISTINCT UNNEST($1::text[]) AS key ORDER BY key OFFSET 0) ordered",
    )
    .bind(keys)
    .fetch_all(&mut **tx)
    .await?;
    if acquired.contains(&false) {
        return Err(error(503, "Concurrent write; retry"));
    }
    Ok(())
}

/// A bounded, single-org, SQL-only commit. On failure the caller can retry each
/// member independently; rollback leaves every confirmed candidate reusable.
async fn publish_group(
    state: &AppState,
    identity: &Identity,
    ready: &[&Prepared],
    claim: Option<&crate::push_job_worker::Claim>,
) -> Result<Vec<UploadResult>, ApiError> {
    let org = &ready[0].session.org_id;
    let mut tx = crate::db::begin(state).await?;
    let result = async {
    // Job rows come first, as for every job writer. A worker holds its job
    // exclusively from validation to release. A client publishing a job's
    // sessions itself shares the row: cancellation, completion, resume, and
    // withdrawal wait for this transaction, or it reads the state they left.
    if let Some(claim) = claim {
        crate::push_job_worker::validate(&mut tx, claim).await?;
    } else {
        let jobs: Vec<_> = ready
            .iter()
            .filter_map(|p| p.session.push_job_id.clone())
            .collect();
        if !jobs.is_empty() {
            sqlx::query("SELECT FROM push_jobs WHERE id=ANY($1) ORDER BY id FOR SHARE")
                .bind(&jobs)
                .execute(&mut *tx)
                .await?;
        }
    }
    lock_set(
        &mut tx,
        ready
            .iter()
            .map(|p| format!("upload:{}", p.session.id))
            .collect(),
    )
    .await?;
    // Cache rows precede the org row, as in the single-item writer. Keys and
    // policy stay locked until all pointers and outcomes commit together.
    // Key share is enough: whoever changes a cache's keys or visibility, or
    // deletes it, takes its row FOR UPDATE. A plain share lock would make
    // two publishers into one cache wait for each other's totals update.
    #[derive(sqlx::FromRow)]
    struct CacheKeys {
        id: i32,
        signing_key_name: Option<String>,
        signing_public_key: Option<String>,
        signing_key_sealed: Option<String>,
    }
    let cache_ids: Vec<_> = ready.iter().map(|p| p.session.cache_id).collect();
    let keys: Vec<CacheKeys> = sqlx::query_as(
        "SELECT id,signing_key_name,signing_public_key,signing_key_sealed \
         FROM caches WHERE id=ANY($1) ORDER BY id FOR KEY SHARE NOWAIT",
    )
    .bind(&cache_ids)
    .fetch_all(&mut *tx)
    .await?;
    // The limit is not read here: quota is the evictor's. The row lock still
    // holds the private-cache policy the reloaded sessions are checked against.
    sqlx::query("SELECT 1 FROM orgs WHERE id=$1 FOR SHARE NOWAIT")
        .bind(org)
        .fetch_one(&mut *tx)
        .await?;
    let ids: Vec<_> = ready.iter().map(|p| p.session.id.clone()).collect();
    let sessions: HashMap<_, _> = load_sessions(&mut *tx, &ids, identity)
        .await?
        .into_iter()
        .map(|s| (s.id.clone(), s))
        .collect();
    #[derive(Serialize)]
    struct Publication<'a> {
        ordinal: usize,
        #[serde(flatten)]
        session: &'a Session,
        key: &'a str,
        operation_id: &'a str,
    }
    let mut results = Vec::with_capacity(ready.len());
    let mut incoming = Vec::new();
    for p in ready {
        let s = &p.session;
        let current = sessions.get(&s.id).ok_or_else(|| error(404, "Not found"))?;
        if current.status == UploadStatus::Completed {
            results.push(completed_result(current));
            continue;
        }
        finalization_authority(state, &mut tx, identity, current, true).await?;
        // The authority check above share-locked this session's batch, so
        // its claim cannot be replaced between this read and the commit.
        if let Some(expected) = &p.finalization_claim {
            let owned: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM upload_finalizations f JOIN upload_finalization_batches b \
                 ON b.id=f.batch_id WHERE f.session_id=$1 AND b.work_id=$2 \
                 AND b.lease_expires_at>clock_timestamp() AND b.expires_at>clock_timestamp())",
            ).bind(&s.id).bind(expected).fetch_one(&mut *tx).await?;
            if !owned {
                return Err(error(409,"Finalization claim expired or replaced"));
            }
        }
        if current.status != UploadStatus::Finalizing || current.file_hash != s.file_hash {
            return Err(error(409, "Conflict"));
        }
        if current.is_public != s.is_public {
            return Err(error(503, "Cache policy changed; retry"));
        }
        if !current.is_public && !current.private_caches {
            return Err(error(403, PRIVATE_CACHES_REFUSED));
        }
        let keys = keys
            .iter()
            .find(|k| k.id == s.cache_id)
            .ok_or_else(|| error(404, "Not found"))?;
        let key = signing::select_key(
            &state.config,
            s.cache_id,
            keys.signing_key_name.as_deref(),
            keys.signing_public_key.as_deref(),
            keys.signing_key_sealed.as_deref(),
        )?;
        signing::render_with_key(
            &cache_path(current),
            !current.is_public,
            &nar(s)?,
            key.as_ref().map(|(name, key)| (name.as_str(), key)),
        )?;
        let ordinal = results.len();
        results.push(UploadResult::published(&s.id, &s.store_path_hash));
        incoming.push(Publication {
            ordinal,
            session: s,
            key: &p.key,
            operation_id: &p.operation,
        });
    }
    if incoming.is_empty() {
        if let Some(claim) = claim {
            crate::push_job_worker::complete(&mut tx, claim).await?;
        }
        return Ok(results);
    }
    // From here this transaction reads and writes published paths. Whoever
    // inserts or deletes a cache's paths first takes its row for the totals
    // the trigger updates, in ID order: publication, eviction, retention, and
    // withdrawal then never wait on each other's path rows, and the checks
    // below hold until commit. This does not conflict with the key share
    // locks above, so it waits only for another writer of the same cache.
    sqlx::query("SELECT FROM caches WHERE id=ANY($1) ORDER BY id FOR NO KEY UPDATE")
        .bind(&cache_ids)
        .execute(&mut *tx)
        .await?;
    // Then the sessions, in ID order. A bulk abort that got there first is
    // seen by the conditional completion below.
    lock_rows(
        &mut tx,
        &incoming
            .iter()
            .map(|p| p.session.id.clone())
            .collect::<Vec<_>>(),
    )
    .await?;
    if incoming.iter().any(|p| p.session.push_job_id.is_some()) {
        // Prerequisites must match the actual first path winner, not a losing
        // job session with different metadata. Fall back to ordered singletons
        // for conflicting identities before any publication mutates SQL.
        let mut winners = HashMap::new();
        for item in &incoming {
            let s = item.session;
            let first = *winners.entry((s.cache_id, &s.store_path_hash)).or_insert(s);
            if (first.push_job_id.is_some() || s.push_job_id.is_some())
                && (first.store_path != s.store_path
                    || first.nar_hash != s.nar_hash
                    || first.nar_size != s.nar_size
                    || first.references_json != s.references_json
                    || first.deriver != s.deriver)
            {
                return Err(error(409, "Conflicting batch manifest identities"));
            }
        }
        crate::push_jobs::publication(
            &mut tx,
            &incoming
                .iter()
                .map(|p| p.session.id.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
    }
    let input = sqlx::types::Json(&incoming);
    // Adopt a candidate only from the bucket the session's visibility names.
    // Discovery chose the key earlier, under a policy that may have changed.
    let owned = sqlx::query(
        "DELETE FROM nar_installations n USING jsonb_to_recordset($1) \
         AS i(key text, operation_id text, id text, is_public boolean) \
         WHERE n.key=i.key AND n.operation_id=i.operation_id AND n.session_id=i.id \
         AND n.phase='ready' AND n.expires_at>NOW() AND n.is_private=NOT i.is_public",
    )
    .bind(input)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if owned != incoming.len() as u64 {
        return Err(error(
            503,
            "Publication attempt expired or cancelled; retry",
        ));
    }
    let existing: Vec<(i32, String)> = sqlx::query_as(
        "SELECT p.cache_id,p.store_path_hash FROM published_paths p \
         JOIN jsonb_to_recordset($1) AS i(cache_id integer, store_path_hash text) \
         ON p.cache_id=i.cache_id AND p.store_path_hash=i.store_path_hash",
    )
    .bind(input)
    .fetch_all(&mut *tx)
    .await?;
    let mut seen: HashSet<_> = existing.into_iter().collect();
    for item in &incoming {
        let s = item.session;
        if !seen.insert((s.cache_id, s.store_path_hash.clone())) {
            results[item.ordinal].already_existed = true;
        }
    }
    // Deduplicate blobs separately from paths: multiple paths may share bytes,
    // and one batch may need both public and private pointers to those bytes.
    // The upsert locks each blob row it adopts, which is what excludes blob GC.
    sqlx::query(
        r#"
        WITH incoming AS (
            SELECT * FROM jsonb_to_recordset($1) AS i(
                ordinal integer, cache_id integer, store_path_hash text, store_path text,
                nar_hash text, nar_size bigint, file_hash text, file_size bigint,
                references_json text, deriver text, system text, is_public boolean, key text)
        ), candidates AS (
            SELECT file_hash, MAX(file_size) AS file_size,
                MIN(key) FILTER (WHERE is_public) AS public_key,
                MIN(key) FILTER (WHERE NOT is_public) AS private_key
            FROM incoming GROUP BY file_hash
        ), blobs AS (
            INSERT INTO blob_objects(file_hash,file_size,compression,r2_key,public_key,private_key)
            SELECT file_hash,file_size,'zstd',COALESCE(public_key,private_key),public_key,private_key
            FROM candidates ORDER BY file_hash
            ON CONFLICT (file_hash,compression) DO UPDATE SET
                public_key=COALESCE(blob_objects.public_key,EXCLUDED.public_key),
                private_key=COALESCE(blob_objects.private_key,EXCLUDED.private_key)
            RETURNING id,file_hash,public_key,private_key
        ), cleanup AS (
            INSERT INTO object_cleanup(is_private,key)
            SELECT NOT i.is_public,i.key FROM incoming i JOIN blobs b USING(file_hash)
            WHERE i.key IS DISTINCT FROM CASE WHEN i.is_public THEN b.public_key ELSE b.private_key END
            ON CONFLICT DO NOTHING
        ), winners AS (
            SELECT DISTINCT ON (cache_id,store_path_hash) * FROM incoming
            ORDER BY cache_id,store_path_hash,ordinal
        )
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,
            blob_object_id,references_json,deriver,system)
        SELECT i.cache_id,i.store_path_hash,i.store_path,i.nar_hash,i.nar_size,
            b.id,i.references_json,i.deriver,i.system FROM winners i JOIN blobs b USING(file_hash)
        ORDER BY i.cache_id,i.store_path_hash
        ON CONFLICT (cache_id,store_path_hash) DO UPDATE SET last_pushed_at=NOW()
        "#,
    ).bind(input).execute(&mut *tx).await?;
    // Completed replays need the immutable receipts, not their staging bytes.
    // Retire those exact keys with publication, never after a failed commit.
    // An abort or cancellation since the reload above must win: only sessions
    // still finalizing complete, and a partial group publishes nothing.
    let completed: i64 = sqlx::query_scalar(
        "WITH completed AS (UPDATE upload_sessions u SET status='completed',publication_result=i.result \
         FROM jsonb_to_recordset($1) AS i(session_id text,result jsonb) WHERE u.id=i.session_id \
         AND u.status='finalizing' RETURNING u.id,u.push_job_id), \
         staging_cleanup AS (INSERT INTO object_cleanup(is_private,key) \
         SELECT TRUE,p.storage_key FROM upload_parts p JOIN completed u ON u.id=p.session_id \
         WHERE starts_with(p.storage_key,'staging/'||u.id||'/') ON CONFLICT DO NOTHING), \
         unblocked AS (UPDATE push_job_members m SET blocked_generation=NULL,publication_error=NULL FROM completed u \
         WHERE m.job_id=u.push_job_id AND m.session_id=u.id AND m.blocked_generation IS NOT NULL) \
         SELECT count(*) FROM completed",
    )
    .bind(json!(
        incoming
            .iter()
            .map(|i| json!({"session_id":i.session.id,"result":results[i.ordinal]}))
            .collect::<Vec<_>>()
    ))
    .fetch_one(&mut *tx)
    .await?;
    if completed != incoming.len() as i64 {
        return Err(error(
            503,
            "Publication attempt expired or cancelled; retry",
        ));
    }
    if let Some(claim) = claim {
        crate::push_job_worker::complete(&mut tx, claim).await?;
    }
    Ok(results)
    }.await;
    match result {
        Ok(results) => {
            tx.commit().await?;
            // Publication never checks quota. Eviction follows the commit.
            state.evictions.request(org);
            Ok(results)
        }
        Err(error) => {
            // Drop only queues ROLLBACK. Wait for PostgreSQL to release the
            // locks before ordered fallback starts another transaction.
            tx.rollback().await?;
            Err(error)
        }
    }
}

struct Prepared {
    session: Session,
    source: PreparedSource,
    key: String,
    operation: String,
    finalization_claim: Option<String>,
}

/// Discover a bounded dependency-closed set of prepared members. This is only a
/// scheduling hint: publish_group reloads authorization, policy, sessions,
/// dependencies, and immutable ownership under its own row locks.
pub(crate) async fn publish_job(
    state: &AppState,
    claim: &mut crate::push_job_worker::Claim,
) -> Result<usize, ApiError> {
    let mut tx = db::begin_read(state).await?;
    // Use this complete frontier scan only when the indexed window cannot fill
    // a turn. Unprepared prerequisites must not hide other independent members.
    let frontier = r#"
        SELECT u.id,n.key,n.operation_id FROM push_job_members m
        JOIN push_jobs j ON j.id=m.job_id
        JOIN upload_sessions u ON u.id=m.session_id AND u.push_job_id=j.id
        JOIN nar_installations n ON n.session_id=u.id
        JOIN caches c ON c.id=j.cache_id
        WHERE j.id=$1 AND m.blocked_generation IS DISTINCT FROM j.grant_generation
            AND u.status='finalizing' AND u.expires_at>NOW()
            AND n.phase='ready' AND n.expires_at>NOW() AND n.is_private=NOT c.is_public
            AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(m.metadata->'references') r
                WHERE left(r.value,32)<>m.store_path_hash AND (
                    SELECT NOT EXISTS (
                        SELECT 1 FROM published_paths p WHERE p.cache_id=j.cache_id
                            AND p.store_path_hash=d.store_path_hash
                            AND d.metadata->>'storePath'=p.store_path AND d.metadata->>'narHash'=p.nar_hash
                            AND (d.metadata->>'narSize')::bigint=p.nar_size
                            AND (d.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver
                            AND p.references_json::jsonb @> (d.metadata->'references')
                            AND (d.metadata->'references') @> p.references_json::jsonb
                    ) FROM push_job_members d
                    WHERE d.job_id=$1 AND d.store_path_hash=left(r.value,32)
                        AND d.metadata->>'storePath'='/nix/store/'||r.value
                )
            )
            AND NOT EXISTS (
                SELECT 1 FROM published_paths p WHERE p.cache_id=j.cache_id
                    AND p.store_path_hash=m.store_path_hash AND NOT (
                        m.metadata->>'storePath'=p.store_path AND m.metadata->>'narHash'=p.nar_hash
                        AND (m.metadata->>'narSize')::bigint=p.nar_size
                        AND (m.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver
                        AND p.references_json::jsonb @> (m.metadata->'references')
                        AND (m.metadata->'references') @> p.references_json::jsonb
                    )
            )
        ORDER BY m.store_path_hash LIMIT $2
        "#;
    let mut candidates: Vec<(String, String, String)> = Vec::new();
    {
        // A timeout in the indexed selector must still allow the complete
        // frontier scan. A savepoint recovers the read transaction.
        let mut expansion = tx.begin().await?;
        let expanded = sqlx::query_as(
        r#"
        WITH RECURSIVE pending_sessions AS MATERIALIZED (
            SELECT id,push_job_id,store_path_hash FROM upload_sessions
            WHERE push_job_id=$1 AND status='finalizing' AND expires_at>NOW()
            ORDER BY publication_order,id LIMIT $2
        ), pending AS MATERIALIZED (
            SELECT u.id,n.key,n.operation_id,m.store_path_hash,m.metadata,j.cache_id
            FROM pending_sessions u
            JOIN push_job_members m ON m.job_id=u.push_job_id AND m.session_id=u.id
                AND m.store_path_hash=u.store_path_hash
            JOIN push_jobs j ON j.id=u.push_job_id
            JOIN nar_installations n ON n.session_id=u.id
            JOIN caches c ON c.id=j.cache_id
            WHERE m.blocked_generation IS DISTINCT FROM j.grant_generation
                AND n.phase='ready' AND n.expires_at>NOW() AND n.is_private=NOT c.is_public
        ), candidates AS MATERIALIZED (
        SELECT m.id,m.key,m.operation_id,m.store_path_hash,ARRAY(
                SELECT left(r.value,32) FROM jsonb_array_elements_text(m.metadata->'references') r
                WHERE left(r.value,32)<>m.store_path_hash AND (
                    SELECT NOT EXISTS (
                        SELECT 1 FROM published_paths p WHERE p.cache_id=m.cache_id
                            AND p.store_path_hash=d.store_path_hash
                            AND d.metadata->>'storePath'=p.store_path AND d.metadata->>'narHash'=p.nar_hash
                            AND (d.metadata->>'narSize')::bigint=p.nar_size
                            AND (d.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver
                            AND p.references_json::jsonb @> (d.metadata->'references')
                            AND (d.metadata->'references') @> p.references_json::jsonb
                    ) FROM push_job_members d
                    WHERE d.job_id=$1 AND d.store_path_hash=left(r.value,32)
                        AND d.metadata->>'storePath'='/nix/store/'||r.value
                )
            ) AS missing FROM pending m
        WHERE NOT EXISTS (
                SELECT 1 FROM published_paths p WHERE p.cache_id=m.cache_id
                    AND p.store_path_hash=m.store_path_hash AND NOT (
                        m.metadata->>'storePath'=p.store_path AND m.metadata->>'narHash'=p.nar_hash
                        AND (m.metadata->>'narSize')::bigint=p.nar_size
                        AND (m.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver
                        AND p.references_json::jsonb @> (m.metadata->'references')
                        AND (m.metadata->'references') @> p.references_json::jsonb
                    )
            )
        ), chosen(hashes) AS (
            SELECT ARRAY[]::text[]
            UNION ALL
            SELECT chosen.hashes||next.store_path_hash FROM chosen
            CROSS JOIN LATERAL (
                SELECT c.store_path_hash FROM candidates c
                WHERE NOT c.store_path_hash=ANY(chosen.hashes) AND c.missing <@ chosen.hashes
                ORDER BY c.store_path_hash LIMIT 1
            ) next WHERE cardinality(chosen.hashes)<$2
        ), batch AS (
            SELECT hashes FROM chosen ORDER BY cardinality(hashes) DESC LIMIT 1
        )
        SELECT c.id,c.key,c.operation_id FROM candidates c,batch
        WHERE c.store_path_hash=ANY(batch.hashes)
        "#,
    ).bind(&claim.job).bind(i64::from(claim.members)).fetch_all(&mut *expansion).await;
        match expanded {
            Ok(rows) => {
                expansion.commit().await?;
                candidates = rows;
            }
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("57014") => {
                expansion.rollback().await?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    if candidates.len() < claim.members as usize {
        let ready: Vec<(String, String, String)> = sqlx::query_as(frontier)
            .bind(&claim.job)
            .bind(i64::from(claim.members))
            .fetch_all(&mut *tx)
            .await?;
        for row in ready {
            if candidates.len() == claim.members as usize {
                break;
            }
            if !candidates.iter().any(|candidate| candidate.0 == row.0) {
                candidates.push(row);
            }
        }
    }
    tx.rollback().await?;
    if candidates.is_empty() {
        return Ok(0);
    }
    let ids: Vec<_> = candidates.iter().map(|(id, _, _)| id.clone()).collect();
    let sessions = load_sessions(&state.pool, &ids, &claim.identity).await?;
    let ready: Vec<_> = sessions
        .into_iter()
        .filter_map(|session| {
            // A member may have been replaced or completed after discovery.
            if session.status != UploadStatus::Finalizing
                || session.push_job_id.as_deref() != Some(&claim.job)
                || session.org_id != claim.org
            {
                return None;
            }
            let (_, key, operation) = candidates.iter().find(|(id, _, _)| *id == session.id)?;
            Some(Prepared {
                session,
                source: PreparedSource::Ready,
                key: key.clone(),
                operation: operation.clone(),
                finalization_claim: None,
            })
        })
        .collect();
    if ready.is_empty() {
        return Ok(0);
    }
    let count = ready.len();
    claim.members = count as i32;
    publish_group(
        state,
        &claim.identity,
        &ready.iter().collect::<Vec<_>>(),
        Some(claim),
    )
    .await?;
    Ok(count)
}

enum PreparedSource {
    Inline(axum::body::Bytes),
    Parts(Vec<Part>),
    Ready,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn prepare_sealed(
    tx: &mut Transaction,
    s: Session,
    parts: Vec<Part>,
    inline: Option<axum::body::Bytes>,
) -> Result<Prepared, ApiError> {
    let finalization_claim: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT b.work_id FROM upload_finalizations f JOIN upload_finalization_batches b \
         ON b.id=f.batch_id WHERE f.session_id=$1",
    )
    .bind(&s.id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    if s.status == UploadStatus::Completed {
        return Ok(Prepared {
            session: s,
            source: PreparedSource::Ready,
            key: String::new(),
            operation: String::new(),
            finalization_claim,
        });
    }
    // The seal authenticated this session and checked its immutable receipt.
    // Reuse only an unexpired, fully verified destination in the right bucket.
    let saved: Option<(String, String, bool)> = sqlx::query_as(
        "WITH retired AS (DELETE FROM nar_installations WHERE session_id=$1 \
         AND phase='preparing' AND lease_expires_at<=NOW() RETURNING key,is_private), \
         cleanup AS (INSERT INTO object_cleanup(is_private,key) \
         SELECT is_private,key FROM retired ON CONFLICT DO NOTHING) \
         SELECT key,operation_id,is_private FROM nar_installations \
         WHERE session_id=$1 AND phase='ready' AND expires_at>NOW()",
    )
    .bind(&s.id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((key, operation, private)) = saved {
        if private == s.is_public {
            return Err(error(409, "Cache policy changed; start a new upload"));
        }
        return Ok(Prepared {
            session: s,
            source: PreparedSource::Ready,
            key,
            operation,
            finalization_claim,
        });
    }
    Ok(Prepared {
        session: s,
        source: inline.map_or(PreparedSource::Parts(parts), PreparedSource::Inline),
        key: String::new(),
        operation: String::new(),
        finalization_claim,
    })
}

async fn confirm_candidate(state: &AppState, ready: &Prepared) -> Result<(), ApiError> {
    let changed = sqlx::query(
        "UPDATE nar_installations SET phase='ready',lease_expires_at=NULL \
         WHERE key=$1 AND operation_id=$2 AND phase='preparing' \
         AND lease_expires_at>NOW() AND expires_at>NOW() AND EXISTS (SELECT 1 FROM \
         upload_sessions WHERE id=$3 AND status='finalizing' AND expires_at>NOW())",
    )
    .bind(&ready.key)
    .bind(&ready.operation)
    .bind(&ready.session.id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(error(409, "Preparation expired or cancelled"));
    }
    Ok(())
}

/// Long preparations renew ownership, not retained quota. Short preparations
/// add no heartbeat queries. A replaced worker can neither renew nor confirm.
async fn with_preparation_lease(
    state: &AppState,
    ready: &Prepared,
    work: impl Future<Output = Result<(), ApiError>>,
) -> Result<(), ApiError> {
    let remaining: f64 = sqlx::query_scalar(
        "SELECT GREATEST(0,EXTRACT(EPOCH FROM LEAST(u.expires_at,b.expires_at)-clock_timestamp()))::double precision \
         FROM upload_sessions u LEFT JOIN upload_finalizations f ON f.session_id=u.id \
         LEFT JOIN upload_finalization_batches b ON b.id=f.batch_id WHERE u.id=$1",
    ).bind(&ready.session.id).fetch_optional(&state.pool).await?
        .ok_or_else(|| error(409,"Preparation expired or cancelled"))?;
    let deadline = tokio::time::sleep(Duration::from_secs_f64(remaining));
    tokio::pin!(deadline);
    let period = Duration::from_secs(20);
    let mut heartbeat = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(work);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(error(401,"Preparation deadline expired")),
            result = &mut work => {
                result?;
                return confirm_candidate(state, ready).await;
            }
            _ = heartbeat.tick() => {
                let changed = sqlx::query(
                    "UPDATE nar_installations SET lease_expires_at=LEAST(expires_at, \
                     NOW()+INTERVAL '60 seconds') WHERE key=$1 AND operation_id=$2 \
                     AND phase='preparing' AND lease_expires_at>NOW() AND expires_at>NOW()",
                )
                .bind(&ready.key)
                .bind(&ready.operation)
                .execute(&state.pool)
                .await?
                .rows_affected();
                if changed != 1 {
                    return Err(error(409, "Preparation expired or cancelled"));
                }
            }
        }
    }
}

async fn retire_candidate(state: &AppState, ready: &Prepared) {
    let retired = sqlx::query(
        "WITH retired AS (DELETE FROM nar_installations WHERE key=$1 AND operation_id=$2 \
         RETURNING key,is_private) INSERT INTO object_cleanup(is_private,key) \
         SELECT is_private,key FROM retired ON CONFLICT DO NOTHING",
    )
    .bind(&ready.key)
    .bind(&ready.operation)
    .execute(&state.pool)
    .await;
    if retired.is_err() {
        tracing::warn!("Preparation retirement deferred to maintenance");
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn prepare(
    state: &AppState,
    identity: &Identity,
    mut ready: Prepared,
) -> Result<Prepared, ApiError> {
    if !matches!(
        ready.source,
        PreparedSource::Parts(_) | PreparedSource::Inline(_)
    ) {
        return Ok(ready);
    }
    // The pipe holds at most two 64 KiB chunks in addition to the reader,
    // verifier, and destination's separately budgeted multipart buffer.
    let admission = match state.preparation_slots.clone().try_acquire_owned() {
        Ok(admission) => admission,
        Err(_) => {
            if !ready.key.is_empty() {
                retire_candidate(state, &ready).await;
            }
            return Err(error(503, "Preparation queue full; retry"));
        }
    };
    let owned = state.clone();
    let identity = identity.clone();
    state
        .tasks
        .spawn(async move {
            let _admission = admission;
            if matches!(ready.source, PreparedSource::Parts(_)) {
                // Queued batch members have no execution lease to expire.
                // Revalidate and own the destination only when work starts.
                let tx = crate::db::begin(&owned).await?;
                (ready.key, ready.operation) =
                    allocate_candidate(&owned, tx, &identity, &ready.session).await?;
            }
            let result = async {
                match &ready.source {
                    PreparedSource::Inline(bytes) => {
                        verify(
                            &owned,
                            &ready.session,
                            std::future::ready(Ok(Box::new(std::io::Cursor::new(bytes.clone()))
                                as Box<dyn Read + Send>)),
                            None,
                        )
                        .await
                    }
                    PreparedSource::Parts(parts) => {
                        with_preparation_lease(&owned, &ready, async {
                            let source = ready
                                .session
                                .r2_upload_key
                                .as_deref()
                                .ok_or_else(|| error(409, "Missing staging upload"))?;
                            owned
                                .storage
                                .complete_multipart(
                                    source,
                                    ready.session.r2_upload_id.as_deref().unwrap(),
                                    parts.iter().map(|p| p.etag.clone().unwrap()).collect(),
                                    ready.session.file_size as u64,
                                )
                                .await
                                .map_err(io_error)?;
                            let reader = async {
                                let reader = owned
                                    .storage
                                    .open(true, source)
                                    .await
                                    .map_err(io_error)?
                                    .reader;
                                Ok(Box::new(tokio_util::io::SyncIoBridge::new(reader))
                                    as Box<dyn Read + Send>)
                            };
                            let (send, receive) = tokio::sync::mpsc::channel(2);
                            let (complete, completed) = tokio::sync::oneshot::channel();
                            let bytes = stream::unfold(receive, |mut receive| async {
                                receive
                                    .recv()
                                    .await
                                    .map(|bytes| (Ok::<_, std::io::Error>(bytes), receive))
                            })
                            .chain(stream::once(async {
                                completed
                                    .await
                                    .map(|()| axum::body::Bytes::new())
                                    .map_err(|_| std::io::Error::other("Verification failed"))
                            }));
                            let (verified, written) = tokio::join!(
                                verify(&owned, &ready.session, reader, Some((send, complete))),
                                owned.storage.write_body(
                                    !ready.session.is_public,
                                    &ready.key,
                                    Body::from_stream(bytes),
                                    ready.session.file_size as u64
                                )
                            );
                            if let Err(written) = written {
                                // Preserve destination admission errors rather than
                                // reporting the verifier's resulting broken pipe.
                                return Err(match verified {
                                    Err(verified) if verified.status == StatusCode::BAD_REQUEST => {
                                        verified
                                    }
                                    _ => written,
                                });
                            }
                            verified?;
                            Ok(())
                        })
                        .await
                    }
                    _ => unreachable!("only fresh sources need preparation"),
                }
            }
            .await;
            if let Err(error) = result {
                if !ready.key.is_empty() {
                    retire_candidate(&owned, &ready).await;
                }
                return Err(error);
            }
            if matches!(ready.source, PreparedSource::Parts(_)) {
                ready.source = PreparedSource::Ready;
            }
            Ok(ready)
        })
        .await
        .map_err(|_| error(500, "Preparation failed"))?
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn publish_prepared(
    state: &AppState,
    identity: &Identity,
    ready: Prepared,
) -> Result<UploadResult, ApiError> {
    if ready.session.status == UploadStatus::Completed {
        return Ok(completed_result(&ready.session));
    }
    // Caller cancellation must not abandon a publication. Durable reservations
    // survive a crash; TaskTracker lets orderly shutdown finish active work.
    let owned = state.clone();
    let identity = identity.clone();
    state
        .tasks
        .spawn(crate::profile_future!(
            async move {
                let job = ready.session.push_job_id.is_some();
                let result = async {
                    let ready = finish_preparation(&owned, &identity, ready).await?;
                    publish(&owned, &identity, &ready).await
                }
                .await;
                if job && !matches!(&result, Ok(row) if row.published) {
                    // A job member this could not publish keeps any candidate
                    // it confirmed, which the job's worker then publishes.
                    owned.publications.wake();
                }
                result
            },
            label = "uploads.publication"
        ))
        .await
        .map_err(|_| error(500, "Publication failed"))?
}

/// Called only inside an owned finalization task. Inline verification has
/// finished; write and confirm its destination without holding a SQL fence.
async fn finish_preparation(
    state: &AppState,
    identity: &Identity,
    mut ready: Prepared,
) -> Result<Prepared, ApiError> {
    if !ready.key.is_empty() {
        return Ok(ready);
    }
    let tx = crate::db::begin(state).await?;
    (ready.key, ready.operation) = allocate_candidate(state, tx, identity, &ready.session).await?;
    let PreparedSource::Inline(bytes) = &ready.source else {
        unreachable!("ready candidate has ownership")
    };
    let result = with_preparation_lease(state, &ready, async {
        state
            .storage
            .write_body(
                !ready.session.is_public,
                &ready.key,
                Body::from(bytes.clone()),
                ready.session.file_size as u64,
            )
            .await?;
        Ok(())
    })
    .await;
    if let Err(error) = result {
        retire_candidate(state, &ready).await;
        return Err(error);
    }
    ready.source = PreparedSource::Ready;
    Ok(ready)
}

/// Reject an oversized incoming set before publishing any member. Only verified
/// sessions count, and duplicate store paths count once, as SQL insertion does.
/// An unlocked read: this is a sanity bound, not the quota. A limit changed
/// meanwhile is the evictor's to restore.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn preflight(state: &AppState, org: &str, ready: &[&Prepared]) -> Result<(), ApiError> {
    let mut tx = crate::profile_future!(
        crate::db::begin(state),
        label = "uploads.preflight_pool_begin"
    )
    .await?;
    let limit: Option<i64> = sqlx::query_scalar!(
        r#"
        SELECT storage_limit
        FROM orgs
        WHERE id = $1
        "#,
        org,
    )
    .fetch_one(&mut *tx)
    .await?;
    if let Some(limit) = limit {
        let cache_ids: Vec<_> = ready.iter().map(|p| p.session.cache_id).collect();
        let hashes: Vec<_> = ready
            .iter()
            .map(|p| p.session.store_path_hash.clone())
            .collect();
        struct ExistingPath {
            cache_id: i32,
            store_path_hash: String,
            file_size: i64,
        }
        let existing = sqlx::query_as!(
            ExistingPath,
            r#"
            SELECT
                p.cache_id,
                p.store_path_hash,
                b.file_size
            FROM UNNEST($1::integer[], $2::text[]) AS incoming(cache_id, hash)
            JOIN published_paths p ON p.cache_id = incoming.cache_id
                AND p.store_path_hash = incoming.hash
            JOIN blob_objects b ON b.id = p.blob_object_id
            "#,
            &cache_ids,
            &hashes,
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut seen = HashSet::new();
        let mut incoming = 0i64;
        for ready in ready {
            let s = &ready.session;
            if !seen.insert((s.cache_id, &s.store_path_hash)) {
                continue;
            }
            let size = existing
                .iter()
                .find(|path| {
                    path.cache_id == s.cache_id && path.store_path_hash == s.store_path_hash
                })
                .map(|path| path.file_size);
            incoming = incoming.saturating_add(size.unwrap_or(s.file_size));
        }
        if incoming > limit {
            return Err(error(413, "Incoming objects exceed retained capacity"));
        }
    }
    tx.commit().await?;
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn finalize_batch(
    state: &AppState,
    identity: &Identity,
    inputs: Vec<Receipt>,
    options: Finalization,
) -> Vec<Option<UploadResult>> {
    let mut results = vec![None; inputs.len()];
    let mut ready = Vec::with_capacity(inputs.len());
    let mut sealed = Vec::with_capacity(inputs.len());
    // Seal one at a time: each seal is a short transaction, and a batch
    // should not occupy several pool connections at once.
    for (index, input) in inputs.into_iter().enumerate() {
        let id = input.session_id.clone();
        let reserved = async {
            input.validate()?;
            let session = load(&state.pool, &id, identity).await?;
            options.validate(&session)?;
            seal(state, identity, &session, &input, None, None).await
        }
        .await;
        match reserved {
            Ok(prepared) => sealed.push((index, id, prepared)),
            Err(e) => results[index] = result_value(&id, Err(e)),
        }
    }
    let hand_over = options.prepare_only;
    let preparations = stream::iter(sealed.into_iter().map(|(index, id, prepared)| async move {
        let result = prepare(state, identity, prepared).await;
        if hand_over && result.is_ok() {
            // This member's candidate is confirmed and its job's worker
            // publishes it. Do not hold that back for the rest of the batch.
            state.publications.wake();
        }
        (index, id, result)
    }))
    .buffered(4);
    tokio::pin!(preparations);
    while let Some((index, id, result)) = preparations.next().await {
        match result {
            Ok(prepared) => ready.push((index, prepared)),
            Err(e) => results[index] = result_value(&id, Err(e)),
        }
    }
    publish_batch(state, identity, ready, results, options).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn publish_batch(
    state: &AppState,
    identity: &Identity,
    ready: Vec<(usize, Prepared)>,
    mut results: Vec<Option<UploadResult>>,
    options: Finalization,
) -> Vec<Option<UploadResult>> {
    let mut pending = Vec::with_capacity(ready.len());
    for (index, p) in ready {
        if p.session.status == UploadStatus::Completed {
            let id = p.session.id.clone();
            results[index] = result_value(&id, publish_prepared(state, identity, p).await);
        } else {
            pending.push((index, p));
        }
    }
    let ready = pending;
    let orgs: HashSet<_> = ready
        .iter()
        .map(|(_, p)| p.session.org_id.clone())
        .collect();
    for org in orgs.into_iter().filter(|_| !options.prepare_only) {
        let group: Vec<_> = ready
            .iter()
            .filter(|(_, p)| p.session.org_id == org)
            .map(|(_, p)| p)
            .collect();
        if let Err(e) = preflight(state, &org, &group).await {
            for (index, p) in &ready {
                if p.session.org_id == org {
                    results[*index] = result_value(
                        &p.session.id,
                        Err(ApiError::new(e.status, e.message.clone())),
                    );
                }
            }
        }
    }
    let owned = state.clone();
    let identity = identity.clone();
    // Own inline allocation through publication too, including later groups
    // when a caller disconnects. Storage never runs inside publish_group.
    let mut failed = results.clone();
    for (index, p) in &ready {
        if failed[*index].is_none() {
            failed[*index] = result_value(&p.session.id, Err(error(500, "Publication failed")));
        }
    }
    let publication = state
        .tasks
        .spawn(async move {
            let mut pending = Vec::new();
            let jobs: Vec<_> = ready
                .iter()
                .filter(|(_, p)| p.session.push_job_id.is_some())
                .map(|(index, _)| *index)
                .collect();
            for (index, p) in ready {
                if results[index].is_some() {
                    continue;
                }
                let id = p.session.id.clone();
                let unconfirmed = p.key.is_empty();
                match finish_preparation(&owned, &identity, p).await {
                    Ok(p) if options.prepare_only => {
                        if unconfirmed {
                            // Confirmed just now, for the job's worker.
                            owned.publications.wake();
                        }
                        results[index] = Some(prepared_value(&p));
                    }
                    Ok(p) => pending.push((index, p)),
                    Err(e) => results[index] = result_value(&id, Err(e)),
                }
            }
            let orgs: HashSet<_> = pending
                .iter()
                .map(|(_, p)| p.session.org_id.clone())
                .collect();
            for org in orgs {
                let group: Vec<_> = pending
                    .iter()
                    .filter(|(_, p)| p.session.org_id == org)
                    .collect();
                for chunk in group.chunks(16) {
                    let members: Vec<_> = chunk.iter().map(|(_, p)| p).collect();
                    match publish_group(&owned, &identity, &members, None).await {
                        Ok(outcomes) => {
                            for ((index, _), result) in chunk.iter().zip(outcomes) {
                                results[*index] = Some(result);
                            }
                        }
                        Err(_) => {
                            // A shared SQL failure rolls the entire group back.
                            // Preserve independent progress and first-success order
                            // using the same publication implementation, one at a time.
                            for (index, p) in chunk {
                                results[*index] = result_value(
                                    &p.session.id,
                                    publish(&owned, &identity, p).await,
                                );
                            }
                        }
                    }
                }
            }
            // A job member this request meant to publish and could not keeps
            // its confirmed candidate, which the job's worker then publishes.
            if !options.prepare_only
                && jobs
                    .iter()
                    .any(|index| !results[*index].as_ref().is_some_and(|row| row.published))
            {
                owned.publications.wake();
            }
            results
        })
        .await;
    match publication {
        Ok(results) => results,
        Err(_) => failed,
    }
}

fn prepared_value(ready: &Prepared) -> UploadResult {
    UploadResult::prepared(&ready.session.id, &ready.session.store_path_hash)
}

/// A completed session replays its stored result. Only this module writes
/// that column, always as an `UploadResult`.
fn completed_result(s: &Session) -> UploadResult {
    s.publication_result
        .clone()
        .and_then(|stored| serde_json::from_value(stored).ok())
        .unwrap_or_else(|| UploadResult::published(&s.id, &s.store_path_hash))
}

/// The filled result slot for one upload, under the session ID it was sent as.
fn result_value(id: &str, result: Result<UploadResult, ApiError>) -> Option<UploadResult> {
    Some(match result {
        Ok(mut row) => {
            row.session_id = id.to_owned();
            row
        }
        Err(e) => UploadResult::failed(id, e.status.as_u16(), &e.message),
    })
}

/// The response for a batch whose every slot is filled. An empty slot would
/// be a bug; it reports a failed publication rather than a malformed row.
fn upload_results(results: Vec<Option<UploadResult>>, ids: &[String]) -> UploadResults {
    UploadResults {
        results: results
            .into_iter()
            .zip(ids)
            .map(|(row, id)| {
                row.unwrap_or_else(|| UploadResult::failed(id, 500, "Publication failed"))
            })
            .collect(),
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn seal_inline(
    state: &AppState,
    identity: &Identity,
    input: &InlineEntry,
    bytes: axum::body::Bytes,
    options: &Finalization,
) -> Result<Prepared, ApiError> {
    let id = &input.session_id;
    let s = load(&state.pool, id, identity).await?;
    options.validate(&s)?;
    if s.r2_upload_id.is_some() || s.part_size != Some(INLINE as i32) || s.nar_size > INLINE {
        return Err(error(409, "Not an inline upload"));
    }
    let receipt = Receipt {
        session_id: id.clone(),
        nar_hash: s.nar_hash.clone(),
        nar_size: unsigned(s.nar_size),
        file_hash: input.file_hash.clone(),
        file_size: input.file_size,
        parts: vec![ReceiptPart {
            part_number: 1,
            etag: input.file_hash.clone(),
        }],
    };
    seal(state, identity, &s, &receipt, Some(bytes), None).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn inline_batch(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Query(options): Query<Finalization>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let state = &state;
    let identity = &identity;
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(error(415, "Expected application/octet-stream"));
    }
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| error(411, "Content-Length required"))?
        .to_str()
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n >= 5)
        .ok_or_else(|| error(400, "Invalid Content-Length"))?;
    if length > MAX_INLINE_FRAME {
        return Err(error(413, "Inline batch too large"));
    }
    let frame = to_bytes(request.into_body(), length)
        .await
        .map_err(|_| error(400, "Frame size mismatch"))?;
    if frame.len() != length {
        return Err(error(400, "Frame size mismatch"));
    }
    let manifest_size = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    if !(1..=MAX_INLINE_MANIFEST).contains(&manifest_size) || 4 + manifest_size >= length {
        return Err(error(400, "Invalid inline manifest length"));
    }
    let body: InlineManifest = serde_json::from_slice(&frame[4..4 + manifest_size])
        .map_err(|_| error(400, "Invalid inline manifest"))?;
    if body.uploads.is_empty()
        || body.uploads.len() > limits::INLINE_BATCH_MAX
        || body.uploads.iter().any(|u| {
            u.session_id.is_empty()
                || !hash_valid(&u.file_hash)
                || !(1..=limits::INLINE_MAX_BYTES).contains(&u.file_size)
        })
    {
        return Err(error(400, "Invalid inline manifest"));
    }
    distinct(body.uploads.iter().map(|u| u.session_id.as_str()))?;
    if 4 + manifest_size
        + body
            .uploads
            .iter()
            .map(|u| u.file_size as usize)
            .sum::<usize>()
        != length
    {
        return Err(error(400, "Frame size mismatch"));
    }
    // Validate the entire envelope and every checksum before any durable work.
    let mut offset = 4 + manifest_size;
    for input in &body.uploads {
        let bytes = &frame[offset..offset + input.file_size as usize];
        if hex::encode(Sha256::digest(bytes)) != input.file_hash {
            return Err(error(400, "File hash mismatch"));
        }
        offset += input.file_size as usize;
    }
    let ids: Vec<_> = body.uploads.iter().map(|u| u.session_id.clone()).collect();
    let mut results = vec![None; body.uploads.len()];
    let mut ready = Vec::with_capacity(body.uploads.len());
    let mut sealed = Vec::with_capacity(body.uploads.len());
    offset = 4 + manifest_size;
    // As with streamed batches, seal one at a time.
    for (index, input) in body.uploads.into_iter().enumerate() {
        let bytes = frame.slice(offset..offset + input.file_size as usize);
        offset += input.file_size as usize;
        match seal_inline(state, identity, &input, bytes, &options).await {
            Ok(prepared) => sealed.push((index, input.session_id, prepared)),
            Err(e) => results[index] = result_value(&input.session_id, Err(e)),
        }
    }
    let preparations = stream::iter(sealed.into_iter().map(|(index, id, prepared)| async move {
        (index, id, prepare(state, identity, prepared).await)
    }))
    .buffered(4);
    tokio::pin!(preparations);
    while let Some((index, id, result)) = preparations.next().await {
        match result {
            Ok(prepared) => ready.push((index, prepared)),
            Err(e) => results[index] = result_value(&id, Err(e)),
        }
    }
    let results = publish_batch(state, identity, ready, results, options).await;
    Ok(respond(StatusCode::OK, &upload_results(results, &ids)))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn inline(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
    Query(options): Query<Finalization>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let state = &state;
    let identity = &identity;
    let id = id.as_str();
    let s = load(&state.pool, id, identity).await?;
    if s.r2_upload_id.is_some() || s.part_size != Some(INLINE as i32) || s.nar_size > INLINE {
        return Err(error(409, "Not an inline upload"));
    }
    let hash = request
        .uri()
        .query()
        .unwrap_or("")
        .split('&')
        .find_map(|p| p.strip_prefix("fileHash="))
        .filter(|s| hash_valid(s))
        .ok_or_else(|| error(400, "Invalid file hash"))?
        .to_owned();
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| error(411, "Content-Length required"))?
        .to_str()
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| error(400, "Invalid Content-Length"))?;
    if length > INLINE {
        return Err(error(413, "Inline upload exceeds 1 MiB"));
    }
    let bytes = to_bytes(request.into_body(), length as usize)
        .await
        .map_err(|_| error(400, "File size mismatch"))?;
    if bytes.len() != length as usize {
        return Err(error(400, "File size mismatch"));
    }
    if hex::encode(Sha256::digest(&bytes)) != hash {
        return Err(error(400, "File hash mismatch"));
    }
    let input = InlineEntry {
        session_id: id.into(),
        file_hash: hash,
        file_size: unsigned(length),
    };
    let result = async {
        let ready = seal_inline(state, identity, &input, bytes, &options).await?;
        let ready = prepare(state, identity, ready).await?;
        if options.prepare_only && ready.session.status != UploadStatus::Completed {
            let owned = state.clone();
            let identity = identity.clone();
            return state
                .tasks
                .spawn(async move {
                    let ready = finish_preparation(&owned, &identity, ready).await?;
                    // Confirmed, for the job's worker to publish.
                    owned.publications.wake();
                    Ok(prepared_value(&ready))
                })
                .await
                .map_err(|_| error(500, "Preparation failed"))?;
        }
        publish_prepared(state, identity, ready).await
    }
    .await;
    Ok(respond(StatusCode::OK, &result_value(id, result)))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn abort(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    drop(request);
    let state = &state;
    let identity = &identity;
    let id = id.as_str();
    let s = load(&state.pool, id, identity).await?;
    let (mut tx, s) = locked(state, &s, identity).await?;
    // A sealed session is abortable too: after a failed verification or
    // publication it could otherwise only wait out its lease. Completed is
    // terminal. Publication holds this session's upload lock from before it
    // re-reads the status until it commits, so exactly one of the two commits.
    // A push job owns its members: cancelling the job is how they stop, so a
    // sealed member is not aborted from under its publication worker.
    let abortable = match s.status {
        UploadStatus::Streaming | UploadStatus::Aborted => true,
        UploadStatus::Finalizing => s.push_job_id.is_none(),
        _ => false,
    };
    if !abortable {
        return Err(error(409, "Conflict"));
    }
    sqlx::query!(
        r#"
        UPDATE upload_sessions
        SET status = 'aborted'
        WHERE id = $1
            AND status <> 'completed'
        "#,
        id,
    )
    .execute(&mut *tx)
    .await?;
    // Release an in-flight attempt's reservation as expiry does. Its key can
    // never be adopted now; a copy which lands late is found by the orphan sweep.
    sqlx::query(
        "WITH retired AS (DELETE FROM nar_installations WHERE session_id=$1 \
         RETURNING key,is_private) INSERT INTO object_cleanup(is_private,key) \
         SELECT is_private,key FROM retired ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let provider = s.r2_upload_id.as_deref().filter(|upload| *upload != s.id);
    if let (Some(key), Some(upload)) = (s.r2_upload_key.as_deref(), provider) {
        sqlx::query("INSERT INTO object_cleanup(is_private,key,upload_id) VALUES(TRUE,$1,$2) ON CONFLICT(is_private,key) DO UPDATE SET upload_id=EXCLUDED.upload_id")
            .bind(key).bind(upload).execute(&mut *tx).await?;
    }
    let old = parts(&mut tx, id).await?;
    tx.commit().await?;
    if let (Some(key), Some(upload)) = (s.r2_upload_key.as_deref(), provider) {
        state
            .storage
            .abort_multipart(true, key, upload)
            .await
            .map_err(io_error)?;
        state.storage.delete(true, key).await.map_err(io_error)?;
    }
    for key in old.into_iter().filter_map(|p| p.storage_key) {
        let _ = state.storage.delete(true, &key).await;
    }
    Ok(respond(StatusCode::OK, &Aborted { aborted: true }))
}

fn request_origin(state: &AppState, request: &Request) -> Result<String, ApiError> {
    // URI authority wins; HTTP/1 origin-form requests carry their origin in Host.
    // Do not use forwarded host headers to send credentials to another origin.
    if state.config.public_url.is_empty() {
        let host = request
            .uri()
            .authority()
            .map(|a| a.as_str())
            .or_else(|| {
                request
                    .headers()
                    .get(header::HOST)
                    .and_then(|v| v.to_str().ok())
            })
            .ok_or_else(|| error(400, "Host required"))?;
        let authority: axum::http::uri::Authority =
            host.parse().map_err(|_| error(400, "Invalid Host"))?;
        configured_origin(&format!(
            "{}://{}",
            request.uri().scheme_str().unwrap_or("http"),
            authority
        ))
        .map_err(|_| error(400, "Invalid Host"))
    } else {
        configured_origin(&state.config.public_url)
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve_parts_batch(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let body: ReservePartsBatch<Value> = json_body(request).await?;
    batch(&body.uploads)?;
    distinct(body.uploads.iter().map(|u| u.session_id.as_str()))?;
    let ids: Vec<_> = body.uploads.iter().map(|u| u.session_id.clone()).collect();
    let outcomes = match reserve_batch(&state, &identity, body.uploads).await {
        Ok(outcomes) => outcomes,
        Err(e) => ids
            .iter()
            .map(|_| Err(ApiError::new(e.status, e.message.clone())))
            .collect(),
    };
    let results = ids
        .into_iter()
        .zip(outcomes)
        .map(|(session_id, outcome)| match outcome {
            Ok(grants) => ReservationResult {
                session_id,
                parts: Some(grants.parts),
                status: None,
                error: None,
            },
            Err(e) => ReservationResult {
                session_id,
                parts: None,
                status: Some(e.status.as_u16()),
                error: Some(e.message),
            },
        })
        .collect();
    Ok(respond(StatusCode::OK, &ReservationResults { results }))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn finalize(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Query(options): Query<Finalization>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let body: FinalizeBatch = json_body(request).await?;
    batch(&body.uploads)?;
    distinct(body.uploads.iter().map(|u| u.session_id.as_str()))?;
    // Validate the envelope before doing any durable work.
    for u in &body.uploads {
        let mut numbers = HashSet::new();
        if !hash_valid(&u.file_hash)
            || !bounded(signed(u.file_size))
            || !bounded(signed(u.nar_size))
            || u.parts.is_empty()
            || u.parts.len() > limits::MAX_PARTS as usize
            || u.parts.iter().any(|p| {
                !(1..=limits::MAX_PARTS).contains(&p.part_number)
                    || p.etag.is_empty()
                    || !numbers.insert(p.part_number)
            })
            || canonical_hash(&u.nar_hash).is_err()
        {
            return Err(error(400, "Invalid stream receipt"));
        }
    }
    // Admission is SQL-only. The durable batch survives both disconnects and
    // process loss, including loss halfway through its individual seals.
    let owned = state.clone();
    let results = state
        .tasks
        .spawn(async move { enqueue_finalizations(&owned, &identity, body.uploads, options).await })
        .await
        .map_err(|_| error(500, "Finalization admission failed"))??;
    let status = if results.results.iter().any(|row| row.stage.is_some()) {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok(respond(status, &results))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve_parts(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let body: Reservations = json_body(request).await?;
    let result = reserve(&state, &identity, &id, body.parts).await?;
    Ok(respond(StatusCode::OK, &result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verification_waits_before_inspecting_input() {
        use object_store::memory::InMemory;
        use std::sync::Arc;
        let mut config = crate::config::Config::default();
        config.resources.verifications = 1;
        let state = AppState::new(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost/unused")
                .unwrap(),
            config,
            crate::storage::Storage::from_stores(
                Arc::new(InMemory::new()),
                Arc::new(InMemory::new()),
            ),
            reqwest::Client::new(),
        )
        .unwrap();
        let session = Session {
            id: String::new(),
            cache_id: 0,
            store_path_hash: String::new(),
            store_path: String::new(),
            nar_hash: String::new(),
            nar_size: 0,
            file_hash: None,
            file_size: 0,
            references_json: String::new(),
            deriver: None,
            system: None,
            status: UploadStatus::Streaming,
            r2_upload_id: None,
            r2_upload_key: None,
            part_size: None,
            staging_capacity: None,
            org_id: String::new(),
            name: String::new(),
            slug: String::new(),
            is_public: false,
            private_caches: false,
            publication_result: None,
            job_authorized: true,
            push_job_id: None,
        };
        let permit = state
            .verification_slots
            .clone()
            .try_acquire_owned()
            .unwrap();
        let opened = std::sync::atomic::AtomicBool::new(false);
        let mut pending = Box::pin(verify(
            &state,
            &session,
            async {
                opened.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(Box::new(std::io::Cursor::new(Vec::<u8>::new())) as Box<dyn Read + Send>)
            },
            None,
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut pending,)
                .await
                .is_err()
        );
        assert!(!opened.load(std::sync::atomic::Ordering::SeqCst));
        drop(permit);
        // Releasing a slot lets the same request inspect its unsealed receipt
        // without retrying admission.
        assert_eq!(pending.await.unwrap_err().status, StatusCode::CONFLICT);
        assert!(opened.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn multipart_bounds() {
        assert_eq!(part_size(1), 8 * MIB);
        assert_eq!(part_size(MAX_OBJECT), 527 * MIB);
        assert!(!basename("00000000000000000000000000000000-../x"));
        assert!(basename("00000000000000000000000000000000-hello-1.0"));
        assert!(!hash_valid(&"A".repeat(64)));
    }
    #[test]
    fn public_origin_is_an_origin_not_a_redirect() {
        assert_eq!(
            configured_origin("https://cache.example/").unwrap(),
            "https://cache.example"
        );
        for invalid in [
            "ftp://cache.example",
            "https://user:pass@cache.example",
            "https://cache.example/a",
            "https://cache.example/?q=1",
            "https://cache.example/#frag",
            "not a url",
        ] {
            assert!(configured_origin(invalid).is_err(), "{invalid}");
        }
    }
}
