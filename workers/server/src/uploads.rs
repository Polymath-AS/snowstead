//! PostgreSQL owns grants, immutable receipts, seals, and abort exclusion.
//! No connection is held during HTTP bodies, verification, or storage I/O.
use std::{
    collections::{HashMap, HashSet},
    io::Read,
};

use crate::db::Transaction;
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::Response,
    routing::{post, put},
};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::{
    AppState,
    auth::Identity,
    error::{ApiError, json_response},
    native, signing,
};

const MIB: i64 = 1024 * 1024;
const MAX_INLINE_MANIFEST: usize = 16 * 1024;
const MAX_INLINE_FRAME: usize = 4 + MAX_INLINE_MANIFEST + 8 * MIB as usize;
const MAX_OBJECT: i64 = 5 * 1024 * 1024 * 1024 * 1024;
const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const PRIVATE_CACHES_REFUSED: &str = "this org does not allow private caches: its private caches keep serving their paths, but take no pushes, and no new ones can be made";

pub(crate) fn router(state: AppState) -> Router<AppState> {
    // Method layers leave Axum's 405/Allow response outside authentication.
    let write = middleware::from_fn_with_state(state, crate::nix::write_access);
    Router::new()
        .route(
            "/_api/v1/caches/{cache}/upload-streams/batch",
            post(create).route_layer(write.clone()),
        )
        .route(
            "/_api/v1/uploads/parts",
            post(reserve_parts_batch).route_layer(write.clone()),
        )
        .route(
            "/_api/v1/uploads/finalize",
            post(finalize).route_layer(write.clone()),
        )
        .route(
            "/_api/v1/uploads/{id}/parts",
            post(reserve_parts).route_layer(write.clone()),
        )
        .route(
            "/_api/v1/uploads/{id}/part/{number}",
            put(put_part).route_layer(write.clone()),
        )
        .route(
            "/_api/v1/uploads/inline/batch",
            post(inline_batch).route_layer(write.clone()),
        )
        .route(
            "/_api/v1/uploads/{id}/inline",
            post(inline).route_layer(write.clone()),
        )
        .route(
            "/_api/v1/uploads/{id}/abort",
            post(abort).route_layer(write),
        )
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
fn basename(s: &str) -> bool {
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
    ((bound + 10_000 * MIB - 1) / (10_000 * MIB) * MIB).clamp(8 * MIB, 1024 * MIB)
}
fn bounded(size: i64) -> bool {
    (1..=MAX_OBJECT).contains(&size)
}
fn batch<T>(items: &[T]) -> Result<(), ApiError> {
    if items.is_empty() || items.len() > 100 {
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

#[derive(Clone)]
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
    status: String,
    r2_upload_id: Option<String>,
    part_size: Option<i32>,
    staging_capacity: Option<i64>,
    org_id: String,
    name: String,
    slug: String,
    is_public: bool,
    private_caches: bool,
    publication_result: Option<Value>,
}
fn authorize(s: &Session, identity: &Identity) -> Result<(), ApiError> {
    match identity {
        Identity::Jwt(c)
            if !c.belongs_to(&s.org_id) || !c.has_cache_access(s.cache_id, &s.name) =>
        {
            Err(error(403, "Forbidden"))
        }
        Identity::OrgKey { org, .. } if org != &s.org_id => Err(error(403, "Forbidden")),
        _ => Ok(()),
    }
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn load(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    identity: &Identity,
) -> Result<Session, ApiError> {
    let s = sqlx::query_as!(
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
            u.status,
            u.r2_upload_id,
            u.part_size,
            u.staging_capacity,
            c.org_id,
            c.name,
            c.is_public,
            o.slug,
            o.private_caches,
            u.publication_result
        FROM upload_sessions u
        JOIN caches c ON c.id = u.cache_id
        JOIN orgs o ON o.id = c.org_id
        WHERE u.id = $1
            AND u.expires_at > NOW()
            AND EXISTS (
                SELECT 1
                FROM cache_protocols p
                WHERE p.cache_id = c.id
                    AND p.protocol = 'nix'
            )
        "#,
        id,
    )
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| error(404, "Not found"))?;
    authorize(&s, identity)?;
    Ok(s)
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn lock(tx: &mut Transaction, key: &str) -> Result<(), ApiError> {
    crate::profile_future!(
        crate::db::advisory_lock(tx, key),
        label = "uploads.advisory_lock_wait"
    )
    .await?;
    Ok(())
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn locked(
    state: &AppState,
    s: &Session,
    identity: &Identity,
) -> Result<(Transaction, Session), ApiError> {
    let mut tx = crate::profile_future!(
        crate::db::begin(state, &s.org_id),
        label = "uploads.session_pool_begin"
    )
    .await?;
    lock(&mut tx, &format!("org:{}", s.org_id)).await?;
    lock(&mut tx, &format!("upload:{}", s.id)).await?;
    // Re-read and reauthorize after the fences, using the same query as preflight.
    let current = load(&mut *tx, &s.id, identity).await?;
    Ok((tx, current))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PathInput {
    store_path: String,
    store_path_hash: String,
    nar_hash: String,
    nar_size: i64,
    compression: String,
    references: Option<Vec<String>>,
    deriver: Option<String>,
    #[serde(default)]
    inline: bool,
}
#[derive(Deserialize)]
struct Create {
    paths: Vec<PathInput>,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn create(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(cache): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let body: Create = json_body(request).await?;
    let state = &state;
    let identity = &identity;
    let cache = cache.as_str();
    batch(&body.paths)?;
    let mut tx = crate::profile_future!(
        crate::db::begin(state, identity.org()),
        label = "uploads.create_pool_begin"
    )
    .await?;
    lock(&mut tx, &format!("org:{}", identity.org())).await?;
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
        FOR SHARE OF c, o NOWAIT
        "#,
        identity.org(),
        cache,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| error(404, "Cache not found"))?;
    if let Identity::Jwt(c) = identity
        && !c.has_cache_access(cache_id, cache)
    {
        return Err(error(403, "Forbidden"));
    }
    if !is_public && !allowed {
        return Err(error(403, PRIVATE_CACHES_REFUSED));
    }
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
    if active + body.paths.len() as i64 > 8192 {
        return Err(error(
            429,
            "Too many active upload sessions; finish or abort existing uploads",
        ));
    }
    let mut sessions = Vec::with_capacity(body.paths.len());
    let mut rows = Vec::with_capacity(body.paths.len());
    for p in body.paths {
        if !store_hash(&p.store_path_hash)
            || !p
                .store_path
                .starts_with(&format!("/nix/store/{}-", p.store_path_hash))
            || !basename(p.store_path.strip_prefix("/nix/store/").unwrap_or(""))
            || !bounded(p.nar_size)
            || p.compression != "zstd"
            || (p.inline && p.nar_size > MIB)
            || p.references
                .as_ref()
                .is_some_and(|r| r.iter().any(|s| !basename(s)))
            || p.deriver
                .as_ref()
                .is_some_and(|s| s.is_empty() || !s.bytes().all(|b| (33..=126).contains(&b)))
        {
            return Err(error(400, "Invalid stream metadata"));
        }
        let hash = canonical_hash(&p.nar_hash)?;
        let id = format!("s2.{}.{}", identity.org(), uuid::Uuid::now_v7());
        let size = if p.inline { MIB } else { part_size(p.nar_size) };
        sessions.push(json!({"sessionId":id,"partSize":size,"inline":p.inline}));
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
    let nar_sizes: Vec<_> = rows.iter().map(|(_, p, _, _)| p.nar_size).collect();
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
    sqlx::query!(
        r#"
        INSERT INTO upload_sessions (
            id, cache_id, store_path_hash, store_path, nar_hash, nar_size,
            file_size, compression, references_json, deriver, status,
            r2_upload_key, r2_upload_id, part_size, expires_at, staging_capacity
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
            $2
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
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(json_response(
        StatusCode::CREATED,
        json!({"sessions":sessions}),
    ))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Reservation {
    part_number: i32,
    size: i64,
}
#[derive(Deserialize)]
struct Reservations {
    parts: Vec<Reservation>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReserveInput {
    session_id: String,
    parts: Value,
}
#[derive(Deserialize)]
struct ReserveBatch {
    uploads: Vec<ReserveInput>,
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
    if s.status != "streaming" {
        return Err(error(409, "Conflict"));
    }
    batch(requested)?;
    let mut seen = HashSet::new();
    if requested.iter().any(|p| {
        !(1..=10_000).contains(&p.part_number)
            || p.size < 1
            || p.size > i64::from(s.part_size.unwrap_or(0))
            || !seen.insert(p.part_number)
    }) {
        return Err(error(400, "Invalid part reservations"));
    }
    let previous = parts(tx, &s.id).await?;
    let previous: HashMap<_, _> = previous.iter().map(|p| (p.part_number, p.size)).collect();
    let added = requested
        .iter()
        .try_fold(0, |added, p| match previous.get(&p.part_number) {
            Some(size) if *size != p.size => Err(error(409, "Part size cannot change")),
            Some(_) => Ok(added),
            None => Ok(added + p.size),
        })?;
    if s.file_size + added > MAX_OBJECT {
        return Err(error(400, "NAR exceeds the multipart object limit"));
    }
    if s.staging_capacity.is_some_and(|n| s.file_size + added > n) {
        return Err(error(413, "Object exceeds cache capacity"));
    }
    let staged = sqlx::query_scalar!(
        r#"
        SELECT COALESCE(SUM(u.file_size), 0)::bigint AS "staged!"
        FROM upload_sessions u
        JOIN caches c ON c.id = u.cache_id
        WHERE c.org_id = $1
            AND u.expires_at > NOW()
            AND u.status IN ('streaming', 'finalizing')
        "#,
        &s.org_id,
    )
    .fetch_one(&mut **tx)
    .await?;
    let budget = s
        .staging_capacity
        .unwrap_or(256 * 1024 * MIB)
        .saturating_mul(2)
        .clamp(512 * MIB, MAX_OBJECT);
    if staged + added > budget {
        return Err(error(429, "Upload staging is busy; retry"));
    }
    let numbers: Vec<_> = requested.iter().map(|p| p.part_number).collect();
    let sizes: Vec<_> = requested.iter().map(|p| p.size).collect();
    sqlx::query!(
        r#"
        INSERT INTO upload_parts (session_id, part_number, size)
        SELECT
            $1,
            p.number,
            p.size
        FROM UNNEST($2::integer[], $3::bigint[]) AS p(number, size)
        ON CONFLICT (session_id, part_number) DO NOTHING
        "#,
        &s.id,
        &numbers,
        &sizes,
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query!(
        r#"
        UPDATE upload_sessions
        SET file_size = file_size + $2
        WHERE id = $1
        "#,
        &s.id,
        added,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve(
    state: &AppState,
    identity: &Identity,
    id: &str,
    value: Value,
    origin: &str,
    authorization: &Option<String>,
) -> Result<Value, ApiError> {
    let s = load(&state.pool, id, identity).await?;
    if s.r2_upload_id.is_none() {
        return Err(error(409, "Not a multipart upload"));
    }
    let requested: Vec<Reservation> =
        serde_json::from_value(value).map_err(|_| error(400, "Invalid part reservations"))?;
    let (mut tx, s) = locked(state, &s, identity).await?;
    reserve_tx(&mut tx, &s, &requested).await?;
    tx.commit().await?;
    Ok(json!({"parts":requested.iter().map(|p| {
        let mut headers = json!({"content-length":p.size.to_string()});
        if let Some(auth) = authorization { headers["authorization"] = json!(auth); }
        json!({"partNumber":p.part_number,"url":format!("{origin}/_api/v1/uploads/{id}/part/{}",p.part_number),"headers":headers})
    }).collect::<Vec<_>>()}))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn put_part(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((id, number)): Path<(String, String)>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let number: i32 = number
        .parse()
        .map_err(|_| error(400, "Invalid part number"))?;
    let state = &state;
    let identity = &identity;
    let id = id.as_str();
    let s = load(&state.pool, id, identity).await?;
    if s.status != "streaming" || s.r2_upload_id.is_none() {
        return Err(error(409, "Conflict"));
    }
    let grant = sqlx::query_scalar!(
        r#"
        SELECT size
        FROM upload_parts
        WHERE session_id = $1
            AND part_number = $2
        "#,
        id,
        number,
    )
    .fetch_optional(&state.pool)
    .await?;
    let size = grant.ok_or_else(|| error(400, "Part must match its reserved content-length"))?;
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        != Some(size.to_string().as_str())
    {
        return Err(error(400, "Part must match its reserved content-length"));
    }
    // The unique key belongs only to this transfer until its receipt commits.
    let key = format!("staging/{id}/{}", uuid::Uuid::now_v7());
    let etag = state
        .storage
        .write_body(true, &key, request.into_body(), size as u64)
        .await?;
    let mut commit_attempted = false;
    let admitted = async {
        let (mut tx, s) = locked(state, &s, identity).await?;
        if s.status != "streaming" {
            return Err(error(409, "Conflict"));
        }
        let old = parts(&mut tx, id)
            .await?
            .into_iter()
            .find(|p| p.part_number == number)
            .ok_or_else(|| error(409, "Conflict"))?;
        if let Some(previous) = old.etag {
            if previous != etag {
                return Err(error(409, "Uploaded part cannot change"));
            }
            return Ok(false);
        }
        sqlx::query!(
            r#"
            UPDATE upload_parts
            SET etag = $3,
                storage_key = $4
            WHERE session_id = $1
                AND part_number = $2
            "#,
            id,
            number,
            &etag,
            &key,
        )
        .execute(&mut *tx)
        .await?;
        commit_attempted = true;
        tx.commit().await?;
        Ok(true)
    }
    .await;
    // A failed COMMIT acknowledgement is ambiguous: never delete a source
    // which PostgreSQL may have durably admitted. Orphan cleanup is separate.
    if matches!(admitted, Ok(false)) || (admitted.is_err() && !commit_attempted) {
        let _ = state.storage.delete(true, &key).await;
    }
    admitted?;
    let mut response = json_response(StatusCode::OK, json!({"partNumber":number,"etag":etag}));
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{etag}\""))
            .map_err(|_| error(500, "Invalid storage receipt"))?,
    );
    Ok(response)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptPart {
    part_number: i32,
    #[serde(deserialize_with = "unquote_etag")]
    etag: String,
}
fn unquote_etag<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    Ok(value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(&value)
        .to_owned())
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Receipt {
    session_id: String,
    nar_hash: String,
    nar_size: i64,
    file_hash: String,
    file_size: i64,
    parts: Vec<ReceiptPart>,
}
#[derive(Deserialize)]
struct Finalize {
    uploads: Vec<Receipt>,
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn seal(
    state: &AppState,
    identity: &Identity,
    receipt: &Receipt,
    inline: bool,
) -> Result<(Session, Vec<Part>), ApiError> {
    if !bounded(receipt.file_size)
        || !bounded(receipt.nar_size)
        || !hash_valid(&receipt.file_hash)
        || receipt.parts.is_empty()
        || receipt.parts.len() > 10_000
    {
        return Err(error(400, "Invalid stream receipt"));
    }
    let nar_hash = canonical_hash(&receipt.nar_hash)?;
    let s = load(&state.pool, &receipt.session_id, identity).await?;
    let (mut tx, mut s) = locked(state, &s, identity).await?;
    if (s.r2_upload_id.is_none()) != inline {
        return Err(error(409, "Conflict"));
    }
    if !matches!(s.status.as_str(), "streaming" | "finalizing" | "completed") {
        return Err(error(409, "Conflict"));
    }
    if inline && (s.nar_size > MIB || receipt.file_size > MIB || s.part_size != Some(MIB as i32)) {
        return Err(error(409, "Not an inline upload"));
    }
    if s.nar_hash != nar_hash || s.nar_size != receipt.nar_size {
        return Err(error(
            400,
            "Stream metadata or parts do not match reservations",
        ));
    }
    if inline && s.status == "streaming" {
        reserve_tx(
            &mut tx,
            &s,
            &[Reservation {
                part_number: 1,
                size: receipt.file_size,
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
        s.file_size = receipt.file_size;
    }
    let stored = parts(&mut tx, &s.id).await?;
    let mut input = receipt.parts.clone();
    input.sort_by_key(|p| p.part_number);
    if s.file_size != receipt.file_size
        || stored.len() != input.len()
        || stored.is_empty()
        || stored.iter().enumerate().any(|(i, p)| {
            p.part_number != i as i32 + 1
                || input[i].part_number != p.part_number
                || input[i].etag.is_empty()
                || (i + 1 < stored.len() && p.size != i64::from(s.part_size.unwrap_or(0)))
        })
    {
        return Err(error(
            400,
            "Stream metadata or parts do not match reservations",
        ));
    }
    if s.status != "streaming" && s.file_hash.as_deref() != Some(&receipt.file_hash) {
        return Err(error(409, "Sealed stream cannot change"));
    }
    if stored.iter().zip(&input).any(|(p, i)| {
        p.etag.as_deref() != Some(i.etag.as_str()) || (!inline && p.storage_key.is_none())
    }) {
        return Err(error(
            if s.status == "streaming" { 400 } else { 409 },
            "Part receipts do not match uploaded bytes",
        ));
    }
    sqlx::query!(
        r#"
        UPDATE upload_sessions
        SET status = CASE WHEN status = 'streaming' THEN 'finalizing' ELSE status END,
            file_hash = $2
        WHERE id = $1
        "#,
        &s.id,
        &receipt.file_hash,
    )
    .execute(&mut *tx)
    .await?;
    s.file_hash = Some(receipt.file_hash.clone());
    if s.status == "streaming" {
        s.status = "finalizing".into();
    }
    tx.commit().await?;
    Ok((s, stored))
}

/// Read sealed parts in order, without materializing an assembled object.
fn part_reader(
    state: &AppState,
    parts: &[Part],
) -> Result<Box<dyn tokio::io::AsyncRead + Unpin + Send>, ApiError> {
    let keys: Vec<String> = parts
        .iter()
        .map(|p| {
            p.storage_key
                .clone()
                .ok_or_else(|| error(400, "Upload incomplete"))
        })
        .collect::<Result<_, _>>()?;
    let storage = state.storage.clone();
    let stream = futures_util::stream::try_unfold(
        (
            storage,
            keys.into_iter(),
            None::<crate::storage::StoredObject>,
        ),
        |(storage, mut keys, mut file)| async move {
            loop {
                if file.is_none() {
                    let Some(key) = keys.next() else {
                        return Ok::<_, std::io::Error>(None);
                    };
                    file = Some(storage.open(true, &key).await?);
                }
                let mut buffer = vec![0; 64 * 1024];
                let n = file.as_mut().unwrap().reader.read(&mut buffer).await?;
                if n == 0 {
                    file = None;
                    continue;
                }
                buffer.truncate(n);
                return Ok(Some((
                    axum::body::Bytes::from(buffer),
                    (storage, keys, file),
                )));
            }
        },
    );
    Ok(Box::new(tokio_util::io::StreamReader::new(Box::pin(
        stream,
    ))))
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn verify(
    state: &AppState,
    s: &Session,
    mut file: Box<dyn Read + Send>,
    output: Option<(
        tokio::sync::mpsc::Sender<axum::body::Bytes>,
        tokio::sync::oneshot::Sender<()>,
    )>,
) -> Result<(), ApiError> {
    // Preparation already owns a bounded admission. Wait here rather than
    // rejecting admitted work when all native verifiers are occupied.
    let permit = state
        .verification_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| error(503, "Verification unavailable"))?;
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
                    output
                        .blocking_send(axum::body::Bytes::copy_from_slice(&buffer[..n]))
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

/// Own an immutable destination before I/O. This does not admit retained bytes
/// or evict anything: both decisions belong to the publication transaction.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn allocate_candidate(
    state: &AppState,
    identity: &Identity,
    s: &Session,
) -> Result<(String, String), ApiError> {
    let (mut tx, current) = locked(state, s, identity).await?;
    if current.status == "completed" {
        return Err(error(503, "Publication completed; retry for its result"));
    }
    if current.status != "finalizing" || current.file_hash != s.file_hash {
        return Err(error(409, "Conflict"));
    }
    if !current.is_public && !current.private_caches {
        return Err(error(403, PRIVATE_CACHES_REFUSED));
    }
    if current.is_public != s.is_public {
        return Err(error(503, "Cache policy changed; retry"));
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
            cache_id, session_id, expires_at
        )
        SELECT $1, $2, $3, 'zstd', $4, $5, cache_id, id, expires_at
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
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Err(error(503, "NAR installation busy; retry"));
    }
    tx.commit().await?;
    Ok((key, operation))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn publish(
    state: &AppState,
    identity: &Identity,
    ready: &Prepared,
    protect: &[(i32, String)],
) -> Result<Value, ApiError> {
    let s = &ready.session;
    let key = &ready.key;
    let operation = &ready.operation;
    let (mut tx, current) = locked(state, s, identity).await?;
    if current.status != "finalizing" || current.file_hash != s.file_hash {
        return Err(error(409, "Conflict"));
    }
    if !current.is_public && !current.private_caches {
        return Err(error(403, PRIVATE_CACHES_REFUSED));
    }
    // Hold policy rows only for this SQL-only commit. A rotation or policy
    // change must either precede this comparison or follow publication.
    sqlx::query("SELECT id FROM caches WHERE id=$1 FOR SHARE NOWAIT")
        .bind(s.cache_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM orgs WHERE id=$1 FOR SHARE NOWAIT")
        .bind(&s.org_id)
        .fetch_one(&mut *tx)
        .await?;
    let current = load(&mut *tx, &s.id, identity).await?;
    if current.is_public != s.is_public {
        return Err(error(503, "Cache policy changed; retry"));
    }
    if !current.is_public && !current.private_caches {
        return Err(error(403, PRIVATE_CACHES_REFUSED));
    }
    let owned = sqlx::query(
        "DELETE FROM nar_installations WHERE key=$1 AND operation_id=$2 \
             AND phase='ready' \
             AND expires_at>NOW() RETURNING key",
    )
    .bind(key)
    .bind(operation)
    .fetch_optional(&mut *tx)
    .await?;
    if owned.is_none() {
        return Err(error(
            503,
            "Publication attempt expired or cancelled; retry",
        ));
    }
    let hash = s.file_hash.as_deref().unwrap();
    lock(&mut tx, &format!("nar:{hash}:zstd")).await?;
    let existing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM published_paths WHERE cache_id=$1 AND store_path_hash=$2)",
    )
    .bind(s.cache_id)
    .bind(&s.store_path_hash)
    .fetch_one(&mut *tx)
    .await?;
    // Validate signing before adoption, but never write mutable metadata.
    signing::render(
        &mut *tx,
        &state.config,
        s.cache_id,
        &cache_path(&current),
        !current.is_public,
        &nar(s)?,
    )
    .await?;
    let capacity: Option<i64> = sqlx::query_scalar("SELECT storage_limit FROM orgs WHERE id=$1")
        .bind(&s.org_id)
        .fetch_one(&mut *tx)
        .await?;
    if let Some(limit) = capacity {
        crate::capacity::admit(
            &mut tx,
            &s.org_id,
            limit,
            if existing { 0 } else { s.file_size },
            protect,
        )
        .await?;
    }
    let (blob_id, adopted): (i64, Option<String>) = sqlx::query_as(
            r#"
            INSERT INTO blob_objects(file_hash, file_size, compression, r2_key, public_key, private_key)
            VALUES ($1, $2, 'zstd', $3, CASE WHEN $4 THEN $3 END, CASE WHEN NOT $4 THEN $3 END)
            ON CONFLICT (file_hash, compression) DO UPDATE SET
                public_key = CASE WHEN $4 THEN COALESCE(blob_objects.public_key, $3) ELSE blob_objects.public_key END,
                private_key = CASE WHEN NOT $4 THEN COALESCE(blob_objects.private_key, $3) ELSE blob_objects.private_key END
            RETURNING id, CASE WHEN $4 THEN public_key ELSE private_key END
            "#
        )
        .bind(hash).bind(s.file_size).bind(key).bind(s.is_public)
        .fetch_one(&mut *tx)
        .await?;
    if adopted.as_deref() != Some(key) {
        sqlx::query(
            "INSERT INTO object_cleanup(is_private,key) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(!s.is_public)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!(
        r#"
            INSERT INTO published_paths (
                cache_id, store_path_hash, store_path, nar_hash, nar_size,
                blob_object_id, references_json, deriver, system
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (cache_id, store_path_hash)
            DO UPDATE SET last_pushed_at = NOW()
            "#,
        s.cache_id,
        &s.store_path_hash,
        &s.store_path,
        &s.nar_hash,
        s.nar_size,
        blob_id,
        &s.references_json,
        s.deriver.as_deref(),
        s.system.as_deref(),
    )
    .execute(&mut *tx)
    .await?;
    let mut result = json!({"sessionId":s.id,"storePathHash":s.store_path_hash,"published":true});
    if existing {
        result["alreadyExisted"] = json!(true);
    }
    sqlx::query("UPDATE upload_sessions SET status='completed', publication_result=$2 WHERE id=$1")
        .bind(&s.id)
        .bind(&result)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(result)
}

struct Prepared {
    session: Session,
    source: PreparedSource,
    key: String,
    operation: String,
}

enum PreparedSource {
    Inline(axum::body::Bytes),
    Parts(Vec<Part>),
    Ready,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn prepare_sealed(
    state: &AppState,
    identity: &Identity,
    s: Session,
    parts: Vec<Part>,
    inline: Option<axum::body::Bytes>,
) -> Result<Prepared, ApiError> {
    if s.status == "completed" {
        return Ok(Prepared {
            session: s,
            source: PreparedSource::Ready,
            key: String::new(),
            operation: String::new(),
        });
    }
    // The seal authenticated this session and checked its immutable receipt.
    // Reuse only an unexpired, fully verified destination in the right bucket.
    let saved: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT key,operation_id,is_private FROM nar_installations \
         WHERE session_id=$1 AND phase='ready' AND expires_at>NOW()",
    )
    .bind(&s.id)
    .fetch_optional(&state.pool)
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
        });
    }
    let mut prepared = Prepared {
        session: s,
        source: inline.map_or(PreparedSource::Parts(parts), PreparedSource::Inline),
        key: String::new(),
        operation: String::new(),
    };
    if matches!(prepared.source, PreparedSource::Parts(_)) {
        // Batch callers perform these SQL decisions sequentially, then stream
        // preparation concurrently without retaining a connection.
        (prepared.key, prepared.operation) =
            allocate_candidate(state, identity, &prepared.session).await?;
    }
    Ok(prepared)
}

async fn confirm_candidate(state: &AppState, ready: &Prepared) -> Result<(), ApiError> {
    let changed = sqlx::query(
        "UPDATE nar_installations SET phase='ready' WHERE key=$1 AND operation_id=$2 \
         AND phase='preparing' AND expires_at>NOW() AND EXISTS (SELECT 1 FROM \
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
async fn prepare(state: &AppState, mut ready: Prepared) -> Result<Prepared, ApiError> {
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
    state
        .tasks
        .spawn(async move {
            let _admission = admission;
            let result = async {
                match &ready.source {
                    PreparedSource::Inline(bytes) => {
                        verify(
                            &owned,
                            &ready.session,
                            Box::new(std::io::Cursor::new(bytes.clone())),
                            None,
                        )
                        .await
                    }
                    PreparedSource::Parts(parts) => {
                        let reader = part_reader(&owned, parts)?;
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
                            verify(
                                &owned,
                                &ready.session,
                                Box::new(tokio_util::io::SyncIoBridge::new(reader)),
                                Some((send, complete))
                            ),
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
                        confirm_candidate(&owned, &ready).await
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
    mut ready: Prepared,
    protect: Vec<(i32, String)>,
) -> Result<Value, ApiError> {
    if ready.session.status == "completed" {
        return Ok(ready.session.publication_result.unwrap_or_else(||
            json!({"sessionId":ready.session.id,"storePathHash":ready.session.store_path_hash,"published":true})));
    }
    // Caller cancellation must not abandon a publication. Durable reservations
    // survive a crash; TaskTracker lets orderly shutdown finish active work.
    let owned = state.clone();
    let identity = identity.clone();
    state
        .tasks
        .spawn(crate::profile_future!(
            async move {
                let mut durable = !ready.key.is_empty();
                let result = async {
                    if !durable {
                        (ready.key, ready.operation) =
                            allocate_candidate(&owned, &identity, &ready.session).await?;
                        match &ready.source {
                            PreparedSource::Inline(bytes) => {
                                owned
                                    .storage
                                    .write_body(
                                        !ready.session.is_public,
                                        &ready.key,
                                        Body::from(bytes.clone()),
                                        ready.session.file_size as u64,
                                    )
                                    .await?;
                            }
                            PreparedSource::Ready | PreparedSource::Parts(_) => {
                                unreachable!("ready candidate has ownership")
                            }
                        }
                        confirm_candidate(&owned, &ready).await?;
                        durable = true;
                    }
                    publish(&owned, &identity, &ready, &protect).await
                }
                .await;
                if result.is_err() && !durable && !ready.key.is_empty() {
                    // Unconfirmed provider writes cannot be adopted. Verified,
                    // confirmed candidates survive SQL errors and lost replies.
                    retire_candidate(&owned, &ready).await;
                }
                result
            },
            label = "uploads.publication"
        ))
        .await
        .map_err(|_| error(500, "Publication failed"))?
}

/// Reject an oversized incoming set before publishing any member. Only verified
/// sessions count, and duplicate store paths count once, as SQL insertion does.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn preflight(state: &AppState, org: &str, ready: &[&Prepared]) -> Result<(), ApiError> {
    let mut tx = crate::profile_future!(
        crate::db::begin(state, org),
        label = "uploads.preflight_pool_begin"
    )
    .await?;
    lock(&mut tx, &format!("org:{org}")).await?;
    let limit: Option<i64> = sqlx::query_scalar!(
        r#"
        SELECT storage_limit
        FROM orgs
        WHERE id = $1
        FOR SHARE NOWAIT
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
async fn finalize_batch(state: &AppState, identity: &Identity, inputs: Vec<Receipt>) -> Vec<Value> {
    let mut results = vec![Value::Null; inputs.len()];
    let mut ready = Vec::with_capacity(inputs.len());
    let mut sealed = Vec::with_capacity(inputs.len());
    // Serialize SQL decisions within this request, not storage I/O. Otherwise
    // this batch could reject its own items on the fail-fast org fence.
    for (index, input) in inputs.into_iter().enumerate() {
        let id = input.session_id.clone();
        let reserved = async {
            let (session, parts) = seal(state, identity, &input, false).await?;
            prepare_sealed(state, identity, session, parts, None).await
        }
        .await;
        match reserved {
            Ok(prepared) => sealed.push((index, id, prepared)),
            Err(e) => results[index] = result_value(&id, Err(e), true),
        }
    }
    let preparations =
        stream::iter(sealed.into_iter().map(|(index, id, prepared)| async move {
            (index, id, prepare(state, prepared).await)
        }))
        .buffered(4);
    tokio::pin!(preparations);
    while let Some((index, id, result)) = preparations.next().await {
        match result {
            Ok(prepared) => ready.push((index, prepared)),
            Err(e) => results[index] = result_value(&id, Err(e), true),
        }
    }
    publish_batch(state, identity, ready, results).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn publish_batch(
    state: &AppState,
    identity: &Identity,
    ready: Vec<(usize, Prepared)>,
    mut results: Vec<Value>,
) -> Vec<Value> {
    let mut pending = Vec::with_capacity(ready.len());
    for (index, p) in ready {
        if p.session.status == "completed" {
            let id = p.session.id.clone();
            results[index] = result_value(
                &id,
                publish_prepared(state, identity, p, vec![]).await,
                true,
            );
        } else {
            pending.push((index, p));
        }
    }
    let ready = pending;
    let orgs: HashSet<_> = ready
        .iter()
        .map(|(_, p)| p.session.org_id.clone())
        .collect();
    for org in orgs {
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
                        true,
                    );
                }
            }
        }
    }
    let protect: Vec<_> = ready
        .iter()
        .map(|(_, p)| (p.session.cache_id, p.session.store_path_hash.clone()))
        .collect();
    for (index, p) in ready {
        if !results[index].is_null() {
            continue;
        }
        let id = p.session.id.clone();
        results[index] = result_value(
            &id,
            publish_prepared(state, identity, p, protect.clone()).await,
            true,
        );
    }
    results
}

fn result_value(id: &str, result: Result<Value, ApiError>, finalize: bool) -> Value {
    match result {
        Ok(mut v) => {
            v["sessionId"] = json!(id);
            v
        }
        Err(e) => {
            let mut v = json!({"sessionId":id,"error":e.message,"status":e.status.as_u16()});
            if finalize {
                v["published"] = json!(false);
            }
            v
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InlineInput {
    session_id: String,
    file_hash: String,
    file_size: usize,
}

#[derive(Deserialize)]
struct InlineBatch {
    uploads: Vec<InlineInput>,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn seal_inline(
    state: &AppState,
    identity: &Identity,
    input: &InlineInput,
) -> Result<(Session, Vec<Part>), ApiError> {
    let id = &input.session_id;
    let s = load(&state.pool, id, identity).await?;
    if s.r2_upload_id.is_some() || s.part_size != Some(MIB as i32) || s.nar_size > MIB {
        return Err(error(409, "Not an inline upload"));
    }
    let receipt = Receipt {
        session_id: id.clone(),
        nar_hash: s.nar_hash,
        nar_size: s.nar_size,
        file_hash: input.file_hash.clone(),
        file_size: input.file_size as i64,
        parts: vec![ReceiptPart {
            part_number: 1,
            etag: input.file_hash.clone(),
        }],
    };
    seal(state, identity, &receipt, true).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn inline_batch(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
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
    let body: InlineBatch = serde_json::from_slice(&frame[4..4 + manifest_size])
        .map_err(|_| error(400, "Invalid inline manifest"))?;
    if body.uploads.is_empty()
        || body.uploads.len() > 8
        || body.uploads.iter().any(|u| {
            u.session_id.is_empty()
                || !hash_valid(&u.file_hash)
                || !(1..=MIB as usize).contains(&u.file_size)
        })
    {
        return Err(error(400, "Invalid inline manifest"));
    }
    distinct(body.uploads.iter().map(|u| u.session_id.as_str()))?;
    if 4 + manifest_size + body.uploads.iter().map(|u| u.file_size).sum::<usize>() != length {
        return Err(error(400, "Frame size mismatch"));
    }
    // Validate the entire envelope and every checksum before any durable work.
    let mut offset = 4 + manifest_size;
    for input in &body.uploads {
        let bytes = &frame[offset..offset + input.file_size];
        if hex::encode(Sha256::digest(bytes)) != input.file_hash {
            return Err(error(400, "File hash mismatch"));
        }
        offset += input.file_size;
    }
    let mut results = vec![Value::Null; body.uploads.len()];
    let mut ready = Vec::with_capacity(body.uploads.len());
    let mut sealed = Vec::with_capacity(body.uploads.len());
    offset = 4 + manifest_size;
    // As with streamed batches, do not race this request's own SQL admissions.
    for (index, input) in body.uploads.into_iter().enumerate() {
        let bytes = frame.slice(offset..offset + input.file_size);
        offset += input.file_size;
        match seal_inline(state, identity, &input).await {
            Ok((session, parts)) => sealed.push((index, input.session_id, session, parts, bytes)),
            Err(e) => results[index] = result_value(&input.session_id, Err(e), true),
        }
    }
    let preparations = stream::iter(sealed.into_iter().map(
        |(index, id, session, parts, bytes)| async move {
            (
                index,
                id,
                async {
                    let prepared =
                        prepare_sealed(state, identity, session, parts, Some(bytes)).await?;
                    prepare(state, prepared).await
                }
                .await,
            )
        },
    ))
    .buffered(4);
    tokio::pin!(preparations);
    while let Some((index, id, result)) = preparations.next().await {
        match result {
            Ok(prepared) => ready.push((index, prepared)),
            Err(e) => results[index] = result_value(&id, Err(e), true),
        }
    }
    let results = publish_batch(state, identity, ready, results).await;
    Ok(json_response(StatusCode::OK, json!({"results":results})))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn inline(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let state = &state;
    let identity = &identity;
    let id = id.as_str();
    let s = load(&state.pool, id, identity).await?;
    if s.r2_upload_id.is_some() || s.part_size != Some(MIB as i32) || s.nar_size > MIB {
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
    if length > MIB {
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
    let input = InlineInput {
        session_id: id.into(),
        file_hash: hash,
        file_size: length as usize,
    };
    let result = async {
        let (session, parts) = seal_inline(state, identity, &input).await?;
        let ready = prepare_sealed(state, identity, session, parts, Some(bytes)).await?;
        let ready = prepare(state, ready).await?;
        let protect = vec![(
            ready.session.cache_id,
            ready.session.store_path_hash.clone(),
        )];
        publish_prepared(state, identity, ready, protect).await
    }
    .await;
    Ok(json_response(
        StatusCode::OK,
        result_value(id, result, true),
    ))
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
    if !matches!(s.status.as_str(), "streaming" | "aborted") {
        return Err(error(409, "Conflict"));
    }
    sqlx::query!(
        r#"
        UPDATE upload_sessions
        SET status = 'aborted'
        WHERE id = $1
        "#,
        id,
    )
    .execute(&mut *tx)
    .await?;
    let old = parts(&mut tx, id).await?;
    tx.commit().await?;
    for key in old.into_iter().filter_map(|p| p.storage_key) {
        let _ = state.storage.delete(true, &key).await;
    }
    Ok(json_response(StatusCode::OK, json!({"aborted":true})))
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
    let origin = request_origin(&state, &request)?;
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body: ReserveBatch = json_body(request).await?;
    batch(&body.uploads)?;
    distinct(body.uploads.iter().map(|u| u.session_id.as_str()))?;
    let mut results = Vec::with_capacity(body.uploads.len());
    for u in body.uploads {
        let r = reserve(
            &state,
            &identity,
            &u.session_id,
            u.parts,
            &origin,
            &authorization,
        )
        .await;
        results.push(result_value(&u.session_id, r, false));
    }
    Ok(json_response(StatusCode::OK, json!({"results":results})))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn finalize(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let body: Finalize = json_body(request).await?;
    batch(&body.uploads)?;
    distinct(body.uploads.iter().map(|u| u.session_id.as_str()))?;
    // Validate the envelope before doing any durable work.
    for u in &body.uploads {
        let mut numbers = HashSet::new();
        if !hash_valid(&u.file_hash)
            || !bounded(u.file_size)
            || !bounded(u.nar_size)
            || u.parts.is_empty()
            || u.parts.len() > 10_000
            || u.parts.iter().any(|p| {
                !(1..=10_000).contains(&p.part_number)
                    || p.etag.is_empty()
                    || !numbers.insert(p.part_number)
            })
            || canonical_hash(&u.nar_hash).is_err()
        {
            return Err(error(400, "Invalid stream receipt"));
        }
    }
    // Own the entire batch before allocating destinations. A disconnected
    // caller must not strand its later, not-yet-streamed reservations.
    let owned = state.clone();
    let results = state
        .tasks
        .spawn(async move { finalize_batch(&owned, &identity, body.uploads).await })
        .await
        .map_err(|_| error(500, "Finalization failed"))?;
    Ok(json_response(StatusCode::OK, json!({"results":results})))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve_parts(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let origin = request_origin(&state, &request)?;
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body: Reservations = json_body(request).await?;
    let result = reserve(
        &state,
        &identity,
        &id,
        serde_json::to_value(body.parts).unwrap(),
        &origin,
        &authorization,
    )
    .await?;
    Ok(json_response(StatusCode::OK, result))
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
            status: String::new(),
            r2_upload_id: None,
            part_size: None,
            staging_capacity: None,
            org_id: String::new(),
            name: String::new(),
            slug: String::new(),
            is_public: false,
            private_caches: false,
            publication_result: None,
        };
        let permit = state
            .verification_slots
            .clone()
            .try_acquire_owned()
            .unwrap();
        let mut pending = Box::pin(verify(
            &state,
            &session,
            Box::new(std::io::Cursor::new(Vec::<u8>::new())),
            None,
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut pending,)
                .await
                .is_err()
        );
        drop(permit);
        // Releasing a slot lets the same request inspect its unsealed receipt
        // without retrying admission.
        assert_eq!(pending.await.unwrap_err().status, StatusCode::CONFLICT);
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
