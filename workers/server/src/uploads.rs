//! PostgreSQL owns grants, immutable receipts, seals, and abort exclusion.
//! No connection is held while reading an HTTP body, assembling, or verifying.
use std::{
    collections::{HashMap, HashSet},
    io::Read,
};

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
use sqlx::{Postgres, Transaction};
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
            o.private_caches
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
async fn lock(tx: &mut Transaction<'_, Postgres>, key: &str) -> Result<(), ApiError> {
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
) -> Result<(Transaction<'static, Postgres>, Session), ApiError> {
    let mut tx =
        crate::profile_future!(state.pool.begin(), label = "uploads.session_pool_begin").await?;
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
    let mut tx =
        crate::profile_future!(state.pool.begin(), label = "uploads.create_pool_begin").await?;
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
        FOR SHARE OF c, o
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
async fn parts(tx: &mut Transaction<'_, Postgres>, id: &str) -> Result<Vec<Part>, ApiError> {
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
    tx: &mut Transaction<'_, Postgres>,
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
    inline: Option<&str>,
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
    if (s.r2_upload_id.is_none()) != inline.is_some() {
        return Err(error(409, "Conflict"));
    }
    if !matches!(s.status.as_str(), "streaming" | "finalizing" | "completed") {
        return Err(error(409, "Conflict"));
    }
    if inline.is_some()
        && (s.nar_size > MIB || receipt.file_size > MIB || s.part_size != Some(MIB as i32))
    {
        return Err(error(409, "Not an inline upload"));
    }
    if s.nar_hash != nar_hash || s.nar_size != receipt.nar_size {
        return Err(error(
            400,
            "Stream metadata or parts do not match reservations",
        ));
    }
    if let Some(key) = inline
        && s.status == "streaming"
    {
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
            SET etag = $2,
                storage_key = $3
            WHERE session_id = $1
                AND part_number = 1
            "#,
            &s.id,
            &receipt.file_hash,
            key,
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
    if stored
        .iter()
        .zip(&input)
        .any(|(p, i)| p.etag.as_deref() != Some(i.etag.as_str()) || p.storage_key.is_none())
    {
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

/// Assemble into a request-unique staged object, using fixed 64 KiB chunks.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn assemble(
    state: &AppState,
    s: &Session,
    parts: &[Part],
    key: &str,
) -> Result<(), ApiError> {
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
                return Ok(Some((buffer, (storage, keys, file))));
            }
        },
    );
    state
        .storage
        .write_body(true, key, Body::from_stream(stream), s.file_size as u64)
        .await?;
    Ok(())
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn verify(state: &AppState, s: &Session, key: &str) -> Result<(), ApiError> {
    let permit = state
        .verification_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(503, "Verification capacity exhausted"))?;
    let object = state.storage.open(true, key).await.map_err(io_error)?;
    // Bridge the R2 response stream into the blocking Zig verifier without
    // spooling it to disk or holding a database connection.
    let mut file = tokio_util::io::SyncIoBridge::new(object.reader);
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
        }
        let digest = verifier.finish().map_err(|_| error(400, "Invalid NAR"))?;
        if digest.file_size != file_size || hex::encode(digest.file_hash) != expected_file {
            return Err(error(400, "File hash or size mismatch"));
        }
        if digest.nar_size != nar_size || digest.nar_hash != expected_nar {
            return Err(error(400, "NAR hash or size mismatch"));
        }
        Ok(())
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

#[derive(PartialEq)]
struct Published {
    store_path: String,
    nar_hash: String,
    nar_size: i64,
    references_json: String,
    deriver: Option<String>,
    system: Option<String>,
    signatures_json: String,
    file_hash: String,
    file_size: i64,
    compression: String,
}
impl Published {
    fn nar(&self, hash: &str) -> Result<signing::Narinfo, ApiError> {
        Ok(signing::Narinfo {
            store_path: self.store_path.clone(),
            store_path_hash: hash.to_owned(),
            nar_hash: self.nar_hash.clone(),
            nar_size: self.nar_size,
            references: serde_json::from_str(&self.references_json)
                .map_err(|_| error(500, "Invalid stored references"))?,
            deriver: self.deriver.clone(),
            system: self.system.clone(),
            signatures: serde_json::from_str(&self.signatures_json)
                .map_err(|_| error(500, "Invalid stored signatures"))?,
            file_hash: self.file_hash.clone(),
            file_size: self.file_size,
            compression: self.compression.clone(),
        })
    }
}

/// Commit ownership before any canonical write. A later publication rollback
/// must not erase GC discovery or protection from an uncertain provider copy.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve_canonical(
    state: &AppState,
    identity: &Identity,
    s: &Session,
    staged: &str,
) -> Result<(String, String), ApiError> {
    let (mut tx, current) = locked(state, s, identity).await?;
    if !matches!(current.status.as_str(), "finalizing" | "completed")
        || current.file_hash != s.file_hash
    {
        return Err(error(409, "Conflict"));
    }
    sqlx::query!(
        r#"
        LOCK TABLE upload_sessions IN ROW EXCLUSIVE MODE
        "#
    )
    .execute(&mut *tx)
    .await?;
    let hash = s.file_hash.as_deref().unwrap();
    let key = if s.is_public {
        format!("nar/{hash}/zstd.nar")
    } else {
        format!("nars/sha256/{hash}/zstd.nar")
    };
    lock(&mut tx, &format!("nar:{hash}:zstd")).await?;
    // An expired legacy MPU can still complete. Neither TTL nor our SQL lock
    // fences a provider request that is already outstanding.
    let reserved = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM upload_sessions
            WHERE r2_upload_key = $1
                AND status <> 'completed'
                AND (r2_upload_id IS NOT NULL OR expires_at > NOW())
        ) AS "exists!"
        "#,
        &key,
    )
    .fetch_one(&mut *tx)
    .await?;
    if reserved {
        return Err(error(503, "NAR installation busy; retry"));
    }
    sqlx::query!(
        r#"
        INSERT INTO blob_objects (file_hash, file_size, compression, r2_key)
        VALUES ($1, $2, 'zstd', $3)
        ON CONFLICT (file_hash, compression) DO NOTHING
        "#,
        hash,
        s.file_size,
        &key,
    )
    .execute(&mut *tx)
    .await?;
    let operation = uuid::Uuid::now_v7().to_string();
    let claimed = sqlx::query!(
        r#"
        INSERT INTO nar_installations (
            key, operation_id, source_key, file_hash, compression, is_private, file_size
        )
        VALUES ($1, $2, $3, $4, 'zstd', $5, $6)
        ON CONFLICT DO NOTHING
        "#,
        &key,
        &operation,
        staged,
        hash,
        !s.is_public,
        s.file_size,
    )
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
    s: &Session,
    staged: &str,
    protect: &[(i32, String)],
) -> Result<Value, ApiError> {
    let (key, operation) = reserve_canonical(state, identity, s, staged).await?;
    let mut uncertain_copy = false;
    let result = async {
        let (mut tx, current) = locked(state, s, identity).await?;
        if !matches!(current.status.as_str(), "finalizing" | "completed")
            || current.file_hash != s.file_hash
        {
            return Err(error(409, "Conflict"));
        }
        if !current.is_public && !current.private_caches {
            return Err(error(403, PRIVATE_CACHES_REFUSED));
        }
        if current.slug != s.slug || current.name != s.name || current.is_public != s.is_public {
            return Err(error(503, "Cache policy changed; retry"));
        }
        // Activation takes this cache row FOR UPDATE. Select the active signing
        // key inside the publication fence so an old render cannot publish after
        // a completed rotation. Reuse this connection, including with a pool of one.
        struct SigningKeys {
            signing_key_name: Option<String>,
            signing_public_key: Option<String>,
            signing_key_sealed: Option<String>,
        }
        let keys = crate::profile_future!(
            sqlx::query_as!(
                SigningKeys,
                r#"
                SELECT
                    signing_key_name,
                    signing_public_key,
                    signing_key_sealed
                FROM caches
                WHERE id = $1
                FOR SHARE
                "#,
                s.cache_id,
            )
            .fetch_one(&mut *tx),
            label = "uploads.signing_row_lock"
        )
        .await?;
        // Match the canonical deletion fence used by the shared SQL repository.
        crate::profile_future!(
            sqlx::query!(
                r#"
                LOCK TABLE upload_sessions IN ROW EXCLUSIVE MODE
                "#
            )
            .execute(&mut *tx),
            label = "uploads.gc_table_lock"
        )
        .await?;
        let hash = s.file_hash.as_deref().unwrap();
        lock(&mut tx, &format!("nar:{hash}:zstd")).await?;
        let existing = sqlx::query_as!(
            Published,
            r#"
            SELECT
                p.store_path,
                p.nar_hash,
                p.nar_size,
                p.references_json,
                p.deriver,
                p.system,
                p.signatures_json,
                b.file_hash,
                b.file_size,
                b.compression
            FROM published_paths p
            JOIN blob_objects b ON b.id = p.blob_object_id
            WHERE p.cache_id = $1
                AND p.store_path_hash = $2
            "#,
            s.cache_id,
            &s.store_path_hash,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let metadata = match &existing {
            Some(p) => p.nar(&s.store_path_hash)?,
            None => nar(s)?,
        };
        let signing_key = signing::select_key(
            &state.config,
            s.cache_id,
            keys.signing_key_name.as_deref(),
            keys.signing_public_key.as_deref(),
            keys.signing_key_sealed.as_deref(),
        )?;
        let rendered = signing::render_with_key(
            &cache_path(s),
            !s.is_public,
            &metadata,
            signing_key.as_ref().map(|(name, key)| (name.as_str(), key)),
        )?;
        let capacity: Option<i64> = sqlx::query_scalar!(
            r#"
            SELECT storage_limit
            FROM orgs
            WHERE id = $1
            FOR SHARE
            "#,
            &s.org_id,
        )
        .fetch_one(&mut *tx)
        .await?;
        if let Some(limit) = capacity {
            crate::capacity::admit(
                &mut tx,
                state,
                &s.org_id,
                limit,
                if existing.is_none() { s.file_size } else { 0 },
                protect,
            )
            .await?;
        }
        // Every caller has independently proven possession. Copy under the
        // content-addressed transaction fence; no request body is involved here.
        uncertain_copy = true;
        state
            .storage
            .copy(true, staged, !s.is_public, &key)
            .await
            .map_err(io_error)?;
        uncertain_copy = false;
        let blob_id = sqlx::query_scalar!(
            r#"
            SELECT id
            FROM blob_objects
            WHERE file_hash = $1
                AND compression = 'zstd'
            "#,
            hash,
        )
        .fetch_one(&mut *tx)
        .await?;
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
        let info = if s.is_public {
            format!("{}/{}.narinfo", cache_path(s), s.store_path_hash)
        } else {
            format!("narinfo/{}/{}.narinfo", cache_path(s), s.store_path_hash)
        };
        state
            .storage
            .put(!s.is_public, &info, rendered.as_bytes())
            .await
            .map_err(io_error)?;
        if s.is_public {
            state
                .storage
                .put(
                    false,
                    &format!("{}/nix-cache-info", cache_path(s)),
                    crate::reads::INFO.as_bytes(),
                )
                .await
                .map_err(io_error)?;
            crate::cdn::schedule_narinfo(
                state,
                &cache_path(s),
                std::slice::from_ref(&s.store_path_hash),
            )
            .await?;
            crate::cdn::schedule_files(state, &[format!("{}/nix-cache-info", cache_path(s))])
                .await?;
        }
        sqlx::query!(
            r#"
            UPDATE upload_sessions
            SET status = 'completed'
            WHERE id = $1
            "#,
            &s.id,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            DELETE FROM nar_installations
            WHERE key = $1
                AND operation_id = $2
            "#,
            &key,
            &operation,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut result =
            json!({"sessionId":s.id,"storePathHash":s.store_path_hash,"published":true});
        if existing.is_some() {
            result["alreadyExisted"] = json!(true);
        }
        Ok(result)
    }
    .await;
    if result.is_err() && !uncertain_copy {
        // The publication transaction has rolled back, but the copy either
        // never started or confirmed completion. Release its pin; the durable
        // blob row remains available to GC. An uncertain copy stays pinned,
        // including across restarts, until explicitly reconciled.
        sqlx::query!(
            r#"
            DELETE FROM nar_installations
            WHERE key = $1
                AND operation_id = $2
            "#,
            &key,
            &operation,
        )
        .execute(&state.pool)
        .await?;
    }
    result
}

struct Prepared {
    session: Session,
    assembled: String,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn prepare(
    state: &AppState,
    identity: &Identity,
    receipt: Receipt,
    inline: Option<&str>,
) -> Result<Prepared, ApiError> {
    let (s, parts) = seal(state, identity, &receipt, inline).await?;
    let assembled = format!("staging/{}/assembled-{}", s.id, uuid::Uuid::now_v7());
    let verified = async {
        assemble(state, &s, &parts, &assembled).await?;
        verify(state, &s, &assembled).await
    }
    .await;
    if let Err(e) = verified {
        let _ = state.storage.delete(true, &assembled).await;
        return Err(e);
    }
    Ok(Prepared {
        session: s,
        assembled,
    })
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn publish_prepared(
    state: &AppState,
    identity: &Identity,
    ready: Prepared,
    protect: Vec<(i32, String)>,
) -> Result<Value, ApiError> {
    // Once external publication starts, caller cancellation must not release
    // its PostgreSQL fence before the last R2 operation settles.
    // TaskTracker also makes orderly shutdown wait for this critical section.
    let owned = state.clone();
    let identity = identity.clone();
    state
        .tasks
        .spawn(crate::profile_future!(
            async move {
                let result = publish(
                    &owned,
                    &identity,
                    &ready.session,
                    &ready.assembled,
                    &protect,
                )
                .await;
                let pinned = sqlx::query_scalar!(
                    r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM nar_installations
                    WHERE source_key = $1
                ) AS "exists!"
                "#,
                    &ready.assembled,
                )
                .fetch_one(&owned.pool)
                .await
                .unwrap_or(true);
                if !pinned {
                    let _ = owned.storage.delete(true, &ready.assembled).await;
                }
                result
            },
            label = "uploads.publication"
        ))
        .await
        .map_err(|_| error(500, "Publication failed"))?
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn finalize_one(
    state: &AppState,
    identity: &Identity,
    receipt: Receipt,
    inline: Option<&str>,
) -> Result<Value, ApiError> {
    let ready = prepare(state, identity, receipt, inline).await?;
    let protect = vec![(
        ready.session.cache_id,
        ready.session.store_path_hash.clone(),
    )];
    publish_prepared(state, identity, ready, protect).await
}

/// Reject an oversized incoming set before publishing any member. Only verified
/// sessions count, and duplicate store paths count once, as SQL insertion does.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn preflight(state: &AppState, org: &str, ready: &[&Prepared]) -> Result<(), ApiError> {
    let mut tx =
        crate::profile_future!(state.pool.begin(), label = "uploads.preflight_pool_begin").await?;
    lock(&mut tx, &format!("org:{org}")).await?;
    let limit: Option<i64> = sqlx::query_scalar!(
        r#"
        SELECT storage_limit
        FROM orgs
        WHERE id = $1
        FOR SHARE
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
    // Overlap preparation only. Ordered buffering preserves the first input's
    // metadata when distinct sessions publish the same store path.
    let preparations = stream::iter(inputs.into_iter().enumerate().map(
        |(index, input)| async move {
            let id = input.session_id.clone();
            (index, id, prepare(state, identity, input, None).await)
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
    publish_batch(state, identity, ready, results).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn publish_batch(
    state: &AppState,
    identity: &Identity,
    ready: Vec<(usize, Prepared)>,
    mut results: Vec<Value>,
) -> Vec<Value> {
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
            let _ = state.storage.delete(true, &p.assembled).await;
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
async fn prepare_inline(
    state: &AppState,
    identity: &Identity,
    input: &InlineInput,
    bytes: axum::body::Bytes,
) -> Result<Prepared, ApiError> {
    let id = &input.session_id;
    let s = load(&state.pool, id, identity).await?;
    if s.r2_upload_id.is_some() || s.part_size != Some(MIB as i32) || s.nar_size > MIB {
        return Err(error(409, "Not an inline upload"));
    }
    let key = format!("staging/{id}/inline-{}", uuid::Uuid::now_v7());
    state
        .storage
        .write_body(true, &key, Body::from(bytes), input.file_size as u64)
        .await?;
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
    let result = prepare(state, identity, receipt, Some(&key)).await;
    discard_unretained_inline(state, id, &key).await?;
    result
}

async fn discard_unretained_inline(state: &AppState, id: &str, key: &str) -> Result<(), ApiError> {
    // Keep an admitted source even on publication failure for immutable replay.
    let retained = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM upload_parts
            WHERE session_id = $1
                AND storage_key = $2
        ) AS "exists!"
        "#,
        id,
        key,
    )
    .fetch_one(&state.pool)
    .await?;
    if !retained {
        let _ = state.storage.delete(true, key).await;
    }
    Ok(())
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
    offset = 4 + manifest_size;
    // Keep ready in input order and drain all item errors before publication.
    let preparations = stream::iter(body.uploads.into_iter().enumerate().map(|(index, input)| {
        let bytes = frame.slice(offset..offset + input.file_size);
        offset += input.file_size;
        async move {
            let result = prepare_inline(state, identity, &input, bytes).await;
            (index, input.session_id, result)
        }
    }))
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
    let key = format!("staging/{id}/inline-{}", uuid::Uuid::now_v7());
    let etag = state
        .storage
        .write_body(true, &key, request.into_body(), length as u64)
        .await?;
    if etag != hash {
        let _ = state.storage.delete(true, &key).await;
        return Err(error(400, "File hash mismatch"));
    }
    let receipt = Receipt {
        session_id: id.into(),
        nar_hash: s.nar_hash,
        nar_size: s.nar_size,
        file_hash: hash.clone(),
        file_size: length,
        parts: vec![ReceiptPart {
            part_number: 1,
            etag: hash,
        }],
    };
    let result = finalize_one(state, identity, receipt, Some(&key)).await;
    discard_unretained_inline(state, id, &key).await?;
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
    let results = finalize_batch(&state, &identity, body.uploads).await;
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
    async fn verification_overload_is_rejected_before_opening_storage() {
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
        };
        let permit = state
            .verification_slots
            .clone()
            .try_acquire_owned()
            .unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            verify(&state, &session, "missing"),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        drop(permit);
        // An admitted verifier reaches the missing object instead of queueing.
        assert_eq!(
            verify(&state, &session, "missing")
                .await
                .unwrap_err()
                .status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
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
