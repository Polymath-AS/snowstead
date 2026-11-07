//! Management policy uses the same org -> cache -> entry fence as publication.
//! SQL withdraws metadata atomically; known legacy objects are queued for GC.
//! Shared NARs belong to GC, never to cache/path withdrawal.
use crate::db::Transaction;
use crate::{
    AppState,
    auth::Identity,
    error::{ApiError, json_response},
    management::ManagementContext,
    management_auth::js_number,
};
use axum::{
    Extension, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::StatusCode,
    response::Response,
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

fn bad(message: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}
fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not Found")
}
fn forbidden() -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "Forbidden")
}
fn date(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}
fn optional_date(at: Option<DateTime<Utc>>) -> Value {
    at.map(date).map(Value::String).unwrap_or(Value::Null)
}
fn ok(value: Value) -> Response {
    json_response(StatusCode::OK, value)
}

fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == 32
        && hash
            .bytes()
            .all(|c| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&c))
}
fn store_path_valid(path: &str) -> bool {
    let Some(base) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    base.is_ascii()
        && base.len() > 33
        && base.len() <= 244
        && hash_valid(&base[..32])
        && base.as_bytes()[32] == b'-'
        && base[33..]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+-._?=".contains(&c))
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn body(request: Request) -> Result<Value, ApiError> {
    let bytes = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| bad("Invalid JSON in request body"))?;
    serde_json::from_slice(&bytes).map_err(|_| bad("Invalid JSON in request body"))
}
fn strict(value: &Value, keys: &[&str]) -> Result<(), ApiError> {
    let object = value.as_object().ok_or_else(|| bad("expected an object"))?;
    if object.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(bad("Unexpected key"));
    }
    Ok(())
}
fn params(request: &Request) -> Vec<(String, String)> {
    // reqwest's URL parser implements URLSearchParams decoding (including '+').
    reqwest::Url::parse(&format!("http://localhost{}", request.uri()))
        .expect("HTTP URI")
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}
fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params.iter().find(|p| p.0 == key).map(|p| p.1.as_str())
}
fn page_limit(params: &[(String, String)], default: i64) -> Result<i64, ApiError> {
    let n = param(params, "limit")
        .map(js_number)
        .unwrap_or(default as f64);
    if n.fract() != 0.0 || !(1.0..=200.0).contains(&n) {
        return Err(bad("limit must be between 1 and 200"));
    }
    Ok(n as i64)
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn fence(tx: &mut Transaction, org: &str) -> Result<(), ApiError> {
    let key = format!("org:{org}");
    crate::profile_future!(
        crate::db::advisory_lock(tx, &key),
        label = "management_policy.org_lock_wait"
    )
    .await?;
    Ok(())
}

pub(crate) struct MetadataTarget {
    paths: Vec<String>,
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl MetadataTarget {
    pub(crate) fn new(_public: bool, slug: &str, moving_from: Option<&str>, name: &str) -> Self {
        let mut paths = Vec::new();
        for slug in std::iter::once(slug).chain(moving_from) {
            let path = if slug == "default" {
                name.to_owned()
            } else {
                format!("{slug}/{name}")
            };
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        Self { paths }
    }

    pub(crate) async fn withdraw(
        &self,
        tx: &mut impl std::ops::DerefMut<Target = sqlx::PgConnection>,
        hashes: &[String],
    ) -> Result<(), ApiError> {
        for path in &self.paths {
            for hash in hashes {
                // Both placements can survive an earlier visibility change.
                for (private, key) in [
                    (false, format!("{path}/{hash}.narinfo")),
                    (true, format!("narinfo/{path}/{hash}.narinfo")),
                ] {
                    sqlx::query("INSERT INTO object_cleanup (is_private, key) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                        .bind(private).bind(key).execute(&mut **tx).await?;
                }
            }
        }
        Ok(())
    }

    async fn withdraw_cache_info(&self, tx: &mut Transaction) -> Result<(), ApiError> {
        // cache-info lives in the public bucket, including stale cache-info
        // left by an interrupted visibility change to private.
        for path in &self.paths {
            sqlx::query("INSERT INTO object_cleanup (is_private, key) VALUES (FALSE, $1) ON CONFLICT DO NOTHING")
                .bind(format!("{path}/nix-cache-info")).execute(&mut **tx).await?;
        }
        Ok(())
    }
}

pub(crate) fn org_router() -> Router<AppState> {
    Router::new()
        .route("/eviction", get(get_eviction))
        .route("/caches/{cache}/pins", get(get_pins).post(create_pin))
        .route("/caches/{cache}/pins/{pin}", delete(remove_pin))
        .route("/caches/{cache}/go", get(get_go))
        .route("/caches/{cache}/sccache", get(get_sccache))
        .route("/caches/{cache}/go/reset", post(reset_go))
        .route("/caches/{cache}/sccache/reset", post(reset_sccache))
        .route("/caches/{cache}/paths", get(get_paths))
        .route("/caches/{cache}/paths/delete", post(remove_paths))
        .route("/caches/{cache}/delete", post(remove_cache))
        .route("/caches/{cache}/evict", post(evict_cache))
        .route("/caches/{cache}/purge", post(purge_cache))
}

pub(crate) fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/caches/{cache}/paths/delete", post(remove_paths))
        .route("/caches/{cache}/delete", post(remove_cache))
        .route("/caches/{cache}/purge", post(purge_cache))
}

#[derive(Deserialize)]
struct CachePath {
    cache: String,
}

#[derive(Deserialize)]
struct PinPath {
    cache: String,
    pin: String,
}

fn context_org(context: &ManagementContext) -> &str {
    context.org.as_deref().unwrap_or("default")
}

fn authorize(identity: &Identity, org: &str, pin_write: bool) -> Result<(), ApiError> {
    match identity {
        Identity::Admin { .. } => Ok(()),
        Identity::OrgKey { org: owner, .. } if owner == org => Ok(()),
        Identity::Jwt(claims)
            if pin_write && claims.belongs_to(org) && claims.has_permission("push") =>
        {
            Ok(())
        }
        _ => Err(forbidden()),
    }
}

struct FencedCache {
    tx: Transaction,
    id: i32,
    public: bool,
    metadata: MetadataTarget,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn load_cache(
    state: &AppState,
    org: &str,
    name: &str,
    identity: &Identity,
) -> Result<FencedCache, ApiError> {
    let mut tx = crate::profile_future!(
        crate::db::begin(state, org),
        label = "management_policy.pool_begin"
    )
    .await?;
    // Reads use the fence as well so multi-statement pin/stats responses are
    // coherent with resets, cache deletion, and publication.
    fence(&mut tx, org).await?;
    let cache = sqlx::query!(
        r#"
        SELECT
            c.id,
            c.is_public,
            o.slug,
            o.moving_from
        FROM caches c
        JOIN orgs o ON o.id = c.org_id
        WHERE c.org_id = $1
            AND c.name = $2
        FOR UPDATE OF c NOWAIT
        "#,
        org,
        name
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(missing)?;
    let id = cache.id;
    let public = cache.is_public;
    let metadata = MetadataTarget::new(public, &cache.slug, cache.moving_from.as_deref(), name);
    if let Identity::Jwt(claims) = identity
        && !claims.has_cache_access(id, name)
    {
        return Err(forbidden());
    }
    Ok(FencedCache {
        tx,
        id,
        public,
        metadata,
    })
}

fn authorize_cache(
    context: &ManagementContext,
    name: &str,
    pin_write: bool,
) -> Result<(), ApiError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || name.starts_with('-')
        || name.ends_with('-')
    {
        return Err(bad(
            "CacheName must be 1-64 lowercase alphanumeric chars or hyphens, no leading/trailing hyphen",
        ));
    }
    authorize(&context.identity, context_org(context), pin_write)
}

async fn get_eviction(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize(&context.identity, org, false)?;
    eviction(&state, org, params(&request)).await
}

async fn purge_cache(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
    request: Request,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &path.cache, false)?;
    if state.config.cdn_zone_id.is_empty() {
        return Err(bad("no CDN is configured to purge"));
    }
    let input = body(request).await?;
    let FencedCache {
        tx,
        public,
        metadata,
        ..
    } = load_cache(&state, org, &path.cache, &context.identity).await?;
    strict(&input, &["storePathHashes"])?;
    let hashes = input
        .get("storePathHashes")
        .map(|value| {
            let values = value
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 500)
                .ok_or_else(|| bad("storePathHashes must contain 1 to 500 hashes"))?;
            let mut hashes = Vec::new();
            for value in values {
                let hash = value
                    .as_str()
                    .filter(|v| hash_valid(v))
                    .ok_or_else(|| bad("invalid store path hash"))?;
                if !hashes.iter().any(|h| h == hash) {
                    hashes.push(hash.to_owned());
                }
            }
            Ok::<_, ApiError>(hashes)
        })
        .transpose()?;
    if !public {
        return Err(bad("private caches are not on the CDN"));
    }
    let path = &metadata.paths[0];
    // Manual network work must never occupy a PostgreSQL connection.
    tx.commit().await?;
    crate::cdn::purge(&state, path, hashes.as_deref()).await?;
    Ok(ok(
        json!({"accepted":true,"paths":hashes.map_or(json!("all"), |h| json!(h))}),
    ))
}

async fn get_pins(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &path.cache, false)?;
    let FencedCache { mut tx, id, .. } =
        load_cache(&state, org, &path.cache, &context.identity).await?;
    protocol(&mut tx, id, "nix").await?;
    let response = ok(json!({"pins":list_pins(&mut tx,id).await?}));
    tx.commit().await?;
    Ok(response)
}

async fn create_pin(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
    request: Request,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &path.cache, true)?;
    let input = body(request).await?;
    let FencedCache { mut tx, id, .. } =
        load_cache(&state, org, &path.cache, &context.identity).await?;
    protocol(&mut tx, id, "nix").await?;
    let response = put_pin(&mut tx, id, input).await?;
    tx.commit().await?;
    Ok(response)
}

async fn remove_pin(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<PinPath>,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &path.cache, true)?;
    let FencedCache { mut tx, id, .. } =
        load_cache(&state, org, &path.cache, &context.identity).await?;
    protocol(&mut tx, id, "nix").await?;
    let pin = path.pin.as_str();
    if !name_valid(pin) {
        return Err(bad("Invalid format"));
    }
    sqlx::query!(
        r#"
                    DELETE FROM pins
                    WHERE cache_id = $1
                        AND name = $2
                    "#,
        id,
        pin
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ok(json!({"deleted":true,"name":pin})))
}

async fn reset_compiler_generation(
    tx: &mut Transaction,
    id: i32,
    kind: &str,
) -> Result<(), ApiError> {
    let generation = uuid::Uuid::now_v7().to_string();
    if kind == "go" {
        sqlx::query!(
            r#"
                        UPDATE caches
                        SET go_generation = $2
                        WHERE id = $1
                        "#,
            id,
            generation
        )
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            r#"
                        UPDATE caches
                        SET sccache_generation = $2
                        WHERE id = $1
                        "#,
            id,
            generation
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn compiler_stats(
    state: AppState,
    context: ManagementContext,
    name: String,
    op: &str,
    reset: bool,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &name, false)?;
    let FencedCache { mut tx, id, .. } = load_cache(&state, org, &name, &context.identity).await?;
    if op == "sccache" || reset {
        protocol(&mut tx, id, op).await?;
    }
    if reset {
        reset_compiler_generation(&mut tx, id, op).await?;
    }
    struct Stats {
        entries: i64,
        size: i64,
        added: Option<DateTime<Utc>>,
    }
    let row = if op == "go" {
        sqlx::query_as!(
            Stats,
            r#"
                    SELECT
                        COUNT(*)::bigint AS "entries!",
                        COALESCE(SUM(e.size), 0)::bigint AS "size!",
                        MAX(e.uploaded_at) AS added
                    FROM go_entries e
                    JOIN caches c ON c.id = e.cache_id
                    WHERE c.id = $1
                        AND e.generation = c.go_generation
                        AND e.expires_at > NOW()
                        AND e.uploaded_at IS NOT NULL
                    "#,
            id
        )
        .fetch_one(&mut *tx)
        .await?
    } else {
        sqlx::query_as!(
            Stats,
            r#"
                    SELECT
                        COUNT(*)::bigint AS "entries!",
                        COALESCE(SUM(e.size), 0)::bigint AS "size!",
                        MAX(e.uploaded_at) AS added
                    FROM sccache_entries e
                    JOIN caches c ON c.id = e.cache_id
                    WHERE c.id = $1
                        AND e.generation = c.sccache_generation
                        AND e.expires_at > NOW()
                        AND e.uploaded_at IS NOT NULL
                    "#,
            id
        )
        .fetch_one(&mut *tx)
        .await?
    };
    let response = ok(
        json!({"entries":row.entries,"size":row.size,"lastAddedAt":optional_date(row.added),"retentionDays":7}),
    );
    tx.commit().await?;
    Ok(response)
}

async fn get_go(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
) -> Result<Response, ApiError> {
    compiler_stats(state, context, path.cache, "go", false).await
}

async fn get_sccache(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
) -> Result<Response, ApiError> {
    compiler_stats(state, context, path.cache, "sccache", false).await
}

async fn reset_go(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
) -> Result<Response, ApiError> {
    compiler_stats(state, context, path.cache, "go", true).await
}

async fn reset_sccache(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
) -> Result<Response, ApiError> {
    compiler_stats(state, context, path.cache, "sccache", true).await
}

async fn get_paths(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
    request: Request,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &path.cache, false)?;
    let FencedCache { mut tx, id, .. } =
        load_cache(&state, org, &path.cache, &context.identity).await?;
    let response = list_paths(&mut tx, id, params(&request)).await?;
    tx.commit().await?;
    Ok(response)
}

async fn remove_paths(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
    request: Request,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &path.cache, false)?;
    let input = body(request).await?;
    let FencedCache {
        mut tx,
        id,
        metadata,
        ..
    } = load_cache(&state, org, &path.cache, &context.identity).await?;
    let response = delete_paths(&metadata, &mut tx, id, input).await?;
    tx.commit().await?;
    Ok(response)
}

async fn remove_cache(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
) -> Result<Response, ApiError> {
    withdraw_cache(state, context, path.cache, true).await
}

async fn evict_cache(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(path): Path<CachePath>,
) -> Result<Response, ApiError> {
    withdraw_cache(state, context, path.cache, false).await
}

// Cache deletion and eviction share the same ordered withdrawal. Deletion
// preserves compiler cleanup records for GC and additionally removes the cache.
async fn withdraw_cache(
    state: AppState,
    context: ManagementContext,
    name: String,
    delete: bool,
) -> Result<Response, ApiError> {
    let org = context_org(&context);
    authorize_cache(&context, &name, false)?;
    let FencedCache {
        mut tx,
        id,
        public,
        metadata,
    } = load_cache(&state, org, &name, &context.identity).await?;
    if !delete {
        sqlx::query!(
            r#"
                    SELECT set_config('snowstead.eviction_reason', 'evict', TRUE)
                    "#
        )
        .fetch_one(&mut *tx)
        .await?;
    }
    let pins = sqlx::query!(
        r#"
                DELETE FROM pins
                WHERE cache_id = $1
                "#,
        id
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if delete {
        // Freeze session/source discovery before adopting legacy
        // canonical uploads, matching publication and GC's table fence.
        sqlx::query!(
            r#"
                    LOCK TABLE upload_sessions IN SHARE ROW EXCLUSIVE MODE NOWAIT
                    "#
        )
        .execute(&mut *tx)
        .await?;
        // Transfer ownership of legacy staging MPUs to the cleanup queue.
        // Pinned MPUs must retain their sessions until their consumer resolves.
        // Rust receipt markers and completed outcomes are not MPUs
        // that this withdrawal may abort.
        let uploads = sqlx::query!(
            r#"
                    SELECT
                        u.r2_upload_key AS "r2_upload_key!",
                        u.r2_upload_id AS "r2_upload_id!",
                        EXISTS (
                            SELECT 1
                            FROM nar_installations i
                            WHERE i.source_key = u.r2_upload_key
                                OR STARTS_WITH(i.source_key, 'staging/' || u.id || '/')
                        ) AS "pinned!"
                    FROM upload_sessions u
                    WHERE u.cache_id = $1
                        AND STARTS_WITH(u.r2_upload_key, 'staging/')
                        AND u.r2_upload_id IS NOT NULL
                        AND u.r2_upload_id <> u.id
                        AND u.status <> 'completed'
                    "#,
            id
        )
        .fetch_all(&mut *tx)
        .await?;
        if uploads.iter().any(|u| u.pinned) {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Upload source is in use; retry cache deletion",
            ));
        }
        for upload in uploads {
            sqlx::query("INSERT INTO object_cleanup (is_private, key, upload_id) VALUES (TRUE, $1, $2) ON CONFLICT (is_private, key) DO UPDATE SET upload_id = EXCLUDED.upload_id")
                .bind(&upload.r2_upload_key).bind(&upload.r2_upload_id).execute(&mut *tx).await?;
        }
    }
    // Expire every session, but preserve completed outcomes: cleanup
    // must distinguish reclaimable bytes from uncertain canonical MPUs.
    // Unfinished finalization rechecks status under this org fence.
    sqlx::query!(
        r#"
                UPDATE upload_sessions
                SET status = CASE WHEN status = 'completed' THEN status ELSE 'aborted' END,
                    expires_at = NOW()
                WHERE cache_id = $1
                "#,
        id
    )
    .execute(&mut *tx)
    .await?;
    let mut nix = 0;
    loop {
        let hashes = sqlx::query_scalar!(
            r#"
                    DELETE FROM published_paths
                    WHERE id IN (
                        SELECT id
                        FROM published_paths
                        WHERE cache_id = $1
                        ORDER BY id
                        LIMIT 500
                    )
                    RETURNING store_path_hash
                    "#,
            id
        )
        .fetch_all(&mut *tx)
        .await?;
        metadata.withdraw(&mut tx, &hashes).await?;
        nix += hashes.len();
        if hashes.len() < 500 {
            break;
        }
    }
    let mut removed = json!({"nix":nix});
    for kind in ["go", "sccache"] {
        // Cache deletion detaches compiler entries through the foreign
        // key, keeping their cleanup records for GC. Explicit eviction
        // withdraws compiler objects before deleting their SQL records.
        if delete {
            continue;
        }
        let mut count = 0;
        loop {
            struct Entry {
                id: String,
                r2_key: String,
            }
            let entries = if kind == "go" {
                sqlx::query_as!(
                    Entry,
                    r#"
                            SELECT
                                id,
                                r2_key
                            FROM go_entries
                            WHERE cache_id = $1
                            ORDER BY id
                            LIMIT 500
                            FOR UPDATE NOWAIT
                            "#,
                    id
                )
                .fetch_all(&mut *tx)
                .await?
            } else {
                sqlx::query_as!(
                    Entry,
                    r#"
                            SELECT
                                id,
                                r2_key
                            FROM sccache_entries
                            WHERE cache_id = $1
                            ORDER BY id
                            LIMIT 500
                            FOR UPDATE NOWAIT
                            "#,
                    id
                )
                .fetch_all(&mut *tx)
                .await?
            };
            for entry in &entries {
                sqlx::query("INSERT INTO object_cleanup (is_private, key) VALUES (TRUE, $1) ON CONFLICT DO NOTHING")
                    .bind(&entry.r2_key).execute(&mut *tx).await?;
            }
            let ids: Vec<_> = entries.iter().map(|e| e.id.clone()).collect();
            if kind == "go" {
                sqlx::query!(
                    r#"
                            DELETE FROM go_entries
                            WHERE id = ANY($1)
                            "#,
                    &ids
                )
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query!(
                    r#"
                            DELETE FROM sccache_entries
                            WHERE id = ANY($1)
                            "#,
                    &ids
                )
                .execute(&mut *tx)
                .await?;
            }
            count += entries.len();
            if entries.len() < 500 {
                break;
            }
        }
        removed[kind] = json!(count);
        reset_compiler_generation(&mut tx, id, kind).await?;
    }
    let response = if delete {
        metadata.withdraw_cache_info(&mut tx).await?;
        // A late legacy canonical MPU completion can outlive its
        // cache. Preserve the reservation independently of that cache,
        // and adopt canonical objects so SQL-driven GC can find them.
        sqlx::query!(
            r#"
                    INSERT INTO nar_installations (
                        key,
                        operation_id,
                        source_key,
                        upload_id,
                        file_hash,
                        compression,
                        is_private,
                        file_size,
                        phase
                    )
                    SELECT
                        r2_upload_key,
                        id,
                        r2_upload_key,
                        r2_upload_id,
                        file_hash,
                        compression,
                        NOT STARTS_WITH(r2_upload_key, 'nar/'),
                        file_size,
                        'legacy-unresolved'
                    FROM upload_sessions
                    WHERE cache_id = $1
                        AND file_hash IS NOT NULL
                        AND r2_upload_key IS NOT NULL
                        AND NOT STARTS_WITH(r2_upload_key, 'staging/')
                        AND r2_upload_id IS NOT NULL
                        AND status <> 'completed'
                    ON CONFLICT DO NOTHING
                    "#,
            id
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
                    INSERT INTO blob_objects (
                        file_hash,
                        file_size,
                        compression,
                        r2_key
                    )
                    SELECT
                        file_hash,
                        file_size,
                        compression,
                        r2_upload_key
                    FROM upload_sessions
                    WHERE cache_id = $1
                        AND file_hash IS NOT NULL
                        AND r2_upload_key IS NOT NULL
                        AND NOT STARTS_WITH(r2_upload_key, 'staging/')
                    ON CONFLICT DO NOTHING
                    "#,
            id
        )
        .execute(&mut *tx)
        .await?;
        // These foreign keys deliberately do not cascade. A transfer
        // that finishes later must find its session missing, never a
        // newly created cache with the same name. Shared NARs stay.
        sqlx::query!(
            r#"
                    DELETE FROM upload_parts
                    WHERE session_id IN (
                        SELECT id
                        FROM upload_sessions
                        WHERE cache_id = $1
                    )
                    "#,
            id
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
                    DELETE FROM upload_sessions
                    WHERE cache_id = $1
                    "#,
            id
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
                    DELETE FROM caches
                    WHERE id = $1
                        AND org_id = $2
                    "#,
            id,
            org
        )
        .execute(&mut *tx)
        .await?;
        ok(json!({"deleted":true,"name":name,"paths":nix}))
    } else {
        ok(json!({"evicted":true,"name":name,"removed":removed,"pinsDeleted":pins}))
    };
    tx.commit().await?;
    if delete && public {
        for path in &metadata.paths {
            crate::cdn::schedule_cache(&state, path).await?;
        }
    }
    Ok(response)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn protocol(tx: &mut Transaction, id: i32, kind: &str) -> Result<(), ApiError> {
    let exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM cache_protocols
            WHERE cache_id = $1
                AND protocol = $2
        ) AS "exists!"
        "#,
        id,
        kind
    )
    .fetch_one(&mut **tx)
    .await?;
    if !exists {
        return Err(missing());
    }
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn list_pins(tx: &mut Transaction, id: i32) -> Result<Vec<Value>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            p.name,
            p.keep_kind,
            p.keep_value,
            p.current_revision,
            r.revision,
            r.store_path,
            r.created_at,
            r.superseded_at,
            (r.revision = p.current_revision
                OR p.keep_kind = 'forever'
                OR (p.keep_kind = 'revisions' AND r.revision > p.current_revision - p.keep_value)
                OR (p.keep_kind = 'days' AND r.superseded_at > NOW() - p.keep_value * INTERVAL '1 day')
            ) AS "pinned!"
        FROM pins p
        JOIN pin_revisions r ON r.pin_id = p.id
        WHERE p.cache_id = $1
        ORDER BY p.name, r.revision DESC
        "#,
        id
    ).fetch_all(&mut **tx).await?;
    let mut pins: Vec<Value> = Vec::new();
    for row in rows {
        let name = row.name;
        if pins.last().is_none_or(|p| p["name"] != name) {
            let kind = row.keep_kind;
            let keep = if kind == "forever" {
                json!("forever")
            } else {
                let mut v = json!({});
                v[&kind] = json!(row.keep_value);
                v
            };
            pins.push(json!({"name":name,"keep":keep,"currentRevision":row.current_revision,"history":[]}));
        }
        pins.last_mut().unwrap()["history"].as_array_mut().unwrap().push(json!({
            "revision":row.revision,"storePath":row.store_path,
            "createdAt":date(row.created_at),"supersededAt":optional_date(row.superseded_at),"pinned":row.pinned
        }));
    }
    Ok(pins)
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn put_pin(tx: &mut Transaction, cache: i32, value: Value) -> Result<Response, ApiError> {
    strict(&value, &["name", "storePath", "keep"])?;
    let name = value["name"]
        .as_str()
        .filter(|s| name_valid(s))
        .ok_or_else(|| bad("Invalid format"))?;
    let root = value["storePath"]
        .as_str()
        .filter(|s| store_path_valid(s))
        .ok_or_else(|| bad("storePath must be a full Nix store path"))?;
    let keep = &value["keep"];
    let (kind, count) = if keep == "forever" {
        ("forever", None)
    } else {
        strict(keep, &["days", "revisions"])?;
        let kind = if keep.get("days").is_some() {
            "days"
        } else {
            "revisions"
        };
        if keep.as_object().unwrap().len() != 1 {
            return Err(bad("Invalid keep"));
        }
        let count = keep[kind]
            .as_f64()
            .filter(|n| n.fract() == 0.0 && (1.0..=10000.0).contains(n))
            .ok_or_else(|| bad("Invalid keep"))? as i32;
        (kind, Some(count))
    };
    let existing = sqlx::query!(
        r#"
        SELECT
            p.id,
            p.current_revision,
            r.store_path AS "store_path?"
        FROM pins p
        LEFT JOIN pin_revisions r ON r.pin_id = p.id
            AND r.revision = p.current_revision
        WHERE p.cache_id = $1
            AND p.name = $2
        "#,
        cache,
        name
    )
    .fetch_optional(&mut **tx)
    .await?;
    let closure = sqlx::query!(
        r#"
        WITH RECURSIVE closure(store_path) AS (
            SELECT $2::text
            UNION
            SELECT CASE
                WHEN ref.value LIKE '/nix/store/%' THEN ref.value
                ELSE '/nix/store/' || ref.value
            END
            FROM closure c
            JOIN published_paths p ON p.cache_id = $1
                AND p.store_path_hash = SUBSTR(c.store_path, 12, 32)
                AND p.store_path = c.store_path
            CROSS JOIN LATERAL JSONB_ARRAY_ELEMENTS_TEXT(p.references_json::jsonb) ref(value)
        ), bounded AS MATERIALIZED (
            SELECT store_path
            FROM closure
            LIMIT 10001
        )
        SELECT
            SUBSTR(c.store_path, 12, 32) AS "hash!",
            p.store_path AS "store_path?"
        FROM bounded c
        LEFT JOIN published_paths p ON p.cache_id = $1
            AND p.store_path_hash = SUBSTR(c.store_path, 12, 32)
            AND p.store_path = c.store_path
        "#,
        cache,
        root
    )
    .fetch_all(&mut **tx)
    .await?;
    if closure.len() > 10000 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Pin closure exceeds 10000 paths",
        ));
    }
    if closure.iter().any(|r| r.store_path.is_none())
        || !closure
            .iter()
            .any(|r| r.store_path.as_deref() == Some(root))
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "The root and its entire closure must be published in this cache",
        ));
    }
    let id = existing
        .as_ref()
        .map(|p| p.id.clone())
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    let same = existing
        .as_ref()
        .is_some_and(|p| p.store_path.as_deref() == Some(root));
    let revision = existing.as_ref().map(|p| p.current_revision).unwrap_or(0) + i32::from(!same);
    sqlx::query!(
        r#"
        INSERT INTO pins (
            id,
            cache_id,
            name,
            keep_kind,
            keep_value,
            current_revision
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cache_id, name) DO UPDATE
        SET keep_kind = EXCLUDED.keep_kind,
            keep_value = EXCLUDED.keep_value,
            current_revision = EXCLUDED.current_revision
        "#,
        &id,
        cache,
        name,
        kind,
        count,
        revision
    )
    .execute(&mut **tx)
    .await?;
    if !same {
        sqlx::query!(
            r#"
            UPDATE pin_revisions
            SET superseded_at = NOW()
            WHERE pin_id = $1
                AND revision = $2
            "#,
            &id,
            revision - 1
        )
        .execute(&mut **tx)
        .await?;
        let rev = uuid::Uuid::now_v7().to_string();
        sqlx::query!(
            r#"
            INSERT INTO pin_revisions (
                id,
                pin_id,
                revision,
                store_path
            )
            VALUES ($1, $2, $3, $4)
            "#,
            &rev,
            &id,
            revision,
            root
        )
        .execute(&mut **tx)
        .await?;
        let hashes: Vec<_> = closure.into_iter().map(|r| r.hash).collect();
        sqlx::query!(
            r#"
            INSERT INTO pin_paths (
                revision_id,
                cache_id,
                store_path_hash
            )
            SELECT
                $1,
                $2,
                UNNEST($3::text[])
            "#,
            rev,
            cache,
            &hashes
        )
        .execute(&mut **tx)
        .await?;
    }
    let missing = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM pin_paths m
            JOIN pin_revisions r ON r.id = m.revision_id
            JOIN pins p ON p.id = r.pin_id
            WHERE p.id = $1
                AND (r.revision = p.current_revision
                    OR p.keep_kind = 'forever'
                    OR (p.keep_kind = 'revisions' AND r.revision > p.current_revision - p.keep_value)
                    OR (p.keep_kind = 'days' AND r.superseded_at > NOW() - p.keep_value * INTERVAL '1 day'))
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_paths e
                    WHERE e.cache_id = m.cache_id
                        AND e.store_path_hash = m.store_path_hash
                )
        ) AS "missing!"
        "#,
        id
    ).fetch_one(&mut **tx).await?;
    if missing {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "A retained revision has missing paths; restore its closure before extending keep",
        ));
    }
    let pin = list_pins(tx, cache)
        .await?
        .into_iter()
        .find(|p| p["name"] == name)
        .unwrap();
    Ok(json_response(
        if existing.is_none() {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        json!({"pin":pin}),
    ))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn list_paths(
    tx: &mut Transaction,
    cache: i32,
    p: Vec<(String, String)>,
) -> Result<Response, ApiError> {
    let limit = page_limit(&p, 50)?;
    let query = param(&p, "q").unwrap_or("").trim();
    let query = query.strip_prefix("/nix/store/").unwrap_or(query);
    if query.encode_utf16().count() > 200 {
        return Err(bad("q must be at most 200 characters"));
    }
    let before = param(&p, "before").map(js_number);
    if before.is_some_and(|n| n.fract() != 0.0 || !(1.0..=9_007_199_254_740_991.0).contains(&n)) {
        return Err(bad("before must be a path id"));
    }
    let pattern = format!(
        "%{}%",
        query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let rows = sqlx::query!(
        r#"
        SELECT
            p.id,
            p.store_path,
            p.store_path_hash,
            b.file_size,
            p.nar_size,
            p.created_at,
            p.last_pushed_at
        FROM published_paths p
        JOIN blob_objects b ON b.id = p.blob_object_id
        WHERE p.cache_id = $1
            AND REGEXP_REPLACE(p.store_path, '^.*/', '') ILIKE $2
            AND ($3::bigint IS NULL OR p.id < $3)
        ORDER BY p.id DESC
        LIMIT $4
        "#,
        cache,
        pattern,
        before.map(|n| n as i64),
        limit
    )
    .fetch_all(&mut **tx)
    .await?;
    let next = if rows.len() == limit as usize {
        rows.last().map(|r| r.id)
    } else {
        None
    };
    Ok(ok(
        json!({"paths":rows.iter().map(|r|json!({"storePath":r.store_path,"storePathHash":r.store_path_hash,"size":r.file_size,"narSize":r.nar_size,"addedAt":date(r.created_at),"lastPushedAt":date(r.last_pushed_at)})).collect::<Vec<_>>(),"next":next}),
    ))
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn delete_paths(
    metadata: &MetadataTarget,
    tx: &mut Transaction,
    cache: i32,
    value: Value,
) -> Result<Response, ApiError> {
    // The Worker's deletion schema strips unknown properties; other policy
    // bodies (pins, purge, and cursors) remain strict.
    if !value.is_object() {
        return Err(bad("expected an object"));
    }
    if value.get("storePathHashes").is_some() == value.get("before").is_some() {
        return Err(bad("give one of storePathHashes or before"));
    }
    let mut named: Vec<String> = Vec::new();
    let before = if let Some(raw) = value.get("before") {
        let raw = raw
            .as_str()
            .ok_or_else(|| bad("before must be an ISO 8601 time"))?;
        Some(
            DateTime::parse_from_rfc3339(raw)
                .map(|at| at.with_timezone(&Utc))
                .or_else(|error| {
                    // ISO date-only strings mean midnight UTC in JavaScript.
                    if raw.len() != 10 {
                        return Err(error);
                    }
                    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
                        .map(|date| date.and_hms_opt(0, 0, 0).unwrap().and_utc())
                })
                .map_err(|_| bad("before must be an ISO 8601 time"))?,
        )
    } else {
        let hashes = value["storePathHashes"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 500)
            .ok_or_else(|| bad("storePathHashes must contain 1 to 500 hashes"))?;
        for hash in hashes {
            let h = hash
                .as_str()
                .filter(|h| hash_valid(h))
                .ok_or_else(|| bad("invalid store path hash"))?;
            if !named.iter().any(|n| n == h) {
                named.push(h.into());
            }
        }
        None
    };
    // Named deletion also withdraws orphan narinfo from a failed publication,
    // except that a retained pin protects its metadata as well as its SQL row.
    let protected = sqlx::query_scalar!(
        r#"
        SELECT store_path_hash
        FROM published_paths
        WHERE cache_id = $1
            AND store_path_hash = ANY($2)
            AND nix_path_pinned(cache_id, store_path_hash, NOW())
        "#,
        cache,
        &named
    )
    .fetch_all(&mut **tx)
    .await?;
    let deleted: Vec<String> = if let Some(before) = before {
        sqlx::query_scalar!(
            r#"
            DELETE FROM published_paths
            WHERE cache_id = $1
                AND id IN (
                    SELECT id
                    FROM published_paths
                    WHERE cache_id = $1
                        AND created_at < $2
                        AND NOT nix_path_pinned(cache_id, store_path_hash, NOW())
                    ORDER BY created_at, id
                    LIMIT 500
                )
            RETURNING store_path_hash
            "#,
            cache,
            before
        )
        .fetch_all(&mut **tx)
        .await?
    } else {
        sqlx::query_scalar!(
            r#"
            DELETE FROM published_paths
            WHERE cache_id = $1
                AND store_path_hash = ANY($2)
                AND NOT nix_path_pinned(cache_id, store_path_hash, NOW())
            RETURNING store_path_hash
            "#,
            cache,
            &named
        )
        .fetch_all(&mut **tx)
        .await?
    };
    let mut withdrawn = deleted.clone();
    for hash in &named {
        if !protected.contains(hash) && !withdrawn.contains(hash) {
            withdrawn.push(hash.clone());
        }
    }
    // Fence only the withdrawn paths, including absent named paths. Unrelated
    // uploads remain valid; completed outcomes may replay but never republish.
    sqlx::query(
        "UPDATE upload_sessions SET status='aborted' WHERE cache_id=$1 \
        AND store_path_hash=ANY($2) AND status<>'completed'",
    )
    .bind(cache)
    .bind(&withdrawn)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE nar_installations SET phase='revoked' WHERE session_id IN ( \
        SELECT id FROM upload_sessions WHERE cache_id=$1 AND store_path_hash=ANY($2))",
    )
    .bind(cache)
    .bind(&withdrawn)
    .execute(&mut **tx)
    .await?;
    metadata.withdraw(tx, &withdrawn).await?;
    let gone = if before.is_some() {
        deleted.clone()
    } else {
        named
            .iter()
            .filter(|h| deleted.contains(h))
            .cloned()
            .collect()
    };
    let not_found: Vec<_> = named.iter().filter(|h| !deleted.contains(h)).collect();
    Ok(ok(
        json!({"deleted":gone,"notFound":not_found,"more":before.is_some() && deleted.len()==500}),
    ))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn eviction(
    state: &AppState,
    org: &str,
    p: Vec<(String, String)>,
) -> Result<Response, ApiError> {
    let limit = page_limit(&p, 50)?;
    let mut used: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut id: Option<String> = None;
    if let Some(raw) = param(&p, "nextCursor") {
        let parsed = if raw.len() <= 2048 {
            STANDARD
                .decode(raw)
                .ok()
                .and_then(|s| serde_json::from_slice::<Value>(&s).ok())
        } else {
            None
        };
        let c = parsed.ok_or_else(|| bad("Invalid nextCursor"))?;
        let valid_used = c["used"].as_str().is_some_and(|s| {
            let s = s.strip_prefix('-').unwrap_or(s);
            let chunks: Vec<_> = s.split('.').collect();
            (chunks.len() == 1
                || (chunks.len() == 2
                    && !chunks[1].is_empty()
                    && chunks[1].len() <= 6
                    && chunks[1].bytes().all(|b| b.is_ascii_digit())))
                && !chunks[0].is_empty()
                && chunks[0].len() <= 12
                && chunks[0].bytes().all(|b| b.is_ascii_digit())
        });
        if strict(&c, &["org", "used", "kind", "id"]).is_err()
            || c["org"] != org
            || !valid_used
            || !matches!(c["kind"].as_str(), Some("nix" | "go" | "sccache"))
            || !c["id"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.encode_utf16().count() <= 128)
        {
            return Err(bad("Invalid nextCursor"));
        }
        used = c["used"].as_str().map(str::to_owned);
        kind = c["kind"].as_str().map(str::to_owned);
        id = c["id"].as_str().map(str::to_owned);
    }
    let recent = param(&p, "recentCursor");
    if recent.is_some_and(|s| {
        s.is_empty()
            || !s.bytes().all(|b| b.is_ascii_digit())
            || s.parse::<u64>()
                .map_or(true, |n| n == 0 || n > 9_007_199_254_740_991)
    }) {
        return Err(bad("Invalid recentCursor"));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query!(
        r#"
        SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY
        "#
    )
    .execute(&mut *tx)
    .await?;
    let rows = sqlx::query!(
        r#"
        WITH active AS MATERIALIZED (
            SELECT
                u.cache_id,
                u.store_path_hash
            FROM upload_sessions u
            JOIN caches c ON c.id = u.cache_id
            WHERE c.org_id = $1
                AND (u.status = 'finalizing'
                    OR (u.status IN ('pending', 'uploading', 'streaming') AND u.expires_at > NOW()))
        ), victims AS (
            SELECT
                'nix'::text AS kind,
                e.id::text AS id,
                c.id AS cache_id,
                c.name,
                e.store_path AS key,
                b.file_size AS size,
                e.last_accessed_at,
                GREATEST(e.last_pushed_at, e.last_accessed_at) AS used
            FROM published_paths e
            JOIN caches c ON c.id = e.cache_id
            JOIN blob_objects b ON b.id = e.blob_object_id
            WHERE c.org_id = $1
                AND NOT nix_path_pinned(e.cache_id, e.store_path_hash, NOW())
                AND NOT EXISTS (
                    SELECT 1
                    FROM active a
                    WHERE a.cache_id = e.cache_id
                        AND a.store_path_hash = e.store_path_hash
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM nar_installations i
                    WHERE i.file_hash = b.file_hash
                        AND i.compression = b.compression
                )
            UNION ALL
            SELECT
                'go',
                e.id,
                c.id,
                c.name,
                e.action,
                e.size,
                e.last_accessed_at,
                GREATEST(e.uploaded_at, e.last_accessed_at)
            FROM go_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.go_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
            UNION ALL
            SELECT
                'sccache',
                e.id,
                c.id,
                c.name,
                e.action,
                e.size,
                e.last_accessed_at,
                GREATEST(e.uploaded_at, e.last_accessed_at)
            FROM sccache_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.sccache_generation
                AND e.uploaded_at IS NOT NULL
                AND e.expires_at > NOW()
        )
        SELECT
            kind AS "kind!",
            id AS "id!",
            cache_id AS "cache_id!",
            name AS "name!",
            key AS "key!",
            size AS "size!",
            last_accessed_at,
            used,
            EXTRACT(EPOCH FROM used)::text AS "epoch!"
        FROM victims
        WHERE $2::text IS NULL
            OR (used, kind, id) > (TO_TIMESTAMP($2::double precision), $3::text, $4::text)
        ORDER BY used, kind, id
        LIMIT $5
        "#,
        org,
        used,
        kind,
        id,
        limit + 1
    )
    .fetch_all(&mut *tx)
    .await?;
    let history = sqlx::query!(
        r#"
        SELECT *
        FROM eviction_logs
        WHERE org_id = $1
            AND evicted_at > NOW() - INTERVAL '30 days'
            AND ($2::bigint IS NULL OR id < $2)
        ORDER BY id DESC
        LIMIT $3
        "#,
        org,
        recent.map(|s| s.parse::<i64>().unwrap()),
        limit + 1
    )
    .fetch_all(&mut *tx)
    .await?;
    let bytes = sqlx::query_scalar!(
        r#"
        SELECT GREATEST(0, COALESCE((
            SELECT SUM(n)
            FROM (
                SELECT c.size AS n
                FROM caches c
                WHERE c.org_id = $1
                UNION ALL
                SELECT e.size
                FROM go_entries e
                JOIN caches c ON c.id = e.cache_id
                WHERE c.org_id = $1
                    AND e.generation = c.go_generation
                    AND e.uploaded_at IS NOT NULL
                    AND e.expires_at > NOW()
                UNION ALL
                SELECT e.size
                FROM sccache_entries e
                JOIN caches c ON c.id = e.cache_id
                WHERE c.org_id = $1
                    AND e.generation = c.sccache_generation
                    AND e.uploaded_at IS NOT NULL
                    AND e.expires_at > NOW()
            ) usage
        ), 0) - storage_limit)::bigint AS "bytes!"
        FROM orgs
        WHERE id = $1
        "#,
        org
    )
    .fetch_one(&mut *tx)
    .await?;
    let page: Vec<_> = rows.iter().take(limit as usize).collect();
    let recent_page: Vec<_> = history.iter().take(limit as usize).collect();
    let cursor = if rows.len() > limit as usize {
        page.last().map(|r| {
            STANDARD.encode(json!({"org":org,"used":r.epoch,"kind":r.kind,"id":r.id}).to_string())
        })
    } else {
        None
    };
    let recent_cursor = if history.len() > limit as usize {
        recent_page.last().map(|r| r.id.to_string())
    } else {
        None
    };
    let response = ok(
        json!({"next":{"items":page.iter().map(|r|json!({"product":r.kind,"cache":r.name,"cacheId":r.cache_id,"key":r.key,"size":r.size,"lastAccessedAt":optional_date(r.last_accessed_at)})).collect::<Vec<_>>(),"bytesToFree":bytes,"cursor":cursor},
        "recent":{"items":recent_page.iter().map(|r|json!({"id":r.id,"cacheId":r.cache_id,"cache":r.cache,"product":r.product,"key":r.key,"size":r.size,"lastAccessedAt":optional_date(r.last_accessed_at),"reason":r.reason,"evictedAt":date(r.evicted_at)})).collect::<Vec<_>>(),"cursor":recent_cursor}}),
    );
    tx.commit().await?;
    Ok(response)
}
