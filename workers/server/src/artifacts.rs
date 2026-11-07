//! Generation-scoped compiler artifacts. SQL reserves/adopts/publishes; HTTP
//! bodies stream to attempt-owned files without borrowing a pool connection.
use crate::db::Transaction;
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio_util::io::ReaderStream;

use crate::{
    AppState,
    auth::{Identity, authenticate_write},
    error::ApiError,
    protocol_policy::CallerLimit,
};

#[derive(Clone, Copy, PartialEq)]
pub enum Product {
    Go,
    Sccache,
}
impl Product {
    fn name(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Sccache => "sccache",
        }
    }
    fn permission(self, write: bool) -> &'static str {
        match (self, write) {
            (Self::Go, true) => "go:write",
            (Self::Go, false) => "go:read",
            (Self::Sccache, true) => "sccache:write",
            (Self::Sccache, false) => "sccache:read",
        }
    }
}

#[derive(Clone)]
pub struct Target {
    pub cache_id: i32,
    pub org: String,
    pub public: bool,
    pub generation: String,
    pub created_at: DateTime<Utc>,
    action: String,
}

struct Entry {
    id: String,
    cache_id: Option<i32>,
    generation: String,
    r2_key: String,
    size: i64,
    output: Option<String>,
    stored_at: Option<DateTime<Utc>>,
    uploaded_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    access_due: bool,
}

fn error(status: StatusCode, message: &str) -> ApiError {
    ApiError::new(status, message)
}
fn busy(message: &str) -> ApiError {
    error(StatusCode::SERVICE_UNAVAILABLE, message)
        .header(header::RETRY_AFTER, HeaderValue::from_static("1"))
}
fn lock_error(error: sqlx::Error) -> ApiError {
    if error
        .as_database_error()
        .is_some_and(|error| error.code().as_deref() == Some("55P03"))
    {
        busy("Upload is busy; retry")
    } else {
        error.into()
    }
}
const PRIVATE_REFUSED: &str = "this org does not allow private caches: its private caches keep serving their paths, but take no pushes, and no new ones can be made";

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn target(
    state: &AppState,
    slug: &str,
    name: &str,
    product: Product,
    action: &str,
) -> Result<Option<Target>, ApiError> {
    Ok(match product {
        Product::Go => {
            sqlx::query_as!(
                Target,
                r#"
                SELECT
                    c.id AS cache_id,
                    c.org_id AS org,
                    c.is_public AS public,
                    c.go_generation AS generation,
                    c.created_at,
                    $3::text AS "action!"
                FROM caches c
                JOIN orgs o ON o.id = c.org_id
                WHERE o.slug = $1
                    AND c.name = $2
                    AND EXISTS (
                        SELECT 1
                        FROM cache_protocols p
                        WHERE p.cache_id = c.id
                            AND p.protocol = 'go'
                    )
                "#,
                slug,
                name,
                action,
            )
            .fetch_optional(&state.pool)
            .await?
        }
        Product::Sccache => {
            sqlx::query_as!(
                Target,
                r#"
                SELECT
                    c.id AS cache_id,
                    c.org_id AS org,
                    c.is_public AS public,
                    c.sccache_generation AS generation,
                    c.created_at,
                    $3::text AS "action!"
                FROM caches c
                JOIN orgs o ON o.id = c.org_id
                WHERE o.slug = $1
                    AND c.name = $2
                    AND EXISTS (
                        SELECT 1
                        FROM cache_protocols p
                        WHERE p.cache_id = c.id
                            AND p.protocol = 'sccache'
                    )
                "#,
                slug,
                name,
                action,
            )
            .fetch_optional(&state.pool)
            .await?
        }
    })
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    target: &Target,
    name: &str,
    product: Product,
    write: bool,
) -> Result<(), ApiError> {
    if !write && target.public {
        return Ok(());
    }
    let identity = authenticate_write(headers, state).await?;
    if let Identity::Jwt(claims) = &identity
        && claims.has_permission(product.permission(write))
        && claims.belongs_to(&target.org)
        && claims.has_cache_access(target.cache_id, name)
    {
        state.protocol_limits.check(
            if write {
                CallerLimit::Push
            } else {
                CallerLimit::Read
            },
            &identity.actor(),
        )?;
        return Ok(());
    }
    Err(error(StatusCode::FORBIDDEN, "Forbidden"))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn download(
    state: &AppState,
    target: &Target,
    head: bool,
    product: Product,
) -> Result<Response, ApiError> {
    let kind = product.name();
    let entry = match product {
        Product::Go => sqlx::query_as!(
            Entry,
            r#"
            SELECT
                e.id,
                e.cache_id,
                e.generation,
                e.r2_key,
                e.size,
                e.output,
                e.stored_at,
                e.uploaded_at,
                e.expires_at,
                (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
            FROM go_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.id = $1
                AND c.go_generation = $2
                AND c.is_public = $3
                AND e.generation = $2
                AND e.action = $4
                AND e.expires_at > NOW()
                AND e.uploaded_at IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM cache_protocols p
                    WHERE p.cache_id = c.id
                        AND p.protocol = 'go'
                )
            "#,
            target.cache_id,
            &target.generation,
            target.public,
            &target.action,
        )
        .fetch_optional(&state.pool)
        .await?,
        Product::Sccache => sqlx::query_as!(
            Entry,
            r#"
            SELECT
                e.id,
                e.cache_id,
                e.generation,
                e.r2_key,
                e.size,
                NULL::text AS output,
                e.stored_at,
                e.uploaded_at,
                e.expires_at,
                (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
            FROM sccache_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.id = $1
                AND c.sccache_generation = $2
                AND c.is_public = $3
                AND e.generation = $2
                AND e.action = $4
                AND e.expires_at > NOW()
                AND e.uploaded_at IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM cache_protocols p
                    WHERE p.cache_id = c.id
                        AND p.protocol = 'sccache'
                )
            "#,
            target.cache_id,
            &target.generation,
            target.public,
            &target.action,
        )
        .fetch_optional(&state.pool)
        .await?,
    }
    .ok_or_else(|| error(StatusCode::NOT_FOUND, "Not Found"))?;
    // Compiler artifacts always live in the private bucket, including artifacts
    // belonging to public caches. Only the protocol serves them after its access checks.
    let object = if head {
        state
            .storage
            .head(true, &entry.r2_key)
            .await
            .map(|metadata| (metadata, None))
    } else {
        state
            .storage
            .open(true, &entry.r2_key)
            .await
            .map(|object| (object.metadata, Some(object.reader)))
    }
    .map_err(|e| {
        error(
            if e.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            if e.kind() == std::io::ErrorKind::NotFound {
                "Not Found"
            } else {
                "Internal error"
            },
        )
    })?;
    let (metadata, reader) = object;
    if metadata.size != entry.size as u64 {
        return Err(error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"));
    }
    if entry.expires_at <= Utc::now() {
        return Err(error(StatusCode::NOT_FOUND, "Not Found"));
    }
    // Neither telemetry write depends on the other. Wait for both, without
    // borrowing a transaction or making transfer success depend on telemetry.
    let bandwidth = async {
        if !head
            && sqlx::query!(
                r#"
                INSERT INTO bandwidth_daily (org_id, cache_id, product, day, bytes)
                VALUES ($1, $2, $3, (NOW() AT TIME ZONE 'UTC')::date, $4)
                ON CONFLICT (org_id, cache_id, product, day) DO UPDATE
                SET bytes = bandwidth_daily.bytes + EXCLUDED.bytes
                "#,
                &target.org,
                target.cache_id,
                kind,
                entry.size,
            )
            .execute(&state.pool)
            .await
            .is_err()
        {
            tracing::warn!("Recording compiler bandwidth failed");
        }
    };
    let access = async {
        if entry.access_due {
            let result = match product {
                Product::Go => sqlx::query!(
                    r#"
                    UPDATE go_entries
                    SET last_accessed_at = NOW()
                    WHERE id = $1
                        AND (last_accessed_at IS NULL OR last_accessed_at < NOW() - INTERVAL '5 minutes')
                    "#,
                    &entry.id,
                )
                .execute(&state.pool)
                .await,
                Product::Sccache => sqlx::query!(
                    r#"
                    UPDATE sccache_entries
                    SET last_accessed_at = NOW()
                    WHERE id = $1
                        AND (last_accessed_at IS NULL OR last_accessed_at < NOW() - INTERVAL '5 minutes')
                    "#,
                    &entry.id,
                )
                .execute(&state.pool)
                .await,
            };
            if result.is_err() {
                tracing::warn!("Recording compiler access failed");
            }
        }
    };
    tokio::join!(bandwidth, access);
    if entry.expires_at <= Utc::now() {
        return Err(error(StatusCode::NOT_FOUND, "Not Found"));
    }
    let body = reader.map_or_else(Body::empty, |reader| {
        Body::from_stream(crate::profile_stream!(
            ReaderStream::new(reader),
            label = "artifacts.download_body"
        ))
    });
    let mut response = (
        [
            ("content-type", "application/octet-stream"),
            ("cache-control", "no-store"),
            ("cloudflare-cdn-cache-control", "no-store"),
            ("x-snowstead-cache", "MISS"),
            ("content-length", &entry.size.to_string()),
            ("etag", &format!("\"{}\"", entry.id)),
        ],
        body,
    )
        .into_response();
    if let Some(output) = entry.output {
        response.headers_mut().insert(
            "x-snowstead-output-id",
            HeaderValue::from_str(&output)
                .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Invalid stored output"))?,
        );
    }
    Ok(response)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn consume_hash(body: Body, size: u64) -> Result<String, ApiError> {
    let stream = crate::profile_stream!(body.into_data_stream(), label = "artifacts.consume_body");
    futures_util::pin_mut!(stream);
    let mut count = 0u64;
    let mut hash = Sha256::new();
    while let Some(bytes) = stream.next().await {
        let bytes = bytes.map_err(|_| error(StatusCode::BAD_REQUEST, "Content length mismatch"))?;
        count = count.saturating_add(bytes.len() as u64);
        if count > size {
            return Err(error(StatusCode::BAD_REQUEST, "Content length mismatch"));
        }
        crate::profile_block!("artifacts.consume_hash", hash.update(&bytes));
    }
    if count != size {
        return Err(error(StatusCode::BAD_REQUEST, "Content length mismatch"));
    }
    Ok(hex::encode(hash.finalize()))
}
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn consume(body: Body, size: u64) -> Result<(), ApiError> {
    consume_hash(body, size).await.map(|_| ())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn org_lock(tx: &mut Transaction, org: &str) -> Result<(), ApiError> {
    let key = format!("org:{org}");
    crate::profile_future!(
        crate::db::advisory_lock(tx, &key),
        label = "artifacts.org_lock_wait"
    )
    .await?;
    Ok(())
}

// Every compiler writer takes org -> cache -> entry. The cache row also fences
// reset/deletion, which cannot be undone by an older in-flight transfer.
struct Policy {
    generation: String,
    public: bool,
    private_caches: bool,
    storage_limit: Option<i64>,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn policy(
    tx: &mut Transaction,
    target: &Target,
    product: Product,
    changed_status: StatusCode,
) -> Result<Option<i64>, ApiError> {
    let row = crate::profile_future!(
        async {
            match product {
                Product::Go => {
                    sqlx::query_as!(
                        Policy,
                        r#"
                        SELECT
                            c.go_generation AS generation,
                            c.is_public AS public,
                            o.private_caches,
                            o.storage_limit
                        FROM caches c
                        JOIN orgs o ON o.id = c.org_id
                        WHERE c.id = $1
                            AND c.org_id = $2
                            AND EXISTS (
                                SELECT 1
                                FROM cache_protocols p
                                WHERE p.cache_id = c.id
                                    AND p.protocol = 'go'
                            )
                        FOR SHARE OF c, o NOWAIT
                        "#,
                        target.cache_id,
                        &target.org,
                    )
                    .fetch_optional(&mut **tx)
                    .await
                }
                Product::Sccache => {
                    sqlx::query_as!(
                        Policy,
                        r#"
                        SELECT
                            c.sccache_generation AS generation,
                            c.is_public AS public,
                            o.private_caches,
                            o.storage_limit
                        FROM caches c
                        JOIN orgs o ON o.id = c.org_id
                        WHERE c.id = $1
                            AND c.org_id = $2
                            AND EXISTS (
                                SELECT 1
                                FROM cache_protocols p
                                WHERE p.cache_id = c.id
                                    AND p.protocol = 'sccache'
                            )
                        FOR SHARE OF c, o NOWAIT
                        "#,
                        target.cache_id,
                        &target.org,
                    )
                    .fetch_optional(&mut **tx)
                    .await
                }
            }
        },
        label = "artifacts.policy_row_lock"
    )
    .await
    .map_err(lock_error)?;
    let changed = || {
        if changed_status == StatusCode::SERVICE_UNAVAILABLE {
            busy("Cache changed; retry")
        } else {
            error(changed_status, "Cache changed; retry")
        }
    };
    let Some(row) = row else {
        return Err(changed());
    };
    if row.generation != target.generation {
        return Err(changed());
    }
    if !row.public && !row.private_caches {
        return Err(error(StatusCode::FORBIDDEN, PRIVATE_REFUSED));
    }
    Ok(row.storage_limit)
}

struct StagingUsage {
    count: i64,
    bytes: i64,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn reserve(
    state: &AppState,
    target: &Target,
    product: Product,
    action: &str,
    size: u64,
    output: Option<&str>,
) -> Result<Entry, ApiError> {
    let kind = product.name();
    let mut tx = crate::profile_future!(
        crate::db::begin(state, &target.org),
        label = "artifacts.reserve_pool_begin"
    )
    .await?;
    org_lock(&mut tx, &target.org).await?;
    let mut limit = policy(&mut tx, target, product, StatusCode::CONFLICT).await?;
    let too_large = || {
        error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Artifact exceeds retained capacity",
        )
    };
    if product == Product::Go && limit.is_some_and(|n| size > n as u64) {
        return Err(too_large());
    }
    let existing = match product {
        Product::Go => sqlx::query_as!(
            Entry,
            r#"
            WITH expired AS (
                UPDATE go_entries
                SET cache_id = NULL
                WHERE cache_id = $1
                    AND generation = $2
                    AND action = $3
                    AND expires_at <= NOW()
            )
            SELECT
                e.id,
                e.cache_id,
                e.generation,
                e.r2_key,
                e.size,
                e.output,
                e.stored_at,
                e.uploaded_at,
                e.expires_at,
                (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
            FROM go_entries e
            WHERE e.cache_id = $1
                AND e.generation = $2
                AND e.action = $3
                AND e.expires_at > NOW()
            FOR UPDATE OF e NOWAIT
            "#,
            target.cache_id,
            &target.generation,
            action,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(lock_error)?,
        Product::Sccache => sqlx::query_as!(
            Entry,
            r#"
            WITH expired AS (
                UPDATE sccache_entries
                SET cache_id = NULL
                WHERE cache_id = $1
                    AND generation = $2
                    AND action = $3
                    AND expires_at <= NOW()
            )
            SELECT
                e.id,
                e.cache_id,
                e.generation,
                e.r2_key,
                e.size,
                NULL::text AS output,
                e.stored_at,
                e.uploaded_at,
                e.expires_at,
                (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
            FROM sccache_entries e
            WHERE e.cache_id = $1
                AND e.generation = $2
                AND e.action = $3
                AND e.expires_at > NOW()
            FOR UPDATE OF e NOWAIT
            "#,
            target.cache_id,
            &target.generation,
            action,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(lock_error)?,
    };
    let existing = match existing {
        Some(entry)
            if entry.stored_at.is_some()
                || entry.uploaded_at.is_some()
                || size <= entry.size as u64 =>
        {
            tx.commit().await?;
            return Ok(entry);
        }
        Some(entry) => {
            // A lost pre-migration acknowledgement may leave an immutable
            // object without stored_at. It needs no reservation growth. Probe
            // without holding SQL locks, then revalidate before growing.
            tx.commit().await?;
            match state.storage.head(true, &entry.r2_key).await {
                Ok(_) => return Ok(entry),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")),
            }
            tx = crate::db::begin(state, &target.org).await?;
            org_lock(&mut tx, &target.org).await?;
            limit = policy(&mut tx, target, product, StatusCode::CONFLICT).await?;
            let current = locked_entry(&mut tx, target, product, &entry.id).await?;
            if current.r2_key != entry.r2_key
                || current.size != entry.size
                || current.output != entry.output
                || current.stored_at != entry.stored_at
                || current.uploaded_at != entry.uploaded_at
            {
                return Err(busy("Upload changed; retry"));
            }
            Some(current)
        }
        None => None,
    };
    if limit.is_some_and(|n| size > n as u64) {
        return Err(too_large());
    }
    let staging = match product {
        Product::Go => {
            sqlx::query_as!(
                StagingUsage,
                r#"
                SELECT
                    COUNT(*) AS "count!",
                    COALESCE(SUM(e.size), 0)::bigint AS "bytes!"
                FROM go_entries e
                JOIN caches c ON c.id = e.cache_id
                WHERE c.org_id = $1
                    AND e.uploaded_at IS NULL
                    AND e.expires_at > NOW()
                "#,
                &target.org,
            )
            .fetch_one(&mut *tx)
            .await?
        }
        Product::Sccache => {
            sqlx::query_as!(
                StagingUsage,
                r#"
                SELECT
                    COUNT(*) AS "count!",
                    COALESCE(SUM(e.size), 0)::bigint AS "bytes!"
                FROM sccache_entries e
                JOIN caches c ON c.id = e.cache_id
                WHERE c.org_id = $1
                    AND e.uploaded_at IS NULL
                    AND e.expires_at > NOW()
                "#,
                &target.org,
            )
            .fetch_one(&mut *tx)
            .await?
        }
    };
    let additional = (size as i64).saturating_sub(existing.as_ref().map_or(0, |e| e.size));
    if (existing.is_none() && staging.count >= 256)
        || staging.bytes.saturating_add(additional) > limit.unwrap_or(1024 * 1024 * 1024)
    {
        return Err(busy("Upload staging is busy; retry"));
    }
    if let Some(mut entry) = existing {
        match product {
            Product::Go => {
                sqlx::query!(
                    "UPDATE go_entries SET size = $2 WHERE id = $1",
                    &entry.id,
                    size as i64,
                )
                .execute(&mut *tx)
                .await?
            }
            Product::Sccache => {
                sqlx::query!(
                    "UPDATE sccache_entries SET size = $2 WHERE id = $1",
                    &entry.id,
                    size as i64,
                )
                .execute(&mut *tx)
                .await?
            }
        };
        entry.size = size as i64;
        tx.commit().await?;
        return Ok(entry);
    }
    let id = uuid::Uuid::now_v7().to_string();
    let key = format!(
        "{kind}/{}/{}/{action}/{id}",
        target.cache_id, target.generation
    );
    let inserted = match product {
        Product::Go => sqlx::query_as!(
            Entry,
            r#"
            INSERT INTO go_entries AS e (
                id,
                cache_id,
                generation,
                action,
                r2_key,
                size,
                expires_at,
                output
            )
            VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '1 hour', $7)
            ON CONFLICT DO NOTHING
            RETURNING
                e.id,
                e.cache_id,
                e.generation,
                e.r2_key,
                e.size,
                e.output,
                e.stored_at,
                e.uploaded_at,
                e.expires_at,
                (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
            "#,
            &id,
            target.cache_id,
            &target.generation,
            action,
            &key,
            size as i64,
            output,
        )
        .fetch_optional(&mut *tx)
        .await?,
        Product::Sccache => sqlx::query_as!(
            Entry,
            r#"
            INSERT INTO sccache_entries AS e (
                id,
                cache_id,
                generation,
                action,
                r2_key,
                size,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '1 hour')
            ON CONFLICT DO NOTHING
            RETURNING
                e.id,
                e.cache_id,
                e.generation,
                e.r2_key,
                e.size,
                NULL::text AS output,
                e.stored_at,
                e.uploaded_at,
                e.expires_at,
                (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
            "#,
            &id,
            target.cache_id,
            &target.generation,
            action,
            &key,
            size as i64,
        )
        .fetch_optional(&mut *tx)
        .await?,
    };
    let entry = match inserted {
        Some(entry) => entry,
        None => match product {
            Product::Go => sqlx::query_as!(
                Entry,
                r#"
                SELECT
                    e.id,
                    e.cache_id,
                    e.generation,
                    e.r2_key,
                    e.size,
                    e.output,
                    e.stored_at,
                    e.uploaded_at,
                    e.expires_at,
                    (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
                FROM go_entries e
                WHERE e.cache_id = $1
                    AND e.generation = $2
                    AND e.action = $3
                    AND e.expires_at > NOW()
                FOR UPDATE OF e NOWAIT
                "#,
                target.cache_id,
                &target.generation,
                action,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(lock_error)?,
            Product::Sccache => sqlx::query_as!(
                Entry,
                r#"
                SELECT
                    e.id,
                    e.cache_id,
                    e.generation,
                    e.r2_key,
                    e.size,
                    NULL::text AS output,
                    e.stored_at,
                    e.uploaded_at,
                    e.expires_at,
                    (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
                FROM sccache_entries e
                WHERE e.cache_id = $1
                    AND e.generation = $2
                    AND e.action = $3
                    AND e.expires_at > NOW()
                FOR UPDATE OF e NOWAIT
                "#,
                target.cache_id,
                &target.generation,
                action,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(lock_error)?,
        }
        .ok_or_else(|| error(StatusCode::CONFLICT, "Action changed; retry"))?,
    };
    tx.commit().await?;
    Ok(entry)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn locked_entry(
    tx: &mut Transaction,
    target: &Target,
    product: Product,
    id: &str,
) -> Result<Entry, ApiError> {
    let entry: Entry = crate::profile_future!(
        async {
            match product {
                Product::Go => sqlx::query_as!(
                    Entry,
                    r#"
                    SELECT
                        e.id,
                        e.cache_id,
                        e.generation,
                        e.r2_key,
                        e.size,
                        e.output,
                        e.stored_at,
                        e.uploaded_at,
                        e.expires_at,
                        (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
                    FROM go_entries e
                    WHERE e.id = $1
                    FOR UPDATE NOWAIT
                    "#,
                    id,
                )
                .fetch_optional(&mut **tx)
                .await,
                Product::Sccache => sqlx::query_as!(
                    Entry,
                    r#"
                    SELECT
                        e.id,
                        e.cache_id,
                        e.generation,
                        e.r2_key,
                        e.size,
                        NULL::text AS output,
                        e.stored_at,
                        e.uploaded_at,
                        e.expires_at,
                        (e.last_accessed_at IS NULL OR e.last_accessed_at < NOW() - INTERVAL '5 minutes') AS "access_due!"
                    FROM sccache_entries e
                    WHERE e.id = $1
                    FOR UPDATE NOWAIT
                    "#,
                    id,
                )
                .fetch_optional(&mut **tx)
                .await,
            }
        },
        label = "artifacts.entry_row_lock"
    )
    .await
    .map_err(lock_error)?
    .ok_or_else(|| busy("Upload expired; retry"))?;
    if entry.cache_id != Some(target.cache_id)
        || entry.generation != target.generation
        || entry.expires_at <= Utc::now()
    {
        return Err(busy("Upload expired; retry"));
    }
    Ok(entry)
}

struct Transfer {
    key: String,
    stored_at: DateTime<Utc>,
    created: bool,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn finish(
    state: &AppState,
    target: &Target,
    product: Product,
    expected: &Entry,
    attempt: Option<Transfer>,
) -> Result<Response, ApiError> {
    let id = &expected.id;
    let kind = product.name();
    let mut tx = crate::profile_future!(
        crate::db::begin(state, &target.org),
        label = "artifacts.adopt_pool_begin"
    )
    .await?;
    org_lock(&mut tx, &target.org).await?;
    policy(&mut tx, target, product, StatusCode::SERVICE_UNAVAILABLE).await?;
    let entry = locked_entry(&mut tx, target, product, id).await?;
    let won = entry.stored_at.is_none() && entry.uploaded_at.is_none();
    if !won
        && ((product == Product::Go
            && (entry.size != expected.size || entry.output != expected.output))
            || (product == Product::Sccache
                && entry.uploaded_at.is_none()
                && entry.size != expected.size))
    {
        tx.rollback().await?;
        if let Some(transfer) = &attempt
            && transfer.key != entry.r2_key
        {
            let _ = state.storage.delete(true, &transfer.key).await;
        }
        return Err(error(
            StatusCode::CONFLICT,
            if product == Product::Go {
                "Action already has a different output"
            } else {
                "Upload in progress; retry"
            },
        ));
    }
    if won {
        let transfer = attempt
            .as_ref()
            .ok_or_else(|| busy("Upload changed; retry"))?;
        match product {
            Product::Go => {
                sqlx::query!(
                    r#"
                    UPDATE go_entries
                    SET
                        r2_key = $2,
                        stored_at = $3,
                        size = $4,
                        output = $5
                    WHERE id = $1
                    "#,
                    id,
                    &transfer.key,
                    transfer.stored_at,
                    expected.size,
                    expected.output.as_deref(),
                )
                .execute(&mut *tx)
                .await?
            }
            Product::Sccache => {
                sqlx::query!(
                    r#"
                    UPDATE sccache_entries
                    SET
                        r2_key = $2,
                        stored_at = $3,
                        size = $4
                    WHERE id = $1
                    "#,
                    id,
                    &transfer.key,
                    transfer.stored_at,
                    expected.size,
                )
                .execute(&mut *tx)
                .await?
            }
        };
    }
    // If this acknowledgement is lost, keep the possibly adopted attempt.
    // Reclamation of crash/cancellation orphans belongs to maintenance.
    tx.commit().await?;
    if !won
        && let Some(transfer) = &attempt
        && transfer.key != entry.r2_key
    {
        let _ = state.storage.delete(true, &transfer.key).await;
    }
    let mut tx = crate::profile_future!(
        crate::db::begin(state, &target.org),
        label = "artifacts.publish_pool_begin"
    )
    .await?;
    org_lock(&mut tx, &target.org).await?;
    let limit = policy(&mut tx, target, product, StatusCode::SERVICE_UNAVAILABLE).await?;
    let entry = locked_entry(&mut tx, target, product, id).await?;
    if let Some(limit) = limit {
        crate::capacity::admit(
            &mut tx,
            &target.org,
            limit,
            if entry.uploaded_at.is_none() {
                entry.size
            } else {
                0
            },
            &[(target.cache_id, format!("{kind}:{id}"))],
        )
        .await
        .map_err(|e| {
            if e.status == StatusCode::SERVICE_UNAVAILABLE {
                e.header(header::RETRY_AFTER, HeaderValue::from_static("1"))
            } else {
                e
            }
        })?;
    }
    if entry.uploaded_at.is_none() {
        let stored = entry
            .stored_at
            .ok_or_else(|| busy("Upload changed; retry"))?;
        match product {
            Product::Go => {
                sqlx::query!(
                    r#"
                    UPDATE go_entries
                    SET
                        uploaded_at = $2,
                        expires_at = $2::timestamptz + INTERVAL '7 days'
                    WHERE id = $1
                    "#,
                    id,
                    stored,
                )
                .execute(&mut *tx)
                .await?
            }
            Product::Sccache => {
                sqlx::query!(
                    r#"
                    UPDATE sccache_entries
                    SET
                        uploaded_at = $2,
                        expires_at = $2::timestamptz + INTERVAL '7 days'
                    WHERE id = $1
                    "#,
                    id,
                    stored,
                )
                .execute(&mut *tx)
                .await?
            }
        };
    }
    tx.commit().await?;
    Ok((
        if won && attempt.as_ref().is_some_and(|t| t.created) {
            StatusCode::CREATED
        } else {
            StatusCode::NO_CONTENT
        },
        [("cache-control", "no-store")],
    )
        .into_response())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn upload(
    state: &AppState,
    target: &Target,
    product: Product,
    action: &str,
    size: u64,
    output: Option<&str>,
    body: Body,
) -> Result<Response, ApiError> {
    let mut entry = reserve(state, target, product, action, size, output).await?;
    let mismatch = || {
        error(
            StatusCode::BAD_REQUEST,
            if product == Product::Go {
                "Artifact checksum or length mismatch"
            } else {
                "Content length mismatch"
            },
        )
    };
    let stored = entry.stored_at.or(entry.uploaded_at);
    let recovered = if stored.is_none() {
        match state.storage.head(true, &entry.r2_key).await {
            Ok(metadata) => Some(metadata.last_modified),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")),
        }
    } else {
        None
    };
    if product == Product::Go
        && (stored.is_some() || recovered.is_some())
        && (entry.output.as_deref() != output || entry.size != size as i64)
    {
        if consume_hash(body, size)
            .await
            .map_err(|_| mismatch())?
            .as_str()
            != output.unwrap_or("")
        {
            return Err(mismatch());
        }
        return Err(error(
            StatusCode::CONFLICT,
            "Action already has a different output",
        ));
    }
    if product == Product::Sccache
        && entry.uploaded_at.is_none()
        && (stored.is_some() || recovered.is_some())
        && entry.size != size as i64
    {
        return Err(error(StatusCode::CONFLICT, "Upload in progress; retry"));
    }
    let attempt = if stored.is_some() || recovered.is_some() {
        let digest = consume_hash(body, size).await.map_err(|_| mismatch())?;
        if product == Product::Go && Some(digest.as_str()) != output {
            return Err(mismatch());
        }
        recovered.map(|stored_at| Transfer {
            key: entry.r2_key.clone(),
            stored_at,
            created: false,
        })
    } else {
        let key = format!(
            "{}-attempt/{}/{}",
            product.name(),
            entry.id,
            uuid::Uuid::now_v7()
        );
        // Attempts share a byte reservation, not an output commitment. The
        // first verified transfer to be adopted fixes the output and size.
        let digest = match state.storage.write_body(true, &key, body, size).await {
            Ok(hash) => hash,
            Err(e) => {
                return Err(if e.status == StatusCode::BAD_REQUEST {
                    mismatch()
                } else {
                    e
                });
            }
        };
        if product == Product::Go && Some(digest.as_str()) != output {
            let _ = state.storage.delete(true, &key).await;
            return Err(mismatch());
        }
        Some(Transfer {
            key,
            stored_at: Utc::now(),
            created: true,
        })
    };
    // Publication is tracked independently of the client connection and drained
    // on shutdown. Cancellation cannot remove a source after SQL adopts it.
    let owned = state.clone();
    let target = target.clone();
    entry.size = size as i64;
    entry.output = output.map(str::to_owned);
    state
        .tasks
        .spawn(crate::profile_future!(
            async move { finish(&owned, &target, product, &entry, attempt).await },
            label = "artifacts.publication"
        ))
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Publication failed"))?
}
