use std::{io, time::SystemTime};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use tokio_util::io::ReaderStream;

use crate::{
    AppState, auth::authorize_read, error::ApiError, protocol_policy::CallerLimit, signing,
};

pub(crate) const INFO: &str = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n";
const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
static ACCESS_WRITES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);

fn record_access(state: &AppState, cache: i32, hash: &str) {
    // LRU telemetry is best-effort, not part of delivering bytes. Bound tasks
    // rather than growing a per-path map or queue behind the database pool.
    let Ok(permit) = ACCESS_WRITES.try_acquire() else {
        return;
    };
    let owned = state.clone();
    let hash = hash.to_owned();
    state.tasks.spawn(async move {
        let _permit = permit;
        if sqlx::query!(
            r#"
            UPDATE published_paths
            SET last_accessed_at = NOW()
            WHERE cache_id = $1
                AND store_path_hash = $2
                AND (last_accessed_at IS NULL OR last_accessed_at < NOW() - INTERVAL '5 minutes')
            "#,
            cache,
            hash,
        )
        .execute(&owned.pool)
        .await
        .is_err()
        {
            tracing::warn!("Recording Nix access failed");
        }
    });
}

fn missing(private: bool) -> Response {
    (
        StatusCode::NOT_FOUND,
        [(
            "cache-control",
            if private {
                "private, no-cache"
            } else {
                "no-store"
            },
        )],
        "Not Found",
    )
        .into_response()
}

fn storage_error(error: io::Error, private: bool) -> Result<Response, ApiError> {
    if error.kind() == io::ErrorKind::NotFound {
        Ok(missing(private))
    } else {
        Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error",
        ))
    }
}

pub(crate) fn valid_name(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_blob(hash: &str, compression: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && matches!(compression, "zstd" | "xz" | "bzip2" | "none")
}

/// Called only after public cache/product and (for NARs) membership admission.
fn public_delivery(
    state: &AppState,
    request: &axum::http::request::Parts,
    key: &str,
) -> Option<Response> {
    if state.config.public_cache_origin.is_empty() {
        return None;
    }
    // Only committed bucket pointers or validated legacy keys enter the URL.
    // Never forward a token,
    // request query, or caller-controlled authority to the public bucket.
    let location = format!(
        "{}/{key}",
        state.config.public_cache_origin.trim_end_matches('/')
    );
    let target = reqwest::Url::parse(&location).expect("validated public cache origin");
    // URL normalization handles case, IPv6, and explicit default ports.
    let same_origin_authority = |authority: &str| {
        reqwest::Url::parse(&format!("{}://{authority}", target.scheme()))
            .is_ok_and(|url| url.origin() == target.origin())
    };
    let same_authority = request
        .uri
        .authority()
        .is_some_and(|v| same_origin_authority(v.as_str()))
        || request
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(same_origin_authority);
    let configured_origin = reqwest::Url::parse(&state.config.public_url).ok();
    // public_url is trusted configuration. Host/URI checks are conservative
    // (scheme-independent); spoofable Forwarded/X-Forwarded-* are never used.
    let configured_same_origin =
        configured_origin.is_some_and(|url| url.origin() == target.origin());
    if request.uri.path() == target.path() && (same_authority || configured_same_origin) {
        return Some(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("cache-control", "no-store")],
                "Public cache redirect loop",
            )
                .into_response(),
        );
    }
    Some(
        (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", target.as_str()), ("cache-control", "no-store")],
        )
            .into_response(),
    )
}

pub async fn handle(State(state): State<AppState>, request: Request) -> Result<Response, ApiError> {
    #[cfg(feature = "profiling")]
    let _profile = hotpath::functions::build_measurement_guard_block(
        concat!(module_path!(), "::handle"),
        false,
    );
    let client_ip = crate::app::client_ip(&state, &request);
    let (request, _) = request.into_parts();
    let alias = request
        .extensions
        .get::<crate::cache_host::OrganizationHost>();
    if request.method != Method::GET && request.method != Method::HEAD {
        return Ok((
            StatusCode::METHOD_NOT_ALLOWED,
            [("allow", "GET, HEAD")],
            "Method Not Allowed",
        )
            .into_response());
    }
    let mut segments: Vec<_> = request
        .uri
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if alias.is_none() && segments.first() == Some(&"private") {
        segments.remove(0);
    }
    if alias.is_none()
        && let ["nar", hash, file] = segments.as_slice()
        && let Some(compression) = file.strip_suffix(".nar")
    {
        if !valid_blob(hash, compression) {
            return Ok(missing(false));
        }
        // A public object left behind by a withdrawal never becomes an
        // unscoped way to read a private cache's content.
        let key = sqlx::query_scalar::<_, Option<String>>(
            r#"
                SELECT COALESCE(b.public_key, CASE WHEN b.r2_key NOT LIKE '%/objects/%'
                    THEN 'nar/' || b.file_hash || '/' || b.compression || '.nar' END)
                FROM published_paths p
                JOIN blob_objects b ON b.id = p.blob_object_id
                JOIN caches c ON c.id = p.cache_id
                WHERE c.is_public
                    AND b.file_hash = $1
                    AND b.compression = $2
                    AND EXISTS (
                        SELECT 1
                        FROM cache_protocols cp
                        WHERE cp.cache_id = c.id
                            AND cp.protocol = 'nix'
                    )
                LIMIT 1
            "#,
        )
        .bind(hash)
        .bind(compression)
        .fetch_optional(&state.pool)
        .await?
        .flatten();
        let Some(key) = key else {
            return Ok(missing(false));
        };
        if let Some(response) = public_delivery(&state, &request, &key) {
            return Ok(response);
        }
        return nar(&state, &request, &key, None).await;
    }
    if segments.len() < 2 {
        return Ok(missing(false));
    }
    let (slug, name, rest) = if let Some(host) = alias {
        // Alias paths are strict, cache-scoped paths, not canonical paths or
        // the legacy /private prefix. Do not normalize repeated separators.
        if request.uri.path().split('/').skip(1).any(str::is_empty) {
            return Ok(missing(false));
        }
        (host.0.as_str(), segments[0], &segments[1..])
    } else if segments[1] == "nix-cache-info"
        || segments[1] == "nar"
        || segments[1].ends_with(".narinfo")
    {
        ("default", segments[0], &segments[1..])
    } else {
        if segments.len() < 3 {
            return Ok(missing(false));
        }
        (segments[0], segments[1], &segments[2..])
    };
    if !valid_name(name, 64)
        || !valid_name(slug, 39)
        || matches!(slug, "nar" | "private" | "_api" | "healthz")
    {
        return Ok(missing(false));
    }
    struct Cache {
        id: i32,
        org_id: String,
        is_public: bool,
        slug: String,
    }
    let cache = sqlx::query_as!(
        Cache,
        r#"
        SELECT
            c.id,
            c.org_id,
            c.is_public,
            o.slug
        FROM caches c
        JOIN orgs o ON o.id = c.org_id
        WHERE c.name = $1
            AND (o.slug = $2 OR o.moving_from = $2)
            AND EXISTS (
                SELECT 1
                FROM cache_protocols cp
                WHERE cp.cache_id = c.id
                    AND cp.protocol = 'nix'
            )
        "#,
        name,
        slug,
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some(Cache {
        id,
        org_id: org,
        is_public: public,
        slug: current_slug,
    }) = cache
    else {
        return Ok(missing(false));
    };
    let private = !public;
    if private {
        authorize_read(&request.headers, &state, id, name, &org).await?;
        let path = if slug == "default" {
            name.to_owned()
        } else {
            format!("{slug}/{name}")
        };
        let ip = client_ip.as_deref().unwrap_or("unknown");
        state
            .protocol_limits
            .check(CallerLimit::Read, &format!("{path}:{ip}"))?;
    }
    // Historical private addresses stay authenticated but do not expose
    // leftovers after an organization moves to a new slug.
    if current_slug != slug {
        return Ok(missing(private));
    }
    let cache_path = if slug == "default" {
        name.to_owned()
    } else {
        format!("{slug}/{name}")
    };
    match rest {
        ["nix-cache-info"] => Ok((
            [
                ("content-type", "text/x-nix-cache-info"),
                (
                    "cache-control",
                    if private {
                        "private, no-cache"
                    } else {
                        "public, max-age=3600"
                    },
                ),
                ("content-length", &INFO.len().to_string()),
            ],
            INFO,
        )
            .into_response()),
        [file] if file.ends_with(".narinfo") => {
            let hash = file.strip_suffix(".narinfo").unwrap();
            if hash.len() != 32 || !hash.bytes().all(|b| NIX32.contains(&b)) {
                return Ok(missing(private));
            }
            let response = scoped_narinfo(&state, &request, id, &cache_path, hash, private).await?;
            if response.status().is_success() {
                record_access(&state, id, hash);
            }
            Ok(response)
        }
        ["nar", hash, file] if file.ends_with(".nar") => {
            let compression = file.strip_suffix(".nar").unwrap();
            if !valid_blob(hash, compression) {
                return Ok(missing(private));
            }
            let key = sqlx::query_scalar::<_, Option<String>>(
                r#"
                    SELECT CASE WHEN $4 THEN
                        COALESCE(b.private_key, CASE WHEN b.r2_key NOT LIKE '%/objects/%'
                            THEN 'nars/sha256/' || b.file_hash || '/' || b.compression || '.nar' END)
                    ELSE
                        COALESCE(b.public_key, CASE WHEN b.r2_key NOT LIKE '%/objects/%'
                            THEN 'nar/' || b.file_hash || '/' || b.compression || '.nar' END)
                    END
                    FROM published_paths p
                    JOIN blob_objects b ON b.id = p.blob_object_id
                    WHERE p.cache_id = $1
                        AND b.file_hash = $2
                        AND b.compression = $3
                    LIMIT 1
                "#,
            )
            .bind(id)
            .bind(hash)
            .bind(compression)
            .bind(private)
            .fetch_optional(&state.pool)
            .await?
            .flatten();
            let Some(key) = key else {
                return Ok(missing(private));
            };
            if !private && let Some(response) = public_delivery(&state, &request, &key) {
                return Ok(response);
            }
            nar(
                &state,
                &request,
                &key,
                if private { Some((id, &org)) } else { None },
            )
            .await
        }
        _ => Ok(missing(private)),
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn nar(
    state: &AppState,
    request: &axum::http::request::Parts,
    key: &str,
    scope: Option<(i32, &str)>,
) -> Result<Response, ApiError> {
    let private = scope.is_some();
    let object = match if request.method == Method::HEAD {
        state
            .storage
            .head(private, key)
            .await
            .map(|metadata| (metadata, None))
    } else {
        state
            .storage
            .open(private, key)
            .await
            .map(|object| (object.metadata, Some(object.reader)))
    } {
        Ok(object) => object,
        Err(error) => return storage_error(error, private),
    };
    let (metadata, reader) = object;
    let size = metadata.size;
    if let Some((id, org)) = scope
        && request.method == Method::GET
    {
        // Count the admitted transfer, like the hosted read path; HEADs do not count.
        if sqlx::query!(
            r#"
            INSERT INTO bandwidth_daily (org_id, cache_id, product, day, bytes)
            VALUES ($1, $2, 'nix', (NOW() AT TIME ZONE 'UTC')::date, $3)
            ON CONFLICT (org_id, cache_id, product, day)
            DO UPDATE SET bytes = bandwidth_daily.bytes + EXCLUDED.bytes
            "#,
            org,
            id,
            size as i64,
        )
        .execute(&state.pool)
        .await
        .is_err()
        {
            tracing::warn!("Recording Nix bandwidth failed");
        }
    }
    let body = reader.map_or_else(Body::empty, |reader| {
        Body::from_stream(crate::profile_stream!(
            ReaderStream::new(reader),
            label = "reads.nar_body"
        ))
    });
    Ok((
        [
            ("content-type", "application/x-nix-nar"),
            (
                "cache-control",
                if private {
                    "private, no-cache"
                } else {
                    "public, max-age=31536000, immutable"
                },
            ),
            ("content-length", &size.to_string()),
        ],
        body,
    )
        .into_response())
}

struct ScopedNarinfo {
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
    signing_key_name: Option<String>,
    signing_public_key: Option<String>,
    signing_key_sealed: Option<String>,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn scoped_narinfo(
    state: &AppState,
    request: &axum::http::request::Parts,
    cache: i32,
    cache_path: &str,
    hash: &str,
    private: bool,
) -> Result<Response, ApiError> {
    // SQL publication is authoritative. Never consult mutable metadata objects:
    // new publications no longer write them, and old ones may be stale.
    // Read signing columns in the same fresh statement snapshot as publication.
    let published = sqlx::query_as!(
        ScopedNarinfo,
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
            b.compression,
            c.signing_key_name,
            c.signing_public_key,
            c.signing_key_sealed
        FROM published_paths p
        JOIN blob_objects b ON b.id = p.blob_object_id
        JOIN caches c ON c.id = p.cache_id
        WHERE p.cache_id = $1
            AND p.store_path_hash = $2
        "#,
        cache,
        hash,
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some(p) = published else {
        return Ok(missing(private));
    };
    if !valid_blob(&p.file_hash, &p.compression) {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid stored blob",
        ));
    }
    let nar = signing::Narinfo {
        store_path: p.store_path,
        store_path_hash: hash.to_owned(),
        nar_hash: p.nar_hash,
        nar_size: p.nar_size,
        references: serde_json::from_str(&p.references_json).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid stored references",
            )
        })?,
        deriver: p.deriver,
        system: p.system,
        signatures: serde_json::from_str(&p.signatures_json).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid stored signatures",
            )
        })?,
        file_hash: p.file_hash,
        file_size: p.file_size,
        compression: p.compression,
    };
    let key = signing::select_key(
        &state.config,
        cache,
        p.signing_key_name.as_deref(),
        p.signing_public_key.as_deref(),
        p.signing_key_sealed.as_deref(),
    )?;
    let body = signing::render_with_key(
        cache_path,
        true,
        &nar,
        key.as_ref().map(|(name, key)| (name.as_str(), key)),
    )?;
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(body.as_bytes())));
    // Key activation can change these bytes without changing publication time.
    // There is no truthful Last-Modified, so date preconditions are ignored.
    let status = precondition(&request.headers, &etag, None);
    let size = body.len();
    let body = if status == StatusCode::OK && request.method == Method::GET {
        Body::from(body)
    } else {
        // Do not let Axum infer a misleading Content-Length: 0 on a 304.
        Body::from_stream(futures_util::stream::empty::<
            Result<axum::body::Bytes, io::Error>,
        >())
    };
    let mut response = (
        status,
        [
            ("content-type", "text/x-nix-narinfo"),
            (
                "cache-control",
                if private {
                    "private, no-cache"
                } else {
                    "public, max-age=300"
                },
            ),
            ("etag", &etag),
        ],
        body,
    )
        .into_response();
    if status == StatusCode::OK {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, size.into());
    }
    Ok(response)
}

fn precondition(headers: &HeaderMap, etag: &str, modified: Option<&str>) -> StatusCode {
    let value = |key| headers.get(key).and_then(|v| v.to_str().ok());
    let matches = |text: &str, weak: bool| {
        text.split(',').any(|tag| {
            let tag = tag.trim();
            tag == "*"
                || if weak {
                    tag.strip_prefix("W/").unwrap_or(tag) == etag
                } else {
                    tag == etag
                }
        })
    };
    let time = |value: Option<&str>| value.and_then(|v| httpdate::parse_http_date(v).ok());
    let modified: Option<SystemTime> = time(modified);
    let failed = if let Some(tag) = value(header::IF_MATCH) {
        !matches(tag, false)
    } else {
        modified
            .zip(time(value(header::IF_UNMODIFIED_SINCE)))
            .is_some_and(|(a, b)| a > b)
    };
    let unchanged = if let Some(tag) = value(header::IF_NONE_MATCH) {
        matches(tag, true)
    } else {
        modified
            .zip(time(value(header::IF_MODIFIED_SINCE)))
            .is_some_and(|(a, b)| a <= b)
    };
    if failed {
        StatusCode::PRECONDITION_FAILED
    } else if unchanged {
        StatusCode::NOT_MODIFIED
    } else {
        StatusCode::OK
    }
}
