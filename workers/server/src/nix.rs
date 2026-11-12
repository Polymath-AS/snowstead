use std::collections::HashSet;

use axum::{
    Extension, Router,
    body::to_bytes,
    extract::{FromRequestParts, MatchedPath, Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use snowstead_protocol::{MissingPaths, limits, routes};

use crate::{
    AppState, auth,
    authz::{self, Action, Principal as Identity, Resource},
    error::ApiError,
    protocol_policy::CallerLimit,
    wire::respond,
};

/// Full API paths: merge this router rather than nesting and stripping the URI.
pub(crate) fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            routes::MISSING_PATHS,
            post(get_missing_paths)
                .put(get_missing_paths)
                .route_layer(middleware::from_fn_with_state(state.clone(), write_access)),
        )
        .merge(crate::uploads::router(state.clone()))
        .merge(crate::push_jobs::router(state))
        // Outermost: refuse an incompatible client before authentication.
        .route_layer(middleware::from_fn(crate::wire::negotiate))
}

pub(crate) async fn write_access(
    State(state): State<AppState>,
    matched: MatchedPath,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    #[cfg(feature = "profiling")]
    let _profile = hotpath::functions::build_measurement_guard_block(
        concat!(module_path!(), "::write_access"),
        false,
    );
    // Authentication precedes parsing, including on malformed requests.
    let identity = auth::authenticate(request.headers(), &state, None).await?;
    state
        .protocol_limits
        .check(CallerLimit::Push, &identity.actor())?;
    let ip = crate::app::client_ip(&state, &request);
    if let Err(denied) =
        authz::authorize(&identity, Action::NixPush, &Resource::Org(identity.org()))
    {
        if matches!(identity, Identity::ApiToken(_)) {
            audit(
                &state.pool,
                &identity,
                None,
                StatusCode::FORBIDDEN,
                json!({"reason":"missing push permission"}),
                ip.as_deref(),
            )
            .await;
        }
        return Err(denied.into());
    }
    let endpoint = match matched.as_str() {
        "/_api/v1/get-missing-paths" => "get-missing-paths",
        "/_api/v1/caches/{cache}/upload-streams/batch" => "create-upload-streams",
        "/_api/v1/uploads/parts" => "reserve-upload-parts-batch",
        "/_api/v1/uploads/finalize" => "finalize-upload-streams",
        "/_api/v1/uploads/inline/batch" => "inline-upload-batch",
        "/_api/v1/uploads/{id}/inline" => "inline-upload",
        "/_api/v1/uploads/{id}/parts" => "reserve-upload-parts",
        "/_api/v1/uploads/{id}/abort" => "abort-upload-stream",
        "/_api/v1/uploads/{id}/part/{number}" => "upload-part",
        "/_api/v1/caches/{cache}/push-jobs" => "create-push-job",
        "/_api/v1/caches/{cache}/push-jobs/{job}" => "push-job-manifest",
        "/_api/v1/caches/{cache}/push-jobs/{job}/manifest/{chunk}" => "push-manifest-chunk",
        "/_api/v1/caches/{cache}/push-jobs/{job}/seal" => "seal-push-manifest",
        "/_api/v1/caches/{cache}/push-jobs/{job}/resume" => "resume-push-job",
        "/_api/v1/caches/{cache}/push-jobs/{job}/cancel" => "cancel-push-job",
        "/_api/v1/caches/{cache}/push-jobs/{job}/complete" => "complete-push-job",
        _ => unreachable!("write middleware is only installed on Nix routes"),
    };
    let cache = if endpoint == "create-upload-streams" {
        let (mut parts, body) = request.into_parts();
        let cache = Path::<String>::from_request_parts(&mut parts, &state)
            .await
            .ok()
            .map(|Path(cache)| cache);
        request = Request::from_parts(parts, body);
        cache
    } else {
        None
    };
    request.extensions_mut().insert(identity.clone());
    let response = next.run(request).await;
    audit(
        &state.pool,
        &identity,
        cache.as_deref(),
        response.status(),
        json!({"endpoint":endpoint}),
        ip.as_deref(),
    )
    .await;
    Ok(response)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn audit(
    pool: &sqlx::PgPool,
    identity: &Identity,
    cache: Option<&str>,
    status: StatusCode,
    detail: Value,
    ip: Option<&str>,
) {
    // Telemetry never changes the response or exposes database diagnostics.
    // Use the pool after protocol work has released its fenced transactions.
    if sqlx::query!(
        r#"
        INSERT INTO audit_logs (actor, action, cache_name, status, detail, ip, org_id)
        VALUES ($1, 'push', $2, $3, $4, $5, $6)
        "#,
        identity.actor(),
        cache,
        i32::from(status.as_u16()),
        detail.to_string(),
        ip,
        identity.org(),
    )
    .execute(pool)
    .await
    .is_err()
    {
        tracing::warn!("Recording Nix push audit failed");
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn get_missing_paths(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    request: Request,
) -> Result<Response, ApiError> {
    let bytes = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid JSON in request body"))?;
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid JSON in request body"))?;
    let (cache_name, hashes) = parse_missing(&body)?;
    let cache = sqlx::query_scalar!(
        r#"
        SELECT c.id
        FROM caches c
        WHERE c.org_id = $1
            AND c.name = $2
            AND EXISTS (
                SELECT 1
                FROM cache_protocols p
                WHERE p.cache_id = c.id
                    AND p.protocol = 'nix'
            )
        "#,
        identity.org(),
        cache_name,
    )
    .fetch_optional(&state.pool)
    .await?;
    let cache_id = cache.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Cache not found"))?;
    authz::authorize(
        &identity,
        Action::NixPush,
        &Resource::cache(identity.org(), cache_id, cache_name),
    )?;
    // Refresh retention and return membership in one statement, without
    // rewriting paths whose daily retention refresh is not due.
    let existing: HashSet<String> = sqlx::query_scalar!(
        r#"
        WITH refreshed AS (
            UPDATE published_paths
            SET last_pushed_at = NOW()
            WHERE cache_id = $1
                AND store_path_hash = ANY($2)
                AND last_pushed_at < NOW() - INTERVAL '1 day'
            RETURNING id
        )
        SELECT store_path_hash
        FROM published_paths
        WHERE cache_id = $1
            AND store_path_hash = ANY($2)
        "#,
        cache_id,
        &hashes,
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .collect();
    let absent: Vec<String> = hashes
        .into_iter()
        .filter(|hash| !existing.contains(hash))
        .collect();
    let served: HashSet<String> = if absent.is_empty() || state.config.upstreams.is_empty() {
        HashSet::new()
    } else {
        sqlx::query_scalar!(
            r#"
            SELECT store_path_hash
            FROM upstream_paths
            WHERE store_path_hash = ANY($1)
                AND upstream = ANY($2)
            "#,
            &absent,
            &state.config.upstreams,
        )
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .collect()
    };
    let missing: Vec<_> = absent
        .iter()
        .filter(|hash| !served.contains(*hash))
        .cloned()
        .collect();
    let upstream: Vec<_> = absent
        .into_iter()
        .filter(|hash| served.contains(hash))
        .collect();
    let unchecked = if state.config.upstreams.is_empty() {
        Vec::new()
    } else {
        missing.clone()
    };
    warm_upstreams(&state, unchecked.clone());
    Ok(respond(
        StatusCode::OK,
        &MissingPaths {
            missing,
            upstream,
            unchecked,
            upstreams: state.config.upstreams.clone(),
        },
    ))
}

fn parse_missing(body: &Value) -> Result<(&str, Vec<String>), ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Missing required fields: cache, storePathHashes",
        )
    };
    // Match the existing schema's type labels, including its array-body guard.
    let received = |value: &Value| match value {
        Value::Null => "null".to_owned(),
        Value::Array(_) => "Array".to_owned(),
        Value::Object(_) => "Object".to_owned(),
        _ => value.to_string(),
    };
    if !body.is_object() {
        let actual = if body.is_array() {
            "undefined".to_owned()
        } else {
            received(body)
        };
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid type: Expected Object but received {actual}"),
        ));
    }
    let cache = body
        .get("cache")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(invalid)?;
    let hashes = body
        .get("storePathHashes")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let hashes = hashes
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "storePathHashes[{index}]: Invalid type: Expected string but received {}",
                        received(value)
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if hashes.len() > limits::MISSING_PATHS_MAX {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "storePathHashes exceeds maximum of 1000",
        ));
    }
    // The current endpoint accepts strings, not just parsed store hashes.
    // Preserve ordering and duplicates: clients use this as a batch filter.
    Ok((cache, hashes))
}

fn warm_upstreams(state: &AppState, hashes: Vec<String>) {
    if hashes.is_empty() {
        return;
    }
    // Upstream discovery is an optimization; never let a slow upstream
    // create an unbounded backlog or delay a client's missing-path answer.
    let Ok(permit) = state.upstream_slots.clone().try_acquire_owned() else {
        return;
    };
    let background = state.clone();
    state.tasks.spawn(async move {
        let _permit = permit;
        let found = stream::iter(hashes.into_iter().map(|hash| {
            let state = &background;
            async move {
                for upstream in &state.config.upstreams {
                    let Ok(mut url) = reqwest::Url::parse(upstream) else {
                        continue;
                    };
                    // One encoded path segment: arbitrary API strings must not
                    // turn an upstream probe into a query or a different path.
                    let Ok(mut segments) = url.path_segments_mut() else {
                        continue;
                    };
                    segments.pop_if_empty().push(&format!("{hash}.narinfo"));
                    drop(segments);
                    if let Ok(response) = crate::profile_future!(
                        state.http.head(url).send(),
                        label = "nix.upstream_head"
                    )
                    .await
                        && response.status().is_success()
                    {
                        return Some((hash, upstream.clone()));
                    }
                }
                None
            }
        }))
        .buffer_unordered(16)
        .filter_map(|found| async { found })
        .collect::<Vec<_>>()
        .await;
        if found.is_empty() {
            return;
        }
        let (hashes, upstreams): (Vec<_>, Vec<_>) = found.into_iter().unzip();
        if sqlx::query!(
            r#"
            INSERT INTO upstream_paths (store_path_hash, upstream)
            SELECT *
            FROM UNNEST($1::text[], $2::text[])
            ON CONFLICT DO NOTHING
            "#,
            &hashes,
            &upstreams,
        )
        .execute(&background.pool)
        .await
        .is_err()
        {
            tracing::warn!("Upstream discovery could not be recorded");
        }
    });
}
