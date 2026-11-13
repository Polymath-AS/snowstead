//! The existing hosted management API, backed by the same PostgreSQL policy
//! rows as protocol admission. No management operation trusts proxy headers.
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::{MatchedPath, OriginalUri, Path, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{
    AppState, auth,
    authz::{self, Action, Principal, Resource},
    error::{ApiError, json_response},
    signing_management,
};

#[derive(Default)]
pub(crate) struct ApiLimits(Mutex<HashMap<String, (Instant, u32)>>);

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl ApiLimits {
    fn check(&self, actor: String) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut calls = crate::profile_block!("management.limiter_mutex_wait", self.0.lock())
            .expect("API limiter poisoned");
        if calls.len() >= 16384 {
            calls.retain(|_, (until, _)| *until > now);
            if !calls.contains_key(&actor) && calls.len() >= 16384 {
                return Err(limited());
            }
        }
        let entry = calls
            .entry(actor)
            .or_insert((now + Duration::from_secs(60), 0));
        if entry.0 <= now {
            *entry = (now + Duration::from_secs(60), 0);
        }
        if entry.1 >= 600 {
            return Err(limited());
        }
        entry.1 += 1;
        Ok(())
    }
}

fn limited() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many requests: slow down, and retry in 60 seconds",
    )
    .header(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("60"),
    )
}

fn bad(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}
fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not Found")
}
fn ok(body: Value) -> Response {
    json_response(StatusCode::OK, body)
}
fn internal() -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn integer(value: &Value) -> Option<i64> {
    value
        .as_f64()
        .filter(|n| n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0)
        .map(|n| n as i64)
}

fn valid_org(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn valid_name(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn cache_name(name: &str) -> Result<(), ApiError> {
    if !valid_name(name, 64) {
        return Err(bad(
            "CacheName must be 1-64 lowercase alphanumeric chars or hyphens, no leading/trailing hyphen",
        ));
    }
    Ok(())
}

fn path(slug: &str, name: &str) -> String {
    if slug == "default" {
        name.into()
    } else {
        format!("{slug}/{name}")
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn set_cache_info(tx: &mut crate::db::Transaction, path: &str) -> Result<(), ApiError> {
    let key = format!("{path}/nix-cache-info");
    sqlx::query(
        "INSERT INTO object_cleanup (is_private, key) VALUES (FALSE, $1) ON CONFLICT DO NOTHING",
    )
    .bind(key)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Org {
    id: String,
    slug: String,
    moving_from: Option<String>,
    storage_limit: Option<i64>,
    private_caches: bool,
    custom_signing_keys: bool,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "management.org_sql"
    )
)]
async fn org(pool: &PgPool, id: &str) -> Result<Option<Org>, ApiError> {
    Ok(sqlx::query_as!(
        Org,
        r#"
        SELECT
            id,
            slug,
            moving_from,
            storage_limit,
            private_caches,
            custom_signing_keys
        FROM orgs
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn body(request: Request) -> Result<Value, ApiError> {
    let bytes = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| bad("Invalid JSON in request body"))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| bad("Invalid JSON in request body"))?;
    if !value.is_object() {
        return Err(bad("expected JSON object"));
    }
    Ok(value)
}

#[derive(Clone)]
pub(crate) struct ManagementContext {
    pub(crate) principal: Principal,
    pub(crate) org: Option<String>,
    /// The scoped org as authorization read it, so a handler which only
    /// reports it need not read it again. Absent for admin routes and for
    /// `PUT /orgs/{org}`, which may create the org.
    row: Option<Org>,
}

#[derive(Deserialize)]
struct RouteParams {
    org: Option<String>,
    cache: Option<String>,
    jti: Option<String>,
    key: Option<String>,
    pin: Option<String>,
}

#[derive(Deserialize)]
struct OrgPath {
    org: String,
}

#[derive(Deserialize)]
struct CachePath {
    cache: String,
}

pub(crate) fn router(state: AppState) -> Router<AppState> {
    let orgs = Router::new()
        .route("/overview", get(org_overview))
        .route("/move", post(move_slug))
        .route("/caches", get(list_caches).post(create_cache))
        .route("/caches/{cache}", get(get_cache))
        .merge(crate::management_auth::org_router())
        .merge(crate::management_policy::org_router())
        .merge(signing_management::org_router());
    let admin = Router::new()
        .route("/orgs", get(list_orgs))
        .route("/orgs/{org}", get(get_org).put(put_org))
        .route("/overview", get(global_overview))
        .route("/caches", get(list_caches).post(create_cache))
        .route("/caches/{cache}", get(get_cache))
        .route("/auth/sync", post(sync_auth))
        .route("/narinfo/backfill", post(backfill))
        .merge(crate::management_auth::admin_router())
        .merge(crate::management_policy::admin_router());
    Router::new()
        .route("/_api/v1/orgs/{org}", get(get_org).put(put_org))
        .route("/_api/v1/orgs/{org}/", get(get_org).put(put_org))
        .nest("/_api/v1/orgs/{org}", orgs)
        .nest("/_api/v1/admin", admin)
        .route_layer(middleware::from_fn_with_state(state, authorize_and_audit))
}

/// What each management route does, for [`authz::authorize`]. Routes not
/// listed here are denied.
fn route_action(method: &Method, endpoint: &str) -> Option<Action> {
    // Axum answers HEAD with the GET handler.
    let method = if method == Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    Some(match (method, endpoint) {
        ("GET", "" | "/" | "/overview" | "/caches" | "/caches/{cache}" | "/eviction") => {
            Action::OrgRead
        }
        ("GET", "/caches/{cache}/pins" | "/caches/{cache}/go" | "/caches/{cache}/sccache") => {
            Action::OrgRead
        }
        ("GET", "/caches/{cache}/paths") => Action::OrgRead,
        ("PUT", "" | "/") => Action::OrgSlugWrite,
        ("POST", "/move") => Action::OrgMove,
        (
            "POST",
            "/caches"
            | "/caches/{cache}/go/reset"
            | "/caches/{cache}/sccache/reset"
            | "/caches/{cache}/paths/delete"
            | "/caches/{cache}/delete"
            | "/caches/{cache}/evict"
            | "/caches/{cache}/purge",
        ) => Action::CacheWrite,
        ("POST", "/caches/{cache}/pins") | ("DELETE", "/caches/{cache}/pins/{pin}") => {
            Action::PinWrite
        }
        ("GET", "/tokens" | "/tokens/{jti}") => Action::TokenRead,
        ("POST", "/tokens" | "/tokens/{jti}/revoke") => Action::TokenWrite,
        ("GET", "/keys") => Action::ApiKeyRead,
        ("POST", "/keys") => Action::ApiKeyCreate,
        ("POST", "/keys/{key}/revoke") => Action::ApiKeyRevoke,
        ("GET", "/caches/{cache}/signing-keys") => Action::SigningKeyRead,
        (
            "POST",
            "/caches/{cache}/signing-keys" | "/caches/{cache}/signing-keys/{key}/activate",
        ) => Action::SigningKeyWrite,
        ("GET", "/audit") => Action::AuditRead,
        _ => return None,
    })
}

async fn authorize_and_audit(
    State(state): State<AppState>,
    Path(params): Path<RouteParams>,
    matched: MatchedPath,
    OriginalUri(uri): OriginalUri,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let admin = matched.as_str().starts_with("/_api/v1/admin");
    let scope = params.org;
    if scope.as_ref().is_some_and(|id| !valid_org(id)) {
        return Err(not_found());
    }
    let endpoint = matched
        .as_str()
        .strip_prefix(if admin {
            "/_api/v1/admin"
        } else {
            "/_api/v1/orgs/{org}"
        })
        .ok_or_else(not_found)?;
    // An assertion signs a hash of the body, so a captured one can't carry
    // another. Management bodies are at most 1 MiB.
    let mut body_sha256 = hex::encode(Sha256::digest(b""));
    if auth::is_assertion(request.headers()) {
        let (parts, stream) = request.into_parts();
        let bytes = to_bytes(stream, 1024 * 1024).await.map_err(|_| {
            ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "Request body is too large")
        })?;
        body_sha256 = hex::encode(Sha256::digest(&bytes));
        request = Request::from_parts(parts, Body::from(bytes));
    }
    let target = auth::Target {
        method: request.method(),
        path: uri
            .path_and_query()
            .map_or_else(|| uri.path(), |p| p.as_str()),
        body_sha256: &body_sha256,
    };
    let mut principal = match request.extensions().get::<authz::TrustedPrincipal>() {
        Some(verified) => verified.0.clone(),
        None => auth::authenticate(request.headers(), &state, Some(target)).await?,
    };
    // Transitional: the old dashboard's operator-secret calls on org routes.
    if !admin && state.config.allow_legacy_web_admin && matches!(principal, Principal::Operator) {
        principal = Principal::LegacyWeb {
            actor: auth::legacy_actor(request.headers()),
        };
    }
    let action = if admin {
        Some(Action::Operate)
    } else {
        route_action(request.method(), endpoint)
    }
    .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "Forbidden"))?;
    // Only API tokens hold cache-level grants, so only they need the ID.
    let cache_id = match (&scope, &params.cache, &principal) {
        (Some(scope), Some(cache), Principal::ApiToken(_)) if !admin => {
            sqlx::query_scalar!(
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
                scope,
                Some(cache.as_str())
            )
            .fetch_optional(&state.pool)
            .await?
        }
        _ => None,
    };
    let resource = match (&scope, &params.cache) {
        (Some(org), Some(name)) if !admin => Resource::Cache {
            org,
            id: cache_id,
            name,
        },
        (Some(org), _) => Resource::Org(org),
        (None, _) => Resource::Service,
    };
    authz::authorize(&principal, action, &resource)?;
    // The operator is trusted, and so are the reads a signed-in person makes:
    // a dashboard page is several of them, and a refusal would show that
    // person an error for browsing. What they change is still counted
    // against them, as is everything an API key or token does.
    let limited = match &principal {
        Principal::Operator => false,
        Principal::WebUser(_) | Principal::LegacyWeb { actor: Some(_) } => {
            !matches!(*request.method(), Method::GET | Method::HEAD)
        }
        Principal::LegacyWeb { actor: None } => false,
        _ => true,
    };
    if limited {
        state.management_limits.check(principal.actor())?;
    }
    let root_put = request.method() == Method::PUT && matches!(endpoint, "" | "/" | "/orgs/{org}");
    let row = match &scope {
        Some(scope) if !root_put => Some(
            org(&state.pool, scope)
                .await?
                .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no org {scope}")))?,
        ),
        _ => None,
    };
    let method = request.method().clone();
    let action = audit_action(&method, endpoint, admin);
    let ip = crate::app::client_ip(&state, &request);
    let old = if action == Some("org.put") {
        org(&state.pool, scope.as_deref().unwrap()).await?
    } else {
        None
    };
    // Only audited mutations need a copy, and only whitelisted fields below
    // enter the log. In particular token and key secrets are never recorded.
    let (mut request, input) = if action.is_some() && method != Method::GET {
        let (parts, stream) = request.into_parts();
        let bytes = to_bytes(stream, 1024 * 1024)
            .await
            .map_err(|_| bad("Invalid JSON in request body"))?;
        let input = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        (Request::from_parts(parts, Body::from(bytes)), input)
    } else {
        (request, Value::Null)
    };
    #[cfg(feature = "observability")]
    crate::observability::identity(&principal, scope.as_deref());
    request.extensions_mut().insert(ManagementContext {
        principal: principal.clone(),
        org: scope.clone(),
        row,
    });
    let response = next.run(request).await;
    if let Some(action) = action {
        let (parts, bytes) = response.into_parts();
        let bytes = to_bytes(bytes, 8 * 1024 * 1024)
            .await
            .map_err(|_| internal())?;
        let output: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut detail = json!({});
        for field in match action {
            "token.create" => &["jti", "subject"][..],
            "key.create" => &["id", "name"],
            "cache.create" => &["private", "protocols", "retentionDays"],
            "cache.delete" => &["paths"],
            "paths.delete" => &["deleted"],
            "signing-key.stage" | "signing-key.activate" => &["id", "publicKey"],
            _ => &[],
        } {
            if let Some(v) = output.get(field) {
                detail[*field] = v.clone();
            }
        }
        if action == "key.create" || action.starts_with("signing-key.") {
            let id = detail.as_object_mut().unwrap().remove("id");
            if let Some(id) = id {
                detail["key"] = id;
            }
        }
        if action == "org.put" {
            let new = if parts.status.is_success() {
                org(&state.pool, scope.as_deref().unwrap()).await?
            } else {
                None
            };
            let terms = |o: Option<Org>| {
                o.map(|o| json!({"slug":o.slug,"storageLimit":o.storage_limit,"privateCaches":o.private_caches,"customSigningKeys":o.custom_signing_keys}))
            };
            detail = json!({"old":terms(old),"new":terms(new)});
        }
        if action == "token.revoke" {
            detail["jti"] = json!(params.jti);
        }
        if action == "key.revoke" {
            detail["key"] = json!(params.key);
        }
        if action == "pin.delete" {
            detail["name"] = json!(params.pin);
        }
        if action == "pin.create" && parts.status.is_success() {
            for field in ["name", "storePath", "keep"] {
                if let Some(value) = input.get(field) {
                    detail[field] = value.clone();
                }
            }
        }
        let cache = if endpoint.starts_with("/caches") {
            params.cache.or_else(|| {
                output
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
        } else {
            None
        };
        // Mark what the transitional path did, so its use is easy to find.
        if matches!(principal, Principal::LegacyWeb { .. }) {
            detail["legacyWeb"] = json!(true);
        }
        let actual_action = if action == "pin.create" && parts.status == StatusCode::OK {
            "pin.update"
        } else {
            action
        };
        if sqlx::query!(
            r#"
            INSERT INTO audit_logs (
                actor,
                action,
                cache_name,
                status,
                detail,
                org_id,
                ip
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            principal.actor(),
            actual_action,
            cache,
            i32::from(parts.status.as_u16()),
            detail.to_string(),
            scope.as_deref(),
            ip
        )
        .execute(&state.pool)
        .await
        .is_err()
        {
            tracing::warn!("Recording management audit failed");
        }
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }
    Ok(response)
}

fn audit_action(method: &Method, endpoint: &str, admin: bool) -> Option<&'static str> {
    match (method.as_str(), endpoint) {
        ("PUT", "" | "/") if !admin => Some("org.put"),
        ("PUT", "/orgs/{org}") if admin => Some("org.put"),
        ("POST", "/tokens") => Some("token.create"),
        ("GET", "/tokens") if admin => Some("token.list"),
        ("POST", "/tokens/{jti}/revoke") => Some("token.revoke"),
        ("POST", "/keys") => Some("key.create"),
        ("POST", "/keys/{key}/revoke") => Some("key.revoke"),
        ("POST", "/caches") => Some("cache.create"),
        ("POST", "/caches/{cache}/signing-keys") => Some("signing-key.stage"),
        ("POST", "/caches/{cache}/signing-keys/{key}/activate") => Some("signing-key.activate"),
        ("POST", "/caches/{cache}/paths/delete") => Some("paths.delete"),
        ("POST", "/caches/{cache}/delete") => Some("cache.delete"),
        ("POST", "/caches/{cache}/purge") => Some("cache.purge"),
        ("POST", "/caches/{cache}/evict") => Some("cache.evict"),
        ("POST", "/caches/{cache}/go/reset") => Some("go.reset"),
        ("POST", "/caches/{cache}/sccache/reset") => Some("sccache.reset"),
        ("POST", "/caches/{cache}/pins") => Some("pin.create"),
        ("DELETE", "/caches/{cache}/pins/{pin}") => Some("pin.delete"),
        ("POST", "/auth/sync") => Some("auth.sync"),
        ("POST", "/narinfo/backfill") => Some("narinfo.backfill"),
        _ => None,
    }
}

async fn get_org(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
) -> Result<Response, ApiError> {
    org_response(&state, context.org.as_deref().unwrap(), context.row, false).await
}

async fn org_overview(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
) -> Result<Response, ApiError> {
    org_response(&state, context.org.as_deref().unwrap(), context.row, true).await
}

async fn list_caches(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let url = query_url(&request)?;
    let filter = context.org.or_else(|| {
        url.query_pairs()
            .find(|(k, _)| k == "org")
            .map(|(_, v)| v.into_owned())
    });
    if filter.as_ref().is_some_and(|s| !valid_org(s)) {
        return Err(bad("org must be an org id"));
    }
    Ok(ok(
        json!({"caches":cache_summaries(&state, filter.as_deref(), None).await?}),
    ))
}

fn query_url(request: &Request) -> Result<reqwest::Url, ApiError> {
    reqwest::Url::parse(&format!("http://snowstead{}", request.uri()))
        .map_err(|_| bad("Invalid URL"))
}

async fn list_orgs(State(state): State<AppState>, request: Request) -> Result<Response, ApiError> {
    // hotpath's attribute captures a shared request reference in a nested
    // future; Body is Send but not Sync. Keep its async timing guard directly.
    #[cfg(feature = "profiling")]
    let _profile = hotpath::functions::build_measurement_guard_block("management.list_orgs", false);
    let url = query_url(&request)?;
    let filter = if request.uri().query().is_some() {
        let raw = request.uri().query().unwrap();
        if raw.len() + 1 > 8192 {
            return Err(ApiError::new(
                StatusCode::URI_TOO_LONG,
                "Organization filter is too long",
            ));
        }
        let pairs: Vec<_> = url.query_pairs().collect();
        if pairs.is_empty()
            || pairs.len() > 50
            || raw.split('&').any(str::is_empty)
            || pairs.iter().any(|(k, v)| k != "id" || !valid_org(v))
        {
            return Err(bad(
                "Use 1 to 50 id parameters, each containing 1 to 128 letters, numbers, underscores, or dashes",
            ));
        }
        Some(
            pairs
                .into_iter()
                .map(|(_, v)| v.into_owned())
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let rows = sqlx::query_as!(
        Org,
        r#"
        SELECT
            id,
            slug,
            moving_from,
            storage_limit,
            private_caches,
            custom_signing_keys
        FROM orgs
        WHERE ($1::text[] IS NULL OR id = ANY($1))
        ORDER BY id
        "#,
        filter.as_deref()
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(ok(json!({"orgs":rows})))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn global_overview(State(state): State<AppState>) -> Result<Response, ApiError> {
    let text = crate::profile_future!(
        sqlx::query_scalar!(
            r#"
        SELECT JSON_BUILD_OBJECT(
            'orgs', (
                SELECT COUNT(*)
                FROM orgs
            ),
            'caches', (
                SELECT COUNT(*)
                FROM caches
            ),
            'paths', (
                SELECT COALESCE(SUM(path_count), 0)
                FROM caches
            ),
            'storedBytes', (
                SELECT COALESCE(SUM(size), 0)
                FROM caches
            ),
            'physicalStoredBytes', (
                SELECT COALESCE(SUM(file_size), 0)
                FROM blob_objects
            ),
            'pendingBytes', (
                SELECT COALESCE(SUM(file_size), 0)
                FROM upload_sessions
                WHERE status = 'finalizing'
                    OR (status IN ('pending', 'uploading', 'streaming') AND expires_at > NOW())
            ),
            'uploadsPending', (
                SELECT COUNT(*)
                FROM upload_sessions
                WHERE status = 'finalizing'
                    OR (status IN ('pending', 'uploading', 'streaming') AND expires_at > NOW())
            ),
            'servedThisMonth', (
                SELECT COALESCE(SUM(bytes), 0)
                FROM bandwidth_daily
                WHERE day >= DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC')::date
            ),
            'publicServedThisMonth', (
                SELECT COALESCE(SUM(public_bytes), 0)
                FROM bandwidth_daily
                WHERE day >= DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC')::date
            ),
            'activeTokens', (
                SELECT COUNT(*)
                FROM api_tokens
                WHERE revoked_at IS NULL
                    AND (expires_at IS NULL OR expires_at > NOW())
            ),
            'apiKeys', (
                SELECT COUNT(*)
                FROM org_api_keys
                WHERE revoked_at IS NULL
            )
        )::text AS "overview!"
        "#
        )
        // Reporting totals may lag; authorization and mutations use primary.
        .fetch_one(&state.read_pool),
        label = "management.global_overview_sql"
    )
    .await?;
    Ok(ok(serde_json::from_str(&text).map_err(|_| internal())?))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn bandwidth(
    pool: &PgPool,
    scope: Option<&str>,
    cache: Option<i32>,
) -> Result<Value, ApiError> {
    let rows = crate::profile_future!(
        sqlx::query!(
            r#"
        SELECT
            product,
            COALESCE(SUM(bytes), 0)::bigint AS "bytes!",
            COALESCE(SUM(public_bytes), 0)::bigint AS "public_bytes!"
        FROM bandwidth_daily
        WHERE day >= DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC')::date
            AND ($1::text IS NULL OR org_id = $1)
            AND ($2::int IS NULL OR cache_id = $2)
        GROUP BY product
        "#,
            scope,
            cache
        )
        .fetch_all(pool),
        label = "management.bandwidth_sql"
    )
    .await?;
    let mut result = json!({"servedThisMonth":0,"publicServedThisMonth":0,"servedThisMonthByProduct":{"nix":0,"go":0,"sccache":0}});
    let mut served = 0;
    let mut public = 0;
    for row in rows {
        served += row.bytes;
        public += row.public_bytes;
        result["servedThisMonthByProduct"][row.product] = json!(row.bytes + row.public_bytes);
    }
    result["servedThisMonth"] = json!(served);
    result["publicServedThisMonth"] = json!(public);
    Ok(result)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "management.org_response"
    )
)]
async fn org_response(
    state: &AppState,
    id: &str,
    row: Option<Org>,
    include_caches: bool,
) -> Result<Response, ApiError> {
    let row = match row {
        Some(row) => row,
        None => org(&state.pool, id)
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no org {id}")))?,
    };
    let mut result = serde_json::to_value(row).map_err(|_| internal())?;
    // Independent read-only reports: one round trip of latency, not one each.
    // The bandwidth import time rides along with usage as a scalar subquery.
    let usage = crate::profile_future!(
        sqlx::query!(
            r#"
        SELECT
            COALESCE(SUM(used), 0)::bigint AS "used!",
            COALESCE(SUM(pending), 0)::bigint AS "pending!",
            (
                SELECT MAX(imported_at)
                FROM bandwidth_daily
            ) AS "updated?"
        FROM (
            SELECT
                SUM(size) AS used,
                0 AS pending
            FROM caches
            WHERE org_id = $1
            UNION ALL
            SELECT
                0,
                SUM(u.file_size)
            FROM upload_sessions u
            JOIN caches c ON c.id = u.cache_id
            WHERE c.org_id = $1
                AND (u.status = 'finalizing'
                    OR (u.status IN ('pending', 'uploading', 'streaming') AND u.expires_at > NOW()))
            UNION ALL
            SELECT
                SUM(e.size) FILTER (WHERE e.uploaded_at IS NOT NULL),
                SUM(e.size) FILTER (WHERE e.uploaded_at IS NULL)
            FROM go_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.go_generation
                AND e.expires_at > NOW()
            UNION ALL
            SELECT
                SUM(e.size) FILTER (WHERE e.uploaded_at IS NOT NULL),
                SUM(e.size) FILTER (WHERE e.uploaded_at IS NULL)
            FROM sccache_entries e
            JOIN caches c ON c.id = e.cache_id
            WHERE c.org_id = $1
                AND e.generation = c.sccache_generation
                AND e.expires_at > NOW()
        ) usage
        "#,
            id
        )
        .fetch_one(&state.read_pool),
        label = "management.org_usage_sql"
    );
    let caches = async {
        Ok(if include_caches {
            Some(cache_summaries(state, Some(id), None).await?)
        } else {
            None
        })
    };
    let (usage, served, caches) = tokio::try_join!(
        async { usage.await.map_err(ApiError::from) },
        bandwidth(&state.read_pool, Some(id), None),
        caches,
    )?;
    result["used"] = json!(usage.used);
    result["pending"] = json!(usage.pending);
    result
        .as_object_mut()
        .unwrap()
        .extend(served.as_object().unwrap().clone());
    let updated: Option<DateTime<Utc>> = usage.updated;
    result["bandwidthUpdatedAt"] =
        json!(updated.map(|at| at.to_rfc3339_opts(SecondsFormat::Millis, true)));
    if let Some(caches) = caches {
        result["caches"] = json!(caches);
    }
    Ok(ok(result))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "management.cache_summaries"
    )
)]
async fn cache_summaries(
    state: &AppState,
    scope: Option<&str>,
    name: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    // Aggregate bandwidth separately from published paths so neither relation
    // multiplies the other's counts. Compute it once, even when stale cache
    // statistics underestimate the selected inventory as a single row.
    let rows = crate::profile_future!(sqlx::query_scalar!(
        r#"
        WITH monthly AS MATERIALIZED (
            SELECT
                b.cache_id,
                SUM(b.bytes)::bigint AS origin,
                SUM(b.public_bytes)::bigint AS public,
                COALESCE(SUM(b.bytes + b.public_bytes) FILTER (WHERE b.product = 'nix'), 0)::bigint AS nix,
                COALESCE(SUM(b.bytes + b.public_bytes) FILTER (WHERE b.product = 'go'), 0)::bigint AS go,
                COALESCE(SUM(b.bytes + b.public_bytes) FILTER (WHERE b.product = 'sccache'), 0)::bigint AS sccache
            FROM bandwidth_daily b
            WHERE b.day >= DATE_TRUNC('month', NOW() AT TIME ZONE 'UTC')::date
                AND b.cache_id = ANY(ARRAY(
                    SELECT c.id
                    FROM caches c
                    WHERE ($1::text IS NULL OR c.org_id = $1)
                        AND ($2::text IS NULL OR c.name = $2)
                ))
            GROUP BY b.cache_id
        ), summaries AS (
            SELECT
                c.id,
                c.name,
                JSONB_BUILD_OBJECT(
                    'name', c.name,
                    'path', CASE WHEN o.slug = 'default' THEN c.name ELSE o.slug || '/' || c.name END,
                    'private', NOT c.is_public,
                    'org', c.org_id,
                    'protocols', ARRAY(
                        SELECT protocol
                        FROM cache_protocols
                        WHERE cache_id = c.id
                        ORDER BY protocol DESC
                    ),
                    'retentionDays', c.retention_days,
                    'createdAt', TO_CHAR(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
                    'paths', c.path_count,
                    'size', c.size,
                    'addedLastWeek', COUNT(p.id) FILTER (WHERE p.created_at >= NOW() - INTERVAL '7 days'),
                    'lastAddedAt', TO_CHAR(MAX(p.created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
                ) AS summary
            FROM caches c
            JOIN orgs o ON o.id = c.org_id
            LEFT JOIN published_paths p ON p.cache_id = c.id
            WHERE ($1::text IS NULL OR c.org_id = $1)
                AND ($2::text IS NULL OR c.name = $2)
            GROUP BY c.id, o.slug
        )
        SELECT (s.summary || JSONB_BUILD_OBJECT(
            'servedThisMonth', COALESCE(m.origin, 0),
            'publicServedThisMonth', COALESCE(m.public, 0),
            'servedThisMonthByProduct', JSONB_BUILD_OBJECT(
                'nix', COALESCE(m.nix, 0),
                'go', COALESCE(m.go, 0),
                'sccache', COALESCE(m.sccache, 0)
            )
        ))::text AS "summary!"
        FROM summaries s
        LEFT JOIN monthly m ON m.cache_id = s.id
        ORDER BY s.name
        "#,
        scope,
        name
    ).fetch_all(&state.read_pool), label = "management.cache_summaries_sql").await?;
    rows.iter()
        .map(|text| serde_json::from_str(text).map_err(|_| internal()))
        .collect()
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn get_cache(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(params): Path<CachePath>,
) -> Result<Response, ApiError> {
    let state = &state;
    let scope = context.org.as_deref().unwrap_or("default");
    let name = params.cache.as_str();
    cache_name(name)?;
    let mut result = cache_summaries(state, Some(scope), Some(name))
        .await?
        .pop()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no cache named {name}")))?;
    let cache = sqlx::query!(
        r#"
        SELECT
            id,
            signing_public_key
        FROM caches
        WHERE org_id = $1
            AND name = $2
        "#,
        scope,
        name
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(not_found)?;
    result["publicKey"] = json!(match cache.signing_public_key {
        Some(key) => Some(key),
        None => signing_management::shared_public_key(&state.config)?,
    });
    let rows = sqlx::query_scalar!(
        r#"
        SELECT JSON_BUILD_OBJECT(
            'storePath', p.store_path,
            'size', b.file_size,
            'addedAt', TO_CHAR(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        )::text AS "path!"
        FROM published_paths p
        JOIN blob_objects b ON b.id = p.blob_object_id
        WHERE p.cache_id = $1
        ORDER BY p.created_at DESC, p.id DESC
        LIMIT 10
        "#,
        cache.id
    )
    .fetch_all(&state.read_pool)
    .await?;
    result["recentPaths"] = Value::Array(
        rows.iter()
            .map(|s| serde_json::from_str(s).map_err(|_| internal()))
            .collect::<Result<_, _>>()?,
    );
    Ok(ok(result))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn put_org(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(params): Path<OrgPath>,
    request: Request,
) -> Result<Response, ApiError> {
    let state = &state;
    let id = params.org.as_str();
    let raw = body(request).await?;
    // Only the operator sets limits; a slug change is authorized by the route.
    let limits = |principal: &Principal| {
        authz::authorize(principal, Action::OrgLimitsWrite, &Resource::Org(id))
    };
    if [
        "storageLimit",
        "privateCaches",
        "customSigningKeys",
        "limitsVersion",
    ]
    .iter()
    .any(|field| raw.get(*field).is_some())
    {
        limits(&context.principal)?;
    }
    if raw.as_object().unwrap().keys().any(|k| {
        ![
            "slug",
            "storageLimit",
            "privateCaches",
            "customSigningKeys",
            "limitsVersion",
        ]
        .contains(&k.as_str())
    }) {
        return Err(bad("Invalid organization settings"));
    }
    // Decimal strings preserve the full Postgres bigint range in JSON clients.
    let version = raw
        .get("limitsVersion")
        .map(|value| {
            value
                .as_str()
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| *v > 0)
                .ok_or_else(|| bad("limitsVersion must be a positive bigint string"))
        })
        .transpose()?;
    if version.is_some()
        && ["storageLimit", "privateCaches", "customSigningKeys"]
            .iter()
            .any(|field| raw.get(*field).is_none())
    {
        return Err(bad("limitsVersion requires the complete limits policy"));
    }
    for field in ["privateCaches", "customSigningKeys"] {
        if raw.get(field).is_some_and(|v| !v.is_boolean()) {
            return Err(bad(format!("{field} must be a boolean")));
        }
    }
    if raw
        .get("storageLimit")
        .is_some_and(|v| !v.is_null() && !integer(v).is_some_and(|n| n >= 0))
    {
        return Err(bad(
            "storageLimit must be a non-negative safe integer or null",
        ));
    }
    let mut tx = crate::profile_future!(
        crate::db::begin(state, id),
        label = "management.put_org_pool_begin"
    )
    .await?;
    // Slug uniqueness spans slug and moving_from, not just either index.
    // Serialize claims before taking the org lock; protocol writers never
    // acquire this namespace lock, so they cannot form a lock cycle.
    if raw.get("slug").is_some() {
        crate::profile_future!(
            crate::db::advisory_lock(&mut tx, "org-slugs"),
            label = "management.slug_namespace_lock_wait"
        )
        .await?;
    }
    let org_key = format!("org:{id}");
    crate::profile_future!(
        crate::db::advisory_lock(&mut tx, &org_key),
        label = "management.put_org_lock_wait"
    )
    .await?;
    // Compare and write under the same org lock. Stale registrations cannot
    // change slugs either; equal versions are safe transport retries.
    let stored_version: Option<i64> =
        sqlx::query_scalar::<_, Option<i64>>("SELECT limits_version FROM orgs WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    if let Some(stored) = stored_version {
        if version.is_some_and(|incoming| incoming <= stored) {
            tx.commit().await?;
            return org_response(state, id, None, false).await;
        }
        if version.is_none()
            && ["storageLimit", "privateCaches", "customSigningKeys"]
                .iter()
                .any(|field| raw.get(*field).is_some())
        {
            return Err(bad("limitsVersion is required for this organization"));
        }
    }
    let current = sqlx::query!(
        r#"
        SELECT
            slug,
            moving_from
        FROM orgs
        WHERE id = $1
        FOR UPDATE NOWAIT
        "#,
        id
    )
    .fetch_optional(&mut *tx)
    .await?;
    // Creating an org sets its limits.
    if current.is_none() {
        limits(&context.principal)?;
    }
    let mut slug = current.as_ref().map(|o| o.slug.clone());
    if let Some(wanted) = raw.get("slug")
        && Some(wanted) != slug.as_ref().map(|s| json!(s)).as_ref()
    {
        if id == "default" {
            return Err(bad("the default org's slug can't change"));
        }
        let wanted=wanted.as_str().filter(|s|valid_name(s,39)).ok_or_else(||bad("slug must be 1 to 39 lowercase letters, digits, or dashes, not starting or ending with a dash"))?;
        if ["default", "nar", "private", "_api", "healthz"].contains(&wanted) {
            return Err(bad(format!("{wanted} is reserved")));
        }
        let holder = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM orgs
                WHERE id <> $1
                    AND (slug = $2 OR moving_from = $2)
            ) AS "exists!"
            "#,
            id,
            wanted
        )
        .fetch_one(&mut *tx)
        .await?;
        if holder {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("{wanted} is taken"),
            ));
        }
        if current.as_ref().is_some_and(|o| o.moving_from.is_some()) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "the last slug change is still moving the org's caches; finish it with POST /move first",
            ));
        }
        slug = Some(wanted.into());
    }
    let slug = slug.ok_or_else(|| bad("slug is needed to create an org"))?;
    let mut moving = current.as_ref().and_then(|o| o.moving_from.clone());
    if current.as_ref().is_some_and(|old| old.slug != slug) {
        let has_caches: bool = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM caches
                WHERE org_id = $1
            ) AS "exists!"
            "#,
            id
        )
        .fetch_one(&mut *tx)
        .await?;
        if has_caches {
            moving = current.as_ref().map(|o| o.slug.clone());
        }
        let names = sqlx::query_scalar!(
            r#"
            SELECT c.name
            FROM caches c
            WHERE c.org_id = $1
                AND c.is_public
                AND EXISTS (
                    SELECT 1
                    FROM cache_protocols p
                    WHERE p.cache_id = c.id
                        AND p.protocol = 'nix'
                )
            "#,
            id
        )
        .fetch_all(&mut *tx)
        .await?;
        for name in names {
            set_cache_info(&mut tx, &path(&slug, &name)).await?;
        }
    }
    sqlx::query!(
        r#"
        INSERT INTO orgs (
            id,
            slug,
            moving_from,
            storage_limit,
            private_caches,
            custom_signing_keys
        )
        VALUES ($1, $2, $3, $4, COALESCE($6, TRUE), COALESCE($7, FALSE))
        ON CONFLICT (id) DO UPDATE
        SET slug = $2,
            moving_from = $3,
            storage_limit = CASE WHEN $5 THEN $4 ELSE orgs.storage_limit END,
            private_caches = COALESCE($6, orgs.private_caches),
            custom_signing_keys = COALESCE($7, orgs.custom_signing_keys)
        "#,
        id,
        &slug,
        moving,
        raw.get("storageLimit").and_then(integer),
        raw.get("storageLimit").is_some(),
        raw.get("privateCaches").and_then(Value::as_bool),
        raw.get("customSigningKeys").and_then(Value::as_bool)
    )
    .execute(&mut *tx)
    .await?;
    if let Some(version) = version {
        sqlx::query("UPDATE orgs SET limits_version = $2 WHERE id = $1")
            .bind(id)
            .bind(version)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    // Report the row this request just wrote, not the one read before it.
    org_response(state, id, None, false).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn create_cache(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let state = &state;
    let scope = context.org.as_deref();
    let raw = body(request).await?;
    let name = raw.get("name").and_then(Value::as_str).unwrap_or("");
    cache_name(name)?;
    if ["nar", "private", "nix-cache-info"].contains(&name) {
        return Err(bad(format!("{name} is reserved")));
    }
    let requested_org = match raw.get("org") {
        None => "default",
        Some(value) => value
            .as_str()
            .filter(|id| valid_org(id))
            .ok_or_else(|| bad("org must be an org id"))?,
    };
    let id = scope.unwrap_or(requested_org);
    let private = raw
        .get("private")
        .map(|v| v.as_bool().ok_or_else(|| bad("private must be a boolean")))
        .transpose()?;
    let retention = raw.get("retentionDays");
    if retention
        .is_some_and(|v| !v.is_null() && !integer(v).is_some_and(|n| (1..=3650).contains(&n)))
    {
        return Err(bad(
            "retentionDays must be a whole number of days from 1 to 3650, or null",
        ));
    }
    let requested = if let Some(p) = raw.get("protocols") {
        let p = p
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| bad("Choose at least one protocol: nix, go, or sccache"))?;
        let mut result = Vec::new();
        for value in p {
            let protocol = value
                .as_str()
                .filter(|s| ["nix", "go", "sccache"].contains(s))
                .ok_or_else(|| bad("Choose at least one protocol: nix, go, or sccache"))?;
            if result.iter().any(|p| p == protocol) {
                return Err(bad("protocols must not contain duplicates"));
            }
            result.push(protocol.to_owned());
        }
        Some(result)
    } else {
        None
    };
    let mut tx = crate::profile_future!(
        crate::db::begin(state, id),
        label = "management.create_cache_pool_begin"
    )
    .await?;
    let org_key = format!("org:{id}");
    crate::profile_future!(
        crate::db::advisory_lock(&mut tx, &org_key),
        label = "management.create_cache_org_lock_wait"
    )
    .await?;
    let policy = sqlx::query!(
        r#"
        SELECT
            slug,
            private_caches
        FROM orgs
        WHERE id = $1
        FOR SHARE NOWAIT
        "#,
        id
    )
    .fetch_optional(&mut *tx)
    .await?;
    let policy =
        policy.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no org {id}")))?;
    let slug = policy.slug;
    let allowed = policy.private_caches;
    let existing = sqlx::query!(
        r#"
        SELECT
            id,
            is_public,
            retention_days,
            created_at
        FROM caches
        WHERE org_id = $1
            AND name = $2
        FOR UPDATE NOWAIT
        "#,
        id,
        name
    )
    .fetch_optional(&mut *tx)
    .await?;
    let old_protocols: Vec<String> = if let Some(c) = &existing {
        sqlx::query_scalar!(
            r#"
            SELECT protocol
            FROM cache_protocols
            WHERE cache_id = $1
            ORDER BY protocol DESC
            "#,
            c.id
        )
        .fetch_all(&mut *tx)
        .await?
    } else {
        Vec::new()
    };
    let protocols = requested
        .or_else(|| existing.as_ref().map(|_| old_protocols.clone()))
        .ok_or_else(|| bad("Choose at least one protocol: nix, go, or sccache"))?;
    if old_protocols.iter().any(|p| !protocols.contains(p)) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Enabled protocols cannot be removed",
        ));
    }
    if existing.is_none()
        && state.config.require_cache_signing_keys
        && state.config.signing_master_key.is_empty()
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "cache signing requires SIGNING_MASTER_KEY",
        ));
    }
    if private == Some(true) && !allowed && existing.as_ref().is_none_or(|c| c.is_public) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "this org does not allow private caches: its private caches keep serving their paths, but take no pushes, and no new ones can be made",
        ));
    }
    let changing = existing
        .as_ref()
        .is_some_and(|c| private == Some(c.is_public));
    if changing {
        let cache = existing.as_ref().unwrap().id;
        let present = sqlx::query!(
            r#"
            SELECT
                EXISTS (
                    SELECT 1
                    FROM published_paths
                    WHERE cache_id = $1
                ) AS "paths!",
                EXISTS (
                    SELECT 1
                    FROM go_entries e
                    JOIN caches c ON c.id = e.cache_id
                    WHERE c.id = $1
                        AND e.generation = c.go_generation
                        AND e.expires_at > NOW()
                ) AS "go!",
                EXISTS (
                    SELECT 1
                    FROM sccache_entries e
                    JOIN caches c ON c.id = e.cache_id
                    WHERE c.id = $1
                        AND e.generation = c.sccache_generation
                        AND e.expires_at > NOW()
                ) AS "sccache!"
            "#,
            cache
        )
        .fetch_one(&mut *tx)
        .await?;
        if present.paths {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "only a cache without published paths can change visibility",
            ));
        }
        for (kind, present) in [("go", present.go), ("sccache", present.sccache)] {
            if present {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "only a cache without {} entries or uploads can change visibility; reset {} data first",
                        if kind == "go" { "Go" } else { kind },
                        if kind == "go" { "Go" } else { kind }
                    ),
                ));
            }
        }
    }
    let created = existing.is_none();
    let cache: i32 = if let Some(c) = &existing {
        c.id
    } else {
        sqlx::query_scalar!(
            r#"
            INSERT INTO caches (
                name,
                org_id,
                is_public
            )
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            name,
            id,
            private != Some(true)
        )
        .fetch_one(&mut *tx)
        .await?
    };
    if created && let Some(key) = signing_management::new_cache_key(&state.config, cache).await? {
        sqlx::query!(
            r#"
            UPDATE caches
            SET signing_key_name = $2,
                signing_public_key = $3,
                signing_key_sealed = $4
            WHERE id = $1
            "#,
            cache,
            &key.signing_key_name,
            &key.signing_public_key,
            &key.signing_key_sealed
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO cache_signing_keys (
                id,
                cache_id,
                signing_key_name,
                signing_public_key,
                signing_key_sealed,
                managed_public_key,
                state
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'active')
            "#,
            key.id,
            cache,
            key.signing_key_name,
            key.signing_public_key,
            key.signing_key_sealed,
            key.managed_public_key
        )
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!(
        r#"
        INSERT INTO cache_protocols (
            cache_id,
            protocol
        )
        SELECT
            $1,
            UNNEST($2::text[])
        ON CONFLICT DO NOTHING
        "#,
        cache,
        &protocols
    )
    .execute(&mut *tx)
    .await?;
    let updated = sqlx::query!(
        r#"
        UPDATE caches
        SET is_public = COALESCE($2, is_public),
            retention_days = CASE WHEN $3 THEN $4 ELSE retention_days END
        WHERE id = $1
        RETURNING is_public,
            retention_days,
            created_at
        "#,
        cache,
        private.map(|p| !p),
        retention.is_some(),
        retention.and_then(integer).map(|n| n as i32)
    )
    .fetch_one(&mut *tx)
    .await?;
    let (public, days, at) = (
        updated.is_public,
        updated.retention_days,
        updated.created_at,
    );
    set_cache_info(&mut tx, &path(&slug, name)).await?;
    tx.commit().await?;
    Ok(json_response(
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        json!({"name":name,"path":path(&slug,name),"private":!public,"protocols":protocols,"retentionDays":days,"createdAt":at.to_rfc3339_opts(SecondsFormat::Millis,true),"created":created,"changed":changing||(!created&&protocols.iter().any(|p|!old_protocols.contains(p)))}),
    ))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn sync_auth(State(state): State<AppState>) -> Result<Response, ApiError> {
    // Authentication reads SQL directly; no KV replica needs synchronization.
    let counts = sqlx::query!(
        r#"
        SELECT
            COUNT(*) AS "caches!",
            COUNT(*) FILTER (WHERE NOT is_public) AS "private!"
        FROM caches
        "#
    )
    .fetch_one(&state.pool)
    .await?;
    let revoked = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) AS "count!"
        FROM api_tokens
        WHERE revoked_at IS NOT NULL
            AND (expires_at IS NULL OR expires_at > NOW())
        "#
    )
    .fetch_one(&state.pool)
    .await?;
    Ok(ok(
        json!({"caches":counts.caches,"private":counts.private,"revocations":revoked}),
    ))
}

struct Published {
    id: i64,
    org_id: String,
    name: String,
    slug: String,
    store_path_hash: String,
}

#[derive(sqlx::FromRow)]
struct BackfillSnapshot {
    cache_id: i32,
    blob_id: i64,
    is_public: bool,
    r2_key: String,
    public_key: Option<String>,
    private_key: Option<String>,
    file_hash: String,
    compression: String,
    file_size: i64,
}

async fn backfill_snapshot(
    tx: &mut crate::db::Transaction,
    row: &Published,
) -> Result<BackfillSnapshot, ApiError> {
    sqlx::query_as::<_, BackfillSnapshot>(
        "SELECT c.id AS cache_id, b.id AS blob_id, c.is_public, b.r2_key, b.public_key,
            b.private_key, b.file_hash, b.compression, b.file_size
         FROM published_paths p JOIN caches c ON c.id=p.cache_id
         JOIN orgs o ON o.id=c.org_id JOIN blob_objects b ON b.id=p.blob_object_id
         WHERE p.id=$1 AND c.org_id=$2 AND p.store_path_hash=$3
         FOR UPDATE OF c,o,b,p NOWAIT",
    )
    .bind(row.id)
    .bind(&row.org_id)
    .bind(&row.store_path_hash)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(not_found)
}

// An uncertain finish commit may already have adopted the key. Only the
// matching, still-unadopted reservation can transfer ownership to cleanup.
async fn retire_backfill(state: &AppState, key: &str, operation: &str) -> Result<(), ApiError> {
    sqlx::query("WITH retired AS (
        DELETE FROM nar_installations i WHERE i.key=$1 AND i.operation_id=$2
            AND NOT EXISTS (SELECT 1 FROM blob_objects b WHERE b.public_key=i.key OR b.private_key=i.key)
        RETURNING is_private,key
    ) INSERT INTO object_cleanup(is_private,key) SELECT is_private,key FROM retired ON CONFLICT DO NOTHING")
        .bind(key).bind(operation).execute(&state.pool).await?;
    Ok(())
}

async fn repair_backfill(state: &AppState, row: &Published) -> Result<bool, ApiError> {
    let operation = uuid::Uuid::now_v7().to_string();
    let mut tx = crate::db::begin(state, &row.org_id).await?;
    crate::db::advisory_lock(&mut tx, &format!("org:{}", row.org_id)).await?;
    let snapshot = backfill_snapshot(&mut tx, row).await?;
    let nar_fence = format!("nar:{}:{}", snapshot.file_hash, snapshot.compression);
    crate::db::advisory_lock(&mut tx, &nar_fence).await?;
    let private = !snapshot.is_public;
    let destination = format!(
        "{}/objects/{operation}/{}/{}.nar",
        if private { "nars" } else { "nar" },
        snapshot.file_hash,
        snapshot.compression
    );
    let pointer = if private {
        &snapshot.private_key
    } else {
        &snapshot.public_key
    };
    let target = pointer.clone().unwrap_or_else(|| {
        format!(
            "{}/{}/{}.nar",
            if private { "nars/sha256" } else { "nar" },
            snapshot.file_hash,
            snapshot.compression
        )
    });
    let source = if private {
        &snapshot.public_key
    } else {
        &snapshot.private_key
    }
    .as_deref()
    .unwrap_or(&snapshot.r2_key)
    .to_owned();
    sqlx::query(
        "INSERT INTO nar_installations (
        key,operation_id,source_key,file_hash,compression,is_private,file_size,
        cache_id,expires_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()+INTERVAL '1 hour')",
    )
    .bind(&destination)
    .bind(&operation)
    .bind(&source)
    .bind(&snapshot.file_hash)
    .bind(&snapshot.compression)
    .bind(private)
    .bind(snapshot.file_size)
    .bind(snapshot.cache_id)
    .execute(&mut *tx)
    .await?;
    if let Err(error) = tx.commit().await {
        let _ = retire_backfill(state, &destination, &operation).await;
        return Err(error.into());
    }
    let result = async {
        // No SQL transaction is held during provider calls. The reservation
        // owns the unique destination and pins its recorded source for GC.
        let copied = match state.storage.head(private, &target).await {
            // Immutable records never use the legacy canonical fallback at
            // read time. They need an adopted bucket pointer even if it exists.
            Ok(_) => pointer.is_none() && snapshot.r2_key.contains("/objects/"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => return Err(internal()),
        };
        if copied {
            state.storage.copy(!source.starts_with("nar/"), &source, private, &destination)
                .await.map_err(|_| internal())?;
        }
        let mut tx = crate::db::begin(state, &row.org_id).await?;
        crate::db::advisory_lock(&mut tx, &format!("org:{}", row.org_id)).await?;
        crate::db::advisory_lock(&mut tx, &nar_fence).await?;
        let fresh = backfill_snapshot(&mut tx, row).await?;
        if fresh.cache_id != snapshot.cache_id || fresh.blob_id != snapshot.blob_id
            || fresh.is_public != snapshot.is_public
            || fresh.r2_key != snapshot.r2_key {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Publication changed; retry"));
        }
        let owned: Option<String> = sqlx::query_scalar("SELECT operation_id FROM nar_installations
            WHERE key=$1 AND operation_id=$2 AND expires_at>NOW() AND phase<>'revoked'
            FOR UPDATE NOWAIT")
            .bind(&destination).bind(&operation)
            .fetch_optional(&mut *tx).await?;
        if owned.is_none() {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Repair expired; retry"));
        }
        let adopted = if copied {
            let query = if private {
                "UPDATE blob_objects SET private_key=$1 WHERE id=$2 AND private_key IS NOT DISTINCT FROM $3"
            } else {
                "UPDATE blob_objects SET public_key=$1 WHERE id=$2 AND public_key IS NOT DISTINCT FROM $3"
            };
            sqlx::query(query).bind(&destination).bind(snapshot.blob_id).bind(pointer)
                .execute(&mut *tx).await?.rows_affected() == 1
        } else { false };
        if !adopted {
            sqlx::query("INSERT INTO object_cleanup(is_private,key) VALUES($1,$2) ON CONFLICT DO NOTHING")
                .bind(private).bind(&destination).execute(&mut *tx).await?;
        }
        sqlx::query("DELETE FROM nar_installations WHERE key=$1 AND operation_id=$2")
            .bind(&destination).bind(&operation).execute(&mut *tx).await?;
        retire_narinfo(&mut tx, row, &path(&row.slug, &row.name)).await?;
        tx.commit().await?;
        Ok(adopted)
    }.await;
    if result.is_err() {
        // Failure here is still safe: durable expiry retains cleanup ownership.
        let _ = retire_backfill(state, &destination, &operation).await;
    }
    result
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn retire_narinfo(
    tx: &mut crate::db::Transaction,
    row: &Published,
    target: &str,
) -> Result<(), ApiError> {
    // Narinfo is rendered from SQL at read time; retire known legacy keys.
    for (private, key) in [
        (false, format!("{target}/{}.narinfo", row.store_path_hash)),
        (
            true,
            format!("narinfo/{target}/{}.narinfo", row.store_path_hash),
        ),
    ] {
        sqlx::query(
            "INSERT INTO object_cleanup (is_private, key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(private)
        .bind(key)
        .execute(&mut **tx)
        .await?;
    }
    set_cache_info(tx, target).await?;
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn backfill(State(state): State<AppState>, request: Request) -> Result<Response, ApiError> {
    let state = &state;
    let input = body(request).await?;
    let after = input
        .get("after")
        .map(|v| {
            integer(v)
                .filter(|n| *n >= 0)
                .ok_or_else(|| bad("after must be a non-negative integer"))
        })
        .transpose()?
        .unwrap_or(0);
    let limit = input
        .get("limit")
        .map(|v| {
            integer(v)
                .filter(|n| (1..=1000).contains(n))
                .ok_or_else(|| bad("limit must be between 1 and 1000"))
        })
        .transpose()?
        .unwrap_or(500);
    let rows = sqlx::query_as!(
        Published,
        r#"
        SELECT
            p.id,
            c.org_id,
            c.name,
            o.slug,
            p.store_path_hash
        FROM published_paths p
        JOIN caches c ON c.id = p.cache_id
        JOIN orgs o ON o.id = c.org_id
        WHERE p.id > $1
        ORDER BY p.id
        LIMIT $2
        "#,
        after,
        limit
    )
    .fetch_all(&state.pool)
    .await?;
    let mut skipped = Vec::new();
    let mut written = 0;
    for row in &rows {
        let target = path(&row.slug, &row.name);
        match repair_backfill(state, row).await {
            Ok(repaired) => written += usize::from(repaired),
            Err(_) => skipped.push(format!("{target}/{}", row.store_path_hash)),
        }
    }
    Ok(ok(
        json!({"written":written,"processed":rows.len()-skipped.len(),"skipped":skipped,"next":if rows.len()==limit as usize{rows.last().map(|r|r.id)}else{None}}),
    ))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn move_slug(
    State(state): State<AppState>,
    Path(params): Path<OrgPath>,
    request: Request,
) -> Result<Response, ApiError> {
    let state = &state;
    let id = params.org.as_str();
    let input = body(request).await?;
    let at = input.get("cursor").filter(|v| !v.is_null());
    at.map(|v| {
        v.get("phase")
            .and_then(Value::as_str)
            .filter(|s| ["public", "private"].contains(s))
            .ok_or_else(|| bad("cursor must be a previous answer's next"))
    })
    .transpose()?;
    let cursor = at.and_then(|v| v.get("cursor"));
    cursor
        .map(|v| {
            v.as_str()
                .ok_or_else(|| bad("cursor must be a previous answer's next"))
        })
        .transpose()?;
    let mut tx = crate::profile_future!(
        crate::db::begin(state, id),
        label = "management.move_slug_pool_begin"
    )
    .await?;
    let org_key = format!("org:{id}");
    crate::profile_future!(
        crate::db::advisory_lock(&mut tx, &org_key),
        label = "management.move_slug_org_lock_wait"
    )
    .await?;
    let moving: Option<String> = sqlx::query_scalar!(
        r#"
        SELECT moving_from
        FROM orgs
        WHERE id = $1
        FOR UPDATE NOWAIT
        "#,
        id
    )
    .fetch_one(&mut *tx)
    .await?;
    let Some(from) = moving else {
        return Ok(ok(json!({"done":true})));
    };
    // Reads already resolve the new slug from SQL. Retire only known old keys;
    // orphan object discovery is not part of a policy transaction.
    let names = sqlx::query_scalar!(
        r#"
            SELECT name
            FROM caches
            WHERE org_id = $1
            "#,
        id
    )
    .fetch_all(&mut *tx)
    .await?;
    for name in names {
        let hashes = sqlx::query_scalar!(
                "SELECT p.store_path_hash FROM published_paths p JOIN caches c ON c.id = p.cache_id WHERE c.org_id = $1 AND c.name = $2",
                id,
                name
            ).fetch_all(&mut *tx).await?;
        crate::management_policy::MetadataTarget::new(true, &from, None, &name)
            .withdraw(&mut tx, &hashes)
            .await?;
        set_cache_info(&mut tx, &path(&from, &name)).await?;
    }
    sqlx::query!(
        r#"
            UPDATE orgs
            SET moving_from = NULL
            WHERE id = $1
            "#,
        id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ok(json!({"done":true})))
}
