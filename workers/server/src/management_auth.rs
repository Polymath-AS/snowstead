//! Token, organization API-key, and audit management. Authentication, rate
//! limiting, org existence checks, and audit writes belong to the caller.
use axum::{
    Extension, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    AppState,
    error::{ApiError, json_response},
    management::ManagementContext,
};

fn bad(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}

fn internal() -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn date(value: Option<DateTime<Utc>>) -> Value {
    value
        .map(|v| json!(v.to_rfc3339_opts(SecondsFormat::Millis, true)))
        .unwrap_or(Value::Null)
}

fn valid_org(org: &str) -> bool {
    !org.is_empty()
        && org.len() <= 128
        && org
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn body(request: Request) -> Result<Value, ApiError> {
    let bytes = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| bad("Invalid JSON in request body"))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| bad("Invalid JSON in request body"))?;
    if !value.is_object() {
        let received = match &value {
            Value::Null => "null".to_owned(),
            Value::Array(_) => "undefined".to_owned(),
            Value::String(s) => format!("\"{s}\""),
            _ => value.to_string(),
        };
        return Err(bad(format!(
            "Invalid type: Expected Object but received {received}"
        )));
    }
    Ok(value)
}

fn string<'a>(
    value: &'a Value,
    field: &str,
    message: &str,
    max: usize,
    too_long: &str,
) -> Result<&'a str, ApiError> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad(message))?;
    if s.encode_utf16().count() > max {
        return Err(bad(too_long));
    }
    Ok(s)
}

fn strings(value: &Value, field: &str, max: usize) -> Result<Vec<String>, ApiError> {
    let message = if field == "caches" {
        "caches must be a non-empty array of cache names"
    } else {
        "perms must be a non-empty array"
    };
    let array = value
        .get(field)
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| bad(message))?;
    let mut result = Vec::new();
    for (index, item) in array.iter().enumerate() {
        let s = if field == "caches" {
            item.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
                bad(format!(
                    "caches[{index}]: each cache entry must be a non-empty string"
                ))
            })?
        } else {
            let s = item.as_str().unwrap_or("");
            if ![
                "pull",
                "push",
                "go:read",
                "go:write",
                "sccache:read",
                "sccache:write",
            ]
            .contains(&s)
            {
                let input = item
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| item.to_string());
                return Err(bad(format!(
                    "perms[{index}]: invalid permission: {input}, expected \"pull\", \"push\", \"go:read\", \"go:write\", \"sccache:read\", or \"sccache:write\""
                )));
            }
            s
        };
        if !result.iter().any(|entry| entry == s) {
            result.push(s.to_owned());
        }
    }
    if array.len() > max {
        return Err(bad(format!("{field} exceeds maximum of {max}")));
    }
    Ok(result)
}

pub fn org_router() -> Router<AppState> {
    Router::new()
        .route("/tokens", get(get_tokens).post(create_token))
        .route("/tokens/{jti}", get(get_token))
        .route("/tokens/{jti}/revoke", post(revoke_token))
        .route("/keys", get(list_keys).post(create_key))
        .route("/keys/{key}/revoke", post(revoke_key))
        .route("/audit", get(list_audit))
}

pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/tokens", get(get_tokens).post(create_token))
        .route("/tokens/{jti}/revoke", post(revoke_token))
}

#[derive(Deserialize)]
struct TokenPath {
    jti: String,
}

#[derive(Deserialize)]
struct KeyPath {
    key: String,
}

/// The org the route names; None on the operator surface. The middleware has
/// already authorized the principal for this route.
fn scope(context: &ManagementContext) -> Option<&str> {
    context.org.as_deref()
}

fn org_scope(context: &ManagementContext) -> Result<&str, ApiError> {
    scope(context).ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "Forbidden"))
}

fn query_url(uri: &Uri) -> Result<reqwest::Url, ApiError> {
    reqwest::Url::parse(&format!("http://localhost{uri}")).map_err(|_| bad("Invalid URL"))
}

fn query(url: &reqwest::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

async fn get_tokens(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let org = scope(&context);
    let url = query_url(&uri)?;
    let filter = org.map(str::to_owned).or_else(|| query(&url, "org"));
    if filter.as_deref().is_some_and(|s| !valid_org(s)) {
        return Err(bad("org must be an org id"));
    }
    list_tokens(&state, filter.as_deref(), org.is_some(), None).await
}

async fn get_token(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(TokenPath { jti }): Path<TokenPath>,
) -> Result<Response, ApiError> {
    let org = org_scope(&context)?;
    list_tokens(&state, Some(org), true, Some(&jti)).await
}

async fn revoke_token(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(TokenPath { jti }): Path<TokenPath>,
    request: Request,
) -> Result<Response, ApiError> {
    let org = scope(&context);
    let principal = &context.principal;
    let value = body(request).await?;
    let reason = string(
        &value,
        "reason",
        "reason must be a non-empty string",
        512,
        "reason exceeds maximum length",
    )?;
    let token_org: String = sqlx::query_scalar(
        "SELECT COALESCE(org_id,'default') FROM api_tokens WHERE jti=$1 AND ($2::text IS NULL OR org_id=$2)",
    ).bind(&jti).bind(org).fetch_optional(&state.pool).await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Token not found or already revoked"))?;
    let mut tx = crate::db::begin(&state, &token_org).await?;
    crate::db::advisory_lock(&mut tx, &format!("org:{token_org}")).await?;
    let changed = sqlx::query!(
        r#"
                UPDATE api_tokens
                SET revoked_at = NOW(),
                    revoked_by = $2,
                    revocation_reason = $3
                WHERE jti = $1
                    AND revoked_at IS NULL
                    AND ($4::text IS NULL OR org_id = $4)
                "#,
        &jti,
        principal.actor(),
        reason,
        org
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Token not found or already revoked",
        ));
    }
    sqlx::query("UPDATE push_jobs SET authorization_jti=NULL,authorization_expires_at=NULL,grant_generation=grant_generation+1 WHERE authorization_jti=$1")
        .bind(&jti).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(json_response(
        StatusCode::OK,
        json!({"revoked":true,"jti":jti}),
    ))
}

async fn list_keys(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
) -> Result<Response, ApiError> {
    let org = org_scope(&context)?;
    let rows = sqlx::query!(
        r#"
                SELECT
                    id,
                    name,
                    created_at,
                    revoked_at
                FROM org_api_keys
                WHERE org_id = $1
                ORDER BY created_at
                "#,
        org
    )
    .fetch_all(&state.pool)
    .await?;
    let keys: Vec<Value> = rows.iter().map(|r| json!({"id":r.id,"name":r.name,"createdAt":date(Some(r.created_at)),"revokedAt":date(r.revoked_at)})).collect();
    Ok(json_response(StatusCode::OK, json!({"keys":keys})))
}

async fn create_key(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let org = org_scope(&context)?;
    let value = body(request).await?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.encode_utf16().count() <= 64)
        .ok_or_else(|| bad("name must be 1 to 64 characters"))?;
    let bytes = crate::auth::random_bytes::<48>().map_err(|_| internal())?;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let id: String = bytes[..16]
        .iter()
        .map(|b| alphabet[(*b as usize) % alphabet.len()] as char)
        .collect();
    let secret = URL_SAFE_NO_PAD.encode(&bytes[16..]);
    let hash = crate::auth::secret_hash(&secret);
    let created = sqlx::query_scalar!(
        r#"
                INSERT INTO org_api_keys (
                    id,
                    org_id,
                    name,
                    secret_hash
                )
                VALUES ($1, $2, $3, $4)
                RETURNING created_at
                "#,
        &id,
        org,
        name,
        hash
    )
    .fetch_one(&state.pool)
    .await?;
    Ok(json_response(
        StatusCode::CREATED,
        json!({"id":id,"name":name,"key":format!("snowstead_key_{id}_{secret}"),"createdAt":date(Some(created))}),
    ))
}

async fn revoke_key(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(KeyPath { key: id }): Path<KeyPath>,
) -> Result<Response, ApiError> {
    let org = org_scope(&context)?;
    let changed = sqlx::query!(
        r#"
                UPDATE org_api_keys
                SET revoked_at = COALESCE(revoked_at, NOW())
                WHERE id = $1
                    AND org_id = $2
                "#,
        &id,
        org
    )
    .execute(&state.pool)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, format!("no key {id}")));
    }
    Ok(json_response(
        StatusCode::OK,
        json!({"revoked":true,"id":id}),
    ))
}

#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "management.list_audit"
    )
)]
async fn list_audit(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let org = org_scope(&context)?;
    let url = query_url(&uri)?;
    let limit = query(&url, "limit").map(|v| js_number(&v)).unwrap_or(50.0);
    if !limit.is_finite() || limit.fract() != 0.0 || !(1.0..=200.0).contains(&limit) {
        return Err(bad("limit must be between 1 and 200"));
    }
    let before = query(&url, "before").map(|v| js_number(&v));
    if before.is_some_and(|v| {
        !v.is_finite() || v.fract() != 0.0 || !(1.0..=9_007_199_254_740_991.0).contains(&v)
    }) {
        return Err(bad("before must be an entry id"));
    }
    let rows = sqlx::query!(
        r#"
                SELECT
                    id,
                    timestamp,
                    actor,
                    action,
                    cache_name,
                    status,
                    detail,
                    ip
                FROM audit_logs
                WHERE org_id = $1
                    AND ($2::bigint IS NULL OR id < $2)
                ORDER BY id DESC
                LIMIT $3
                "#,
        org,
        before.map(|v| v as i64),
        limit as i64
    )
    .fetch_all(&state.read_pool)
    .await?;
    let mut entries = Vec::new();
    for r in &rows {
        let detail: Value = serde_json::from_str(&r.detail).map_err(|_| internal())?;
        entries.push(json!({"id":r.id,"at":date(Some(r.timestamp)),"actor":r.actor,"action":r.action,"cache":r.cache_name,"status":r.status,"detail":detail,"ip":r.ip}));
    }
    let next = if entries.len() == limit as usize {
        entries
            .last()
            .map(|v| v["id"].clone())
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Ok(json_response(
        StatusCode::OK,
        json!({"entries":entries,"next":next}),
    ))
}

// URLSearchParams uses JavaScript Number, accepting whitespace and radix
// prefixes as well as decimal/exponent notation.
pub(crate) fn js_number(value: &str) -> f64 {
    let value = value.trim();
    if value.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0b", 2),
        ("0B", 2),
        ("0o", 8),
        ("0O", 8),
    ] {
        if let Some(digits) = value.strip_prefix(prefix) {
            return u64::from_str_radix(digits, radix)
                .map(|v| v as f64)
                .unwrap_or(f64::NAN);
        }
    }
    value.parse().unwrap_or(f64::NAN)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn create_token(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    request: Request,
) -> Result<Response, ApiError> {
    let scope = scope(&context);
    let principal = &context.principal;
    let value = body(request).await?;
    let requested_org = value
        .get("org")
        .map(|v| {
            v.as_str()
                .filter(|s| valid_org(s))
                .ok_or_else(|| bad("org must be an org id"))
        })
        .transpose()?;
    let subject = string(
        &value,
        "subject",
        "subject must be a non-empty string",
        256,
        "subject exceeds maximum length",
    )?;
    let caches = strings(&value, "caches", 50)?;
    let perms = strings(&value, "perms", 10)?;
    // Null keeps the token until it is revoked: `snowstead login` offers
    // tokens that never expire.
    let days = match value.get("expiresInDays") {
        None => Some(90),
        Some(Value::Null) => None,
        Some(v) => Some(
            v.as_f64()
                .filter(|n| n.fract() == 0.0 && (1.0..=365.0).contains(n))
                .ok_or_else(|| bad("expiresInDays must be between 1 and 365"))? as i64,
        ),
    };
    let org = scope.or(requested_org).unwrap_or("default");
    let mut tx = state.pool.begin().await?;
    let literals: Vec<_> = caches
        .iter()
        .filter(|entry| !entry.contains('*'))
        .cloned()
        .collect();
    let resolved = if literals.is_empty() {
        Vec::new()
    } else {
        sqlx::query!(
            r#"
            SELECT
                name,
                id
            FROM caches
            WHERE org_id = $1
                AND name = ANY($2::text[])
            FOR KEY SHARE
            "#,
            org,
            &literals
        )
        .fetch_all(&mut *tx)
        .await?
    };
    let resolved: std::collections::HashMap<_, _> =
        resolved.into_iter().map(|r| (r.name, r.id)).collect();
    let mut entries = Vec::new();
    for entry in &caches {
        if entry.contains('*') {
            if entry.is_empty()
                || entry.len() > 64
                || !entry.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'*' | b'-')
                })
            {
                return Err(bad(format!("{entry} must be cache name characters and *")));
            }
            entries.push(entry.clone());
        } else {
            let id = resolved
                .get(entry)
                .ok_or_else(|| bad(format!("{entry} is not a cache of {org}")))?;
            entries.push(format!("id:{id}"));
        }
    }
    let expires = days.map(|days| Utc::now() + chrono::Duration::days(days));
    let (jti, token, hash) = crate::auth::issue_token().map_err(|_| internal())?;
    sqlx::query!(
        r#"
        INSERT INTO api_tokens (
            jti,
            subject,
            secret_hash,
            expires_at,
            created_by,
            org_id
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        &jti,
        subject,
        hash,
        expires,
        principal.actor(),
        org
    )
    .execute(&mut *tx)
    .await?;
    // The token's scope lives only in these rows, read on every request.
    sqlx::query!(
        r#"
        INSERT INTO token_permissions (
            token_jti,
            permission,
            position
        )
        SELECT $1, permission, position
        FROM UNNEST($2::text[]) WITH ORDINALITY AS requested(permission, position)
        "#,
        &jti,
        &perms
    )
    .execute(&mut *tx)
    .await?;
    // Explicit ordinality keeps generated row IDs (and later listings) in
    // request order, including patterns interleaved with literal cache IDs.
    sqlx::query!(
        r#"
        INSERT INTO token_caches (
            token_jti,
            cache_id,
            pattern
        )
        SELECT
            $1,
            CASE WHEN entry LIKE 'id:%' THEN SUBSTR(entry, 4)::int END,
            CASE WHEN entry NOT LIKE 'id:%' THEN entry END
        FROM UNNEST($2::text[]) WITH ORDINALITY AS requested(entry, position)
        ORDER BY position
        "#,
        &jti,
        &entries
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(json_response(
        StatusCode::CREATED,
        json!({"token":token,"jti":jti,"subject":subject,"caches":caches,"perms":perms,"org":org,"expiresAt":date(expires)}),
    ))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "management.list_tokens"
    )
)]
async fn list_tokens(
    state: &AppState,
    filter: Option<&str>,
    scoped: bool,
    jti: Option<&str>,
) -> Result<Response, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            t.jti,
            t.subject,
            t.org_id,
            t.created_at,
            t.expires_at,
            t.created_by,
            t.revoked_at,
            t.revoked_by,
            t.revocation_reason,
            t.last_used_at,
            ARRAY(
                SELECT p.permission
                FROM token_permissions p
                WHERE p.token_jti = t.jti
                ORDER BY p.position
            ) AS "perms!",
            ARRAY(
                SELECT COALESCE(c.name, 'id:' || tc.cache_id::text, tc.pattern)
                FROM token_caches tc
                LEFT JOIN caches c ON c.id = tc.cache_id
                    AND ($1::text IS NULL OR c.org_id = $1)
                WHERE tc.token_jti = t.jti
                ORDER BY tc.id
            ) AS "entries!"
        FROM api_tokens t
        WHERE ($1::text IS NULL OR t.org_id = $1)
            AND ($2::text IS NULL OR t.jti = $2)
        "#,
        filter,
        jti
    )
    .fetch_all(&state.pool)
    .await?;
    let mut tokens = Vec::new();
    for r in rows {
        let mut token = json!({"jti":r.jti,"subject":r.subject,"caches":r.entries,"perms":r.perms,"org":r.org_id,"createdAt":date(Some(r.created_at)),"expiresAt":date(r.expires_at),"createdBy":r.created_by,"revokedAt":date(r.revoked_at),"revokedBy":r.revoked_by,"revocationReason":r.revocation_reason});
        if scoped {
            token["lastUsedAt"] = date(r.last_used_at);
        }
        tokens.push(token);
    }
    if jti.is_some() {
        let token = tokens
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Token not found"))?;
        Ok(json_response(StatusCode::OK, json!({"token":token})))
    } else {
        Ok(json_response(StatusCode::OK, json!({"tokens":tokens})))
    }
}
