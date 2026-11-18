//! Authentication: turn a request's credential into a [`Principal`]. Nothing
//! here grants access; callers ask [`crate::authz::authorize`].
//!
//! Credentials, by form:
//! - `ADMIN_SECRET`: the operator, for `/_api/v1/admin` only.
//! - `snowstead_key_<id>_<secret>`: an org API key.
//! - `snowstead_tok_<jti>_<secret>`: an API token. Only a hash of the secret
//!   is stored; scope comes from `token_permissions` and `token_caches`.
//! - A JWT-era API token, accepted only while its `jti` is listed and
//!   unrevoked in `api_tokens`, with scope from the database, not its claims.
//! - A self-hosted shared `AUTH_TOKEN`, only when explicitly enabled.
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use subtle::ConstantTimeEq;

use crate::{
    AppState,
    authz::{ApiToken, CacheGrant, Permission, Principal},
    error::ApiError,
};

pub(crate) const JWT_CLOCK_SKEW_SECONDS: i64 = 60;
const JWT_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
pub(crate) const TOKEN_PREFIX: &str = "snowstead_tok_";
const KEY_PREFIX: &str = "snowstead_key_";
fn auth_error(status: StatusCode, read: bool) -> ApiError {
    let error = ApiError::new(
        status,
        if status == StatusCode::UNAUTHORIZED {
            "Unauthorized"
        } else {
            "Forbidden"
        },
    );
    if status == StatusCode::UNAUTHORIZED {
        error.header(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(if read {
                "Basic realm=\"snowstead\""
            } else {
                "Bearer"
            }),
        )
    } else {
        error
    }
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    let (scheme, token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .ok_or_else(|| auth_error(StatusCode::UNAUTHORIZED, false))?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(auth_error(StatusCode::UNAUTHORIZED, false));
    }
    Ok(token)
}

fn equal_secret(a: &str, b: &str) -> bool {
    let a_hash = Sha256::digest(a.as_bytes());
    let b_hash = Sha256::digest(b.as_bytes());
    bool::from(a_hash.ct_eq(&b_hash)) & (a.len() == b.len())
}

pub(crate) fn secret_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

pub(crate) fn random_bytes<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// A new opaque API token: its ID (`jti`), the bearer value shown once, and
/// the hash to store.
pub(crate) fn issue_token() -> std::io::Result<(String, String, String)> {
    let id = uuid::Uuid::now_v7().to_string();
    let secret = URL_SAFE_NO_PAD.encode(random_bytes::<32>()?);
    let hash = secret_hash(&secret);
    Ok((id.clone(), format!("{TOKEN_PREFIX}{id}_{secret}"), hash))
}

#[derive(Debug, Deserialize)]
struct Claims {
    jti: String,
    sub: String,
    iss: String,
    aud: String,
    caches: Vec<String>,
    perms: Vec<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
    iat: i64,
}

// Match atob's acceptance of padded and unpadded base64url, including standard
// base64 characters, without relaxing the exact encoded JWT header.
fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let normalized: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000c}'))
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    let mut config = base64::engine::general_purpose::GeneralPurposeConfig::new();
    config = config
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, config)
        .decode(normalized)
        .ok()
}

/// Check a JWT-era token's signature and well-formedness. Its claims only
/// identify the token; scope comes from its database row.
#[cfg_attr(feature = "profiling", hotpath::measure)]
fn verify_jwt(token: &str, secret: &str, now: f64) -> Option<Claims> {
    if token.encode_utf16().count() > 4096 {
        return None;
    }
    let mut parts = token.split('.');
    let encoded_header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() || encoded_header != JWT_HEADER {
        return None;
    }
    let mut raw: serde_json::Value = serde_json::from_slice(&decode_base64(payload)?).ok()?;
    // JS safe integers include JSON numbers written as 1.0 or 1e3.
    for field in ["iat", "exp"] {
        if field == "exp" && raw.get(field).is_none() {
            continue;
        }
        let number = raw.get(field)?.as_f64()?;
        if number.fract() != 0.0 || number.abs() > 9_007_199_254_740_991.0 {
            return None;
        }
        raw[field] = serde_json::json!(number as i64);
    }
    if raw.get("org").is_some_and(|org| !org.is_string()) {
        return None;
    }
    let claims: Claims = serde_json::from_value(raw).ok()?;
    if claims.jti.is_empty()
        || claims.sub.is_empty()
        || claims.iss != "snowstead"
        || claims.aud != "snowstead"
        || claims.org.as_ref().is_some_and(String::is_empty)
        || claims.caches.is_empty()
        || claims.caches.len() > 50
        || claims.caches.iter().any(String::is_empty)
        || claims.perms.is_empty()
        || claims.perms.len() > 10
        || claims.perms.iter().any(|p| Permission::parse(p).is_none())
        || claims.iat as f64 > now + JWT_CLOCK_SKEW_SECONDS as f64
        || claims.exp.is_some_and(|exp| {
            exp <= claims.iat || exp as f64 <= now - JWT_CLOCK_SKEW_SECONDS as f64
        })
    {
        return None;
    }
    let signature = decode_base64(signature)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(format!("{encoded_header}.{payload}").as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(claims)
}

fn now() -> f64 {
    chrono::Utc::now().timestamp_millis() as f64 / 1000.0
}

/// How a presented API token proves itself against its row.
enum TokenProof<'a> {
    Secret(&'a str),
    /// A verified JWT naming this org.
    Jwt {
        org: &'a str,
    },
}

/// Load a listed, live token and its scope, or reject the credential.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn token(
    state: &AppState,
    id: &str,
    proof: TokenProof<'_>,
    read: bool,
) -> Result<Principal, ApiError> {
    let row = crate::profile_future!(
        sqlx::query!(
            r#"
            SELECT
                COALESCE(t.org_id, 'default') AS "org!",
                t.secret_hash,
                t.expires_at,
                -- Expiry allows the clock skew JWT verification always has.
                t.revoked_at IS NULL
                    AND (t.expires_at IS NULL OR t.expires_at > NOW() - INTERVAL '60 seconds')
                    AS "live!",
                t.last_used_at IS NULL OR t.last_used_at <= NOW() - INTERVAL '5 minutes'
                    AS "usage_due!",
                ARRAY(
                    SELECT p.permission
                    FROM token_permissions p
                    WHERE p.token_jti = t.jti
                    ORDER BY p.position
                ) AS "permissions!",
                ARRAY(
                    SELECT tc.cache_id
                    FROM token_caches tc
                    WHERE tc.token_jti = t.jti
                        AND tc.cache_id IS NOT NULL
                    ORDER BY tc.id
                ) AS "cache_ids!: Vec<i32>",
                ARRAY(
                    SELECT tc.pattern
                    FROM token_caches tc
                    WHERE tc.token_jti = t.jti
                        AND tc.pattern IS NOT NULL
                    ORDER BY tc.id
                ) AS "patterns!: Vec<String>"
            FROM api_tokens t
            WHERE t.jti = $1
            "#,
            id,
        )
        .fetch_optional(&state.pool),
        label = "auth.token_sql"
    )
    .await?;
    let rejected = || auth_error(StatusCode::UNAUTHORIZED, read);
    // Compare a hash even for unknown IDs, so timing doesn't reveal which exist.
    let stored = row
        .as_ref()
        .and_then(|row| row.secret_hash.as_deref())
        .unwrap_or("");
    let proven = match proof {
        TokenProof::Secret(secret) => {
            equal_secret(&secret_hash(secret), stored) & !stored.is_empty()
        }
        TokenProof::Jwt { org } => row
            .as_ref()
            .is_some_and(|row| row.secret_hash.is_none() && row.org == org),
    };
    let Some(row) = row.filter(|row| proven && row.live) else {
        return Err(rejected());
    };
    if row.usage_due {
        record_use(state, id).await;
    }
    let principal = Principal::ApiToken(ApiToken {
        id: id.to_owned(),
        org: row.org,
        permissions: row
            .permissions
            .iter()
            .filter_map(|p| Permission::parse(p))
            .collect(),
        caches: row
            .cache_ids
            .into_iter()
            .map(CacheGrant::Id)
            .chain(row.patterns.into_iter().map(CacheGrant::Pattern))
            .collect(),
        expires_at: row.expires_at,
    });
    #[cfg(feature = "observability")]
    crate::observability::identity(&principal, None);
    Ok(principal)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn record_use(state: &AppState, id: &str) {
    // Await bounded pool work; never spawn an unbounded task per request.
    // Telemetry is best-effort and the predicate limits actual writes.
    // A finalization or publication holds this row shared until it commits;
    // skip the stamp rather than park a connection behind it.
    if crate::profile_future!(
        sqlx::query!(
            r#"
            UPDATE api_tokens
            SET last_used_at = NOW()
            WHERE jti = (
                SELECT jti
                FROM api_tokens
                WHERE jti = $1
                    AND (last_used_at IS NULL OR last_used_at <= NOW() - INTERVAL '5 minutes')
                FOR NO KEY UPDATE SKIP LOCKED
            )
            "#,
            id,
        )
        .execute(&state.pool),
        label = "auth.record_use_sql"
    )
    .await
    .is_err()
    {
        tracing::warn!("Token usage telemetry failed");
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn org_key(state: &AppState, rest: &str) -> Result<Principal, ApiError> {
    let invalid = || auth_error(StatusCode::UNAUTHORIZED, false);
    let (id, secret) = rest.split_once('_').ok_or_else(invalid)?;
    if id.len() != 16
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || secret.is_empty()
    {
        return Err(invalid());
    }
    struct OrgKey {
        org_id: String,
        secret_hash: String,
        revoked: bool,
    }
    let row = crate::profile_future!(
        sqlx::query_as!(
            OrgKey,
            r#"
        SELECT
            org_id,
            secret_hash,
            revoked_at IS NOT NULL AS "revoked!"
        FROM org_api_keys
        WHERE id = $1
        "#,
            id,
        )
        .fetch_optional(&state.pool),
        label = "auth.org_key_sql"
    )
    .await?;
    let valid = equal_secret(
        &secret_hash(secret),
        row.as_ref().map(|r| r.secret_hash.as_str()).unwrap_or(""),
    );
    match row {
        Some(key) if valid && !key.revoked => Ok(Principal::OrgKey {
            org: key.org_id,
            key_id: id.into(),
        }),
        _ => Err(invalid()),
    }
}

/// Identify the holder of a native credential, or reject it with 401.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn principal(state: &AppState, credential: &str, read: bool) -> Result<Principal, ApiError> {
    let rejected = || auth_error(StatusCode::UNAUTHORIZED, read);
    let config = &state.config;
    if !config.admin_secret.is_empty() && equal_secret(credential, &config.admin_secret) {
        return Ok(Principal::Operator);
    }
    if let Some(rest) = credential.strip_prefix(KEY_PREFIX) {
        return org_key(state, rest).await.map_err(|_| rejected());
    }
    if let Some(rest) = credential.strip_prefix(TOKEN_PREFIX) {
        let (id, secret) = rest.split_once('_').ok_or_else(rejected)?;
        if uuid::Uuid::try_parse(id).is_err() || secret.is_empty() || secret.len() > 128 {
            return Err(rejected());
        }
        return token(state, id, TokenProof::Secret(secret), read).await;
    }
    if let Some(shared) = &config.shared_auth_token
        && equal_secret(credential, shared)
    {
        return Ok(Principal::SharedToken);
    }
    if !config.jwt_secret.is_empty()
        && let Some(claims) = verify_jwt(credential, &config.jwt_secret, now())
    {
        let org = claims.org.as_deref().unwrap_or("default");
        return token(state, &claims.jti, TokenProof::Jwt { org }, read).await;
    }
    Err(rejected())
}

/// Authenticate a native bearer credential.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<Principal, ApiError> {
    let credential = bearer(headers)?;
    principal(state, credential, false).await
}

/// A token holder may inspect their own current scope without management access.
pub(crate) async fn status(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ApiError> {
    let Principal::ApiToken(token) = authenticate(&headers, &state).await? else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Credential status requires an API token",
        ));
    };
    let organization = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(&token.org)
        .fetch_one(&state.pool)
        .await?;
    let caches = sqlx::query_scalar(
        "SELECT COALESCE(c.name, tc.pattern) FROM token_caches tc \
         LEFT JOIN caches c ON c.id = tc.cache_id AND c.org_id = $2 \
         WHERE tc.token_jti = $1 ORDER BY tc.id",
    )
    .bind(&token.id)
    .bind(&token.org)
    .fetch_all(&state.pool)
    .await?;
    let status = snowstead_protocol::AuthStatus {
        organization,
        permissions: token
            .permissions
            .iter()
            .map(|p| p.as_str().into())
            .collect(),
        caches,
        expires_at: token.expires_at.map(|date| date.to_rfc3339()),
    };
    Ok(crate::error::json_response(
        StatusCode::OK,
        serde_json::json!(status),
    ))
}

/// Authenticate a Nix read: a bearer token, or a Basic password as Nix's
/// netrc sends it. Failures challenge for Basic credentials.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authenticate_read(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Principal, ApiError> {
    let credential = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .and_then(|(scheme, value)| {
            let value = value.trim();
            if scheme.eq_ignore_ascii_case("bearer") {
                return Some(value.to_owned());
            }
            if !scheme.eq_ignore_ascii_case("basic") {
                return None;
            }
            let bytes = decode_base64(value)?;
            let decoded = String::from_utf8(bytes).ok()?;
            Some(decoded.split_once(':')?.1.to_owned())
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| auth_error(StatusCode::UNAUTHORIZED, true))?;
    principal(state, &credential, true).await
}

/// Authorize a private Nix read of a cache.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authorize_read(
    headers: &HeaderMap,
    state: &AppState,
    cache_id: i32,
    cache_name: &str,
    org: &str,
) -> Result<(), ApiError> {
    let principal = authenticate_read(headers, state).await?;
    crate::authz::authorize(
        &principal,
        crate::authz::Action::Use(Permission::PULL),
        &crate::authz::Resource::cache(org, cache_id, cache_name),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::{Value, json};

    fn payload() -> Value {
        json!({"jti":"existing-client", "sub":"cli", "iss":"snowstead", "aud":"snowstead", "caches":["id:7", "ci-*-release"], "perms":["pull", "push"], "iat":1000})
    }

    fn sign(payload: &Value, header: &str) -> String {
        let input = format!(
            "{header}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap())
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(b"test-secret").unwrap();
        mac.update(input.as_bytes());
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn existing_token_without_org_or_expiry() {
        let claims = verify_jwt(&sign(&payload(), JWT_HEADER), "test-secret", 2000.0).unwrap();
        assert_eq!(claims.jti, "existing-client");
        assert_eq!(claims.org, None);
    }

    #[test]
    fn expiry_and_future_issue_skew_boundaries() {
        let mut p = payload();
        p["exp"] = json!(2000);
        let token = sign(&p, JWT_HEADER);
        assert!(verify_jwt(&token, "test-secret", 2059.999).is_some());
        assert!(verify_jwt(&token, "test-secret", 2060.0).is_none());
        p["exp"] = json!(1000);
        assert!(verify_jwt(&sign(&p, JWT_HEADER), "test-secret", 1000.0).is_none());
        p.as_object_mut().unwrap().remove("exp");
        assert!(verify_jwt(&sign(&p, JWT_HEADER), "test-secret", 940.0).is_some());
        assert!(verify_jwt(&sign(&p, JWT_HEADER), "test-secret", 939.999).is_none());
    }

    #[test]
    fn rejects_invalid_claims_signature_and_noncanonical_header() {
        let token = sign(&payload(), JWT_HEADER);
        assert!(verify_jwt(&token, "wrong-secret", 1000.0).is_none());
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"HS256"}"#);
        assert!(verify_jwt(&sign(&payload(), &header), "test-secret", 1000.0).is_none());
        for (field, value) in [
            ("aud", json!("other")),
            ("iss", json!("other")),
            ("perms", json!(["admin"])),
            ("caches", json!([])),
            ("org", Value::Null),
            ("exp", Value::Null),
            ("iat", json!(1000.5)),
        ] {
            let mut p = payload();
            p[field] = value;
            assert!(
                verify_jwt(&sign(&p, JWT_HEADER), "test-secret", 1000.0).is_none(),
                "{field}"
            );
        }
    }

    #[test]
    fn issued_tokens_are_opaque_and_store_only_a_hash() {
        let (id, token, hash) = issue_token().unwrap();
        let rest = token.strip_prefix(TOKEN_PREFIX).unwrap();
        let (token_id, secret) = rest.split_once('_').unwrap();
        assert_eq!(token_id, id);
        assert!(uuid::Uuid::try_parse(&id).is_ok());
        assert_eq!(secret.len(), 43);
        assert_eq!(hash, secret_hash(secret));
        assert!(!token.contains(&hash));
    }

    #[tokio::test]
    async fn public_authentication_and_challenges_without_database() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let config = crate::config::Config {
            shared_auth_token: Some("legacy-secret".into()),
            admin_secret: "operator-secret".into(),
            ..Default::default()
        };
        let storage = crate::storage::Storage::from_stores(
            std::sync::Arc::new(object_store::memory::InMemory::new()),
            std::sync::Arc::new(object_store::memory::InMemory::new()),
        );
        let state = AppState::new(pool, config, storage, reqwest::Client::new()).unwrap();
        let mut headers = HeaderMap::new();
        assert!(
            authenticate(&headers, &state)
                .await
                .err()
                .unwrap()
                .headers
                .contains_key(header::WWW_AUTHENTICATE)
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer legacy-secret"),
        );
        assert!(matches!(
            authenticate(&headers, &state).await,
            Ok(Principal::SharedToken)
        ));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer operator-secret"),
        );
        // An actor header names no one: the operator is always just "admin".
        headers.insert(
            "x-snowstead-actor",
            HeaderValue::from_static("dev@example.test"),
        );
        let operator = authenticate(&headers, &state).await.unwrap();
        assert!(matches!(operator, Principal::Operator));
        assert_eq!(operator.actor(), "admin");
        // Hosted assertions are never core credentials.
        for credential in [
            "Bearer snowstead_web.payload.signature",
            "Bearer snowsvc1.payload.signature",
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(credential));
            assert_eq!(
                authenticate(&headers, &state).await.err().unwrap().status,
                StatusCode::UNAUTHORIZED
            );
        }
        headers.clear();
        let error = authorize_read(&headers, &state, 1, "private", "default")
            .await
            .err()
            .unwrap();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            error.headers[header::WWW_AUTHENTICATE],
            "Basic realm=\"snowstead\""
        );
        // The shared token authenticates but never reads.
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("user:legacy-secret")))
                .unwrap(),
        );
        assert_eq!(
            authorize_read(&headers, &state, 1, "private", "default")
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::FORBIDDEN
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("user:token"))).unwrap(),
        );
        assert_eq!(
            authorize_read(&headers, &state, 1, "private", "default")
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
}
