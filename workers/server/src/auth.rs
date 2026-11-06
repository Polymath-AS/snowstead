//! Hosted token authentication. JWT claims remain authoritative; SQL only
//! supplies revocations, so signed tokens absent from api_tokens still work.
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{AppState, error::ApiError};

const DEFAULT_ORG: &str = "default";
const JWT_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
pub(crate) const JWT_CLOCK_SKEW_SECONDS: i64 = 60;
const PERMISSIONS: &[&str] = &[
    "pull",
    "push",
    "go:read",
    "go:write",
    "sccache:read",
    "sccache:write",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    pub jti: String,
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub caches: Vec<String>,
    pub perms: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    pub iat: i64,
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl Claims {
    pub fn has_permission(&self, permission: &str) -> bool {
        self.perms.iter().any(|p| p == permission)
    }

    pub fn has_cache_access(&self, id: i32, name: &str) -> bool {
        self.caches.iter().any(|entry| {
            if entry.starts_with("id:") {
                entry == &format!("id:{id}")
            } else {
                matches_pattern(entry, name)
            }
        })
    }

    pub fn belongs_to(&self, org: &str) -> bool {
        self.org.as_deref().unwrap_or(DEFAULT_ORG) == org
    }
}

#[derive(Clone, Debug)]
pub enum Identity {
    Jwt(Claims),
    Legacy,
    Admin { on_behalf_of: Option<String> },
    OrgKey { org: String, key_id: String },
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl Identity {
    pub fn org(&self) -> &str {
        match self {
            Self::Jwt(claims) => claims.org.as_deref().unwrap_or(DEFAULT_ORG),
            Self::OrgKey { org, .. } => org,
            _ => DEFAULT_ORG,
        }
    }

    pub fn actor(&self) -> String {
        match self {
            Self::Jwt(claims) => claims.jti.clone(),
            Self::Legacy => "legacy".into(),
            Self::Admin {
                on_behalf_of: Some(actor),
            } => format!("user:{actor}"),
            Self::Admin { on_behalf_of: None } => "admin".into(),
            Self::OrgKey { key_id, .. } => format!("key:{key_id}"),
        }
    }
}

fn matches_pattern(pattern: &str, name: &str) -> bool {
    let Some((first, rest)) = pattern.split_once('*') else {
        return pattern == name;
    };
    let Some(mut remaining) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts = rest.split('*').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return remaining.ends_with(part);
        }
        let Some(at) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[at + part.len()..];
    }
    false
}

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

fn admin_identity(headers: &HeaderMap) -> Identity {
    let actor = headers
        .get("x-snowstead-actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let on_behalf_of = (!actor.is_empty()
        && actor.encode_utf16().count() <= 254
        && !actor.chars().any(|c| c.is_whitespace() || c.is_control()))
    .then(|| actor.to_owned());
    Identity::Admin { on_behalf_of }
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
        || claims
            .perms
            .iter()
            .any(|p| !PERMISSIONS.contains(&p.as_str()))
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

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn check_revocation(state: &AppState, claims: &Claims, read: bool) -> Result<bool, ApiError> {
    struct Revocation {
        revoked: bool,
        usage_due: bool,
    }
    let token = crate::profile_future!(
        sqlx::query_as!(
            Revocation,
            r#"
            SELECT
                revoked_at IS NOT NULL AS "revoked!",
                COALESCE(org_id, 'default') = $2
                    AND (last_used_at IS NULL OR last_used_at <= NOW() - INTERVAL '5 minutes')
                    AS "usage_due!"
            FROM api_tokens
            WHERE jti = $1
            "#,
            &claims.jti,
            claims.org.as_deref().unwrap_or(DEFAULT_ORG),
        )
        .fetch_optional(&state.pool),
        label = "auth.revocation_sql"
    )
    .await?;
    if token.as_ref().is_some_and(|token| token.revoked) {
        return Err(auth_error(StatusCode::UNAUTHORIZED, read));
    }
    // The required revocation read also tells us whether telemetry is due.
    // Most requests need no second pool acquisition or no-op UPDATE.
    Ok(token.is_some_and(|token| token.usage_due))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn record_use(state: &AppState, claims: &Claims) {
    // Await bounded pool work; never spawn an unbounded task per request.
    // Telemetry is best-effort and the predicate limits actual writes.
    if crate::profile_future!(
        sqlx::query!(
            r#"
            UPDATE api_tokens
            SET last_used_at = NOW()
            WHERE jti = $1
                AND COALESCE(org_id, 'default') = $2
                AND (last_used_at IS NULL OR last_used_at <= NOW() - INTERVAL '5 minutes')
            "#,
            &claims.jti,
            claims.org.as_deref().unwrap_or(DEFAULT_ORG),
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
pub async fn authenticate_write(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Identity, ApiError> {
    if state.config.jwt_secret.is_empty() && state.config.auth_token.is_empty() {
        return Err(auth_error(StatusCode::FORBIDDEN, false));
    }
    let token = bearer(headers)?;
    if !state.config.jwt_secret.is_empty() {
        if let Some(claims) = verify_jwt(token, &state.config.jwt_secret, now()) {
            if check_revocation(state, &claims, false).await? {
                record_use(state, &claims).await;
            }
            #[cfg(feature = "observability")]
            crate::observability::identity(&Identity::Jwt(claims.clone()), None);
            return Ok(Identity::Jwt(claims));
        }
        if state.config.auth_token.is_empty() {
            return Err(auth_error(StatusCode::UNAUTHORIZED, false));
        }
    }
    if !state.config.auth_token.is_empty() && equal_secret(token, &state.config.auth_token) {
        return Ok(Identity::Legacy);
    }
    Err(auth_error(StatusCode::FORBIDDEN, false))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authenticate_admin(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Identity, ApiError> {
    if state.config.admin_secret.is_empty() {
        return Err(auth_error(StatusCode::FORBIDDEN, false));
    }
    if equal_secret(bearer(headers)?, &state.config.admin_secret) {
        return Ok(admin_identity(headers));
    }
    Err(auth_error(StatusCode::FORBIDDEN, false))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authenticate_org(
    headers: &HeaderMap,
    state: &AppState,
    org: &str,
) -> Result<Identity, ApiError> {
    let token = bearer(headers)?;
    if !state.config.admin_secret.is_empty() && equal_secret(token, &state.config.admin_secret) {
        return Ok(admin_identity(headers));
    }
    let invalid = || auth_error(StatusCode::FORBIDDEN, false);
    let rest = token.strip_prefix("snowstead_key_").ok_or_else(invalid)?;
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
    let hash = hex::encode(Sha256::digest(secret.as_bytes()));
    let valid = equal_secret(
        &hash,
        row.as_ref().map(|r| r.secret_hash.as_str()).unwrap_or(""),
    );
    match row {
        Some(key) if valid && !key.revoked && key.org_id == org => Ok(Identity::OrgKey {
            org: org.into(),
            key_id: id.into(),
        }),
        _ => Err(invalid()),
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authorize_read(
    headers: &HeaderMap,
    state: &AppState,
    cache_id: i32,
    cache_name: &str,
    org: &str,
) -> Result<(), ApiError> {
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
    if state.config.jwt_secret.is_empty() {
        return Err(auth_error(StatusCode::FORBIDDEN, true));
    }
    let claims = verify_jwt(&credential, &state.config.jwt_secret, now())
        .ok_or_else(|| auth_error(StatusCode::UNAUTHORIZED, true))?;
    let usage_due = check_revocation(state, &claims, true).await?;
    if !claims.has_permission("pull")
        || !claims.has_cache_access(cache_id, cache_name)
        || !claims.belongs_to(org)
    {
        return Err(auth_error(StatusCode::FORBIDDEN, true));
    }
    if usage_due {
        record_use(state, &claims).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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
        assert!(claims.belongs_to("default"));
        assert!(!claims.belongs_to("other"));
        assert!(claims.has_permission("pull"));
        assert!(!claims.has_permission("go:read"));
        assert!(claims.has_cache_access(7, "renamed"));
        assert!(!claims.has_cache_access(8, "renamed"));
        assert!(claims.has_cache_access(8, "ci-linux-release"));
        assert!(!claims.has_cache_access(8, "ci-linux-release-extra"));
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

    #[hegel::test]
    fn cache_patterns_match_a_literal_star_model(tc: hegel::TestCase) {
        use hegel::generators as gs;

        let pattern: String = tc
            .draw(gs::vecs(gs::sampled_from(&['a', 'b', 'é', '.', '[', '*'])).max_size(16))
            .into_iter()
            .collect();
        let name =
            tc.draw(gs::vecs(gs::sampled_from(&['a', 'b', 'é', '.', '[', '*'])).max_size(16));
        // Dynamic programming over Unicode characters, independent of the
        // production matcher's greedy searches over literal substrings.
        let mut matched = vec![false; name.len() + 1];
        matched[0] = true;
        for token in pattern.chars() {
            let mut next = vec![false; name.len() + 1];
            next[0] = token == '*' && matched[0];
            for (i, &letter) in name.iter().enumerate() {
                next[i + 1] = if token == '*' {
                    matched[i + 1] || next[i]
                } else {
                    matched[i] && token == letter
                };
            }
            matched = next;
        }
        let mut claims: Claims = serde_json::from_value(payload()).unwrap();
        claims.caches = vec![pattern];
        assert_eq!(
            claims.has_cache_access(7, &name.iter().collect::<String>()),
            matched[name.len()]
        );
    }

    #[tokio::test]
    async fn public_authentication_and_challenges_without_database() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let config = crate::config::Config {
            auth_token: "legacy-secret".into(),
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
            authenticate_write(&headers, &state)
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
            authenticate_write(&headers, &state).await,
            Ok(Identity::Legacy)
        ));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer operator-secret"),
        );
        headers.insert(
            "x-snowstead-actor",
            HeaderValue::from_static("dev@example.test"),
        );
        assert_eq!(
            authenticate_admin(&headers, &state)
                .await
                .ok()
                .unwrap()
                .actor(),
            "user:dev@example.test"
        );
        assert!(matches!(
            authenticate_org(&headers, &state, "any-org").await,
            Ok(Identity::Admin { .. })
        ));
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
            StatusCode::FORBIDDEN
        );
    }
}
