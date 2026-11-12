//! Authentication: turn a request's credential into a [`Principal`]. Nothing
//! here grants access; callers ask [`crate::authz::authorize`].
//!
//! Credentials, by form:
//! - `ADMIN_SECRET`: the operator, for `/_api/v1/admin` only.
//! - `snowstead_web.<claims>.<signature>`: a dashboard user, from an Ed25519
//!   assertion the web signs per request, bound to its method and path.
//! - `snowstead_key_<id>_<secret>`: an org API key.
//! - `snowstead_tok_<jti>_<secret>`: an API token. Only a hash of the secret
//!   is stored; scope comes from `token_permissions` and `token_caches`.
//! - A JWT-era API token, accepted only while its `jti` is listed and
//!   unrevoked in `api_tokens`, with scope from the database, not its claims.
//! - A self-hosted shared `AUTH_TOKEN`, only when explicitly enabled.
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use subtle::ConstantTimeEq;

use crate::{
    AppState,
    authz::{ApiToken, CacheGrant, Permission, Principal, Role, WebUser},
    error::ApiError,
};

pub(crate) const JWT_CLOCK_SKEW_SECONDS: i64 = 60;
const JWT_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
pub(crate) const TOKEN_PREFIX: &str = "snowstead_tok_";
const KEY_PREFIX: &str = "snowstead_key_";
const ASSERTION_PREFIX: &str = "snowstead_web.";
const ASSERTION_AUDIENCE: &str = "snowstead-cache";
/// The longest an assertion may claim to live.
const ASSERTION_LIFETIME_SECONDS: i64 = 60;
const ASSERTION_SKEW_SECONDS: i64 = 30;

/// The request an assertion must be bound to.
#[derive(Clone, Copy)]
pub struct Target<'a> {
    pub method: &'a Method,
    /// Path and query exactly as received.
    pub path: &'a str,
    /// Hex SHA-256 of the request body; of the empty string when it has none.
    pub body_sha256: &'a str,
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

/// The local development key: its private half is published in the
/// dashboard's `.env.example`, so only `pnpm dev` may accept it.
pub fn local_dev_web_key() -> VerifyingKey {
    assertion_keys("2aLdazRgIkJp0m0Ik8oS5B0sUJQvwU6jvSaO4wWP/o0=").expect("a valid key")[0]
}

/// Whether the request presents a web assertion, whose body must be hashed.
pub fn is_assertion(headers: &HeaderMap) -> bool {
    bearer(headers).is_ok_and(|credential| credential.starts_with(ASSERTION_PREFIX))
}

/// The old dashboard's unverified `x-snowstead-actor`, for the transitional
/// `ALLOW_LEGACY_WEB_ADMIN` path only.
pub fn legacy_actor(headers: &HeaderMap) -> Option<String> {
    let actor = headers
        .get("x-snowstead-actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    (!actor.is_empty()
        && actor.encode_utf16().count() <= 254
        && !actor.chars().any(|c| c.is_whitespace() || c.is_control()))
    .then(|| actor.to_owned())
}

/// Parse `WEB_ASSERTION_PUBLIC_KEYS`.
pub fn assertion_keys(value: &str) -> anyhow::Result<Vec<VerifyingKey>> {
    value
        .split_whitespace()
        .map(|key| {
            let bytes: [u8; 32] = STANDARD
                .decode(key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "WEB_ASSERTION_PUBLIC_KEYS must be base64 raw 32-byte Ed25519 public keys"
                    )
                })?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
                anyhow::anyhow!("WEB_ASSERTION_PUBLIC_KEYS contains an invalid Ed25519 key")
            })?;
            anyhow::ensure!(
                !key.is_weak(),
                "WEB_ASSERTION_PUBLIC_KEYS contains a weak Ed25519 key"
            );
            Ok(key)
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assertion {
    aud: String,
    org: String,
    sub: String,
    email: String,
    role: String,
    iat: i64,
    exp: i64,
    method: String,
    path: String,
    body: String,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
fn verify_assertion(
    keys: &[VerifyingKey],
    credential: &str,
    target: Target,
    now: i64,
) -> Option<WebUser> {
    if keys.is_empty() || credential.len() > 8192 {
        return None;
    }
    let (signed, signature) = credential.rsplit_once('.')?;
    let payload = signed.strip_prefix(ASSERTION_PREFIX)?;
    if payload.contains('.') {
        return None;
    }
    let signature: [u8; 64] = URL_SAFE_NO_PAD.decode(signature).ok()?.try_into().ok()?;
    let signature = Signature::from_bytes(&signature);
    if !keys
        .iter()
        .any(|key| key.verify_strict(signed.as_bytes(), &signature).is_ok())
    {
        return None;
    }
    let claims: Assertion = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    let email = claims.email.trim();
    let valid = claims.aud == ASSERTION_AUDIENCE
        && claims.exp > claims.iat
        && claims.exp - claims.iat <= ASSERTION_LIFETIME_SECONDS
        && claims.iat <= now + ASSERTION_SKEW_SECONDS
        && now < claims.exp.saturating_add(ASSERTION_SKEW_SECONDS)
        && claims.method == target.method.as_str()
        && claims.path == target.path
        && claims.body == target.body_sha256
        && valid_id(&claims.org)
        && valid_id(&claims.sub)
        && email == claims.email
        && email.contains('@')
        && email.encode_utf16().count() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    if !valid {
        return None;
    }
    Some(WebUser {
        org: claims.org,
        user_id: claims.sub,
        email: claims.email,
        role: Role::parse(&claims.role)?,
    })
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
    if crate::profile_future!(
        sqlx::query!(
            r#"
            UPDATE api_tokens
            SET last_used_at = NOW()
            WHERE jti = $1
                AND (last_used_at IS NULL OR last_used_at <= NOW() - INTERVAL '5 minutes')
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

/// Identify the holder of `credential`, or reject it with 401. A web
/// assertion is accepted only when `target` is the request it was signed for.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn principal(
    state: &AppState,
    credential: &str,
    target: Option<Target<'_>>,
    read: bool,
) -> Result<Principal, ApiError> {
    let rejected = || auth_error(StatusCode::UNAUTHORIZED, read);
    let config = &state.config;
    if !config.admin_secret.is_empty() && equal_secret(credential, &config.admin_secret) {
        return Ok(Principal::Operator);
    }
    if credential.starts_with(ASSERTION_PREFIX) {
        let target = target.ok_or_else(rejected)?;
        let user = verify_assertion(
            &state.assertion_keys,
            credential,
            target,
            chrono::Utc::now().timestamp(),
        )
        .ok_or_else(rejected)?;
        return Ok(Principal::WebUser(user));
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

/// Authenticate a bearer credential. `target` is the request being served,
/// for web assertions; protocol routes pass None, which rejects them.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
    target: Option<Target<'_>>,
) -> Result<Principal, ApiError> {
    let credential = bearer(headers)?;
    principal(state, credential, target, false).await
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
    principal(state, &credential, None, true).await
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
        crate::authz::Action::NixPull,
        &crate::authz::Resource::cache(org, cache_id, cache_name),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
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

    fn assertion(key: &SigningKey, claims: &Value) -> String {
        let signed = format!(
            "{ASSERTION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        let signature = key.sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn claims() -> Value {
        json!({"aud":"snowstead-cache","org":"org_a","sub":"user_1","email":"dev@example.test","role":"member",
            "iat":1000,"exp":1030,"method":"POST","path":"/_api/v1/orgs/org_a/tokens?x=1","body":BODY})
    }

    // Hex SHA-256 of `{"subject":"ci"}`.
    const BODY: &str = "d58c1d618af77c6b21971af2ee5da4a65f4ee8abd7c11f460384500f3ed9770a";

    #[test]
    fn assertions_bind_key_lifetime_method_path_and_body() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        let keys = [key.verifying_key()];
        let post = Method::POST;
        let target = Target {
            method: &post,
            path: "/_api/v1/orgs/org_a/tokens?x=1",
            body_sha256: BODY,
        };
        let user = verify_assertion(&keys, &assertion(&key, &claims()), target, 1010).unwrap();
        assert_eq!(
            (user.org.as_str(), user.user_id.as_str(), user.role),
            ("org_a", "user_1", Role::Member)
        );
        assert!(verify_assertion(&keys, &assertion(&other, &claims()), target, 1010).is_none());
        assert!(verify_assertion(&[], &assertion(&key, &claims()), target, 1010).is_none());
        // Skew allows a little clock drift either way, and no more.
        assert!(verify_assertion(&keys, &assertion(&key, &claims()), target, 970).is_some());
        assert!(verify_assertion(&keys, &assertion(&key, &claims()), target, 969).is_none());
        assert!(verify_assertion(&keys, &assertion(&key, &claims()), target, 1059).is_some());
        assert!(verify_assertion(&keys, &assertion(&key, &claims()), target, 1060).is_none());
        let get = Method::GET;
        for wrong in [
            Target {
                method: &get,
                ..target
            },
            Target {
                path: "/_api/v1/orgs/org_a/tokens",
                ..target
            },
            Target {
                path: "/_api/v1/orgs/org_b/tokens?x=1",
                ..target
            },
            // A captured assertion can't carry another body.
            Target {
                body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ..target
            },
        ] {
            assert!(verify_assertion(&keys, &assertion(&key, &claims()), wrong, 1010).is_none());
        }
        for (field, value) in [
            ("aud", json!("snowstead")),
            ("exp", json!(1061)),
            ("exp", json!(1000)),
            ("role", json!("operator")),
            ("org", json!("org/a")),
            ("email", json!("not an email")),
            ("email", json!("")),
            ("sub", json!("")),
            ("extra", json!(true)),
        ] {
            let mut c = claims();
            c[field] = value;
            assert!(
                verify_assertion(&keys, &assertion(&key, &c), target, 1010).is_none(),
                "{field}"
            );
        }
        // Tampering with the signed payload invalidates the signature.
        let genuine = assertion(&key, &claims());
        let mut c = claims();
        c["role"] = json!("owner");
        let forged = format!(
            "{ASSERTION_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap()),
            genuine.rsplit_once('.').unwrap().1
        );
        assert!(verify_assertion(&keys, &forged, target, 1010).is_none());
    }

    #[test]
    fn assertion_keys_must_be_valid_ed25519_keys() {
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let encoded = STANDARD.encode(key.as_bytes());
        assert_eq!(assertion_keys("").unwrap().len(), 0);
        assert_eq!(
            assertion_keys(&format!(" {encoded}\n{encoded} ")).unwrap(),
            vec![key, key]
        );
        assert!(assertion_keys("not-base64!").is_err());
        assert!(assertion_keys(&STANDARD.encode([1u8; 31])).is_err());
        // The identity point is a weak key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(assertion_keys(&STANDARD.encode(identity)).is_err());
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
            authenticate(&headers, &state, None)
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
            authenticate(&headers, &state, None).await,
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
        let operator = authenticate(&headers, &state, None).await.unwrap();
        assert!(matches!(operator, Principal::Operator));
        assert_eq!(operator.actor(), "admin");
        // Without configured keys, no assertion is accepted.
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Bearer {}",
                assertion(&SigningKey::from_bytes(&[7; 32]), &claims())
            ))
            .unwrap(),
        );
        let post = Method::POST;
        let target = Target {
            method: &post,
            path: "/_api/v1/orgs/org_a/tokens?x=1",
            body_sha256: BODY,
        };
        assert_eq!(
            authenticate(&headers, &state, Some(target))
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::UNAUTHORIZED
        );
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
