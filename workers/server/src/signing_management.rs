//! Authenticated organization signing management. The caller owns auth and audit.
use std::{fs::File, io::Read};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axum::{
    Extension, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    AppState,
    auth::Identity,
    config::Config,
    error::{ApiError, json_response},
    management::ManagementContext,
};

pub struct NewCacheKey {
    pub id: String,
    pub signing_key_name: String,
    pub signing_public_key: String,
    pub signing_key_sealed: String,
    pub managed_public_key: Option<String>,
}

fn internal() -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn decode(text: &str) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let compact = Zeroizing::new(
        text.bytes()
            .filter(|b| !b" \t\r\n\x0c".contains(b))
            .collect::<Vec<_>>(),
    );
    GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(&*compact)
    .map(Zeroizing::new)
    .map_err(|_| internal())
}

fn random(bytes: &mut [u8]) -> Result<(), ApiError> {
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(bytes))
        .map_err(|_| internal())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub fn shared_public_key(config: &Config) -> Result<Option<String>, ApiError> {
    if config.signing_private_key.is_empty() {
        return Ok(None);
    }
    let bytes = decode(&config.signing_private_key)?;
    // Match signingPublicKey: a full Nix secret advertises its supplied public half.
    let public = if bytes.len() == 64 {
        STANDARD.encode(&bytes[32..])
    } else if bytes.len() == 32 {
        let seed = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| internal())?);
        STANDARD.encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
    } else {
        return Err(internal());
    };
    Ok(Some(format!("{}:{public}", config.signing_key_name)))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
fn seal(
    config: &Config,
    cache_id: i32,
    id: String,
    name: String,
    secret: &[u8],
    managed: bool,
) -> Result<NewCacheKey, ApiError> {
    let master = decode(&config.signing_master_key)?;
    if master.len() != 32 {
        return Err(internal());
    }
    let cipher = Aes256Gcm::new_from_slice(&master).map_err(|_| internal())?;
    let public_bytes = STANDARD.encode(&secret[32..]);
    let public = format!("{name}:{public_bytes}");
    let aad = serde_json::to_vec(&("v2", cache_id, &id, &name, &public)).map_err(|_| internal())?;
    let mut iv = [0u8; 12];
    random(&mut iv)?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: secret,
                aad: &aad,
            },
        )
        .map_err(|_| internal())?;
    let mut boxed = iv.to_vec();
    boxed.extend_from_slice(&ciphertext);
    Ok(NewCacheKey {
        signing_key_sealed: format!("v2:{id}:{}", STANDARD.encode(boxed)),
        id,
        signing_key_name: name,
        signing_public_key: public,
        managed_public_key: managed.then_some(public_bytes),
    })
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn new_cache_key(
    config: &Config,
    cache_id: i32,
) -> Result<Option<NewCacheKey>, ApiError> {
    if config.signing_master_key.is_empty() {
        return Ok(None);
    }
    let id = uuid::Uuid::now_v7().to_string();
    let mut seed = Zeroizing::new([0u8; 32]);
    random(seed.as_mut())?;
    let key = SigningKey::from_bytes(&seed);
    let mut secret = Zeroizing::new([0u8; 64]);
    secret[..32].copy_from_slice(seed.as_ref());
    secret[32..].copy_from_slice(key.verifying_key().as_bytes());
    seal(
        config,
        cache_id,
        id.clone(),
        format!("{}-{cache_id}-{id}", config.signing_key_name),
        secret.as_ref(),
        true,
    )
    .map(Some)
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
fn import(config: &Config, cache_id: i32, material: &str) -> Result<NewCacheKey, ApiError> {
    let (name, encoded) = material.split_once(':').ok_or_else(internal)?;
    if name.is_empty()
        || name.len() > 200
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/+-".contains(&b))
        || encoded.len() != 88
        || !encoded.ends_with("==")
    {
        return Err(internal());
    }
    let secret = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| internal())?);
    if secret.len() != 64 || Zeroizing::new(STANDARD.encode(&*secret)).as_str() != encoded {
        return Err(internal());
    }
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&secret[..32]).map_err(|_| internal())?);
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().as_bytes() != &secret[32..] {
        return Err(internal());
    }
    seal(
        config,
        cache_id,
        uuid::Uuid::now_v7().to_string(),
        name.to_owned(),
        &secret,
        false,
    )
}

struct Current {
    signing_key_name: Option<String>,
    signing_public_key: Option<String>,
}

struct History {
    id: String,
    signing_key_name: String,
    signing_public_key: String,
    signing_key_sealed: Option<String>,
    managed_public_key: Option<String>,
    state: String,
    created_at: DateTime<Utc>,
}

async fn current_for_update(
    conn: &mut sqlx::PgConnection,
    cache_id: i32,
) -> Result<Current, ApiError> {
    Ok(sqlx::query_as!(
        Current,
        r#"
            SELECT
                signing_key_name,
                signing_public_key
            FROM caches
            WHERE id = $1
            FOR UPDATE
            "#,
        cache_id
    )
    .fetch_one(conn)
    .await?)
}

async fn history(conn: &mut sqlx::PgConnection, cache_id: i32) -> Result<Vec<History>, ApiError> {
    Ok(sqlx::query_as!(
        History,
        r#"
            SELECT
                id,
                signing_key_name,
                signing_public_key,
                signing_key_sealed,
                managed_public_key,
                state,
                created_at
            FROM cache_signing_keys
            WHERE cache_id = $1
            "#,
        cache_id
    )
    .fetch_all(conn)
    .await?)
}

pub fn org_router() -> Router<AppState> {
    Router::new()
        .route(
            "/caches/{cache}/signing-keys",
            get(list_keys).post(create_key),
        )
        .route(
            "/caches/{cache}/signing-keys/{key}/activate",
            post(activate_key),
        )
}

#[derive(Deserialize)]
struct CachePath {
    cache: String,
}

#[derive(Deserialize)]
struct KeyPath {
    cache: String,
    key: String,
}

async fn cache_id(
    state: &AppState,
    context: &ManagementContext,
    name: &str,
) -> Result<i32, ApiError> {
    let org = context
        .org
        .as_deref()
        .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "Forbidden"))?;
    match &context.identity {
        Identity::Admin { .. } => {}
        Identity::OrgKey { org: own, .. } if own == org => {}
        _ => return Err(ApiError::new(StatusCode::FORBIDDEN, "Forbidden")),
    }
    sqlx::query_scalar!(
        r#"
        SELECT id
        FROM caches
        WHERE org_id = $1
            AND name = $2
        "#,
        org,
        name
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no cache"))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn list_keys(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(CachePath { cache }): Path<CachePath>,
) -> Result<Response, ApiError> {
    let cache_id = cache_id(&state, &context, &cache).await?;
    let mut tx = state.pool.begin().await?;
    let current = sqlx::query_as!(
        Current,
        r#"
            SELECT
                signing_key_name,
                signing_public_key
            FROM caches
            WHERE id = $1
            FOR SHARE
            "#,
        cache_id
    )
    .fetch_one(&mut *tx)
    .await?;
    let rows = history(&mut tx, cache_id).await?;
    let shared = current.signing_public_key.is_none();
    let public = match current.signing_public_key {
        Some(p) => Some(p),
        None => shared_public_key(&state.config)?,
    };
    let mut keys: Vec<Value> = rows
        .iter()
        .map(|k| {
            json!({"id": k.id, "publicKey": k.signing_public_key, "state": k.state,
            "createdAt": k.created_at.to_rfc3339_opts(SecondsFormat::Millis, true)})
        })
        .collect();
    if let Some(p) = &public
        && !rows.iter().any(|k| &k.signing_public_key == p)
    {
        keys.push(json!({"id": null, "publicKey": p, "state": "active"}));
    }
    tx.commit().await?;
    Ok(json_response(
        StatusCode::OK,
        json!({"activePublicKey": public, "shared": shared, "keys": keys}),
    ))
}

async fn mutation_body(
    state: &AppState,
    request: Request,
    org: &str,
) -> Result<(Value, Option<Zeroizing<String>>, bool), ApiError> {
    if state.config.signing_master_key.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "managed signing requires SIGNING_MASTER_KEY",
        ));
    }
    let bytes = Zeroizing::new(
        to_bytes(request.into_body(), 1024 * 1024)
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Signing request body exceeds 1 MiB",
                )
            })?
            .to_vec(),
    );
    let mut body: Value = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid JSON in request body"))?;
    if !body.is_object() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "expected JSON object",
        ));
    }
    let secret = body.as_object_mut().unwrap().remove("secretKey");
    // Move the request's secret into a zeroizing owner before any await.
    let secret = match secret {
        Some(Value::String(s)) => Some(Zeroizing::new(s)),
        Some(_) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid Nix secret key",
            ));
        }
        None => None,
    };
    let custom: bool = sqlx::query_scalar!(
        r#"
        SELECT custom_signing_keys
        FROM orgs
        WHERE id = $1
        "#,
        org
    )
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or(false);
    Ok((body, secret, custom))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn create_key(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(CachePath { cache }): Path<CachePath>,
    request: Request,
) -> Result<Response, ApiError> {
    let cache_id = cache_id(&state, &context, &cache).await?;
    let (_, secret, custom) =
        mutation_body(&state, request, context.org.as_deref().unwrap()).await?;
    let key = if let Some(secret) = secret {
        if !custom {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "custom signing keys are not allowed for this organization",
            ));
        }
        import(&state.config, cache_id, &secret)
            .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid Nix secret key"))?
    } else {
        new_cache_key(&state.config, cache_id)
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "managed signing unavailable"))?
    };
    let mut tx = state.pool.begin().await?;
    let current = current_for_update(&mut tx, cache_id).await?;
    let mut made = false;
    if current.signing_key_name.as_deref() != Some(&key.signing_key_name)
        && key.signing_key_name != state.config.signing_key_name
    {
        made = sqlx::query!(
            r#"
                INSERT INTO cache_signing_keys (
                    id,
                    cache_id,
                    signing_key_name,
                    signing_public_key,
                    signing_key_sealed,
                    managed_public_key
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT DO NOTHING
                "#,
            &key.id,
            cache_id,
            &key.signing_key_name,
            &key.signing_public_key,
            &key.signing_key_sealed,
            key.managed_public_key.as_deref()
        )
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;
    }
    tx.commit().await?;
    if made {
        Ok(json_response(
            StatusCode::CREATED,
            json!({"id":key.id,"publicKey":key.signing_public_key,"state":"staged"}),
        ))
    } else {
        Err(ApiError::new(
            StatusCode::CONFLICT,
            "key name or managed public key already used",
        ))
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn activate_key(
    State(state): State<AppState>,
    Extension(context): Extension<ManagementContext>,
    Path(KeyPath { cache, key: id }): Path<KeyPath>,
    request: Request,
) -> Result<Response, ApiError> {
    let cache_id = cache_id(&state, &context, &cache).await?;
    let (body, _secret, custom) =
        mutation_body(&state, request, context.org.as_deref().unwrap()).await?;
    let mut tx = state.pool.begin().await?;
    let current = current_for_update(&mut tx, cache_id).await?;
    let rows = history(&mut tx, cache_id).await?;
    let target = rows
        .iter()
        .find(|k| k.id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no signing key"))?;
    if target.state != "staged"
        || target
            .signing_key_sealed
            .as_ref()
            .is_none_or(|s| s.is_empty())
    {
        return Err(ApiError::new(StatusCode::CONFLICT, "key is not staged"));
    }
    if target
        .managed_public_key
        .as_ref()
        .is_none_or(|p| p.is_empty())
        && !custom
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "custom signing keys are not allowed for this organization",
        ));
    }
    let old = match current.signing_public_key {
        Some(p) => Some(p),
        None => shared_public_key(&state.config)?,
    };
    let trusted = body
        .get("trustedPublicKeys")
        .and_then(Value::as_array)
        .filter(|a| a.iter().all(Value::is_string));
    if !trusted.is_some_and(|trusted| {
        rows.iter()
            .map(|k| &k.signing_public_key)
            .chain(old.iter())
            .all(|p| trusted.iter().any(|v| v.as_str() == Some(p)))
    }) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "confirm trustedPublicKeys includes all existing and staged public keys before activation",
        ));
    }
    if let Some(old) = old
        && !rows.iter().any(|k| k.signing_public_key == old)
    {
        sqlx::query!(
            r#"
            INSERT INTO cache_signing_keys (
                id,
                cache_id,
                signing_key_name,
                signing_public_key,
                state
            )
            VALUES ($1, $2, $3, $4, 'retired')
            "#,
            uuid::Uuid::now_v7().to_string(),
            cache_id,
            old.split(':').next().unwrap_or(""),
            &old
        )
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!(
        r#"
        UPDATE cache_signing_keys
        SET state = 'retired',
            signing_key_sealed = NULL
        WHERE cache_id = $1
            AND state = 'active'
        "#,
        cache_id
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        r#"
        UPDATE cache_signing_keys
        SET state = 'active'
        WHERE id = $1
        "#,
        &id
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        r#"
        UPDATE caches
        SET signing_key_name = $1,
            signing_public_key = $2,
            signing_key_sealed = $3
        WHERE id = $4
        "#,
        &target.signing_key_name,
        &target.signing_public_key,
        target.signing_key_sealed.as_deref(),
        cache_id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(json_response(
        StatusCode::OK,
        json!({"id":id,"publicKey":target.signing_public_key,"state":"active"}),
    ))
}
