//! Tokens from the JWT era work only while listed in `api_tokens`, with the
//! scope recorded there. Register a test-minted JWT the way migration 0015
//! backfills existing rows, and return it.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sqlx::PgPool;

pub async fn register(pool: &PgPool, token: String) -> String {
    let payload = token.split('.').nth(1).expect("a JWT");
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    let jti = claims["jti"].as_str().unwrap();
    let strings = |field: &str| -> Vec<String> {
        claims[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    sqlx::query(
        "INSERT INTO api_tokens (jti, subject, org_id, created_by, expires_at) \
         VALUES ($1, $2, $3, 'test', to_timestamp($4)) ON CONFLICT (jti) DO NOTHING",
    )
    .bind(jti)
    .bind(claims["sub"].as_str().unwrap())
    .bind(claims["org"].as_str())
    .bind(claims["exp"].as_f64())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO token_permissions (token_jti, permission, position) \
         SELECT $1, p, n FROM UNNEST($2::text[]) WITH ORDINALITY AS g(p, n) ON CONFLICT DO NOTHING",
    )
    .bind(jti)
    .bind(strings("perms"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO token_caches (token_jti, cache_id, pattern) \
         SELECT $1, CASE WHEN e ~ '^id:[0-9]+$' THEN substr(e, 4)::int END, \
         CASE WHEN e !~ '^id:[0-9]+$' THEN e END \
         FROM UNNEST($2::text[]) WITH ORDINALITY AS g(e, n) ORDER BY n ON CONFLICT DO NOTHING",
    )
    .bind(jti)
    .bind(strings("caches"))
    .execute(pool)
    .await
    .unwrap();
    token
}
