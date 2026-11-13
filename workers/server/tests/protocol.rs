mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    routing::head,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use common::router;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_server::{
    AppState, auth,
    authz::{self, Action, Resource},
    config::Config,
};
use sqlx::PgPool;
use tower::ServiceExt;

#[path = "support/tokens.rs"]
mod tokens;

/// A JWT-era token as issued, before it is listed in `api_tokens`.
fn jwt(org: Option<&str>, caches: &[&str], perms: &[&str], jti: &str) -> String {
    let mut claims = json!({ "jti": jti, "sub": "unchanged-cli", "iss": "snowstead", "aud": "snowstead", "iat": 1,
        "caches": caches, "perms": perms });
    if let Some(org) = org {
        claims["org"] = json!(org);
    }
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"contract-secret").unwrap();
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(
            snowstead_protocol::PROTOCOL_VERSION_HEADER,
            snowstead_protocol::PROTOCOL_VERSION,
        )
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body =
        serde_json::from_slice(&body).unwrap_or_else(|_| json!(String::from_utf8_lossy(&body)));
    (status, headers, body)
}

/// A listed JWT-era token, which still works with its database scope.
async fn token(
    pool: &PgPool,
    org: Option<&str>,
    caches: &[&str],
    perms: &[&str],
    jti: &str,
) -> String {
    tokens::register(pool, jwt(org, caches, perms, jti)).await
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn hosted_v1_missing_paths_and_authorization(pool: PgPool) {
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_alpha','alpha'),('org_beta','beta');
        INSERT INTO caches (name,org_id) VALUES ('main','org_alpha'),('main','org_beta'),('go-only','org_alpha'),('local','default');
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id, CASE WHEN name='go-only' THEN 'go' ELSE 'nix' END FROM caches;
        INSERT INTO blob_objects (file_hash,file_size,compression,r2_key) VALUES (repeat('a',64),17,'zstd','nar/existing');
        INSERT INTO published_paths (cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,last_pushed_at)
        SELECT c.id, CASE WHEN c.org_id='org_alpha' THEN repeat('0',32) ELSE repeat('1',32) END,
            '/nix/store/test', 'sha256:test', 41, b.id, now()-interval '3 days'
        FROM caches c CROSS JOIN blob_objects b WHERE c.name='main';")
        .execute(&pool).await.unwrap();
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!(
        "http://{}/upstream",
        upstream_listener.local_addr().unwrap()
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let warming_hash = "4".repeat(32);
    let upstream_app = Router::new().route(
        &format!("/upstream/{warming_hash}.narinfo"),
        head(|| async { StatusCode::OK }),
    );
    let server = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let state = AppState::new(
        pool.clone(),
        Config {
            jwt_secret: "contract-secret".into(),
            shared_auth_token: Some("legacy-secret".into()),
            admin_secret: "operator-secret".into(),
            upstreams: vec![upstream.clone()],
            ..Default::default()
        },
        common::storage(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let known = "0".repeat(32);
    let other_org = "1".repeat(32);
    let known_upstream = "2".repeat(32);
    let missing = "3".repeat(32);
    sqlx::query("INSERT INTO upstream_paths (store_path_hash,upstream) VALUES ($1,$2)")
        .bind(&known_upstream)
        .bind(&upstream)
        .execute(&pool)
        .await
        .unwrap();
    let alpha = token(
        &pool,
        Some("org_alpha"),
        &["main"],
        &["push"],
        "alpha-token",
    )
    .await;
    let path = "/_api/v1/get-missing-paths";
    let body = json!({"cache":"main", "storePathHashes":[known, other_org, known_upstream, missing, missing]});
    let (status, headers, result) = request(&app, "POST", path, Some(&alpha), body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        result,
        json!({"missing":[other_org,missing,missing], "upstream":[known_upstream],
        "unchecked":[other_org,missing,missing], "upstreams":[upstream]})
    );
    let refreshed: bool = sqlx::query_scalar("SELECT last_pushed_at > now()-interval '1 minute' FROM published_paths p JOIN caches c ON c.id=p.cache_id WHERE c.org_id='org_alpha'")
        .fetch_one(&pool).await.unwrap();
    assert!(refreshed);
    let untouched: bool = sqlx::query_scalar("SELECT last_pushed_at < now()-interval '2 days' FROM published_paths p JOIN caches c ON c.id=p.cache_id WHERE c.org_id='org_beta'")
        .fetch_one(&pool).await.unwrap();
    assert!(untouched);
    assert_eq!(
        request(&app, "PUT", path, Some(&alpha), body.clone())
            .await
            .0,
        StatusCode::OK
    );
    for (body, message) in [
        (
            Value::Null,
            "Invalid type: Expected Object but received null",
        ),
        (
            json!([]),
            "Invalid type: Expected Object but received undefined",
        ),
        (json!({}), "Missing required fields: cache, storePathHashes"),
        (
            json!({"cache":"main","storePathHashes":["valid",42]}),
            "storePathHashes[1]: Invalid type: Expected string but received 42",
        ),
        (
            json!({"cache":"main","storePathHashes":vec!["x";1001]}),
            "storePathHashes exceeds maximum of 1000",
        ),
    ] {
        let (status, _, result) = request(&app, "POST", path, Some(&alpha), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(result, json!({"error":message}));
    }
    assert_eq!(
        request(
            &app,
            "POST",
            path,
            Some(&alpha),
            json!({"cache":"main","storePathHashes":vec!["x";1000]})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, headers, _) = request(&app, "GET", path, None, Value::Null).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let mut allowed: Vec<_> = headers[header::ALLOW]
        .to_str()
        .unwrap()
        .split(',')
        .map(str::trim)
        .collect();
    allowed.sort_unstable();
    assert_eq!(allowed, ["POST", "PUT"]);
    let (status, headers, _) = request(&app, "POST", path, None, Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    let (status, headers, error) =
        request(&app, "POST", path, Some("wrong-secret"), Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(error["error"], "Unauthorized");
    for (credential, cache, expected) in [
        (
            token(&pool, Some("org_beta"), &["main"], &["push"], "beta-token").await,
            "go-only",
            StatusCode::NOT_FOUND,
        ),
        (
            token(
                &pool,
                Some("org_alpha"),
                &["elsewhere"],
                &["push"],
                "wrong-cache",
            )
            .await,
            "main",
            StatusCode::FORBIDDEN,
        ),
        (
            token(
                &pool,
                Some("org_alpha"),
                &["*"],
                &["go:write"],
                "wrong-product",
            )
            .await,
            "main",
            StatusCode::FORBIDDEN,
        ),
        (
            token(
                &pool,
                Some("org_alpha"),
                &["*"],
                &["push"],
                "disabled-product",
            )
            .await,
            "go-only",
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            request(
                &app,
                "POST",
                path,
                Some(&credential),
                json!({"cache":cache,"storePathHashes":[]})
            )
            .await
            .0,
            expected
        );
    }
    for credential in [
        "legacy-secret".to_owned(),
        token(&pool, None, &["local"], &["push"], "old-token").await,
    ] {
        assert_eq!(
            request(
                &app,
                "POST",
                path,
                Some(&credential),
                json!({"cache":"local","storePathHashes":[]})
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let alpha_id: i32 =
        sqlx::query_scalar("SELECT id FROM caches WHERE org_id='org_alpha' AND name='main'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let id_token = token(
        &pool,
        Some("org_alpha"),
        &[&format!("id:{alpha_id}")],
        &["push", "pull"],
        "revocable",
    )
    .await;
    // A validly signed JWT that is not listed is rejected, whatever it claims.
    let unlisted = jwt(Some("org_alpha"), &["*"], &["push", "pull"], "unlisted");
    assert_eq!(
        request(&app, "POST", path, Some(&unlisted), body.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "POST", path, Some(&id_token), body.clone())
            .await
            .0,
        StatusCode::OK
    );
    let first_use: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_used_at FROM api_tokens WHERE jti='revocable'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut read_headers = HeaderMap::new();
    read_headers.insert(
        header::AUTHORIZATION,
        format!("Basic {}", STANDARD.encode(format!("user:{id_token}")))
            .parse()
            .unwrap(),
    );
    auth::authorize_read(&read_headers, &state, alpha_id, "main", "org_alpha")
        .await
        .unwrap();
    let recent_use: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_used_at FROM api_tokens WHERE jti='revocable'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(recent_use, first_use);
    sqlx::query(
        "UPDATE api_tokens SET last_used_at=now()-interval '10 minutes' WHERE jti='revocable'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        request(&app, "POST", path, Some(&id_token), body.clone())
            .await
            .0,
        StatusCode::OK
    );
    let refreshed: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_used_at FROM api_tokens WHERE jti='revocable'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(refreshed > first_use);
    assert_eq!(
        auth::authorize_read(&read_headers, &state, alpha_id, "main", "org_beta")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE api_tokens SET revoked_at=now() WHERE jti='revocable'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "POST", path, Some(&id_token), body.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        auth::authorize_read(&read_headers, &state, alpha_id, "main", "org_alpha")
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    // Org keys retain the existing secret-hash format and never cross orgs.
    let key = "snowstead_key_0123456789abcdef_key-secret";
    sqlx::query("INSERT INTO org_api_keys (id,org_id,name,secret_hash) VALUES ('0123456789abcdef','org_alpha','test',$1)")
        .bind(hex::encode(Sha256::digest(b"key-secret"))).execute(&pool).await.unwrap();
    let mut key_headers = HeaderMap::new();
    key_headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {key}").parse().unwrap(),
    );
    let key_principal = auth::authenticate(&key_headers, &state, None)
        .await
        .unwrap();
    assert_eq!(key_principal.actor(), "key:0123456789abcdef");
    assert!(authz::authorize(&key_principal, Action::OrgRead, &Resource::Org("org_alpha")).is_ok());
    assert!(authz::authorize(&key_principal, Action::OrgRead, &Resource::Org("org_beta")).is_err());
    // Background positive discovery is recorded, then used by the next request.
    state.finish_background().await;
    request(
        &app,
        "POST",
        path,
        Some(&alpha),
        json!({"cache":"main","storePathHashes":[warming_hash]}),
    )
    .await;
    state.finish_background().await;
    let (_, _, result) = request(
        &app,
        "POST",
        path,
        Some(&alpha),
        json!({"cache":"main","storePathHashes":[warming_hash]}),
    )
    .await;
    assert_eq!(result["missing"], json!([]));
    assert_eq!(result["upstream"], json!([warming_hash]));
    assert_eq!(
        request(&app, "GET", "/healthz", None, Value::Null).await.2,
        json!({"ok":true,"service":"snowstead"})
    );
    assert_eq!(
        request(&app, "POST", "/healthz", None, Value::Null).await.0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "PUT", "/", None, Value::Null).await.2,
        json!({"service":"snowstead","status":"ok"})
    );
    state.finish_background().await;
    pool.close().await;
    assert_eq!(
        request(&app, "GET", "/healthz", None, Value::Null).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn nix_push_audits_permission_failures_and_endpoint_responses(pool: PgPool) {
    sqlx::raw_sql(
        "INSERT INTO caches (name,org_id) VALUES ('local','default');
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .execute(&pool)
    .await
    .unwrap();
    let state = AppState::new(
        pool.clone(),
        Config {
            jwt_secret: "contract-secret".into(),
            shared_auth_token: Some("legacy-secret".into()),
            public_url: "https://cache.example.test".into(),
            ..Default::default()
        },
        common::storage(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state);
    let pull = token(&pool, None, &["*"], &["pull"], "pull-only").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_api/v1/get-missing-paths")
                .header(
                    snowstead_protocol::PROTOCOL_VERSION_HEADER,
                    snowstead_protocol::PROTOCOL_VERSION,
                )
                .header("authorization", format!("Bearer {pull}"))
                .header("cf-connecting-ip", "198.51.100.99")
                .extension(axum::extract::ConnectInfo(
                    "192.0.2.4:9876".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::from("not JSON"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let row: (String, String, i32, String, Option<String>, String) = sqlx::query_as(
        "SELECT actor,action,status,detail,ip,org_id FROM audit_logs ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            "pull-only".into(),
            "push".into(),
            403,
            "{\"reason\":\"missing push permission\"}".into(),
            Some("192.0.2.4".into()),
            "default".into()
        )
    );

    let (status, _, _) = request(
        &app,
        "POST",
        "/_api/v1/get-missing-paths",
        Some("legacy-secret"),
        json!({"cache":"local","storePathHashes":[]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for (method, path, endpoint, cache, expected) in [
        (
            "POST",
            "/_api/v1/caches/local/upload-streams/batch",
            "create-upload-streams",
            Some("local"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/_api/v1/uploads/parts",
            "reserve-upload-parts-batch",
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/_api/v1/uploads/finalize",
            "finalize-upload-streams",
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/_api/v1/uploads/absent/parts",
            "reserve-upload-parts",
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/_api/v1/uploads/absent/inline",
            "inline-upload",
            None,
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            "/_api/v1/uploads/absent/abort",
            "abort-upload-stream",
            None,
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, _, _) = request(&app, method, path, Some("legacy-secret"), json!({})).await;
        assert_eq!(status, expected, "{endpoint}");
        let row: (String, String, Option<String>, i32, String) = sqlx::query_as(
            "SELECT actor,action,cache_name,status,detail FROM audit_logs ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                "legacy".into(),
                "push".into(),
                cache.map(str::to_owned),
                i32::from(expected.as_u16()),
                json!({"endpoint":endpoint}).to_string()
            )
        );
    }
    // Method/route and authentication failures never reach the TS audit hook.
    for (method, path, credential) in [
        ("PUT", "/_api/v1/uploads/parts", Some("legacy-secret")),
        (
            "PUT",
            "/_api/v1/uploads/absent/part/1",
            Some("legacy-secret"),
        ),
        ("POST", "/_api/v1/unknown", Some("legacy-secret")),
        ("POST", "/_api/v1/get-missing-paths", None),
    ] {
        request(&app, method, path, credential, json!({})).await;
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 8);
    // Audit storage failure must not change the already determined response.
    sqlx::query("DROP TABLE audit_logs")
        .execute(&pool)
        .await
        .unwrap();
    let (status, _, body) = request(
        &app,
        "POST",
        "/_api/v1/get-missing-paths",
        Some("legacy-secret"),
        json!({"cache":"local","storePathHashes":[]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["missing"], json!([]));
}
