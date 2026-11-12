mod common;

#[path = "support/web.rs"]
mod web;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sha2::Digest;
use snowstead_server::{AppState, config::Config, router};
use sqlx::PgPool;
use tower::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let (path, token) = match token {
        Some(token) if token == "operator-secret" => {
            let (path, token) =
                web::dashboard(method, path, token, None, body.to_string().as_bytes());
            (path, Some(token))
        }
        _ => (path.to_owned(), token.map(str::to_owned)),
    };
    let mut request = Request::builder()
        .method(method)
        .uri(path.as_str())
        .header("content-type", "application/json");
    if let Some(token) = &token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let result =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, result)
}

async fn app(pool: &PgPool) -> Router {
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_alpha','alpha'),('org_beta','beta');
        INSERT INTO caches (name,org_id,is_public) VALUES ('main','org_alpha',false),('other','org_alpha',false),('main','org_beta',false),('local','default',false);
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id,'nix' FROM caches;")
        .execute(pool).await.unwrap();
    router(
        AppState::new(
            pool.clone(),
            Config {
                jwt_secret: "contract-secret".into(),
                admin_secret: "operator-secret".into(),
                web_assertion_public_keys: web::public_key(),
                shared_auth_token: Some("legacy-secret".into()),
                ..Default::default()
            },
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    )
}

async fn key(app: &Router, org: &str) -> Value {
    let (status, value) = call(
        app,
        "POST",
        &format!("/_api/v1/orgs/{org}/keys"),
        Some("operator-secret"),
        json!({"name":"  CI  "}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["name"], "CI");
    value
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn keys_scope_operator_boundary_and_idempotent_revoke(pool: PgPool) {
    let app = app(&pool).await;
    let alpha = key(&app, "org_alpha").await;
    let beta = key(&app, "org_beta").await;
    let credential = alpha["key"].as_str().unwrap();
    let path = "/_api/v1/orgs/org_alpha/keys";
    assert_eq!(
        call(&app, "GET", path, None, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    for token in [
        "bogus".to_owned(),
        "snowstead_key_0000000000000000_missing".to_owned(),
        format!("{credential}wrong"),
    ] {
        let (status, body) = call(&app, "GET", path, Some(&token), Value::Null).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Unauthorized");
    }
    assert_eq!(
        call(&app, "GET", path, Some("legacy-secret"), Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/_api/v1/admin/tokens",
            Some("bogus"),
            Value::Null
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, list) = call(&app, "GET", path, Some(credential), Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["keys"].as_array().unwrap().len(), 1);
    assert!(list["keys"][0].get("key").is_none());
    assert!(list["keys"][0].get("secretHash").is_none());
    assert!(list["keys"][0].get("secret_hash").is_none());
    assert!(!list.to_string().contains(credential));
    for path in [
        "/_api/v1/admin/tokens",
        "/_api/v1/orgs/org_beta/tokens",
        "/_api/v1/orgs/org_beta/audit",
    ] {
        assert_eq!(
            call(&app, "GET", path, Some(credential), Value::Null)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        call(
            &app,
            "POST",
            path,
            Some(credential),
            json!({"name":"escalation"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/_api/v1/orgs/org_beta/keys",
            Some(credential),
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let wrong_key = format!("{path}/{}/revoke", beta["id"].as_str().unwrap());
    assert_eq!(
        call(&app, "POST", &wrong_key, Some(credential), json!({}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let revoke = format!("{path}/{}/revoke", alpha["id"].as_str().unwrap());
    assert_eq!(
        call(&app, "POST", &revoke, Some(credential), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "POST", &revoke, Some("operator-secret"), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "GET", path, Some(credential), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let stored: String = sqlx::query_scalar("SELECT secret_hash FROM org_api_keys WHERE id=$1")
        .bind(alpha["id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 64);
    assert!(!credential.contains(&stored));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn created_tokens_work_on_protocol_and_follow_cache_ids(pool: PgPool) {
    let app = app(&pool).await;
    let alpha = key(&app, "org_alpha").await;
    let credential = alpha["key"].as_str().unwrap();
    let path = "/_api/v1/orgs/org_alpha/tokens";
    let (status, made) = call(&app,"POST",path,Some(credential),json!({"org":"org_beta","subject":"ci","caches":["main","main","ci-*"],"perms":["pull","push","push"],"expiresInDays":null})).await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    assert_eq!(made["caches"], json!(["main", "ci-*"]));
    assert_eq!(made["perms"], json!(["pull", "push"]));
    assert_eq!(made["org"], "org_alpha");
    assert_eq!(made["expiresAt"], Value::Null);
    // The token is opaque; the service keeps a hash of its secret and its
    // scope in normalized rows, never in the token itself.
    let token = made["token"].as_str().unwrap();
    let jti = made["jti"].as_str().unwrap();
    let secret = token
        .strip_prefix(&format!("snowstead_tok_{jti}_"))
        .unwrap();
    assert!(!secret.is_empty() && !secret.contains('.'));
    let cache_id: i32 =
        sqlx::query_scalar("SELECT id FROM caches WHERE org_id='org_alpha' AND name='main'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let (hash, caches_json, perms_json): (String, String, String) =
        sqlx::query_as("SELECT secret_hash, caches_json, perms_json FROM api_tokens WHERE jti=$1")
            .bind(jti)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(hash, hex::encode(sha2::Sha256::digest(secret.as_bytes())));
    assert!(!token.contains(&hash));
    assert_eq!((caches_json.as_str(), perms_json.as_str()), ("[]", "[]"));
    let grants: Vec<(Option<i32>, Option<String>)> =
        sqlx::query_as("SELECT cache_id, pattern FROM token_caches WHERE token_jti=$1 ORDER BY id")
            .bind(jti)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        grants,
        [(Some(cache_id), None), (None, Some("ci-*".into()))]
    );
    let perms: Vec<String> = sqlx::query_scalar(
        "SELECT permission FROM token_permissions WHERE token_jti=$1 ORDER BY position",
    )
    .bind(jti)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(perms, ["pull", "push"]);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM token_caches WHERE token_jti=$1")
        .bind(made["jti"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let missing = "/_api/v1/get-missing-paths";
    assert_eq!(
        call(
            &app,
            "POST",
            missing,
            Some(token),
            json!({"cache":"main","storePathHashes":["0".repeat(32)]})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "POST",
            missing,
            Some(token),
            json!({"cache":"other","storePathHashes":["0".repeat(32)]})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/beta/main/nix-cache-info",
            Some(token),
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE caches SET name='renamed' WHERE id=$1")
        .bind(cache_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            missing,
            Some(token),
            json!({"cache":"renamed","storePathHashes":["0".repeat(32)]})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/alpha/renamed/nix-cache-info",
            Some(token),
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    let single = format!("{path}/{}", made["jti"].as_str().unwrap());
    let (status, listed) = call(&app, "GET", &single, Some(credential), Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["token"]["caches"], json!(["renamed", "ci-*"]));
    assert_eq!(
        listed["token"]["createdBy"],
        format!("key:{}", alpha["id"].as_str().unwrap())
    );
    assert!(listed["token"].get("lastUsedAt").is_some());
    assert!(listed["token"].get("token").is_none());
    let wrong = format!(
        "/_api/v1/orgs/org_beta/tokens/{}/revoke",
        made["jti"].as_str().unwrap()
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &wrong,
            Some("operator-secret"),
            json!({"reason":"wrong org"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let revoke = format!("{single}/revoke");
    assert_eq!(
        call(
            &app,
            "POST",
            &revoke,
            Some(credential),
            json!({"reason":"rotation"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &revoke,
            Some(credential),
            json!({"reason":"rotation"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "POST",
            missing,
            Some(token),
            json!({"cache":"renamed","storePathHashes":["0".repeat(32)]})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn token_batches_preserve_interleaved_order_and_first_error(pool: PgPool) {
    let app = app(&pool).await;
    let path = "/_api/v1/orgs/org_alpha/tokens";
    let requested = json!(["z-*", "other", "main", "a-*", "other", "z-*"]);
    let (status, made) = call(
        &app,
        "POST",
        path,
        Some("operator-secret"),
        json!({"subject":"ordered","caches":requested,"perms":["pull"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    assert_eq!(made["caches"], json!(["z-*", "other", "main", "a-*"]));
    let ids: Vec<(String, i32)> =
        sqlx::query_as("SELECT name,id FROM caches WHERE org_id='org_alpha'")
            .fetch_all(&pool)
            .await
            .unwrap();
    let ids: std::collections::HashMap<_, _> = ids.into_iter().collect();
    let expected = json!([
        "z-*",
        format!("id:{}", ids["other"]),
        format!("id:{}", ids["main"]),
        "a-*"
    ]);
    let entries: Vec<String> = sqlx::query_scalar("SELECT coalesce('id:'||cache_id::text,pattern) FROM token_caches WHERE token_jti=$1 ORDER BY id")
        .bind(made["jti"].as_str().unwrap()).fetch_all(&pool).await.unwrap();
    assert_eq!(json!(entries), expected);
    let (_, listed) = call(
        &app,
        "GET",
        &format!("{path}/{}", made["jti"].as_str().unwrap()),
        Some("operator-secret"),
        Value::Null,
    )
    .await;
    assert_eq!(listed["token"]["caches"], made["caches"]);
    for (caches, error) in [
        (
            json!(["missing-z", "missing-a", "BAD*"]),
            "missing-z is not a cache of org_alpha",
        ),
        (
            json!(["main", "BAD*", "missing"]),
            "BAD* must be cache name characters and *",
        ),
    ] {
        let (status, value) = call(
            &app,
            "POST",
            path,
            Some("operator-secret"),
            json!({"subject":"invalid","caches":caches,"perms":["pull"]}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(value["error"], error);
    }
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tokens, 1);
    let (status, wildcard) = call(
        &app,
        "POST",
        path,
        Some("operator-secret"),
        json!({"subject":"wildcard","caches":["*"],"perms":["pull"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{wildcard}");
    let (_, listed) = call(
        &app,
        "GET",
        &format!("{path}/{}", wildcard["jti"].as_str().unwrap()),
        Some("operator-secret"),
        Value::Null,
    )
    .await;
    assert_eq!(listed["token"]["caches"], json!(["*"]));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn admin_token_validation_and_audit_pagination(pool: PgPool) {
    let app = app(&pool).await;
    let path = "/_api/v1/admin/tokens";
    for (body, error) in [
        (json!({}), "subject must be a non-empty string"),
        (
            json!({"subject":"ci","caches":[],"perms":["pull"]}),
            "caches must be a non-empty array of cache names",
        ),
        (
            json!({"subject":"ci","caches":["*"],"perms":["pull"],"expiresInDays":0}),
            "expiresInDays must be between 1 and 365",
        ),
        (
            json!({"subject":"ci","caches":["BAD*"],"perms":["pull"]}),
            "BAD* must be cache name characters and *",
        ),
        (
            json!({"subject":"ci","caches":["main"],"perms":["pull"]}),
            "main is not a cache of default",
        ),
    ] {
        let (status, value) = call(&app, "POST", path, Some("operator-secret"), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
        assert_eq!(value["error"], error);
    }
    let (status, made) = call(
        &app,
        "POST",
        path,
        Some("operator-secret"),
        json!({"subject":"ci","caches":["local"],"perms":["pull"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    assert_eq!(made["org"], "default");
    assert!(made["expiresAt"].is_string());
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{path}/{}", made["jti"].as_str().unwrap()),
            Some("operator-secret"),
            Value::Null,
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, list) = call(&app, "GET", path, Some("operator-secret"), Value::Null).await;
    assert!(list["tokens"][0].get("lastUsedAt").is_none());
    assert!(list["tokens"][0].get("token").is_none());
    let alpha = key(&app, "org_alpha").await;
    let credential = alpha["key"].as_str().unwrap();
    // Discard router-generated audit rows so pagination has deterministic data.
    sqlx::query("DELETE FROM audit_logs")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("INSERT INTO audit_logs (actor,action,status,detail,org_id) VALUES ('admin','test.first',200,'{\"safe\":1}','org_alpha'),('admin','test.second',201,'{}','org_alpha'),('admin','test.foreign',200,'{}','org_beta')").execute(&pool).await.unwrap();
    let audit = "/_api/v1/orgs/org_alpha/audit";
    let (status, page) = call(
        &app,
        "GET",
        &format!("{audit}?limit=1"),
        Some(credential),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["entries"][0]["action"], "test.second");
    assert_eq!(page["next"], page["entries"][0]["id"]);
    let (_, older) = call(
        &app,
        "GET",
        &format!("{audit}?before={}&limit=2", page["next"]),
        Some(credential),
        Value::Null,
    )
    .await;
    assert_eq!(older["entries"].as_array().unwrap().len(), 1);
    assert_eq!(older["entries"][0]["detail"], json!({"safe":1}));
    assert_eq!(older["next"], Value::Null);
    for query in [
        "limit=0",
        "limit=201",
        "limit=1.5",
        "before=0",
        "before=9007199254740992",
    ] {
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("{audit}?{query}"),
                Some(credential),
                Value::Null
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn dashboard_users_create_keys_as_themselves_without_logging_secrets(pool: PgPool) {
    let app = app(&pool).await;
    // The operator secret no longer reaches org routes, and an actor header
    // names no one.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_api/v1/orgs/org_alpha/keys")
                .header("authorization", "Bearer operator-secret")
                .header("x-snowstead-actor", "dev@example.test")
                .header("content-type", "application/json")
                .body(Body::from(json!({"name":"dashboard"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let path = "/_api/v1/orgs/org_alpha/keys";
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_api/v1/orgs/org_alpha/keys")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        web::assertion(
                            "POST",
                            path,
                            "org_alpha",
                            "owner",
                            "dev@example.test",
                            json!({"name":"dashboard"}).to_string().as_bytes(),
                        )
                    ),
                )
                .header("cf-connecting-ip", "198.51.100.99")
                .extension(axum::extract::ConnectInfo(
                    "192.0.2.23:43210".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name":"dashboard"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let key: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let credential = key["key"].as_str().unwrap();
    let (status, audit) = call(
        &app,
        "GET",
        "/_api/v1/orgs/org_alpha/audit",
        Some(credential),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit["entries"][0]["actor"], "user:dev@example.test");
    assert_eq!(audit["entries"][0]["ip"], "192.0.2.23");
    assert_eq!(
        audit["entries"][0]["detail"],
        json!({"key":key["id"],"name":"dashboard"})
    );
    assert!(!audit.to_string().contains(credential));
    let hash: String = sqlx::query_scalar("SELECT secret_hash FROM org_api_keys WHERE id=$1")
        .bind(key["id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!audit.to_string().contains(&hash));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn dashboard_assertions_are_bound_to_org_role_and_request(pool: PgPool) {
    let app = app(&pool).await;
    let as_user = |method: &str, path: &str, org: &str, role: &str, body: &Value| {
        let body = body.to_string();
        web::assertion(
            method,
            path,
            org,
            role,
            "person@example.test",
            body.as_bytes(),
        )
    };
    let caches = "/_api/v1/orgs/org_alpha/caches";
    let keys = "/_api/v1/orgs/org_alpha/keys";
    let org = "/_api/v1/orgs/org_alpha";
    let status = |method: &'static str, path: &'static str, credential: String, body: Value| {
        let app = app.clone();
        async move { call(&app, method, path, Some(&credential), body).await.0 }
    };
    assert_eq!(
        status(
            "GET",
            caches,
            as_user("GET", caches, "org_alpha", "member", &Value::Null),
            Value::Null
        )
        .await,
        StatusCode::OK
    );
    // Members can't manage API keys; owners can.
    let named = json!({"name":"deploy"});
    assert_eq!(
        status(
            "POST",
            keys,
            as_user("POST", keys, "org_alpha", "member", &named),
            named.clone()
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(
            "POST",
            keys,
            as_user("POST", keys, "org_alpha", "owner", &named),
            named.clone()
        )
        .await,
        StatusCode::CREATED
    );
    // Another org's user, or an assertion for another request, gets nothing.
    assert_eq!(
        status(
            "GET",
            caches,
            as_user("GET", caches, "org_beta", "owner", &Value::Null),
            Value::Null
        )
        .await,
        StatusCode::FORBIDDEN,
        "an org_beta user is not authorized on org_alpha"
    );
    let beta = "/_api/v1/orgs/org_beta/caches";
    assert_eq!(
        status(
            "GET",
            caches,
            as_user("GET", beta, "org_beta", "owner", &Value::Null),
            Value::Null
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(
            "POST",
            keys,
            as_user("GET", keys, "org_alpha", "owner", &named),
            named.clone()
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // A captured assertion can't carry a different body.
    assert_eq!(
        status(
            "POST",
            keys,
            as_user("POST", keys, "org_alpha", "owner", &named),
            json!({"name":"other"})
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // Owners change the slug; only the operator sets limits or creates orgs.
    assert_eq!(
        status(
            "PUT",
            org,
            as_user(
                "PUT",
                org,
                "org_alpha",
                "member",
                &json!({"slug":"alpha-2"})
            ),
            json!({"slug":"alpha-2"})
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(
            "PUT",
            org,
            as_user("PUT", org, "org_alpha", "owner", &json!({"slug":"alpha-2"})),
            json!({"slug":"alpha-2"})
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        status(
            "PUT",
            org,
            as_user("PUT", org, "org_alpha", "owner", &json!({"storageLimit":1})),
            json!({"storageLimit":1})
        )
        .await,
        StatusCode::FORBIDDEN
    );
    let fresh = "/_api/v1/orgs/org_fresh";
    assert_eq!(
        status(
            "PUT",
            fresh,
            as_user("PUT", fresh, "org_fresh", "owner", &json!({"slug":"fresh"})),
            json!({"slug":"fresh"})
        )
        .await,
        StatusCode::FORBIDDEN
    );
    // The operator works on its own surface (dashboard_users_create_keys_as_
    // themselves_without_logging_secrets checks it is refused on org routes).
    let admin_org = "/_api/v1/admin/orgs/org_alpha";
    let (status_code, updated) = call(
        &app,
        "PUT",
        admin_org,
        Some("operator-secret"),
        json!({"storageLimit":5}),
    )
    .await;
    assert_eq!(status_code, StatusCode::OK, "{updated}");
    let (status_code, read) =
        call(&app, "GET", admin_org, Some("operator-secret"), Value::Null).await;
    assert_eq!(status_code, StatusCode::OK);
    assert_eq!(
        (read["slug"].as_str(), read["storageLimit"].as_i64()),
        (Some("alpha-2"), Some(5))
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/_api/v1/admin/orgs/org_missing",
            Some("operator-secret"),
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let key = key(&app, "org_alpha").await;
    assert_eq!(
        status(
            "GET",
            admin_org,
            key["key"].as_str().unwrap().into(),
            Value::Null
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

async fn raw(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> StatusCode {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
        .status()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn legacy_dashboard_calls_work_only_while_explicitly_allowed(pool: PgPool) {
    let keys = "/_api/v1/orgs/org_alpha/keys";
    let legacy = [
        ("authorization", "Bearer operator-secret"),
        ("x-snowstead-actor", "dev@example.test"),
        ("content-type", "application/json"),
    ];
    let body = r#"{"name":"rollout"}"#;
    // Off by default: the operator secret doesn't reach org routes.
    let off = app(&pool).await;
    assert_eq!(
        raw(&off, "POST", keys, &legacy, body).await,
        StatusCode::FORBIDDEN
    );
    let on = router(
        AppState::new(
            pool.clone(),
            Config {
                admin_secret: "operator-secret".into(),
                allow_legacy_web_admin: true,
                ..Default::default()
            },
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    assert_eq!(
        raw(&on, "POST", keys, &legacy, body).await,
        StatusCode::CREATED
    );
    // As before, it may set limits on the org route.
    assert_eq!(
        raw(
            &on,
            "PUT",
            "/_api/v1/orgs/org_alpha",
            &legacy,
            r#"{"storageLimit":7}"#
        )
        .await,
        StatusCode::OK
    );
    let (actor, detail): (String, String) = sqlx::query_as(
        "SELECT actor, detail FROM audit_logs WHERE action='key.create' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actor, "user:dev@example.test");
    assert_eq!(
        serde_json::from_str::<Value>(&detail).unwrap()["legacyWeb"],
        true
    );
    // It never reaches protocol routes.
    assert_eq!(
        raw(
            &on,
            "POST",
            "/_api/v1/get-missing-paths",
            &legacy,
            r#"{"cache":"main","storePathHashes":[]}"#
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn head_requests_are_authorized_as_reads(pool: PgPool) {
    let app = app(&pool).await;
    let caches = "/_api/v1/orgs/org_alpha/caches";
    let credential = format!(
        "Bearer {}",
        web::assertion(
            "HEAD",
            caches,
            "org_alpha",
            "member",
            "dev@example.test",
            b""
        )
    );
    assert_eq!(
        raw(&app, "HEAD", caches, &[("authorization", &credential)], "").await,
        StatusCode::OK
    );
}
