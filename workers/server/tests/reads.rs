mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::PgPool;
use std::time::Duration;
use tower::ServiceExt;

const CDN: &str = "https://cdn.example.test";

fn credential() -> String {
    let claims = json!({"jti":"reads-test", "sub":"test", "iss":"snowstead", "aud":"snowstead",
        "iat":1, "org":"org_alpha", "caches":["secret"], "perms":["pull"]});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"read-test-secret").unwrap();
    mac.update(input.as_bytes());
    format!(
        "Bearer {input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

async fn fixture(pool: &PgPool, origin: &str, storage: Storage) -> AppState {
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_alpha','alpha');
        INSERT INTO caches (name,org_id,is_public) VALUES
        ('main','org_alpha',true),('secret','org_alpha',false),('empty','org_alpha',true);
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id,'nix' FROM caches;
        INSERT INTO blob_objects (file_hash,file_size,compression,r2_key)
        VALUES (repeat('a',64),32,'zstd','nar/legacy');
        INSERT INTO published_paths (cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
        SELECT c.id,repeat('0',32),'/nix/store/test','sha256:' || repeat('0',64),32,b.id
        FROM caches c CROSS JOIN blob_objects b WHERE c.name IN ('main','secret');")
        .execute(pool).await.unwrap();
    AppState::new(
        pool.clone(),
        Config {
            admin_secret: "operator-secret".into(),
            jwt_secret: "read-test-secret".into(),
            signing_master_key: STANDARD.encode([42; 32]),
            signing_key_name: "reads-test".into(),
            public_cache_origin: origin.into(),
            ..Default::default()
        },
        storage,
        reqwest::Client::new(),
    )
    .unwrap()
}

async fn read(app: &Router, method: &str, path: &str, headers: &[(&str, &str)]) -> Response {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    tokio::time::timeout(
        Duration::from_secs(5),
        app.clone().oneshot(request.body(Body::empty()).unwrap()),
    )
    .await
    .expect("read touched blocked storage or exceeded deadline")
    .unwrap()
}

async fn text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 16384)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn signing_post(app: &Router, path: &str, body: Value) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", "Bearer operator-secret")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    serde_json::from_str(&text(response).await).unwrap()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn stale_objects_never_override_current_public_metadata_or_signing(pool: PgPool) {
    let storage = common::storage();
    let state = fixture(&pool, CDN, storage.clone()).await;
    let app = router(state.clone());
    let path = format!("/alpha/main/{}.narinfo", "0".repeat(32));
    storage
        .put(false, path.trim_start_matches('/'), b"stale metadata")
        .await
        .unwrap();
    storage
        .put(false, "alpha/main/nix-cache-info", b"stale cache info")
        .await
        .unwrap();
    assert_eq!(
        text(read(&app, "GET", "/alpha/main/nix-cache-info", &[]).await).await,
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
    );
    let initial = read(&app, "GET", &path, &[]).await;
    let mut etag = initial.headers()[header::ETAG].to_str().unwrap().to_owned();
    assert!(text(initial).await.contains("NarSize: 32\n"));
    sqlx::query("UPDATE published_paths SET nar_size=99,system='current-system',signatures_json='[\"upstream:kept\"]' WHERE cache_id=(SELECT id FROM caches WHERE name='main')")
        .execute(&pool).await.unwrap();
    let response = read(&app, "GET", &path, &[("if-none-match", &etag)]).await;
    assert_eq!(response.status(), StatusCode::OK);
    etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let current = text(response).await;
    assert!(current.contains("NarSize: 99\n"));
    assert!(current.contains("System: current-system\n"));
    assert!(current.contains("Sig: upstream:kept\n"));
    let keys = "/_api/v1/orgs/org_alpha/caches/main/signing-keys";
    let mut trusted = Vec::new();
    for _ in 0..2 {
        let key = signing_post(&app, keys, json!({})).await;
        trusted.push(key["publicKey"].as_str().unwrap().to_owned());
        signing_post(
            &app,
            &format!("{keys}/{}/activate", key["id"].as_str().unwrap()),
            json!({"trustedPublicKeys":trusted}),
        )
        .await;
        let response = read(&app, "GET", &path, &[("if-none-match", &etag)]).await;
        assert_eq!(response.status(), StatusCode::OK);
        let next = response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        assert_ne!(etag, next);
        assert!(!response.headers().contains_key(header::LAST_MODIFIED));
        let body = text(response).await;
        assert!(body.contains(&format!(
            "Sig: {}:",
            trusted.last().unwrap().split_once(':').unwrap().0
        )));
        etag = next;
        for method in ["GET", "HEAD"] {
            let response = read(&app, method, &path, &[("if-none-match", &etag)]).await;
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
            assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
            assert!(text(response).await.is_empty());
        }
    }
    sqlx::query(
        "DELETE FROM published_paths WHERE cache_id=(SELECT id FROM caches WHERE name='main')",
    )
    .execute(&pool)
    .await
    .unwrap();
    for method in ["GET", "HEAD"] {
        let response = read(&app, method, &path, &[("if-none-match", &etag)]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!response.headers().contains_key(header::LOCATION));
    }
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn nar_delivery_uses_only_admitted_bucket_pointer(pool: PgPool) {
    let storage = common::storage();
    let state = fixture(&pool, CDN, storage.clone()).await;
    let app = router(state.clone());
    let hash = "a".repeat(64);
    let public = format!("nar/objects/01900000-0000-7000-8000-000000000001/{hash}/zstd.nar");
    let private = format!("nars/objects/01900000-0000-7000-8000-000000000002/{hash}/zstd.nar");
    let scoped = format!("/alpha/main/nar/{hash}/zstd.nar");
    let global = format!("/nar/{hash}/zstd.nar");
    let secret = format!("/alpha/secret/nar/{hash}/zstd.nar");
    let credential = credential();
    let auth = [("authorization", credential.as_str())];
    storage.put(true, &private, b"private bytes").await.unwrap();
    sqlx::query("UPDATE blob_objects SET r2_key=$1,private_key=$1")
        .bind(&private)
        .execute(&pool)
        .await
        .unwrap();
    for method in ["GET", "HEAD"] {
        for path in [&scoped, &global] {
            assert_eq!(
                read(&app, method, path, &[]).await.status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                read(&app, method, path, &[("x-snowstead-cdn-read", "1")])
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            read(&app, method, &secret, &auth).await.status(),
            StatusCode::OK
        );
    }
    sqlx::query("UPDATE blob_objects SET public_key=$1")
        .bind(&public)
        .execute(&pool)
        .await
        .unwrap();
    for method in ["GET", "HEAD"] {
        for path in [&scoped, &global] {
            let response = read(&app, method, path, &[]).await;
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(
                response.headers()[header::LOCATION],
                format!("{CDN}/{public}")
            );
            let response = read(&app, method, path, &[("x-snowstead-cdn-read", "1")]).await;
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(
                response.headers()[header::LOCATION],
                format!("{CDN}/{public}")
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!response.headers().contains_key("x-snowstead-cdn-read"));
        }
        assert_eq!(
            read(
                &app,
                method,
                &format!("/alpha/empty/nar/{hash}/zstd.nar"),
                &[]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    // Without a CDN, public reads still use the public bucket and pointer.
    storage.put(false, &public, b"public bytes").await.unwrap();
    let direct = router(
        AppState::new(
            pool.clone(),
            Config::default(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    assert_eq!(
        text(read(&direct, "GET", &scoped, &[]).await).await,
        "public bytes"
    );
    assert_eq!(
        text(read(&app, "GET", &secret, &auth).await).await,
        "private bytes"
    );
    sqlx::query("UPDATE blob_objects SET private_key=NULL")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        read(&app, "GET", &secret, &auth).await.status(),
        StatusCode::NOT_FOUND
    );
    // Legacy rows alone retain canonical fallback, independently per bucket.
    sqlx::query("UPDATE blob_objects SET public_key=NULL,r2_key='legacy'")
        .execute(&pool)
        .await
        .unwrap();
    storage
        .put(
            true,
            &format!("nars/sha256/{hash}/zstd.nar"),
            b"legacy private",
        )
        .await
        .unwrap();
    assert_eq!(
        text(read(&app, "GET", &secret, &auth).await).await,
        "legacy private"
    );
    let response = read(&app, "GET", &global, &[]).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()[header::LOCATION],
        format!("{CDN}/nar/{hash}/zstd.nar")
    );
    sqlx::query(
        "DELETE FROM published_paths WHERE cache_id=(SELECT id FROM caches WHERE name='main')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        read(&app, "GET", &global, &[]).await.status(),
        StatusCode::NOT_FOUND
    );
    state.finish_background().await;
}
