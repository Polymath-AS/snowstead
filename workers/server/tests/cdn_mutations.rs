mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::PgPool;
use tokio::io::AsyncReadExt;
use tower::ServiceExt;

async fn call(app: &Router, path: &str, method: &str, value: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", "Bearer operator")
                .header("content-type", "application/json")
                .body(Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn jobs(storage: &Storage) -> Vec<Value> {
    let mut jobs = Vec::new();
    for key in storage.list(true, "cdn-purges", None, 1000).await.unwrap() {
        let mut bytes = Vec::new();
        storage
            .open(true, &key)
            .await
            .unwrap()
            .reader
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        jobs.push(serde_json::from_slice(&bytes).unwrap());
    }
    jobs
}

async fn clear_jobs(state: &AppState, storage: &Storage) {
    // Let the tracked dispatchers finish before manipulating the test backlog.
    // TaskTracker may accept later work after close, and wait still tracks it.
    state.finish_background().await;
    for key in storage.list(true, "cdn-purges", None, 1000).await.unwrap() {
        storage.delete(true, &key).await.unwrap();
    }
}

async fn fixture(pool: PgPool) -> (AppState, Storage) {
    let config = Config {
        admin_secret: "operator".into(),
        public_cache_origin: "https://cdn.example.test".into(),
        public_url: "https://service.example.test".into(),
        cdn_zone_id: "test-zone".into(),
        cdn_purge_token: "test-token".into(),
        auth_token: "legacy".into(),
        ..Default::default()
    };
    // Every outbound attempt is confined to a closed loopback endpoint. No DNS
    // or request can reach Cloudflare; failed jobs must remain durable.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy).unwrap())
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();
    let storage = common::storage();
    let state = AppState::new(pool, config, storage.clone(), http).unwrap();
    (state, storage)
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn public_mutations_queue_invalidations_and_private_metadata_stays_off_cdn(pool: PgPool) {
    let (state, storage) = fixture(pool.clone()).await;
    let app = router(state.clone());
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_cdn','before');
        INSERT INTO caches(name,org_id,is_public) VALUES ('public','org_cdn',true),('private','org_cdn',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;
        INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) VALUES(repeat('a',64),5,'none','nar/seed');
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
        SELECT c.id,repeat('0',32),'/nix/store/00000000000000000000000000000000-fixture','sha256:'||repeat('0',64),5,b.id FROM caches c CROSS JOIN blob_objects b;")
        .execute(&pool).await.unwrap();
    let file_hash = "a".repeat(64);
    let hash = "0".repeat(32);
    storage
        .put(false, &format!("nar/{file_hash}/none.nar"), b"bytes")
        .await
        .unwrap();
    storage
        .put(true, &format!("nars/sha256/{file_hash}/none.nar"), b"bytes")
        .await
        .unwrap();
    let (status, result) = call(&app, "/_api/v1/admin/narinfo/backfill", "POST", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["written"], 2);
    let queued = jobs(&storage).await;
    assert!(
        queued
            .iter()
            .any(|j| j["cachePath"] == "before/public" && j["hashes"] == json!([hash]))
    );
    assert!(
        queued
            .iter()
            .any(|j| j["files"] == json!(["before/public/nix-cache-info"]))
    );
    assert!(
        !queued
            .iter()
            .any(|j| j.to_string().contains("before/private"))
    );
    assert!(
        storage
            .list(false, "cdn-purges", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    clear_jobs(&state, &storage).await;

    assert_eq!(
        call(
            &app,
            "/_api/v1/orgs/org_cdn",
            "PUT",
            json!({"slug":"after"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, page) = call(&app, "/_api/v1/orgs/org_cdn/move", "POST", json!({})).await;
    assert_eq!(page["next"]["phase"], "private");
    let queued = jobs(&storage).await;
    let files: Vec<&str> = queued
        .iter()
        .filter_map(|j| j["files"].as_array())
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    assert!(files.contains(&format!("before/public/{hash}.narinfo").as_str()));
    assert!(files.contains(&format!("after/public/{hash}.narinfo").as_str()));
    assert!(files.contains(&"after/public/nix-cache-info"));
    clear_jobs(&state, &storage).await;

    let private = "/_api/v1/orgs/org_cdn/caches/private/paths/delete";
    assert_eq!(
        call(&app, private, "POST", json!({"storePathHashes":[hash]}))
            .await
            .0,
        StatusCode::OK
    );
    assert!(jobs(&storage).await.is_empty());
    let public = "/_api/v1/orgs/org_cdn/caches/public/paths/delete";
    assert_eq!(
        call(&app, public, "POST", json!({"storePathHashes":[hash]}))
            .await
            .0,
        StatusCode::OK
    );
    let queued = jobs(&storage).await;
    for path in ["before/public", "after/public"] {
        assert!(
            queued
                .iter()
                .any(|j| j["cachePath"] == path && j["hashes"] == json!([hash]))
        );
    }
    clear_jobs(&state, &storage).await;
    assert_eq!(
        call(
            &app,
            "/_api/v1/orgs/org_cdn/caches/public/delete",
            "POST",
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    let queued = jobs(&storage).await;
    assert!(
        queued
            .iter()
            .any(|j| j["cachePath"] == "after/public" && j["wholeCache"] == true)
    );

    // The manual purge contract rejects private caches and malformed input;
    // transport failures must never be reported as accepted purges.
    let endpoint = "/_api/v1/orgs/org_cdn/caches/private/purge";
    assert_eq!(
        call(&app, endpoint, "POST", json!({})).await,
        (
            StatusCode::BAD_REQUEST,
            json!({"error":"private caches are not on the CDN"})
        )
    );
    assert_eq!(
        call(
            &app,
            "/_api/v1/orgs/org_cdn/caches",
            "POST",
            json!({"name":"replacement","protocols":["nix"]})
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let endpoint = "/_api/v1/orgs/org_cdn/caches/replacement/purge";
    for input in [
        json!([]),
        json!({"storePathHashes":[]}),
        json!({"storePathHashes":["../secret"]}),
        json!({"unexpected":true}),
    ] {
        assert_eq!(
            call(&app, endpoint, "POST", input).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(&app, endpoint, "POST", json!({"storePathHashes":[hash]}))
            .await
            .0,
        StatusCode::BAD_GATEWAY
    );
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn publication_and_capacity_eviction_invalidate_both_discovery_urls(pool: PgPool) {
    let (state, storage) = fixture(pool.clone()).await;
    let app = router(state.clone());
    sqlx::raw_sql("INSERT INTO caches(name) VALUES ('main');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;
        INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) VALUES(repeat('a',64),500,'none','nar/old');
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,last_pushed_at)
        SELECT c.id,repeat('1',32),'/nix/store/11111111111111111111111111111111-old','sha256:'||repeat('0',64),500,b.id,'2000-01-01' FROM caches c CROSS JOIN blob_objects b;
        UPDATE orgs SET storage_limit=300 WHERE id='default';")
        .execute(&pool).await.unwrap();
    let old_hash = "1".repeat(32);
    storage
        .put(false, &format!("main/{old_hash}.narinfo"), b"old discovery")
        .await
        .unwrap();
    // An independently framed regular-file NAR, small enough for inline upload.
    let mut nar = Vec::new();
    for value in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
        b"newly published contents",
        b")",
    ] {
        nar.extend_from_slice(&(value.len() as u64).to_le_bytes());
        nar.extend_from_slice(value);
        nar.resize(nar.len() + (8 - value.len() % 8) % 8, 0);
    }
    let compressed = zstd::stream::encode_all(nar.as_slice(), 3).unwrap();
    assert!(compressed.len() < 300);
    let hash = "2".repeat(32);
    let input = json!({"paths":[{
        "storePath":format!("/nix/store/{hash}-new"),"storePathHash":hash,
        "narHash":format!("sha256:{}",hex::encode(Sha256::digest(&nar))),"narSize":nar.len(),
        "compression":"zstd","references":[],"inline":true
    }]});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_api/v1/caches/main/upload-streams/batch")
                .header("authorization", "Bearer legacy")
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let created: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["sessions"][0]["sessionId"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/_api/v1/uploads/{id}/inline?fileHash={}",
                    hex::encode(Sha256::digest(&compressed))
                ))
                .header("authorization", "Bearer legacy")
                .header("content-length", compressed.len())
                .body(Body::from(compressed))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(result["published"], true, "{result}");
    let queued = jobs(&storage).await;
    for hash in [&hash, &old_hash] {
        assert!(
            queued
                .iter()
                .any(|j| j["cachePath"] == "main" && j["hashes"] == json!([hash]))
        );
    }
    assert!(
        queued
            .iter()
            .any(|j| j["files"] == json!(["main/nix-cache-info"]))
    );
    assert!(
        storage
            .head(false, &format!("main/{old_hash}.narinfo"))
            .await
            .is_err()
    );
    assert!(
        storage
            .head(false, &format!("main/{hash}.narinfo"))
            .await
            .is_ok()
    );
    state.finish_background().await;
}
