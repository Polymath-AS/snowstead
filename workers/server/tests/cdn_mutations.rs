mod common;

#[path = "support/web.rs"]
mod web;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::PgPool;
use tokio::io::AsyncReadExt;
use tower::ServiceExt;

async fn call(app: &Router, path: &str, method: &str, value: Value) -> (StatusCode, Value) {
    // Nix pushes use the self-hosted shared token; management, the operator.
    let secret = if path.starts_with("/_api/v1/caches/") {
        "shared-token"
    } else {
        "operator"
    };
    let (path, credential) = web::dashboard(method, path, secret, None);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path.as_str())
                .header("authorization", format!("Bearer {credential}"))
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

async fn read(app: &Router, path: &str, authenticated: bool) -> (StatusCode, String) {
    let mut request = Request::builder().uri(path);
    if authenticated {
        let claims = json!({"jti":"metadata-test", "sub":"test", "iss":"snowstead", "aud":"snowstead",
            "iat":1, "org":"org_metadata", "caches":["private"], "perms":["pull"]});
        let input = format!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(b"metadata-test-secret").unwrap();
        mac.update(input.as_bytes());
        request = request.header(
            "authorization",
            format!(
                "Bearer {input}.{}",
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            ),
        );
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn assert_cleanup(pool: &PgPool, private: bool, key: &str) {
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM object_cleanup WHERE is_private=$1 AND key=$2)"
        )
        .bind(private)
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap(),
        "missing cleanup: private={private}, key={key}"
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn publication_and_capacity_eviction_use_sql_membership_and_legacy_cleanup(pool: PgPool) {
    let storage = common::storage();
    let config = Config {
        admin_secret: "operator".into(),
        web_assertion_public_keys: web::public_key(),
        shared_auth_token: Some("shared-token".into()),
        public_cache_origin: "https://cdn.example.test".into(),
        public_url: "https://service.example.test".into(),
        ..Default::default()
    };
    let state = AppState::new(
        pool.clone(),
        config,
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
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
    let file_hash = hex::encode(Sha256::digest(&compressed));
    let hash = "2".repeat(32);
    let input = json!({"paths":[{
        "storePath":format!("/nix/store/{hash}-new"),"storePathHash":hash,
        "narHash":format!("sha256:{}",hex::encode(Sha256::digest(&nar))),"narSize":nar.len(),
        "compression":"zstd","references":[],"inline":true
    }]});
    let (status, created) = call(
        &app,
        "/_api/v1/caches/main/upload-streams/batch",
        "POST",
        input,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["sessions"][0]["sessionId"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/_api/v1/uploads/{id}/inline?fileHash={file_hash}"))
                .header("authorization", "Bearer shared-token")
                .header("content-length", compressed.len())
                .body(Body::from(compressed.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(result["published"], true, "{result}");
    let (status, metadata) = read(&app, &format!("/main/{hash}.narinfo"), false).await;
    assert_eq!(status, StatusCode::OK, "{metadata}");
    assert!(metadata.contains(&format!("StorePath: /nix/store/{hash}-new")));
    assert!(metadata.contains(&format!("URL: nar/{file_hash}/zstd.nar")));
    assert_eq!(
        read(&app, &format!("/main/{old_hash}.narinfo"), false)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        read(
            &app,
            &format!("/main/nar/{}/none.nar", "a".repeat(64)),
            false
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, listed) = call(
        &app,
        "/_api/v1/orgs/default/caches/main/paths",
        "GET",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["paths"].as_array().unwrap().len(), 1);
    assert_eq!(listed["paths"][0]["storePathHash"], hash);
    assert_cleanup(&pool, false, &format!("main/{old_hash}.narinfo")).await;
    // The legacy object survives until GC, but cannot restore SQL membership.
    assert!(
        storage
            .head(false, &format!("main/{old_hash}.narinfo"))
            .await
            .is_ok()
    );
    assert!(
        storage
            .head(false, &format!("main/{hash}.narinfo"))
            .await
            .is_err()
    );
    assert!(storage.head(false, "main/nix-cache-info").await.is_err());
    assert_eq!(
        read(&app, "/main/nix-cache-info", false).await.0,
        StatusCode::OK
    );
    let key: String = sqlx::query_scalar("SELECT public_key FROM blob_objects WHERE file_hash=$1")
        .bind(&file_hash)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(key.starts_with("nar/objects/"));
    let mut bytes = Vec::new();
    storage
        .open(false, &key)
        .await
        .unwrap()
        .reader
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes, compressed);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/main/nar/{file_hash}/zstd.nar"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()["location"],
        format!("https://cdn.example.test/{key}")
    );
    state.finish_background().await;
    assert!(jobs(&storage).await.is_empty());
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn backfill_move_and_withdrawal_use_sql_and_queue_legacy_cleanup(pool: PgPool) {
    let storage = common::storage();
    let config = Config {
        admin_secret: "operator".into(),
        web_assertion_public_keys: web::public_key(),
        jwt_secret: "metadata-test-secret".into(),
        public_cache_origin: "https://cdn.example.test".into(),
        public_url: "https://service.example.test".into(),
        ..Default::default()
    };
    let state = AppState::new(
        pool.clone(),
        config,
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_metadata','before');
        -- The JWT read() presents is listed, with the scope its claims name.
        INSERT INTO api_tokens (jti,subject,org_id,created_by) VALUES ('metadata-test','test','org_metadata','test');
        INSERT INTO token_permissions (token_jti,permission,position) VALUES ('metadata-test','pull',1);
        INSERT INTO token_caches (token_jti,pattern) VALUES ('metadata-test','private');
        INSERT INTO caches(name,org_id,is_public) VALUES ('public','org_metadata',true),('private','org_metadata',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;
        INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) VALUES(repeat('a',64),5,'none','nar/objects/seed');
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
        SELECT c.id,repeat('0',32),'/nix/store/00000000000000000000000000000000-fixture','sha256:'||repeat('0',64),5,b.id FROM caches c CROSS JOIN blob_objects b;")
        .execute(&pool).await.unwrap();
    storage
        .put(false, "nar/objects/seed", b"bytes")
        .await
        .unwrap();
    let hash = "0".repeat(32);
    let file_hash = "a".repeat(64);
    // Leave stale metadata in both placements. Reads must use SQL, and policy
    // transactions must queue cleanup instead of rewriting/deleting objects.
    for name in ["public", "private"] {
        storage
            .put(false, &format!("before/{name}/{hash}.narinfo"), b"stale")
            .await
            .unwrap();
        storage
            .put(
                true,
                &format!("narinfo/before/{name}/{hash}.narinfo"),
                b"stale",
            )
            .await
            .unwrap();
    }
    let (status, result) = call(&app, "/_api/v1/admin/narinfo/backfill", "POST", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["written"], 2);
    assert_eq!(result["processed"], 2);
    assert_eq!(result["skipped"], json!([]));
    let (public_key, private_key): (String, String) =
        sqlx::query_as("SELECT public_key,private_key FROM blob_objects WHERE file_hash=$1")
            .bind(&file_hash)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(public_key.starts_with("nar/objects/"));
    assert!(private_key.starts_with("nars/objects/"));
    assert!(storage.head(false, &public_key).await.is_ok());
    assert!(storage.head(true, &private_key).await.is_ok());
    assert!(storage.head(false, &private_key).await.is_err());
    for (name, private) in [("public", false), ("private", true)] {
        let path = format!("before/{name}");
        let (status, body) = read(&app, &format!("/{path}/{hash}.narinfo"), private).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("-fixture"));
        assert!(body.contains(&format!("URL: nar/{file_hash}/none.nar")));
        assert_cleanup(&pool, false, &format!("{path}/{hash}.narinfo")).await;
        assert_cleanup(&pool, true, &format!("narinfo/{path}/{hash}.narinfo")).await;
        assert_cleanup(&pool, false, &format!("{path}/nix-cache-info")).await;
    }
    for suffix in [
        format!("{hash}.narinfo"),
        "nix-cache-info".into(),
        format!("nar/{file_hash}/none.nar"),
    ] {
        assert_eq!(
            read(&app, &format!("/before/private/{suffix}"), false)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        read(
            &app,
            &format!("/before/private/nar/{file_hash}/none.nar"),
            true
        )
        .await,
        (StatusCode::OK, "bytes".into())
    );
    assert_eq!(
        call(
            &app,
            "/_api/v1/orgs/org_metadata",
            "PUT",
            json!({"slug":"after"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, result) = call(&app, "/_api/v1/orgs/org_metadata/move", "POST", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result, json!({"done":true}));
    for (name, private) in [("public", false), ("private", true)] {
        assert_eq!(
            read(&app, &format!("/before/{name}/{hash}.narinfo"), private)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            read(&app, &format!("/after/{name}/{hash}.narinfo"), private)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            read(&app, &format!("/after/{name}/nix-cache-info"), private)
                .await
                .0,
            StatusCode::OK
        );
        let (status, result) = call(
            &app,
            &format!("/_api/v1/orgs/org_metadata/caches/{name}/paths/delete"),
            "POST",
            json!({"storePathHashes":[hash]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["deleted"], json!([hash]));
        assert_eq!(
            read(&app, &format!("/after/{name}/{hash}.narinfo"), private)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            read(
                &app,
                &format!("/after/{name}/nar/{file_hash}/none.nar"),
                private
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let (status, listed) = call(
            &app,
            &format!("/_api/v1/orgs/org_metadata/caches/{name}/paths"),
            "GET",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["paths"], json!([]));
        for slug in ["before", "after"] {
            assert_cleanup(&pool, false, &format!("{slug}/{name}/{hash}.narinfo")).await;
            assert_cleanup(
                &pool,
                true,
                &format!("narinfo/{slug}/{name}/{hash}.narinfo"),
            )
            .await;
        }
        assert!(
            storage
                .head(false, &format!("before/{name}/{hash}.narinfo"))
                .await
                .is_ok()
        );
    }
    assert!(storage.head(false, &public_key).await.is_ok());
    assert!(storage.head(true, &private_key).await.is_ok());
    state.finish_background().await;
    assert!(jobs(&storage).await.is_empty());
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn cache_deletion_queues_public_purge_and_manual_purges_validate_and_report_failures(
    pool: PgPool,
) {
    let config = Config {
        admin_secret: "operator".into(),
        web_assertion_public_keys: web::public_key(),
        public_cache_origin: "https://cdn.example.test".into(),
        public_url: "https://service.example.test".into(),
        cdn_zone_id: "test-zone".into(),
        cdn_purge_token: "test-token".into(),
        ..Default::default()
    };
    // Confine outbound attempts to a closed loopback endpoint. Failed purges
    // must remain durable and must not be reported as accepted.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy).unwrap())
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();
    let storage = common::storage();
    let state = AppState::new(pool.clone(), config, storage.clone(), http).unwrap();
    let app = router(state.clone());
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_cdn','before');
        INSERT INTO caches(name,org_id,is_public) VALUES ('public','org_cdn',true),('private','org_cdn',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;")
        .execute(&pool).await.unwrap();

    let endpoint = "/_api/v1/orgs/org_cdn/caches/private/purge";
    assert_eq!(
        call(&app, endpoint, "POST", json!({})).await,
        (
            StatusCode::BAD_REQUEST,
            json!({"error":"private caches are not on the CDN"})
        )
    );
    let endpoint = "/_api/v1/orgs/org_cdn/caches/public/purge";
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
        call(
            &app,
            endpoint,
            "POST",
            json!({"storePathHashes":["0".repeat(32)]})
        )
        .await
        .0,
        StatusCode::BAD_GATEWAY
    );

    for cache in ["private", "public"] {
        assert_eq!(
            call(
                &app,
                &format!("/_api/v1/orgs/org_cdn/caches/{cache}/delete"),
                "POST",
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );
        state.finish_background().await;
        let queued = jobs(&storage).await;
        if cache == "private" {
            assert!(queued.is_empty());
        } else {
            assert_eq!(queued.len(), 1);
            assert_eq!(queued[0]["cachePath"], "before/public");
            assert_eq!(queued[0]["wholeCache"], true);
            assert!(
                storage
                    .list(false, "cdn-purges", None, 100)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
