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
use object_store::{ObjectStore, ObjectStoreExt, memory::InMemory, path::Path};
use serde_json::{Value, json};
use sha2::Sha256;
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::PgPool;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tower::ServiceExt;

fn jwt(org: &str, cache: &str, perms: &[&str]) -> String {
    let p = json!({"jti":format!("policy-{org}-{cache}-{}", perms.join("+")),"sub":"ci","iss":"snowstead","aud":"snowstead","iat":1,"org":org,"caches":[cache],"perms":perms});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(p.to_string())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"policy-jwt").unwrap();
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
async fn fixture(pool: &PgPool) -> AppState {
    fixture_with_storage(pool, common::storage()).await
}

async fn fixture_with_storage(pool: &PgPool, storage: Storage) -> AppState {
    sqlx::raw_sql("INSERT INTO orgs(id,slug) VALUES ('policy_a','policy-a'),('policy_b','policy-b');
        INSERT INTO caches(name,org_id,is_public) VALUES ('shared','policy_a',true),('shared','policy_b',true);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,protocol FROM caches CROSS JOIN (VALUES('nix'),('go'),('sccache')) p(protocol);")
        .execute(pool).await.unwrap();
    AppState::new(pool.clone(), config(), storage, reqwest::Client::new()).unwrap()
}

fn config() -> Config {
    Config {
        admin_secret: "policy-admin".into(),
        web_assertion_public_keys: web::public_key(),
        jwt_secret: "policy-jwt".into(),
        ..Default::default()
    }
}
async fn send(
    app: &Router,
    method: &str,
    path: &str,
    credential: &str,
    value: Value,
) -> (StatusCode, Value) {
    let (path, credential) = if credential == "policy-admin" {
        web::dashboard(method, path, credential, None, value.to_string().as_bytes())
    } else {
        (path.to_owned(), credential.to_owned())
    };
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
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}
fn path(suffix: &str) -> String {
    format!("/_api/v1/orgs/policy_a/caches/shared/{suffix}")
}
async fn publish(pool: &PgPool, digit: char, name: &str, refs: Value) -> String {
    let hash = digit.to_string().repeat(32);
    let root = format!("/nix/store/{hash}-{name}");
    let blob:i64=sqlx::query_scalar("INSERT INTO blob_objects(file_hash,compression,r2_key,file_size) VALUES($1,'zstd',$1,12) RETURNING id")
        .bind(format!("policy-{hash}")).fetch_one(pool).await.unwrap();
    sqlx::query("INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,references_json) SELECT id,$1,$2,'sha256:test',20,$3,$4 FROM caches WHERE org_id='policy_a' AND name='shared'")
        .bind(&hash).bind(&root).bind(blob).bind(refs.to_string()).execute(pool).await.unwrap();
    root
}

#[path = "support/tokens.rs"]
mod tokens;

/// A listed JWT-era token, which works with the scope its row records.
async fn token(pool: &PgPool, org: &str, cache: &str, perms: &[&str]) -> String {
    tokens::register(pool, jwt(org, cache, perms)).await
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn closure_revision_retention_and_scoped_deletion(pool: PgPool) {
    let state = fixture(&pool).await;
    let app = router(state);
    let dep = publish(&pool, 'b', "dependency", json!([])).await;
    let root = publish(&pool, 'a', "root", json!([dep])).await;
    let write = token(&pool, "policy_a", "shared", &["push"]).await;
    let pin = json!({"name":"release","storePath":root,"keep":{"revisions":1}});
    for credential in [
        token(&pool, "policy_b", "*", &["push"]).await,
        token(&pool, "policy_a", "other", &["push"]).await,
        token(&pool, "policy_a", "*", &["pull"]).await,
    ] {
        assert_eq!(
            send(&app, "POST", &path("pins"), &credential, pin.clone())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let (status, result) = send(&app, "POST", &path("pins"), &write, pin.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["pin"]["currentRevision"], 1);
    assert_eq!(
        send(&app, "GET", &path("pins"), &write, Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, result) = send(&app, "POST", &path("pins"), &write, pin).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["pin"]["history"].as_array().unwrap().len(), 1);
    let hashes = json!({"storePathHashes":["a".repeat(32),"b".repeat(32)]});
    let (_, result) = send(
        &app,
        "POST",
        &path("paths/delete"),
        "policy-admin",
        hashes.clone(),
    )
    .await;
    assert_eq!(result["deleted"], json!([]));
    assert_eq!(result["notFound"], hashes["storePathHashes"]);
    let next = publish(&pool, 'c', "next", json!([])).await;
    let (status, result) = send(
        &app,
        "POST",
        &path("pins"),
        &write,
        json!({"name":"release","storePath":next,"keep":{"revisions":1}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["pin"]["currentRevision"], 2);
    assert_eq!(result["pin"]["history"][1]["pinned"], false);
    let (_, deleted) = send(&app, "POST", &path("paths/delete"), "policy-admin", hashes).await;
    assert_eq!(deleted["deleted"].as_array().unwrap().len(), 2);
    let (status, result) = send(
        &app,
        "POST",
        &path("pins"),
        &write,
        json!({"name":"release","storePath":next,"keep":"forever"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{result}");
    let (status, result) = send(
        &app,
        "POST",
        &path("pins"),
        &write,
        json!({"name":"missing","storePath":root,"keep":"forever"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{result}");
    let (status, result) = send(&app, "POST", &path("evict"), "policy-admin", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["removed"]["nix"], 1);
    assert_eq!(result["pinsDeleted"], 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM caches WHERE org_id='policy_b'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let (status, result) = send(&app, "POST", &path("purge"), "policy-admin", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(result["error"], "no CDN is configured to purge");
    let (status, result) = send(&app, "POST", &path("delete"), "policy-admin", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result, json!({"deleted":true,"name":"shared","paths":0}));
    assert_eq!(
        send(&app, "GET", &path("paths"), "policy-admin", Value::Null)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn date_only_deletion_uses_midnight_utc_and_ignores_unknown_properties(pool: PgPool) {
    let app = router(fixture(&pool).await);
    let old = publish(&pool, 'a', "old", json!([])).await;
    let boundary = publish(&pool, 'b', "boundary", json!([])).await;
    sqlx::query("UPDATE published_paths SET created_at=CASE WHEN store_path=$1 THEN '2025-12-31T23:59:59Z'::timestamptz ELSE '2026-01-01T00:00:00Z'::timestamptz END WHERE cache_id=(SELECT id FROM caches WHERE org_id='policy_a' AND name='shared')")
        .bind(&old).execute(&pool).await.unwrap();

    for input in [
        json!({"before":"not-a-date"}),
        json!({"before":"2026-13-01"}),
        json!({"before":"2026-01-01","storePathHashes":["a".repeat(32)]}),
        json!({"ignored":true}),
        Value::Null,
    ] {
        let (status, result) =
            send(&app, "POST", &path("paths/delete"), "policy-admin", input).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    }
    let (status, result) = send(
        &app,
        "POST",
        &path("paths/delete"),
        "policy-admin",
        json!({"before":"2026-01-01","ignored":true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(
        result,
        json!({"deleted":["a".repeat(32)],"notFound":[],"more":false})
    );
    let (_, remaining) = send(&app, "GET", &path("paths"), "policy-admin", Value::Null).await;
    assert_eq!(remaining["paths"].as_array().unwrap().len(), 1);
    assert_eq!(remaining["paths"][0]["storePath"], boundary);

    // Unknown fields are stripped only for deletion, not for pin settings.
    let (status, result) = send(
        &app,
        "POST",
        &path("pins"),
        "policy-admin",
        json!({"name":"release","storePath":boundary,"keep":"forever","ignored":true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    assert_eq!(result["error"], "Unexpected key");

    let (status, result) = send(
        &app,
        "POST",
        &path("paths/delete"),
        "policy-admin",
        json!({"storePathHashes":["b".repeat(32)],"ignored":true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["deleted"], json!(["b".repeat(32)]));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn listing_eviction_cursors_and_generation_resets(pool: PgPool) {
    let state = fixture(&pool).await;
    let app = router(state);
    publish(&pool, 'a', "literal_%", json!([])).await;
    publish(&pool, 'b', "other", json!([])).await;
    let (status, result) = send(
        &app,
        "GET",
        &path("paths?q=literal_%25"),
        "policy-admin",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["paths"].as_array().unwrap().len(), 1);
    let (_, result) = send(
        &app,
        "GET",
        &path("paths?limit=1"),
        "policy-admin",
        Value::Null,
    )
    .await;
    let before = result["next"].as_i64().unwrap();
    let (_, result) = send(
        &app,
        "GET",
        &path(&format!("paths?limit=1&before={before}")),
        "policy-admin",
        Value::Null,
    )
    .await;
    assert_eq!(result["paths"].as_array().unwrap().len(), 1);
    for limit in ["0x1", "0X1", "0o1", "0b1", "%201%20"] {
        for (route, field) in [
            (path(&format!("paths?limit={limit}")), "paths"),
            (
                format!("/_api/v1/orgs/policy_a/eviction?limit={limit}"),
                "next",
            ),
        ] {
            let (status, page) = send(&app, "GET", &route, "policy-admin", Value::Null).await;
            assert_eq!(status, StatusCode::OK, "{route}: {page}");
            let items = if field == "next" {
                &page["next"]["items"]
            } else {
                &page[field]
            };
            assert_eq!(items.as_array().unwrap().len(), 1, "{route}: {page}");
        }
    }
    for encoded in [
        format!("0x{before:x}"),
        format!("0o{before:o}"),
        format!("0b{before:b}"),
        format!("%20{before}%20"),
    ] {
        let (status, page) = send(
            &app,
            "GET",
            &path(&format!("paths?limit=1&before={encoded}")),
            "policy-admin",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{encoded}: {page}");
        assert_eq!(page["paths"], result["paths"], "{encoded}: {page}");
    }
    let url = "/_api/v1/orgs/policy_a/eviction?limit=1";
    let (status, result) = send(&app, "GET", url, "policy-admin", Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["next"]["items"].as_array().unwrap().len(), 1);
    let cursor = result["next"]["cursor"].as_str().unwrap();
    let (status, result) = send(
        &app,
        "GET",
        &format!("/_api/v1/orgs/policy_b/eviction?nextCursor={cursor}"),
        "policy-admin",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    for kind in ["go", "sccache"] {
        sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {kind}_entries(id,cache_id,generation,action,r2_key,size,uploaded_at,expires_at{}) SELECT $1,id,{kind}_generation,'action',$1,9,now(),now()+interval '1 day'{} FROM caches WHERE org_id='policy_a'",if kind=="go"{",output"}else{""},if kind=="go"{",'output'"}else{""})))
            .bind(format!("policy-{kind}")).execute(&pool).await.unwrap();
        let (status, result) = send(&app, "GET", &path(kind), "policy-admin", Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["entries"], 1);
        let (status, result) = send(
            &app,
            "POST",
            &path(&format!("{kind}/reset")),
            "policy-admin",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(
            result,
            json!({"entries":0,"size":0,"lastAddedAt":null,"retentionDays":7})
        );
        // Reset retires metadata, not physical files or cleanup records.
        assert_eq!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM {kind}_entries WHERE id=$1"
            )))
            .bind(format!("policy-{kind}"))
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn reset_eviction_and_deletion_fence_slow_compiler_publication(pool: PgPool) {
    let bounded = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let state = fixture(&bounded).await;
    let app = router(state);
    let credential = token(&pool, "policy_a", "shared", &["go:write", "sccache:write"]).await;
    for product in ["go", "sccache"] {
        for operation in [
            format!("{product}/reset"),
            "evict".to_owned(),
            "delete".to_owned(),
        ] {
            let action = "d".repeat(64);
            let url = if product == "go" {
                format!("/_api/v1/go/policy-a/shared/v1/actions/{action}")
            } else {
                format!("/_api/v1/sccache/policy-a/shared/d/d/d/{action}")
            };
            let bytes = b"still transferring";
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            let body = Body::from_stream(futures_util::stream::once(async move {
                started_tx.send(()).unwrap();
                resume_rx.await.unwrap();
                Ok::<_, std::io::Error>(axum::body::Bytes::from_static(bytes))
            }));
            use sha2::Digest;
            let request = Request::builder()
                .method("PUT")
                .uri(&url)
                .header("authorization", format!("Bearer {credential}"))
                .header("content-length", bytes.len())
                .header("x-snowstead-output-id", hex::encode(Sha256::digest(bytes)))
                .body(body)
                .unwrap();
            let upload = tokio::spawn(app.clone().oneshot(request));
            tokio::time::timeout(std::time::Duration::from_secs(3), started_rx)
                .await
                .unwrap()
                .unwrap();
            let (status, result) = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                send(&app, "POST", &path(&operation), "policy-admin", json!({})),
            )
            .await
            .expect("a slow transfer must not hold the SQL connection");
            assert_eq!(status, StatusCode::OK, "{result}");
            if operation == "delete" {
                sqlx::raw_sql("INSERT INTO caches(name,org_id,is_public) VALUES ('shared','policy_a',true);
                    INSERT INTO cache_protocols(cache_id,protocol) SELECT id,protocol FROM caches CROSS JOIN (VALUES('nix'),('go'),('sccache')) p(protocol) WHERE org_id='policy_a';")
                    .execute(&bounded).await.unwrap();
            }
            resume_tx.send(()).unwrap();
            let response = upload.await.unwrap().unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()["retry-after"], "1");
            assert_eq!(
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                    "SELECT count(*) FROM {product}_entries WHERE uploaded_at IS NOT NULL"
                )))
                .fetch_one(&bounded)
                .await
                .unwrap(),
                0
            );
            let response = app
                .clone()
                .oneshot(Request::builder().uri(&url).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn cyclic_closure_days_retention_and_session_cleanup(pool: PgPool) {
    let state = fixture(&pool).await;
    let app = router(state);
    let root = format!("/nix/store/{}-root", "a".repeat(32));
    let dep = publish(&pool, 'b', "dependency", json!([root])).await;
    publish(
        &pool,
        'a',
        "root",
        json!([dep.strip_prefix("/nix/store/").unwrap()]),
    )
    .await;
    let (status, result) = send(
        &app,
        "POST",
        &path("pins"),
        "policy-admin",
        json!({"name":"cycle","storePath":root,"keep":{"days":1}}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pin_paths")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    let next = publish(&pool, 'c', "next", json!([])).await;
    let (status, result) = send(
        &app,
        "POST",
        &path("pins"),
        "policy-admin",
        json!({"name":"cycle","storePath":next,"keep":{"days":1}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["pin"]["history"][1]["pinned"], true);
    sqlx::query("UPDATE pin_revisions SET superseded_at=now()-interval '2 days' WHERE revision=1")
        .execute(&pool)
        .await
        .unwrap();
    let (_, result) = send(&app, "GET", &path("pins"), "policy-admin", Value::Null).await;
    assert_eq!(result["pins"][0]["history"][1]["pinned"], false);
    let (status, result) = send(
        &app,
        "POST",
        &path("paths/delete"),
        "policy-admin",
        json!({"before":"9999-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["deleted"].as_array().unwrap().len(), 2);
    for _ in 0..2 {
        let (status, result) = send(
            &app,
            "DELETE",
            &path("pins/cycle"),
            "policy-admin",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result, json!({"deleted":true,"name":"cycle"}));
    }
    sqlx::raw_sql("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,expires_at) SELECT 'policy-stage',id,repeat('d',32),'/nix/store/staged','sha256:test',20,'hash',12,'zstd',now()+interval '1 hour' FROM caches WHERE org_id='policy_a';
        INSERT INTO upload_parts(session_id,part_number,etag,size) VALUES ('policy-stage',1,'part',12);")
        .execute(&pool).await.unwrap();
    let (status, result) = send(&app, "POST", &path("delete"), "policy-admin", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["paths"], 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM upload_parts")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM upload_sessions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

async fn object_exists(store: &InMemory, key: &str) -> bool {
    match store.head(&Path::from(key)).await {
        Ok(_) => true,
        Err(object_store::Error::NotFound { .. }) => false,
        Err(error) => panic!("unexpected object-store failure: {error}"),
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn withdrawal_queues_known_metadata_in_both_slug_paths_but_retains_shared_nars(pool: PgPool) {
    let public = Arc::new(InMemory::new());
    let private = Arc::new(InMemory::new());
    let storage = Storage::from_stores(public.clone(), private.clone());
    let state = fixture_with_storage(&pool, storage.clone()).await;
    sqlx::query("UPDATE orgs SET moving_from='policy-old' WHERE id='policy_a'")
        .execute(&pool)
        .await
        .unwrap();
    let app = router(state.clone());
    // Recreate the cache between the two cases: same names, independent buckets.
    for is_private in [false, true] {
        if is_private {
            sqlx::raw_sql("INSERT INTO caches(name,org_id,is_public) VALUES ('shared','policy_a',false);
                INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches WHERE org_id='policy_a';")
                .execute(&pool).await.unwrap();
        }
        let first = if is_private { 'd' } else { 'a' };
        let pinned = if is_private { 'f' } else { 'b' };
        publish(&pool, first, "first", json!([])).await;
        let root = publish(&pool, pinned, "pinned", json!([])).await;
        let hashes = [
            first.to_string().repeat(32),
            pinned.to_string().repeat(32),
            "0".repeat(32),
        ];
        for slug in ["policy-a", "policy-old"] {
            for hash in &hashes {
                let key = format!(
                    "{}{slug}/shared/{hash}.narinfo",
                    if is_private { "narinfo/" } else { "" }
                );
                storage.put(is_private, &key, b"metadata").await.unwrap();
            }
            storage
                .put(
                    false,
                    &format!("{slug}/shared/nix-cache-info"),
                    b"cache info",
                )
                .await
                .unwrap();
        }
        let canonical_public = format!("nar/policy-{}/zstd.nar", hashes[1]);
        let canonical_private = format!("nars/sha256/policy-{}/zstd.nar", hashes[1]);
        sqlx::query("UPDATE blob_objects SET r2_key=$2 WHERE file_hash=$1")
            .bind(format!("policy-{}", hashes[1]))
            .bind(if is_private {
                &canonical_private
            } else {
                &canonical_public
            })
            .execute(&pool)
            .await
            .unwrap();
        // The same canonical object remains referenced by another org/cache.
        sqlx::query("INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id) SELECT other.id,p.store_path_hash,p.store_path,p.nar_hash,p.nar_size,p.blob_object_id FROM published_paths p JOIN caches source ON source.id=p.cache_id CROSS JOIN caches other WHERE source.org_id='policy_a' AND p.store_path_hash=$1 AND other.org_id='policy_b'")
            .bind(&hashes[1]).execute(&pool).await.unwrap();
        for (bucket, key) in [
            (false, canonical_public.as_str()),
            (true, canonical_private.as_str()),
        ] {
            storage.put(bucket, key, b"shared NAR").await.unwrap();
        }
        storage
            .put(is_private, "policy-b/shared/other.narinfo", b"another org")
            .await
            .unwrap();
        let (status, result) = send(
            &app,
            "POST",
            &path("pins"),
            "policy-admin",
            json!({"name":"release","storePath":root,"keep":"forever"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{result}");
        let (status, result) = send(
            &app,
            "POST",
            &path("paths/delete"),
            "policy-admin",
            json!({"storePathHashes":hashes}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(
            result,
            json!({"deleted":[hashes[0]],"notFound":[hashes[1],hashes[2]],"more":false})
        );
        let store = if is_private { &private } else { &public };
        for slug in ["policy-a", "policy-old"] {
            for (hash, queued) in [(&hashes[0], true), (&hashes[1], false), (&hashes[2], true)] {
                let key = format!(
                    "{}{slug}/shared/{hash}.narinfo",
                    if is_private { "narinfo/" } else { "" }
                );
                assert!(object_exists(store, &key).await, "{key}");
                let found: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM object_cleanup WHERE is_private=$1 AND key=$2)",
                )
                .bind(is_private)
                .bind(&key)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(found, queued, "{key}");
            }
        }
        // Exercise timestamp selection as well, with the retained path protected.
        let timed = if is_private { '3' } else { '2' };
        publish(&pool, timed, "timestamp", json!([])).await;
        for slug in ["policy-a", "policy-old"] {
            storage
                .put(
                    is_private,
                    &format!(
                        "{}{slug}/shared/{}.narinfo",
                        if is_private { "narinfo/" } else { "" },
                        timed.to_string().repeat(32)
                    ),
                    b"timestamp metadata",
                )
                .await
                .unwrap();
        }
        let (status, result) = send(
            &app,
            "POST",
            &path("paths/delete"),
            "policy-admin",
            json!({"before":"9999-01-01T00:00:00Z"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["deleted"], json!([timed.to_string().repeat(32)]));
        for slug in ["policy-a", "policy-old"] {
            assert!(
                object_exists(
                    store,
                    &format!(
                        "{}{slug}/shared/{}.narinfo",
                        if is_private { "narinfo/" } else { "" },
                        timed.to_string().repeat(32)
                    )
                )
                .await
            );
        }
        // Orphan objects are not authoritative and need not be listed/deleted.
        for n in 0..501 {
            let hash = format!("{n:032}");
            let key = format!(
                "{}policy-a/shared/{hash}.narinfo",
                if is_private { "narinfo/" } else { "" }
            );
            storage
                .put(is_private, &key, b"orphan metadata")
                .await
                .unwrap();
        }
        for kind in ["go", "sccache"] {
            let key = format!("{kind}/evicted-{is_private}");
            sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {kind}_entries(id,cache_id,generation,action,r2_key,size,uploaded_at,expires_at{}) SELECT $1,id,{kind}_generation,'action',$1,9,now(),now()+interval '1 day'{} FROM caches WHERE org_id='policy_a'",if kind=="go"{",output"}else{""},if kind=="go"{",'output'"}else{""})))
                .bind(&key).execute(&pool).await.unwrap();
            storage.put(true, &key, b"compiler data").await.unwrap();
            storage
                .put(false, &key, b"wrong bucket sentinel")
                .await
                .unwrap();
        }
        let (status, result) = send(&app, "POST", &path("evict"), "policy-admin", json!({})).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["removed"]["nix"], 1);
        for kind in ["go", "sccache"] {
            let key = format!("{kind}/evicted-{is_private}");
            assert_eq!(result["removed"][kind], 1);
            assert!(object_exists(&private, &key).await);
            assert!(sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM object_cleanup WHERE is_private AND key=$1 AND upload_id IS NULL)")
                .bind(&key).fetch_one(&pool).await.unwrap());
            assert!(object_exists(&public, &key).await);
        }
        for slug in ["policy-a", "policy-old"] {
            let prefix = format!("{}{slug}/shared", if is_private { "narinfo/" } else { "" });
            let keys = storage.list(is_private, &prefix, None, 1000).await.unwrap();
            assert!(keys.iter().any(|k| k.ends_with(".narinfo")), "{keys:?}");
            assert!(object_exists(&public, &format!("{slug}/shared/nix-cache-info")).await);
        }
        // Metadata published since eviction must be withdrawn by cache deletion.
        let final_path = if is_private { '5' } else { '4' };
        publish(&pool, final_path, "final", json!([])).await;
        for slug in ["policy-a", "policy-old"] {
            storage
                .put(
                    is_private,
                    &format!(
                        "{}{slug}/shared/{}.narinfo",
                        if is_private { "narinfo/" } else { "" },
                        final_path.to_string().repeat(32)
                    ),
                    b"published metadata",
                )
                .await
                .unwrap();
            storage
                .put(
                    is_private,
                    &format!(
                        "{}{slug}/shared/{}.narinfo",
                        if is_private { "narinfo/" } else { "" },
                        "1".repeat(32)
                    ),
                    b"orphan",
                )
                .await
                .unwrap();
        }
        let (status, result) = send(&app, "POST", &path("delete"), "policy-admin", json!({})).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["paths"], 1);
        for slug in ["policy-a", "policy-old"] {
            let key = format!("{slug}/shared/nix-cache-info");
            assert!(object_exists(&public, &key).await);
            assert!(
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS (SELECT 1 FROM object_cleanup WHERE NOT is_private AND key=$1)"
                )
                .bind(&key)
                .fetch_one(&pool)
                .await
                .unwrap()
            );
            let prefix = format!("{}{slug}/shared", if is_private { "narinfo/" } else { "" });
            assert!(
                !storage
                    .list(is_private, &prefix, None, 1000)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(object_exists(&public, &canonical_public).await);
        assert!(object_exists(&private, &canonical_private).await);
        assert!(object_exists(store, "policy-b/shared/other.narinfo").await);
    }
}

#[derive(Debug, Default)]
struct DeleteControl {
    fail: AtomicBool,
}

#[derive(Debug)]
struct ControlledStore {
    inner: Arc<dyn ObjectStore>,
    key: String,
    control: Arc<DeleteControl>,
    repair: Option<(PgPool, &'static str)>,
}

impl std::fmt::Display for ControlledStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlledStore")
    }
}

#[async_trait::async_trait]
impl ObjectStore for ControlledStore {
    async fn put_opts(
        &self,
        path: &Path,
        bytes: object_store::PutPayload,
        options: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.inner.put_opts(path, bytes, options).await
    }
    async fn put_multipart_opts(
        &self,
        path: &Path,
        options: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.inner.put_multipart_opts(path, options).await
    }
    async fn get_opts(
        &self,
        path: &Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        if path.as_ref() == self.key
            && !options.head
            && let Some((pool, action)) = &self.repair
        {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                // This pool has one connection. A held SQL transaction would
                // prevent the provider call from observing its durable lease.
                let durable: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nar_installations WHERE source_key=$1 AND session_id IS NULL AND cache_id IS NOT NULL AND phase='preparing' AND expires_at>NOW())")
                    .bind(&self.key).fetch_one(pool).await.unwrap();
                assert!(durable);
                sqlx::query(*action).execute(pool).await.unwrap();
            }).await.expect("provider I/O must not hold a SQL connection");
        }
        self.inner.get_opts(path, options).await
    }
    fn delete_stream(
        &self,
        paths: futures_util::stream::BoxStream<'static, object_store::Result<Path>>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<Path>> {
        use futures_util::StreamExt;
        let inner = self.inner.clone();
        let key = self.key.clone();
        let control = self.control.clone();
        paths
            .then(move |path| {
                let inner = inner.clone();
                let key = key.clone();
                let control = control.clone();
                async move {
                    let path = path?;
                    if path.as_ref() == key && control.fail.load(Ordering::SeqCst) {
                        return Err(object_store::Error::Generic {
                            store: "test",
                            source: Box::new(std::io::Error::other("injected deletion failure")),
                        });
                    }
                    inner.delete(&path).await?;
                    Ok(path)
                }
            })
            .boxed()
    }
    fn list(
        &self,
        prefix: Option<&Path>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
    {
        self.inner.list(prefix)
    }
    async fn list_with_delimiter(
        &self,
        prefix: Option<&Path>,
    ) -> object_store::Result<object_store::ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(
        &self,
        from: &Path,
        to: &Path,
        options: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(from, to, options).await
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn metadata_store_failures_do_not_block_sql_withdrawal(pool: PgPool) {
    let public = Arc::new(InMemory::new());
    let delayed_key = format!("policy-a/shared/{}.narinfo", "a".repeat(32));
    let failed_key = format!("policy-a/shared/{}.narinfo", "b".repeat(32));
    let delayed = Arc::new(DeleteControl::default());
    let failed = Arc::new(DeleteControl::default());
    failed.fail.store(true, Ordering::SeqCst);
    let storage = Storage::from_stores(
        Arc::new(ControlledStore {
            inner: Arc::new(ControlledStore {
                inner: public.clone(),
                key: failed_key.clone(),
                control: failed.clone(),
                repair: None,
            }),
            key: delayed_key.clone(),
            control: delayed.clone(),
            repair: None,
        }),
        Arc::new(InMemory::new()),
    );
    let app = router(fixture_with_storage(&pool, storage.clone()).await);
    publish(&pool, 'a', "delayed", json!([])).await;
    publish(&pool, 'b', "failed", json!([])).await;
    for operation in ["paths/delete", "evict", "delete"] {
        storage
            .put(false, &delayed_key, b"old metadata")
            .await
            .unwrap();
        storage
            .put(false, &failed_key, b"retry metadata")
            .await
            .unwrap();
        let input = if operation == "paths/delete" {
            json!({"storePathHashes":["a".repeat(32), "b".repeat(32)]})
        } else {
            json!({})
        };
        let (status, result) = send(&app, "POST", &path(operation), "policy-admin", input).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        let stored = public
            .get(&Path::from(delayed_key.clone()))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(stored.as_ref(), b"old metadata");
        assert!(object_exists(&public, &failed_key).await);
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM object_cleanup WHERE NOT is_private AND key=$1)"
            )
            .bind(&failed_key)
            .fetch_one(&pool)
            .await
            .unwrap()
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn backfill_copy_has_durable_ownership_and_rejects_stale_adoption(pool: PgPool) {
    fixture(&pool).await;
    publish(&pool, 'a', "repair", json!([])).await;
    let source = "nars/objects/original/content/zstd.nar";
    sqlx::query("UPDATE blob_objects SET r2_key=$1")
        .bind(source)
        .execute(&pool)
        .await
        .unwrap();
    let one = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let public = Arc::new(InMemory::new());
    let private = Arc::new(InMemory::new());
    for (action, expected_written, expected_skipped) in [
        (
            "UPDATE nar_installations SET phase='revoked' WHERE cache_id=(SELECT id FROM caches WHERE org_id='policy_a')",
            0,
            1,
        ),
        (
            "UPDATE blob_objects SET public_key='nar/objects/winner/content/none.nar'",
            0,
            0,
        ),
        ("SELECT 1", 1, 0),
    ] {
        sqlx::query("UPDATE blob_objects SET public_key=NULL")
            .execute(&pool)
            .await
            .unwrap();
        let storage = Storage::from_stores(
            public.clone(),
            Arc::new(ControlledStore {
                inner: private.clone(),
                key: source.into(),
                control: Arc::default(),
                repair: Some((one.clone(), action)),
            }),
        );
        storage.put(true, source, b"twelve bytes").await.unwrap();
        // New immutable records cannot silently reuse this legacy fallback.
        storage
            .put(
                false,
                &format!("nar/policy-{}/zstd.nar", "a".repeat(32)),
                b"twelve bytes",
            )
            .await
            .unwrap();
        let app = router(
            AppState::new(
                one.clone(),
                config(),
                storage.clone(),
                reqwest::Client::new(),
            )
            .unwrap(),
        );
        let (status, result) = send(
            &app,
            "POST",
            "/_api/v1/admin/narinfo/backfill",
            "policy-admin",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["written"], expected_written);
        assert_eq!(
            result["skipped"].as_array().unwrap().len(),
            expected_skipped
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        let pointer: Option<String> = sqlx::query_scalar("SELECT public_key FROM blob_objects")
            .fetch_one(&pool)
            .await
            .unwrap();
        if let Some(pointer) = pointer {
            assert!(
                !sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM object_cleanup WHERE key=$1)"
                )
                .bind(&pointer)
                .fetch_one(&pool)
                .await
                .unwrap()
            );
        }
        let keys = storage.list(false, "nar/objects", None, 100).await.unwrap();
        for key in keys {
            let adopted: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM blob_objects WHERE public_key=$1)")
                    .bind(&key)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            let queued: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM object_cleanup WHERE NOT is_private AND key=$1)",
            )
            .bind(&key)
            .fetch_one(&pool)
            .await
            .unwrap();
            // Earlier iterations' objects stay queued, never synchronously deleted.
            assert!(adopted || queued, "unowned repair destination: {key}");
        }
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT r2_key FROM blob_objects")
                .fetch_one(&pool)
                .await
                .unwrap(),
            source
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn absent_named_deletion_and_empty_eviction_cancel_only_affected_sessions(pool: PgPool) {
    let state = fixture(&pool).await;
    let hash = "a".repeat(32);
    let app = router(state);
    sqlx::raw_sql("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,status,expires_at)
        SELECT c.org_id || '-' || s.name,c.id,repeat(s.hash,32),'/nix/store/staged','sha256:test',20,'hash',12,'zstd',s.status,now()+interval '1 hour'
        FROM caches c CROSS JOIN (VALUES ('target','a','pending'),('unrelated','b','pending'),('done','a','completed')) s(name,hash,status);")
        .execute(&pool).await.unwrap();
    for operation in ["paths/delete", "paths/delete", "evict", "evict"] {
        let input = if operation == "paths/delete" {
            json!({"storePathHashes":[hash]})
        } else {
            json!({})
        };
        let (status, result) = send(&app, "POST", &path(operation), "policy-admin", input).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        let sessions: Vec<(String, String)> =
            sqlx::query_as("SELECT id,status FROM upload_sessions ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            sessions,
            vec![
                ("policy_a-done".into(), "completed".into()),
                ("policy_a-target".into(), "aborted".into()),
                (
                    "policy_a-unrelated".into(),
                    if operation == "evict" {
                        "aborted"
                    } else {
                        "pending"
                    }
                    .into()
                ),
                ("policy_b-done".into(), "completed".into()),
                ("policy_b-target".into(), "pending".into()),
                ("policy_b-unrelated".into(), "pending".into()),
            ]
        );
        if operation == "evict" {
            let expiry: Vec<(String, bool)> = sqlx::query_as(
                "SELECT id,expires_at<=NOW() FROM upload_sessions WHERE status<>'completed' ORDER BY id",
            )
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(
                expiry,
                vec![
                    ("policy_a-target".into(), true),
                    ("policy_a-unrelated".into(), true),
                    ("policy_b-target".into(), false),
                    ("policy_b-unrelated".into(), false),
                ]
            );
        }
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn policy_contention_fails_fast_without_withdrawing_rows(pool: PgPool) {
    let app = router(fixture(&pool).await);
    publish(&pool, 'a', "root", json!([])).await;
    for advisory in [false, true] {
        let mut holder = pool.begin().await.unwrap();
        let query = if advisory {
            "SELECT pg_advisory_xact_lock(hashtextextended('org:policy_a',0))"
        } else {
            "SELECT id FROM caches WHERE org_id='policy_a' FOR UPDATE"
        };
        sqlx::query(query).execute(&mut *holder).await.unwrap();
        let (status, result) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            send(
                &app,
                "POST",
                &path("paths/delete"),
                "policy-admin",
                json!({"storePathHashes":["a".repeat(32)]}),
            ),
        )
        .await
        .expect("policy writes must not queue behind locks");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{result}");
        holder.rollback().await.unwrap();
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM object_cleanup")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn cleanup_queue_failure_rolls_back_metadata_and_session_cancellation(pool: PgPool) {
    let app = router(fixture(&pool).await);
    publish(&pool, 'a', "root", json!([])).await;
    sqlx::raw_sql("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,expires_at)
        SELECT 'rollback-session',id,repeat('a',32),'/nix/store/staged','sha256:test',20,'hash',12,'zstd',now()+interval '1 hour' FROM caches WHERE org_id='policy_a';")
        .execute(&pool).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected queue failure'; END $$;
        CREATE TRIGGER reject_cleanup BEFORE INSERT ON object_cleanup FOR EACH ROW EXECUTE FUNCTION reject_cleanup();")
        .execute(&pool).await.unwrap();
    let (status, _) = send(
        &app,
        "POST",
        &path("paths/delete"),
        "policy-admin",
        json!({"storePathHashes":["a".repeat(32)]}),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM object_cleanup")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM upload_sessions WHERE id='rollback-session'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        "pending"
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn management_never_materializes_mutable_metadata(pool: PgPool) {
    let storage = common::storage();
    let app = router(fixture_with_storage(&pool, storage.clone()).await);
    publish(&pool, 'a', "root", json!([])).await;
    let (status, result) = send(
        &app,
        "POST",
        "/_api/v1/admin/narinfo/backfill",
        "policy-admin",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let (status, result) = send(
        &app,
        "POST",
        "/_api/v1/orgs/policy_a/caches",
        "policy-admin",
        json!({"name":"new-cache","protocols":["nix"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let (status, result) = send(
        &app,
        "PUT",
        "/_api/v1/orgs/policy_a",
        "policy-admin",
        json!({"slug":"new-policy"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let (status, result) = send(
        &app,
        "POST",
        "/_api/v1/orgs/policy_a/move",
        "policy-admin",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["done"], true);
    for private in [false, true] {
        for prefix in ["nar", "nars", "narinfo", "policy-a", "new-policy"] {
            assert!(
                storage
                    .list(private, prefix, None, 1000)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
    assert!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM object_cleanup")
            .fetch_one(&pool)
            .await
            .unwrap()
            > 0
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn cache_deletion_adopts_legacy_canonical_objects_and_preserves_uncertain_uploads(
    pool: PgPool,
) {
    let storage = common::storage();
    let app = router(fixture_with_storage(&pool, storage.clone()).await);
    for private in [false, true] {
        let cache: i32 = sqlx::query_scalar(
            "INSERT INTO caches(name,org_id,is_public) VALUES($1,'policy_a',$2) RETURNING id",
        )
        .bind(if private {
            "legacy-private"
        } else {
            "legacy-public"
        })
        .bind(!private)
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut expected_blobs = Vec::new();
        let mut expected_tombstones = Vec::new();
        for (status, size) in [("completed", 4_i64), ("finalizing", 7)] {
            let id = format!("legacy-{private}-{status}");
            let key = format!(
                "{}/{id}/zstd.nar",
                if private { "nars/sha256" } else { "nar" },
            );
            let upload = format!("provider-{id}");
            sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at)
                VALUES($1,$2,$1,'/nix/store/'||$1,'sha256:test',$3,$1,$3,'zstd',$4,$5,$6,now()+interval '1 day')")
                .bind(&id).bind(cache).bind(size).bind(status).bind(&key).bind(&upload)
                .execute(&pool).await.unwrap();
            storage
                .put(private, &key, &vec![1; size as usize])
                .await
                .unwrap();
            expected_blobs.push((id.clone(), key.clone(), size));
            if status != "completed" {
                expected_tombstones.push(json!({
                    "key":key,"operation_id":id,"source_key":key,"upload_id":upload,
                    "file_hash":id,"is_private":private,"file_size":size,"phase":"legacy-unresolved",
                }));
            }
        }
        let url = format!(
            "/_api/v1/orgs/policy_a/caches/legacy-{}/delete",
            if private { "private" } else { "public" }
        );
        let (status, result) = send(&app, "POST", &url, "policy-admin", json!({})).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM upload_sessions WHERE cache_id=$1")
                .bind(cache)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0,
        );
        let prefix = format!("legacy-{private}-%");
        let blobs: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT file_hash,r2_key,file_size FROM blob_objects WHERE file_hash LIKE $1 ORDER BY file_hash",
        ).bind(&prefix).fetch_all(&pool).await.unwrap();
        assert_eq!(blobs, expected_blobs);
        let tombstones: Vec<String> = sqlx::query_scalar(
            "SELECT row_to_json(i)::text FROM (SELECT key,operation_id,source_key,upload_id,file_hash,is_private,file_size,phase FROM nar_installations WHERE file_hash LIKE $1 ORDER BY file_hash) i",
        ).bind(prefix).fetch_all(&pool).await.unwrap();
        let tombstones: Vec<Value> = tombstones
            .iter()
            .map(|row| serde_json::from_str(row).unwrap())
            .collect();
        assert_eq!(tombstones, expected_tombstones);
        for (_, key, _) in blobs {
            assert!(storage.head(private, &key).await.is_ok());
        }
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn cache_deletion_queues_only_unpinned_unfinished_provider_mpus(pool: PgPool) {
    use axum::body::Bytes;
    use object_store::{aws::AmazonS3Builder, multipart::MultipartStore};

    let r2 = Config::from_env();
    let endpoint = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
    assert_eq!(r2.r2_endpoint, endpoint);
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    let provider = AmazonS3Builder::new()
        .with_region("auto")
        .with_endpoint(&endpoint)
        .with_bucket_name(&r2.r2_bucket_name)
        .with_access_key_id(&r2.r2_access_key_id)
        .with_secret_access_key(&r2.r2_secret_access_key)
        .with_allow_http(true)
        .with_virtual_hosted_style_request(false)
        .build()
        .unwrap();
    let storage = Storage::new(&r2).unwrap();
    let app = router(fixture_with_storage(&pool, storage.clone()).await);
    // A store without abort support proves SQL withdrawal never calls it.
    let unavailable = router(
        AppState::new(
            pool.clone(),
            config(),
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    for case in [
        "unfinished",
        "already-aborted",
        "completed",
        "marker",
        "pinned",
        "pinned-part",
        "pinned-completed",
    ] {
        let cache: i32 = sqlx::query_scalar(
            "INSERT INTO caches(name,org_id) VALUES($1,'policy_a') RETURNING id",
        )
        .bind(case)
        .fetch_one(&pool)
        .await
        .unwrap();
        let original_id = uuid::Uuid::now_v7().to_string();
        let key = format!("staging/{original_id}/legacy");
        let object = Path::from(key.clone());
        let upload = provider.create_multipart(&object).await.unwrap();
        let part = provider
            .put_part(&object, &upload, 0, Bytes::from_static(b"data").into())
            .await
            .unwrap();
        // Give even the receipt marker a live provider MPU. If deletion
        // accidentally treats the marker as a provider ID, completion fails.
        let id = if case == "marker" {
            upload.clone()
        } else {
            original_id.clone()
        };
        let status = if case.ends_with("completed") {
            "completed"
        } else {
            "streaming"
        };
        sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at)
            VALUES($1,$2,$1,'/nix/store/'||$1,'sha256:test',4,$1,4,'zstd',$3,$4,$5,now()+interval '1 day')")
            .bind(&id).bind(cache).bind(status).bind(&key).bind(&upload)
            .execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO upload_parts(session_id,part_number,etag,size) VALUES($1,1,'receipt',4)",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
        let source = if case == "pinned-part" {
            format!("staging/{id}/parts/1")
        } else {
            key.clone()
        };
        if case.starts_with("pinned") {
            storage.put(true, &source, b"source").await.unwrap();
            sqlx::query("INSERT INTO nar_installations(key,operation_id,source_key,file_hash,compression,is_private,file_size)
                VALUES($1,$2,$3,$2,'zstd',true,6)")
                .bind(format!("nars/sha256/{id}/zstd.nar")).bind(&id).bind(&source)
                .execute(&pool).await.unwrap();
        }
        if case == "already-aborted" {
            provider.abort_multipart(&object, &upload).await.unwrap();
        }
        if case.ends_with("completed") {
            provider
                .complete_multipart(&object, &upload, vec![part.clone()])
                .await
                .unwrap();
        }
        let url = format!("/_api/v1/orgs/policy_a/caches/{case}/delete");
        if matches!(case, "pinned" | "pinned-part") {
            let (status, result) = send(&app, "POST", &url, "policy-admin", json!({})).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{result}");
            let retained: (String, String, String, i64) = sqlx::query_as(
                "SELECT u.status,u.r2_upload_key,u.r2_upload_id,(SELECT count(*) FROM upload_parts WHERE session_id=u.id)
                FROM upload_sessions u JOIN caches c ON c.id=u.cache_id WHERE u.id=$1",
            ).bind(&id).fetch_one(&pool).await.unwrap();
            assert_eq!(
                retained,
                ("streaming".into(), key.clone(), upload.clone(), 1)
            );
            assert!(storage.head(true, &source).await.is_ok());
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM nar_installations WHERE operation_id=$1"
                )
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap(),
                1
            );
            // The original provider ID remains usable while deletion waits.
            provider
                .put_part(&object, &upload, 0, Bytes::from_static(b"data").into())
                .await
                .unwrap();
            // Reconcile the installation lease; retry transfers this MPU's
            // original provider ID to the cleanup queue.
            sqlx::query("DELETE FROM nar_installations WHERE operation_id=$1")
                .bind(&id)
                .execute(&pool)
                .await
                .unwrap();
        }
        let (status, result) = send(&unavailable, "POST", &url, "policy-admin", json!({})).await;
        assert_eq!(status, StatusCode::OK, "{case}: {result}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM caches WHERE id=$1")
                .bind(cache)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM upload_sessions WHERE id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM upload_parts WHERE session_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        let queued: Option<String> =
            sqlx::query_scalar("SELECT upload_id FROM object_cleanup WHERE is_private AND key=$1")
                .bind(&key)
                .fetch_optional(&pool)
                .await
                .unwrap()
                .flatten();
        let should_abort = matches!(
            case,
            "unfinished" | "already-aborted" | "pinned" | "pinned-part"
        );
        assert_eq!(queued.as_deref(), should_abort.then_some(upload.as_str()));
        if should_abort {
            if case != "already-aborted" {
                provider
                    .put_part(&object, &upload, 0, Bytes::from_static(b"data").into())
                    .await
                    .unwrap();
            }
            // Model the asynchronous queue consumer, using the retained ID.
            let _ = provider
                .abort_multipart(&object, queued.as_ref().unwrap())
                .await;
        }
        if case.ends_with("completed") {
            assert_eq!(storage.head(true, &key).await.unwrap().size, 4);
        } else {
            let completed = provider
                .complete_multipart(&object, &upload, vec![part])
                .await;
            if should_abort {
                assert!(
                    completed.is_err(),
                    "queued provider abort must make the MPU non-completable"
                );
            } else {
                completed.unwrap();
            }
        }
        if case.starts_with("pinned") {
            assert!(storage.head(true, &source).await.is_ok());
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM nar_installations WHERE operation_id=$1"
                )
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap(),
                i64::from(case == "pinned-completed")
            );
        }
    }
}
