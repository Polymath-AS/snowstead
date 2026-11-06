mod common;

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use object_store::{limit::LimitStore, memory::InMemory};
use serde_json::json;
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

const CDN: &str = "https://cdn.example.test";
const NAR: &str = "representative streamed NAR bytes";

async fn fixture(pool: PgPool, origin: &str) -> AppState {
    fixture_with_storage(pool, origin, common::storage()).await
}

fn config(origin: &str) -> Config {
    Config {
        jwt_secret: "cdn-test-secret".into(),
        public_cache_origin: origin.into(),
        ..Default::default()
    }
}

async fn fixture_with_storage(pool: PgPool, origin: &str, storage: Storage) -> AppState {
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_alpha','alpha'),('org_beta','beta');
        INSERT INTO caches (name,org_id,is_public) VALUES
        ('main','org_alpha',true),('main','org_beta',true),('secret','org_alpha',false),
        ('go-only','org_alpha',true),('local','default',true);
        INSERT INTO cache_protocols (cache_id,protocol)
        SELECT id,CASE WHEN name='go-only' THEN 'go' ELSE 'nix' END FROM caches;
        INSERT INTO blob_objects (file_hash,file_size,compression,r2_key)
        VALUES (repeat('a',64),32,'zstd','nar/public'),(repeat('b',64),32,'zstd','nar/private');
        INSERT INTO published_paths (cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
        SELECT c.id,repeat('0',32),'/nix/store/test','sha256:test',32,b.id
        FROM caches c JOIN blob_objects b ON b.file_hash=CASE WHEN c.name='secret' THEN repeat('b',64) ELSE repeat('a',64) END
        WHERE c.org_id='org_alpha' AND c.name IN ('main','secret');")
        .execute(&pool).await.unwrap();
    AppState::new(pool, config(origin), storage, reqwest::Client::new()).unwrap()
}

fn token(org: &str, cache: &str) -> String {
    let claims = json!({"jti":"cdn-test", "sub":"test", "iss":"snowstead", "aud":"snowstead",
        "iat":1, "org":org, "caches":[cache], "perms":["pull"]});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"cdn-test-secret").unwrap();
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
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
    .expect("read did not complete within its deadline")
    .unwrap()
}

fn redirect(response: &Response, location: &str) {
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers()[header::LOCATION], location);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key("x-snowstead-cdn-read"));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn public_redirects_without_objects_or_published_narinfo(pool: PgPool) {
    // A GET or HEAD would wait forever for a zero-permit store. Successful
    // redirects/handoffs therefore prove storage is not on the delivery path.
    let storage = Storage::from_stores(
        Arc::new(LimitStore::new(InMemory::new(), 0)),
        Arc::new(LimitStore::new(InMemory::new(), 0)),
    );
    let state = fixture_with_storage(pool.clone(), CDN, storage).await;
    let app = router(state.clone());
    let hash = "1".repeat(32); // Deliberately absent from SQL and object storage.
    let blob = "a".repeat(64);
    for method in ["GET", "HEAD"] {
        for (path, key) in [
            (
                "/alpha/main/nix-cache-info".to_owned(),
                "alpha/main/nix-cache-info".to_owned(),
            ),
            (
                "/local/nix-cache-info".to_owned(),
                "local/nix-cache-info".to_owned(),
            ),
            (
                format!("/alpha/main/{hash}.narinfo"),
                format!("alpha/main/{hash}.narinfo"),
            ),
            (
                format!("/private/alpha/main/{hash}.narinfo"),
                format!("alpha/main/{hash}.narinfo"),
            ),
            (
                format!("/alpha/main/nar/{blob}/zstd.nar"),
                format!("nar/{blob}/zstd.nar"),
            ),
            (
                format!("/nar/{blob}/zstd.nar"),
                format!("nar/{blob}/zstd.nar"),
            ),
        ] {
            let response = read(
                &app,
                method,
                &format!("{path}?token=secret&download=1"),
                &[
                    ("authorization", "Bearer do-not-copy"),
                    ("cookie", "session=do-not-copy"),
                    ("if-none-match", "\"cached\""),
                    ("range", "bytes=0-7"),
                ],
            )
            .await;
            redirect(&response, &format!("{CDN}/{key}"));
            assert!(
                to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let response = read(&app, method, &path, &[("x-snowstead-cdn-read", "1")]).await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(response.headers()["x-snowstead-cdn-read"], "1");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }
    redirect(
        &read(
            &app,
            "GET",
            &format!("/alpha/main/{}.narinfo", "0".repeat(32)),
            &[],
        )
        .await,
        &format!("{CDN}/alpha/main/{}.narinfo", "0".repeat(32)),
    );
    state.finish_background().await;
    let accessed: Vec<String> = sqlx::query_scalar("SELECT c.name FROM published_paths p JOIN caches c ON c.id=p.cache_id WHERE p.last_accessed_at IS NOT NULL ORDER BY c.name")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(accessed, ["main"]);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn gateway_handoff_and_security_guards(pool: PgPool) {
    // The admission-only gateway contract is independent of redirect config.
    let state = fixture(pool.clone(), "").await;
    let app = router(state.clone());
    let cdn_state = AppState::new(
        pool.clone(),
        config(CDN),
        common::storage(),
        reqwest::Client::new(),
    )
    .unwrap();
    let cdn_app = router(cdn_state);
    let blob = "a".repeat(64);
    let hash = "1".repeat(32);
    let handoff = [("x-snowstead-cdn-read", "1")];
    for method in ["GET", "HEAD"] {
        for path in [
            "/alpha/main/nix-cache-info".to_owned(),
            format!("/alpha/main/{hash}.narinfo"),
            format!("/alpha/main/nar/{blob}/zstd.nar"),
            format!("/nar/{blob}/zstd.nar"),
        ] {
            let response = read(&app, method, &path, &handoff).await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path}");
            assert_eq!(response.headers()["x-snowstead-cdn-read"], "1");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!response.headers().contains_key(header::LOCATION));
        }
    }
    for path in [
        "/alpha/no-such-cache/nix-cache-info".to_owned(),
        "/alpha/go-only/nix-cache-info".to_owned(),
        "/alpha/main/invalid.narinfo".to_owned(),
        "/alpha/main/%2e%2e.narinfo".to_owned(),
        "/alpha/main/nix-cache-info/extra".to_owned(),
        format!("/beta/main/nar/{blob}/zstd.nar"),
        format!("/alpha/main/nar/{blob}/invalid.nar"),
        format!("/nar/{}/zstd.nar", "b".repeat(64)),
    ] {
        for app in [&app, &cdn_app] {
            for headers in [&handoff[..], &[][..]] {
                let response = read(app, "GET", &path, headers).await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
                assert!(!response.headers().contains_key(header::LOCATION));
                assert!(!response.headers().contains_key("x-snowstead-cdn-read"));
            }
        }
    }
    sqlx::query("DELETE FROM cache_protocols WHERE cache_id=(SELECT id FROM caches WHERE org_id='org_alpha' AND name='main')")
        .execute(&pool).await.unwrap();
    for path in [
        "/alpha/main/nix-cache-info".to_owned(),
        format!("/alpha/main/{hash}.narinfo"),
        format!("/nar/{blob}/zstd.nar"),
    ] {
        assert_eq!(
            read(&app, "HEAD", &path, &handoff).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        read(&app, "POST", "/local/nix-cache-info", &handoff)
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn private_stays_authenticated_and_streamed(pool: PgPool) {
    let storage = common::storage();
    let state = fixture_with_storage(pool.clone(), CDN, storage.clone()).await;
    let hash = "0".repeat(32);
    let blob = "b".repeat(64);
    sqlx::query("UPDATE published_paths SET nar_hash='sha256:' || repeat('0',64)")
        .execute(&pool)
        .await
        .unwrap();
    let narinfo = format!(
        "StorePath: /nix/store/test\nURL: nar/{blob}/zstd.nar\nCompression: zstd\nFileHash: sha256:{blob}\nFileSize: 32\nNarHash: sha256:{}\nNarSize: 32\n",
        "0".repeat(52)
    );
    // Only the canonical bytes and SQL publication exist, as at cutover.
    assert!(
        storage
            .head(true, &format!("narinfo/alpha/secret/{hash}.narinfo"))
            .await
            .is_err()
    );
    storage
        .put(
            true,
            &format!("nars/sha256/{blob}/zstd.nar"),
            NAR.as_bytes(),
        )
        .await
        .unwrap();
    let app = router(state);
    let credential = format!("Bearer {}", token("org_alpha", "secret"));
    let wrong_org = format!("Bearer {}", token("org_beta", "secret"));
    let wrong_cache = format!("Bearer {}", token("org_alpha", "main"));
    for (path, bytes) in [
        (
            "/alpha/secret/nix-cache-info".to_owned(),
            "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n",
        ),
        (format!("/alpha/secret/{hash}.narinfo"), narinfo.as_str()),
        (format!("/private/alpha/secret/nar/{blob}/zstd.nar"), NAR),
    ] {
        for method in ["GET", "HEAD"] {
            assert_eq!(
                read(&app, method, &path, &[("x-snowstead-cdn-read", "1")])
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            for denied in [&wrong_org, &wrong_cache] {
                assert_eq!(
                    read(
                        &app,
                        method,
                        &path,
                        &[("authorization", denied), ("x-snowstead-cdn-read", "1")]
                    )
                    .await
                    .status(),
                    StatusCode::FORBIDDEN
                );
            }
            let response = read(
                &app,
                method,
                &path,
                &[
                    ("authorization", &credential),
                    ("x-snowstead-cdn-read", "1"),
                ],
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-cache"
            );
            assert!(!response.headers().contains_key(header::LOCATION));
            assert!(!response.headers().contains_key("x-snowstead-cdn-read"));
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(
                body.as_ref(),
                if method == "HEAD" {
                    b""
                } else {
                    bytes.as_bytes()
                }
            );
        }
    }
}

async fn signing_post(app: &Router, path: &str, body: serde_json::Value) -> serde_json::Value {
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
    serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn private_sql_representation_validators_and_key_activation(pool: PgPool) {
    let storage = common::storage();
    let initial = fixture_with_storage(pool.clone(), CDN, storage.clone()).await;
    let mut cfg = config(CDN);
    cfg.admin_secret = "operator-secret".into();
    cfg.signing_master_key = STANDARD.encode([42; 32]);
    cfg.signing_key_name = "fixture".into();
    let state = AppState::new(pool.clone(), cfg, storage.clone(), reqwest::Client::new()).unwrap();
    let app = router(state.clone());
    drop(initial);
    sqlx::query("UPDATE published_paths SET nar_hash='sha256:' || repeat('0',64),
        references_json='[\"11111111111111111111111111111111-z\",\"00000000000000000000000000000000-a\"]',
        deriver='00000000000000000000000000000000-test.drv',system='x86_64-linux',signatures_json='[\"upstream:kept\"]'")
        .execute(&pool).await.unwrap();
    let hash = "0".repeat(32);
    let path = format!("/alpha/secret/{hash}.narinfo");
    let credential = format!("Bearer {}", token("org_alpha", "secret"));
    let expected = format!(
        "StorePath: /nix/store/test\nURL: nar/{}/zstd.nar\nCompression: zstd\nFileHash: sha256:{}\nFileSize: 32\nNarHash: sha256:{}\nNarSize: 32\nReferences: 11111111111111111111111111111111-z 00000000000000000000000000000000-a\nDeriver: 00000000000000000000000000000000-test.drv\nSystem: x86_64-linux\nSig: upstream:kept\n",
        "b".repeat(64),
        "b".repeat(64),
        "0".repeat(52)
    );
    let mut etag = format!("\"{}\"", hex::encode(Sha256::digest(expected.as_bytes())));
    for method in ["HEAD", "GET"] {
        let response = read(&app, method, &path, &[("authorization", &credential)]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::ETAG], etag);
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            expected.len().to_string()
        );
        assert!(!response.headers().contains_key(header::LAST_MODIFIED));
        assert_eq!(
            to_bytes(response.into_body(), 8192).await.unwrap().as_ref(),
            if method == "HEAD" {
                b""
            } else {
                expected.as_bytes()
            }
        );
    }
    // Old objects (including an orphan without SQL membership) never win.
    storage
        .put(
            true,
            &format!("narinfo/alpha/secret/{hash}.narinfo"),
            b"stale private object",
        )
        .await
        .unwrap();
    let orphan = format!("/alpha/secret/{}.narinfo", "1".repeat(32));
    storage
        .put(true, &format!("narinfo{orphan}"), b"orphan")
        .await
        .unwrap();
    for method in ["GET", "HEAD"] {
        for (conditions, status) in [
            (
                vec![("if-none-match", format!("\"other\", W/{etag}"))],
                StatusCode::NOT_MODIFIED,
            ),
            (
                vec![("if-none-match", "*".into())],
                StatusCode::NOT_MODIFIED,
            ),
            (
                vec![("if-match", format!("W/{etag}"))],
                StatusCode::PRECONDITION_FAILED,
            ),
            (
                vec![
                    ("if-match", "\"other\"".into()),
                    ("if-none-match", etag.clone()),
                ],
                StatusCode::PRECONDITION_FAILED,
            ),
            (vec![("if-match", "*".into())], StatusCode::OK),
            (
                vec![
                    ("if-match", etag.clone()),
                    (
                        "if-unmodified-since",
                        "Sat, 01 Jan 2000 00:00:00 GMT".into(),
                    ),
                ],
                StatusCode::OK,
            ),
            (
                vec![("if-modified-since", "Sat, 01 Jan 2100 00:00:00 GMT".into())],
                StatusCode::OK,
            ),
            (
                vec![(
                    "if-unmodified-since",
                    "Sat, 01 Jan 2000 00:00:00 GMT".into(),
                )],
                StatusCode::OK,
            ),
            (
                vec![
                    ("if-none-match", "\"other\"".into()),
                    ("if-modified-since", "Sat, 01 Jan 2100 00:00:00 GMT".into()),
                ],
                StatusCode::OK,
            ),
        ] {
            let mut headers = vec![("authorization", credential.as_str())];
            headers.extend(conditions.iter().map(|(k, v)| (*k, v.as_str())));
            let response = read(&app, method, &path, &headers).await;
            assert_eq!(response.status(), status, "{method} {conditions:?}");
            assert_eq!(response.headers()[header::ETAG], etag);
            assert!(!response.headers().contains_key(header::LAST_MODIFIED));
            if status == StatusCode::NOT_MODIFIED {
                assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
            } else if status == StatusCode::PRECONDITION_FAILED {
                // The dispatcher replaces HEAD error bodies with Body::empty;
                // Axum may correctly describe that empty 412 response as zero.
                if let Some(length) = response.headers().get(header::CONTENT_LENGTH) {
                    assert_eq!(length, "0");
                }
            }
            let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
            assert_eq!(
                bytes.as_ref(),
                if method == "GET" && status == StatusCode::OK {
                    expected.as_bytes()
                } else {
                    b""
                }
            );
        }
        assert_eq!(
            read(
                &app,
                method,
                &orphan,
                &[("authorization", &credential), ("if-match", "*")]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            read(&app, method, &path, &[("if-none-match", &etag)])
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let published_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT created_at FROM published_paths WHERE cache_id=(SELECT id FROM caches WHERE name='secret')").fetch_one(&pool).await.unwrap();
    let keys = "/_api/v1/orgs/org_alpha/caches/secret/signing-keys";
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
        for method in ["HEAD", "GET"] {
            let response = read(
                &app,
                method,
                &path,
                &[("authorization", &credential), ("if-none-match", &etag)],
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let next = response.headers()[header::ETAG]
                .to_str()
                .unwrap()
                .to_owned();
            assert_ne!(next, etag);
            assert!(!response.headers().contains_key(header::LAST_MODIFIED));
            let size = response.headers()[header::CONTENT_LENGTH]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
            if method == "GET" {
                assert_eq!(bytes.len(), size);
                assert_eq!(next, format!("\"{}\"", hex::encode(Sha256::digest(&bytes))));
                let text = std::str::from_utf8(&bytes).unwrap();
                assert!(text.starts_with(&expected));
                assert!(text.contains(&format!(
                    "Sig: {}:",
                    trusted.last().unwrap().split_once(':').unwrap().0
                )));
                etag = next;
            } else {
                assert!(bytes.is_empty());
            }
        }
    }
    let unchanged: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT created_at FROM published_paths WHERE cache_id=(SELECT id FROM caches WHERE name='secret')").fetch_one(&pool).await.unwrap();
    assert_eq!(published_at, unchanged);
    let (name, public, sealed): (String, String, String) = sqlx::query_as(
        "SELECT signing_key_name,signing_public_key,signing_key_sealed FROM caches WHERE name='secret'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // Even matching validators cannot serve an old response or bypass a bad
    // active key. Each request must observe the current signing columns.
    for (name, public, sealed) in [
        (None, Some(public.as_str()), Some(sealed.as_str())),
        (Some(name.as_str()), None, Some(sealed.as_str())),
        (Some(name.as_str()), Some(public.as_str()), None),
        (Some(name.as_str()), Some(public.as_str()), Some("corrupt")),
        (Some(name.as_str()), Some("corrupt"), Some(sealed.as_str())),
    ] {
        sqlx::query("UPDATE caches SET signing_key_name=$1,signing_public_key=$2,signing_key_sealed=$3 WHERE name='secret'")
            .bind(name).bind(public).bind(sealed).execute(&pool).await.unwrap();
        for method in ["GET", "HEAD"] {
            let response = read(
                &app,
                method,
                &path,
                &[("authorization", &credential), ("if-none-match", &etag)],
            )
            .await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!response.headers().contains_key(header::ETAG));
        }
    }
    sqlx::query("UPDATE caches SET signing_key_name=$1,signing_public_key=$2,signing_key_sealed=$3 WHERE name='secret'")
        .bind(name).bind(public).bind(sealed).execute(&pool).await.unwrap();
    assert_eq!(
        read(
            &app,
            "GET",
            &path,
            &[("authorization", &credential), ("if-none-match", &etag)],
        )
        .await
        .status(),
        StatusCode::NOT_MODIFIED
    );
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn redirect_loop_is_rejected_without_trusting_forwarded_headers(pool: PgPool) {
    let state = fixture(pool.clone(), CDN).await;
    let app = router(state.clone());
    for path in [
        "/alpha/main/nix-cache-info".to_owned(),
        format!("/nar/{}/zstd.nar", "a".repeat(64)),
    ] {
        for host in ["cdn.example.test", "CDN.EXAMPLE.TEST:443"] {
            let response = read(&app, "GET", &path, &[("host", host)]).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!response.headers().contains_key(header::LOCATION));
        }
        let response = read(&app, "GET", &format!("{CDN}{path}"), &[]).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let response = read(
            &app,
            "GET",
            &path,
            &[
                ("host", "origin.example.test"),
                ("forwarded", "host=cdn.example.test;proto=https"),
                ("x-forwarded-host", "cdn.example.test"),
                ("x-forwarded-proto", "https"),
            ],
        )
        .await;
        redirect(&response, &format!("{CDN}{path}"));
    }
    let mut config = config(CDN);
    config.public_url = CDN.into();
    let error = AppState::new(pool, config, common::storage(), reqwest::Client::new())
        .err()
        .expect("same-origin config must be rejected");
    assert_eq!(
        error.to_string(),
        "Public URL and public cache origin must use different origins"
    );
}

async fn mock_cdn(request: Request) -> Response {
    assert!(request.uri().query().is_none());
    assert!(!request.headers().contains_key(header::AUTHORIZATION));
    if request
        .headers()
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v == "\"cdn-etag\"")
    {
        return (StatusCode::NOT_MODIFIED, [("etag", "\"cdn-etag\"")]).into_response();
    }
    if request
        .headers()
        .get(header::RANGE)
        .is_some_and(|v| v == "bytes=0-7")
    {
        return (
            StatusCode::PARTIAL_CONTENT,
            [
                ("etag", "\"cdn-etag\"".to_owned()),
                ("content-range", format!("bytes 0-7/{}", NAR.len())),
            ],
            &NAR[..8],
        )
            .into_response();
    }
    let body = if request.method() == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(futures_util::stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(&NAR.as_bytes()[..8])),
            Ok(Bytes::from_static(&NAR.as_bytes()[8..])),
        ]))
    };
    (
        [
            ("etag", "\"cdn-etag\"".to_owned()),
            ("content-length", NAR.len().to_string()),
        ],
        body,
    )
        .into_response()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn tcp_client_follows_redirect_and_cdn_owns_bytes_ranges_and_validators(pool: PgPool) {
    tcp_delivery(pool, false).await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn alias_tcp_client_preserves_cdn_ranges_and_validators(pool: PgPool) {
    tcp_delivery(pool, true).await;
}

async fn tcp_delivery(pool: PgPool, alias: bool) {
    let cdn_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", cdn_listener.local_addr().unwrap());
    let app = router(if alias {
        alias_fixture(pool, &origin).await
    } else {
        fixture(pool, &origin).await
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prefix = if alias { "" } else { "/alpha" };
    let url = format!(
        "http://{}{prefix}/main/nar/{}/zstd.nar?token=do-not-copy",
        listener.local_addr().unwrap(),
        "a".repeat(64)
    );
    let (stop_cdn, stopped_cdn) = tokio::sync::oneshot::channel();
    let cdn = tokio::spawn(async move {
        axum::serve(cdn_listener, Router::new().fallback(mock_cdn))
            .with_graceful_shutdown(async {
                let _ = stopped_cdn.await;
            })
            .await
            .unwrap();
    });
    let (stop_app, stopped_app) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped_app.await;
            })
            .await
            .unwrap();
    });
    let mut headers = axum::http::HeaderMap::new();
    if alias {
        headers.insert(header::HOST, "alpha.snowstead.com".parse().unwrap());
    }
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();
    let response = client
        .get(&url)
        .bearer_auth("do-not-copy")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.url().as_str(),
        format!("{origin}/nar/{}/zstd.nar", "a".repeat(64))
    );
    assert_eq!(response.headers()[header::ETAG], "\"cdn-etag\"");
    assert_eq!(response.bytes().await.unwrap().as_ref(), NAR.as_bytes());
    let response = client.head(&url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        NAR.len().to_string()
    );
    assert!(response.bytes().await.unwrap().is_empty());
    let response = client
        .get(&url)
        .header(header::RANGE, "bytes=0-7")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers()[header::CONTENT_RANGE],
        format!("bytes 0-7/{}", NAR.len())
    );
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        &NAR.as_bytes()[..8]
    );
    let response = client
        .get(&url)
        .header(header::IF_NONE_MATCH, "\"cdn-etag\"")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert!(response.bytes().await.unwrap().is_empty());
    stop_app.send(()).unwrap();
    stop_cdn.send(()).unwrap();
    server.await.unwrap();
    cdn.await.unwrap();
}

async fn alias_fixture(pool: PgPool, origin: &str) -> AppState {
    let _seed = fixture(pool.clone(), origin).await;
    let mut cfg = config(origin);
    cfg.cache_host_suffix = "snowstead.com".into();
    cfg.cache_canonical_hosts = "api.snowstead.com origin.snowstead.com".into();
    cfg.signing_key_name = "alias-test".into();
    cfg.signing_private_key = STANDARD.encode([7; 32]);
    sqlx::query("UPDATE published_paths SET nar_hash='sha256:' || repeat('0',64), signatures_json='[\"upstream:kept\"]'")
        .execute(&pool).await.unwrap();
    let storage = common::storage();
    storage
        .put(
            true,
            &format!("nars/sha256/{}/zstd.nar", "b".repeat(64)),
            NAR.as_bytes(),
        )
        .await
        .unwrap();
    AppState::new(pool, cfg, storage, reqwest::Client::new()).unwrap()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn organization_hosts_are_read_only_and_isolated(pool: PgPool) {
    let state = alias_fixture(pool.clone(), CDN).await;
    sqlx::raw_sql("INSERT INTO orgs(id,slug) VALUES ('reserved','docs');
        INSERT INTO caches(name,org_id,is_public) VALUES ('main','reserved',true);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches WHERE org_id='reserved';")
        .execute(&pool).await.unwrap();
    let app = router(state.clone());
    let blob = "a".repeat(64);
    let alpha = [("host", "alpha.snowstead.com")];
    for method in ["GET", "HEAD"] {
        for path in [
            "/",
            "/healthz",
            "/_api/v1/orgs",
            "/private/alpha/main/nix-cache-info",
            "/alpha/main/nix-cache-info",
            "/main//nix-cache-info",
            "/main/nix-cache-info/",
            "/main/%2e%2e/nix-cache-info",
            "/go-only/nix-cache-info",
        ] {
            assert_eq!(
                read(&app, method, path, &alpha).await.status(),
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        assert_eq!(
            read(&app, method, &format!("/nar/{blob}/zstd.nar"), &alpha)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        for host in [
            "unknown.snowstead.com",
            "a.b.snowstead.com",
            "-alpha.snowstead.com",
            "alpha_.snowstead.com",
        ] {
            assert_eq!(
                read(&app, method, "/main/nix-cache-info", &[("host", host)])
                    .await
                    .status(),
                StatusCode::NOT_FOUND,
                "{host}"
            );
        }
        for host in [
            "www",
            "docs",
            "admin",
            "cache",
            "cache-staging",
            "auth",
            "staging",
            "status",
            "mail",
            "orgs",
            "invitations",
            "default",
            "nar",
            "private",
            "_api",
            "healthz",
        ] {
            assert_eq!(
                read(
                    &app,
                    method,
                    "/",
                    &[("host", &format!("{host}.snowstead.com"))]
                )
                .await
                .status(),
                StatusCode::NOT_FOUND
            );
        }
        for host in ["api.snowstead.com", "origin.snowstead.com"] {
            assert_eq!(
                read(
                    &app,
                    method,
                    "/",
                    &[("host", host), ("x-forwarded-host", "alpha.snowstead.com")]
                )
                .await
                .status(),
                StatusCode::OK
            );
            redirect(
                &read(
                    &app,
                    method,
                    "/alpha/main/nix-cache-info",
                    &[("host", host)],
                )
                .await,
                &format!("{CDN}/alpha/main/nix-cache-info"),
            );
        }
        redirect(
            &read(
                &app,
                method,
                "/main/nix-cache-info",
                &[("host", "ALPHA.SNOWSTEAD.COM:443")],
            )
            .await,
            &format!("{CDN}/alpha/main/nix-cache-info"),
        );
        assert_eq!(
            read(
                &app,
                method,
                &format!("/main/nar/{blob}/zstd.nar"),
                &[("host", "beta.snowstead.com")]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        redirect(
            &read(&app, method, &format!("/main/nar/{blob}/zstd.nar"), &alpha).await,
            &format!("{CDN}/nar/{blob}/zstd.nar"),
        );
        assert_eq!(
            read(&app, method, "/secret/nix-cache-info", &alpha)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            read(
                &app,
                method,
                "/main/nix-cache-info",
                &[("host", "docs.snowstead.com")]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            read(
                &app,
                method,
                "/main/nix-cache-info",
                &[("host", "alpha.snowstead.com..")]
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let path = format!("/secret/nar/{}/zstd.nar", "b".repeat(64));
        assert_eq!(
            read(&app, method, &path, &alpha).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let credential = format!("Bearer {}", token("org_alpha", "secret"));
        let response = read(
            &app,
            method,
            &path,
            &[
                ("host", "alpha.snowstead.com"),
                ("authorization", &credential),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-cache"
        );
        assert!(!response.headers().contains_key(header::LOCATION));
        assert_eq!(
            to_bytes(response.into_body(), 8192).await.unwrap().as_ref(),
            if method == "HEAD" {
                b""
            } else {
                NAR.as_bytes()
            }
        );
        for (org, cache) in [("org_beta", "secret"), ("org_alpha", "main")] {
            let denied = format!("Bearer {}", token(org, cache));
            assert_eq!(
                read(
                    &app,
                    method,
                    "/secret/nix-cache-info",
                    &[("host", "alpha.snowstead.com"), ("authorization", &denied)]
                )
                .await
                .status(),
                StatusCode::FORBIDDEN
            );
        }
        let credential = format!("Bearer {}", token("org_alpha", "secret"));
        assert_eq!(
            read(
                &app,
                method,
                "/secret/nix-cache-info",
                &[
                    ("host", "alpha.snowstead.com"),
                    ("authorization", &credential)
                ]
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        for path in ["/", "/_api/v1/orgs", "/upload", "/main/nix-cache-info"] {
            let response = read(&app, method, path, &alpha).await;
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()["allow"], "GET, HEAD");
        }
    }
    sqlx::query("UPDATE orgs SET slug='renamed',moving_from='alpha' WHERE id='org_alpha'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        read(&app, "GET", "/main/nix-cache-info", &alpha)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    redirect(
        &read(
            &app,
            "GET",
            "/main/nix-cache-info",
            &[("host", "renamed.snowstead.com")],
        )
        .await,
        &format!("{CDN}/renamed/main/nix-cache-info"),
    );
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn alias_metadata_is_scoped_signed_and_conditional(pool: PgPool) {
    use ed25519_dalek::{Signature, SigningKey};
    let state = alias_fixture(pool.clone(), CDN).await;
    let app = router(state.clone());
    let credential = format!("Bearer {}", token("org_alpha", "secret"));
    for (cache, blob, private) in [
        ("main", "a".repeat(64), false),
        ("secret", "b".repeat(64), true),
    ] {
        let path = format!("/{cache}/{}.narinfo", "0".repeat(32));
        let headers = [
            ("host", "alpha.snowstead.com"),
            ("authorization", credential.as_str()),
            ("range", "bytes=0-7"),
            ("x-snowstead-cdn-read", "1"),
        ];
        let response = read(&app, "GET", &path, &headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::LOCATION));
        assert_eq!(
            response.headers()["cloudflare-cdn-cache-control"],
            "no-store"
        );
        let etag = response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        let size = response.headers()[header::CONTENT_LENGTH].clone();
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains(&format!("\nURL: nar/{blob}/zstd.nar\n")));
        assert!(text.contains("\nSig: upstream:kept\n"));
        let sig = text
            .lines()
            .find_map(|line| line.strip_prefix("Sig: alias-test:"))
            .unwrap();
        let signature = Signature::from_slice(&STANDARD.decode(sig).unwrap()).unwrap();
        let fingerprint = format!("1;/nix/store/test;sha256:{};32;", "0".repeat(52));
        SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .verify_strict(fingerprint.as_bytes(), &signature)
            .unwrap();
        let base = reqwest::Url::parse(&format!("https://alpha.snowstead.com/{cache}/")).unwrap();
        let url = text
            .lines()
            .find_map(|line| line.strip_prefix("URL: "))
            .unwrap();
        assert_eq!(
            base.join(url).unwrap().path(),
            format!("/{cache}/nar/{blob}/zstd.nar")
        );
        for method in ["GET", "HEAD"] {
            for (condition, value, status) in [
                ("if-none-match", etag.as_str(), StatusCode::NOT_MODIFIED),
                ("if-match", "\"wrong\"", StatusCode::PRECONDITION_FAILED),
            ] {
                let mut conditions = headers.to_vec();
                conditions.push((condition, value));
                let response = read(&app, method, &path, &conditions).await;
                assert_eq!(response.status(), status);
                assert!(
                    to_bytes(response.into_body(), 8192)
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
        }
        let response = read(&app, "HEAD", &path, &headers).await;
        assert_eq!(response.headers()[header::CONTENT_LENGTH], size);
        assert!(
            to_bytes(response.into_body(), 8192)
                .await
                .unwrap()
                .is_empty()
        );
        if private {
            assert_eq!(
                read(
                    &app,
                    "GET",
                    &path,
                    &[("host", "alpha.snowstead.com"), ("if-none-match", &etag)]
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
    sqlx::query("DELETE FROM published_paths WHERE cache_id=(SELECT id FROM caches WHERE org_id='org_alpha' AND name='main')").execute(&pool).await.unwrap();
    assert_eq!(
        read(
            &app,
            "GET",
            &format!("/main/{}.narinfo", "0".repeat(32)),
            &[("host", "alpha.snowstead.com")]
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    state.finish_background().await;
}
