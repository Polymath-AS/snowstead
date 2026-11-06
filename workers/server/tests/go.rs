mod common;

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use object_store::{ObjectStoreExt, memory::InMemory};
use serde_json::json;
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;

fn token(org: &str, cache: &str, perms: &[&str]) -> String {
    let claims = json!({"jti":"compiler-test","sub":"compiler","iss":"snowstead","aud":"snowstead","iat":1,"org":org,"caches":[cache],"perms":perms});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"fixture-jwt").unwrap();
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
    sqlx::raw_sql("INSERT INTO orgs(id,slug) VALUES ('org_a','alpha'),('org_b','beta');
        INSERT INTO caches(name,org_id,is_public) VALUES ('compiler','org_a',false),('compiler','org_b',false),('public','org_a',true);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,kind FROM caches CROSS JOIN (VALUES ('go'),('sccache'),('nix')) p(kind);")
        .execute(pool).await.unwrap();
    AppState::new(pool.clone(), config(), storage, reqwest::Client::new()).unwrap()
}

fn config() -> Config {
    Config {
        jwt_secret: "fixture-jwt".into(),
        auth_token: "legacy".into(),
        ..Default::default()
    }
}
fn path(cache: &str, digit: char) -> String {
    format!(
        "/_api/v1/go/alpha/{cache}/v1/actions/{}",
        digit.to_string().repeat(64)
    )
}
async fn send(
    app: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    headers: &[(&str, &str)],
    bytes: &[u8],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = credential {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    for (key, value) in headers {
        req = req.header(*key, *value);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(bytes.to_vec())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    (
        status,
        headers,
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}
async fn put(app: &Router, path: &str, token: &str, bytes: &[u8]) -> StatusCode {
    send(
        app,
        "PUT",
        path,
        Some(token),
        &[
            ("content-length", &bytes.len().to_string()),
            ("x-snowstead-output-id", &hex::encode(Sha256::digest(bytes))),
        ],
        bytes,
    )
    .await
    .0
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn public_compiler_routes_read_existing_private_bucket_objects(pool: PgPool) {
    let public = Arc::new(InMemory::new());
    let private = Arc::new(InMemory::new());
    let storage = Storage::from_stores(public.clone(), private.clone());
    let app = router(fixture_with_storage(&pool, storage).await);
    let cache_id: i32 = sqlx::query_scalar("SELECT id FROM caches WHERE name='public'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let action = "a".repeat(64);
    let bytes = Bytes::from_static(b"existing R2 compiler artifact");
    let output = hex::encode(Sha256::digest(&bytes));
    for product in ["go", "sccache"] {
        let id = format!("existing-{product}");
        let key = format!("{product}/{cache_id}/0/{action}/{id}");
        private
            .put(&key.clone().into(), bytes.clone().into())
            .await
            .unwrap();
        let (extra_column, extra_value) = if product == "go" {
            (",output", ",$6")
        } else {
            ("", "")
        };
        let query = format!(
            "INSERT INTO {product}_entries (id,cache_id,generation,action,r2_key,size,uploaded_at,expires_at{extra_column})
             VALUES ($1,$2,'0',$3,$4,$5,now(),now()+interval '1 day'{extra_value})"
        );
        let mut insert = sqlx::query(sqlx::AssertSqlSafe(query))
            .bind(&id)
            .bind(cache_id)
            .bind(&action)
            .bind(&key)
            .bind(bytes.len() as i64);
        if product == "go" {
            insert = insert.bind(&output);
        }
        insert.execute(&pool).await.unwrap();
        let url = if product == "go" {
            path("public", 'a')
        } else {
            format!("/_api/v1/sccache/alpha/public/a/a/a/{action}")
        };
        for method in ["HEAD", "GET"] {
            let (status, headers, body) = send(&app, method, &url, None, &[], &[]).await;
            assert_eq!(status, StatusCode::OK, "{product} {method}");
            assert_eq!(headers["content-length"], bytes.len().to_string());
            assert_eq!(headers["cache-control"], "no-store");
            assert_eq!(headers["etag"], format!("\"{id}\""));
            if product == "go" {
                assert_eq!(headers["x-snowstead-output-id"], output);
            }
            assert_eq!(
                body.as_slice(),
                if method == "HEAD" {
                    &[]
                } else {
                    bytes.as_ref()
                }
            );
        }
        assert!(public.head(&key.into()).await.is_err());
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn go_auth_checksum_immutable_replay_and_expiry(pool: PgPool) {
    let storage = common::storage();
    let state = fixture_with_storage(&pool, storage.clone()).await;
    let app = router(state.clone());
    let write = token("org_a", "compiler", &["go:write"]);
    let read = token("org_a", "compiler", &["go:read"]);
    let url = path("compiler", 'a');
    assert_eq!(
        send(&app, "GET", &url, None, &[], &[]).await.0,
        StatusCode::UNAUTHORIZED
    );
    for denied in [
        "legacy".to_owned(),
        token(
            "org_a",
            "*",
            &["push", "pull", "sccache:read", "sccache:write"],
        ),
        token("org_b", "*", &["go:read", "go:write"]),
        token("org_a", "other", &["go:read", "go:write"]),
    ] {
        assert_eq!(
            send(&app, "GET", &url, Some(&denied), &[], &[]).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            put(&app, &url, &denied, b"bytes").await,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        send(&app, "GET", &url, Some(&read), &[], &[]).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(&app, &url, &read, b"bytes").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, "GET", &path("public", 'a'), None, &[], &[])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let bytes = b"immutable Go object with independently hashed output";
    let digest = hex::encode(Sha256::digest(bytes));
    assert_eq!(
        send(
            &app,
            "PUT",
            &url,
            Some(&write),
            &[
                ("content-length", "3"),
                ("x-snowstead-output-id", &"0".repeat(64))
            ],
            b"bad"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // A failed transfer must not commit its output or size. A corrected retry
    // can publish without waiting for the shared reservation to expire.
    assert_eq!(put(&app, &url, &write, bytes).await, StatusCode::CREATED);
    let expiry: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT expires_at FROM go_entries WHERE cache_id IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(put(&app, &url, &write, bytes).await, StatusCode::NO_CONTENT);
    assert_eq!(
        put(&app, &url, &write, b"different output").await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            &app,
            "PUT",
            &url,
            Some(&write),
            &[
                ("content-length", &bytes.len().to_string()),
                ("x-snowstead-output-id", &digest)
            ],
            b"short"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let app =
        router(AppState::new(pool.clone(), config(), storage, reqwest::Client::new()).unwrap());
    for method in ["HEAD", "GET"] {
        let (status, headers, body) = send(&app, method, &url, Some(&read), &[], &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["x-snowstead-output-id"], digest);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["content-length"], bytes.len().to_string());
        assert!(headers.contains_key("etag"));
        assert_eq!(
            body,
            if method == "HEAD" {
                b"".as_slice()
            } else {
                bytes
            }
        );
    }
    let metered: i64 = sqlx::query_scalar("SELECT bytes FROM bandwidth_daily WHERE product='go'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(metered, bytes.len() as i64);
    let after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT expires_at FROM go_entries WHERE cache_id IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after, expiry);
    sqlx::query("UPDATE go_entries SET expires_at=now()-interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, "GET", &url, Some(&read), &[], &[]).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(&app, &url, &write, b"new generation of this action").await,
        StatusCode::CREATED
    );
    assert_eq!(
        put(&app, &path("compiler", 'b'), &write, b"").await,
        StatusCode::CREATED
    );
    assert_eq!(
        send(
            &app,
            "PUT",
            &path("compiler", 'c'),
            Some(&write),
            &[
                ("content-length", "67108865"),
                ("x-snowstead-output-id", &digest)
            ],
            &[]
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    sqlx::query("DELETE FROM cache_protocols WHERE protocol='go'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, "GET", &url, Some(&read), &[], &[]).await.0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn compiler_expiration_is_checked_after_waiting_for_access_recording(pool: PgPool) {
    let app = router(fixture(&pool).await);
    let credential = token("org_a", "compiler", &["go:write", "go:read"]);
    let url = path("compiler", '9');
    assert_eq!(
        put(&app, &url, &credential, b"expires during read").await,
        StatusCode::CREATED
    );
    for method in ["GET", "HEAD"] {
        let expires: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "UPDATE go_entries SET expires_at=now()+interval '2 seconds',last_accessed_at=NULL RETURNING expires_at",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut lock = pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM go_entries FOR UPDATE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let pending = {
            let app = app.clone();
            let url = url.clone();
            let credential = credential.clone();
            tokio::spawn(async move { send(&app, method, &url, Some(&credential), &[], &[]).await })
        };
        // The row lock stalls telemetry, after the object has been opened.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
                )
                .bind(pid)
                .fetch_one(&pool)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("read must reach access recording while the entry is still live");
        tokio::time::sleep(
            (expires - chrono::Utc::now()).to_std().unwrap_or_default()
                + std::time::Duration::from_millis(10),
        )
        .await;
        lock.rollback().await.unwrap();
        let (status, _, _) = pending.await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn failed_duplicate_cannot_expire_an_inflight_compiler_upload(pool: PgPool) {
    let bounded = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let app = router(fixture(&bounded).await);
    let credential = token(
        "org_a",
        "compiler",
        &["go:write", "go:read", "sccache:write", "sccache:read"],
    );
    for product in ["go", "sccache"] {
        let url = if product == "go" {
            path("compiler", '2')
        } else {
            format!("/_api/v1/sccache/alpha/compiler/2/2/2/{}", "2".repeat(64))
        };
        let bytes = b"valid compiler artifact";
        let digest = hex::encode(Sha256::digest(bytes));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let body = Body::from_stream(
            futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(&bytes[..5]))])
                .chain(futures_util::stream::once(async move {
                    // Polling the second chunk proves the first has been consumed.
                    started_tx.send(()).unwrap();
                    resume_rx.await.unwrap();
                    Ok::<_, std::io::Error>(Bytes::from_static(&bytes[5..]))
                })),
        );
        let request = Request::builder()
            .method("PUT")
            .uri(&url)
            .header("authorization", format!("Bearer {credential}"))
            .header("content-length", bytes.len())
            .header("x-snowstead-output-id", &digest)
            .body(body)
            .unwrap();
        let task = tokio::spawn(app.clone().oneshot(request));
        tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        // A larger failed duplicate grows the shared byte reservation but
        // must not invalidate the original writer or change its stored size.
        let invalid = if product == "go" {
            vec![b'!'; bytes.len() + 5]
        } else {
            vec![b'!'; bytes.len() - 1]
        };
        let (status, _, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            send(
                &app,
                "PUT",
                &url,
                Some(&credential),
                &[
                    ("content-length", &(bytes.len() + 5).to_string()),
                    ("x-snowstead-output-id", &digest),
                ],
                &invalid,
            ),
        )
        .await
        .expect("an in-flight body must not hold the sole SQL connection");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{product}");
        resume_tx.send(()).unwrap();
        let response = task.await.unwrap().unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{product}: {body:?}");
        let (status, _, downloaded) = send(&app, "GET", &url, Some(&credential), &[], &[]).await;
        assert_eq!(status, StatusCode::OK, "{product}");
        assert_eq!(downloaded, bytes, "{product}");
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn compiler_capacity_is_shared_with_nix_and_cannot_evict_its_own_replay(pool: PgPool) {
    let state = fixture(&pool).await;
    let app = router(state);
    let credential = token(
        "org_a",
        "compiler",
        &["go:write", "go:read", "sccache:write", "sccache:read"],
    );
    let go = path("compiler", 'e');
    let cc = format!("/_api/v1/sccache/alpha/compiler/f/f/f/{}", "f".repeat(64));
    assert_eq!(
        put(&app, &go, &credential, &[1; 18]).await,
        StatusCode::CREATED
    );
    sqlx::raw_sql("INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) VALUES (repeat('a',64),14,'zstd','fixture');
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,last_pushed_at)
        SELECT c.id,repeat('0',32),'/nix/store/pinned','sha256:fixture',1,b.id,'2001-01-01' FROM caches c CROSS JOIN blob_objects b WHERE c.org_id='org_a' AND c.name='compiler';
        INSERT INTO pins(id,cache_id,name,keep_kind,current_revision) SELECT 'pin',id,'keep','forever',1 FROM caches WHERE org_id='org_a' AND name='compiler';
        INSERT INTO pin_revisions(id,pin_id,revision,store_path) VALUES ('rev','pin',1,'/nix/store/pinned');
        INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) SELECT 'rev',id,repeat('0',32) FROM caches WHERE org_id='org_a' AND name='compiler';
        UPDATE go_entries SET uploaded_at='2000-01-01',last_accessed_at=NULL;
        UPDATE orgs SET storage_limit=35 WHERE id='org_a';").execute(&pool).await.unwrap();
    assert_eq!(
        put(&app, &cc, &credential, &[2; 20]).await,
        StatusCode::CREATED
    );
    assert_eq!(
        send(&app, "GET", &go, Some(&credential), &[], &[]).await.0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE orgs SET storage_limit=40 WHERE id='org_a'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        put(&app, &go, &credential, &[3; 26]).await,
        StatusCode::CREATED
    );
    assert_eq!(
        send(&app, "GET", &cc, Some(&credential), &[], &[]).await.0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE orgs SET storage_limit=30 WHERE id='org_a'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        put(&app, &go, &credential, &[3; 26]).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        send(&app, "GET", &go, Some(&credential), &[], &[]).await.2,
        vec![3; 26]
    );
    let pins: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pins, 1);
    sqlx::raw_sql("DELETE FROM pin_paths; UPDATE orgs SET storage_limit=40 WHERE id='org_a'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        put(&app, &path("compiler", 'f'), &credential, &[4; 32]).await,
        StatusCode::CREATED
    );
    let pins: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pins, 0);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn competing_writers_and_recovery_never_replace_or_delete_adopted_bytes(pool: PgPool) {
    let state = fixture(&pool).await;
    let app = router(state);
    let credential = token(
        "org_a",
        "compiler",
        &["go:write", "go:read", "sccache:write", "sccache:read"],
    );
    for product in ["go", "sccache"] {
        let url = if product == "go" {
            path("compiler", '1')
        } else {
            format!("/_api/v1/sccache/alpha/compiler/1/1/1/{}", "1".repeat(64))
        };
        let a = b"first";
        let b = b"other";
        let (first, second) = tokio::join!(
            put(&app, &url, &credential, a),
            put(&app, &url, &credential, b)
        );
        let mut statuses = [first, second];
        statuses.sort();
        assert_eq!(
            statuses,
            [
                StatusCode::CREATED,
                if product == "go" {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::NO_CONTENT
                }
            ]
        );
        let winner = if first == StatusCode::CREATED { a } else { b };
        assert_eq!(
            send(&app, "GET", &url, Some(&credential), &[], &[]).await.2,
            winner
        );
        if product == "sccache" {
            sqlx::query("UPDATE sccache_entries SET uploaded_at=NULL WHERE cache_id IS NOT NULL")
                .execute(&pool)
                .await
                .unwrap();
            assert_eq!(
                put(&app, &url, &credential, b"different size").await,
                StatusCode::CONFLICT
            );
            assert_eq!(
                put(&app, &url, &credential, winner).await,
                StatusCode::NO_CONTENT
            );
            assert_eq!(
                send(&app, "GET", &url, Some(&credential), &[], &[]).await.2,
                winner
            );
        }
        // Model a pre-migration transfer whose file reached storage but whose
        // database acknowledgement was lost. Both retries must recover the
        // same immutable file; neither may reclaim it as a losing attempt.
        sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE {product}_entries SET stored_at=NULL,uploaded_at=NULL WHERE cache_id IS NOT NULL")))
            .execute(&pool).await.unwrap();
        if product == "sccache" {
            sqlx::query("UPDATE orgs SET storage_limit=10 WHERE id='org_a'")
                .execute(&pool)
                .await
                .unwrap();
            // Existing immutable bytes need no extra staging reservation:
            // conflict handling must take precedence over charging growth.
            assert_eq!(
                put(&app, &url, &credential, &[0; 11]).await,
                StatusCode::CONFLICT
            );
            sqlx::query("UPDATE orgs SET storage_limit=NULL WHERE id='org_a'")
                .execute(&pool)
                .await
                .unwrap();
        }
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let make = || {
            let barrier = barrier.clone();
            let body = Body::from_stream(futures_util::stream::once(async move {
                barrier.wait().await;
                Ok::<_, std::io::Error>(Bytes::copy_from_slice(winner))
            }));
            app.clone().oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&url)
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-length", winner.len())
                    .header("x-snowstead-output-id", hex::encode(Sha256::digest(winner)))
                    .body(body)
                    .unwrap(),
            )
        };
        let (first, second) = tokio::join!(make(), make());
        assert_eq!(first.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(second.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(
            send(&app, "GET", &url, Some(&credential), &[], &[]).await.2,
            winner
        );
    }
}
