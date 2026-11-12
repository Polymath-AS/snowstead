use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::TryStreamExt;
use hmac::{Hmac, KeyInit, Mac};
use object_store::{ObjectStore, memory::InMemory};
use serde_json::json;
use sha2::Sha256;
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

fn jwt(org: &str, cache: &str, perms: &[&str]) -> String {
    let claims = json!({"jti":format!("sccache-{org}-{cache}-{}", perms.join("+")),"sub":"cli","iss":"snowstead","aud":"snowstead","iat":1,"org":org,"caches":[cache],"perms":perms});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"test-jwt").unwrap();
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    length: Option<&str>,
    bytes: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "backend.local");
    if let Some(credential) = credential {
        request = request.header("authorization", format!("Bearer {credential}"));
    }
    if let Some(length) = length {
        request = request.header("content-length", length);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

async fn fixture(pool: &PgPool) -> (Router, [Arc<InMemory>; 2]) {
    sqlx::raw_sql("INSERT INTO orgs(id,slug) VALUES ('org_a','alpha'),('org_b','beta');
        INSERT INTO caches(name,org_id,is_public,created_at) VALUES ('vault','org_a',false,'2020-01-02 03:04:05+00'),('public','org_a',true,'2020-01-02 03:04:05+00'),('vault','org_b',false,'2020-01-02 03:04:05+00');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'sccache' FROM caches;
        INSERT INTO caches(name,org_id) VALUES ('disabled','org_a');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'go' FROM caches WHERE name='disabled';")
        .execute(pool).await.unwrap();
    let stores = [Arc::new(InMemory::new()), Arc::new(InMemory::new())];
    let app = router(
        AppState::new(
            pool.clone(),
            Config {
                jwt_secret: String::from_utf8(b"test-jwt".to_vec()).unwrap(),
                shared_auth_token: Some("legacy".into()),
                admin_secret: "admin".into(),
                ..Default::default()
            },
            Storage::from_stores(stores[0].clone(), stores[1].clone()),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    (app, stores)
}

fn archive(cache: &str, digit: char) -> String {
    format!(
        "/_api/v1/sccache/alpha/{cache}/{digit}/{digit}/{digit}/{}",
        digit.to_string().repeat(64)
    )
}

#[path = "support/tokens.rs"]
mod tokens;

/// A listed JWT-era token, which works with the scope its row records.
async fn token(pool: &PgPool, org: &str, cache: &str, perms: &[&str]) -> String {
    tokens::register(pool, jwt(org, cache, perms)).await
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn private_misses_require_explicit_product_org_and_cache_permissions(pool: PgPool) {
    let (app, _stores) = fixture(&pool).await;
    let path = archive("vault", 'a');
    let read = token(&pool, "org_a", "vault", &["sccache:read"]).await;
    let write = token(&pool, "org_a", "vault", &["sccache:write"]).await;
    for method in ["GET", "HEAD"] {
        assert_eq!(
            send(&app, method, &path, None, None, vec![]).await.0,
            StatusCode::UNAUTHORIZED
        );
        for denied in [
            "legacy".to_owned(),
            "admin".to_owned(),
            token(&pool, "org_b", "*", &["sccache:read"]).await,
            token(&pool, "org_a", "other", &["sccache:read"]).await,
            token(
                &pool,
                "org_a",
                "*",
                &["pull", "push", "go:read", "go:write"],
            )
            .await,
            write.clone(),
        ] {
            assert_eq!(
                send(&app, method, &path, Some(&denied), None, vec![])
                    .await
                    .0,
                StatusCode::FORBIDDEN,
                "{method}"
            );
        }
        assert_eq!(
            send(&app, method, &path, Some(&read), None, vec![]).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(&app, method, &archive("public", 'a'), None, None, vec![])
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    for denied in [
        "legacy".to_owned(),
        "admin".to_owned(),
        read,
        token(&pool, "org_a", "*", &["push", "go:write"]).await,
        token(&pool, "org_b", "*", &["sccache:write"]).await,
        token(&pool, "org_a", "other", &["sccache:write"]).await,
    ] {
        assert_eq!(
            send(&app, "PUT", &path, Some(&denied), Some("0"), vec![])
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        send(
            &app,
            "PUT",
            &archive("public", 'a'),
            None,
            Some("0"),
            vec![]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "GET", &archive("disabled", 'a'), None, None, vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, "PUT", &path, Some(&write), Some("0"), vec![])
            .await
            .0,
        StatusCode::CREATED
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn virtual_directories_probe_and_canonical_paths(pool: PgPool) {
    let (app, stores) = fixture(&pool).await;
    let write = token(&pool, "org_a", "*", &["sccache:write"]).await;
    let read = token(&pool, "org_a", "*", &["sccache:read"]).await;
    for suffix in ["", "a/", "a/b/", "a/b/c/"] {
        let path = format!("/_api/v1/sccache/alpha/public///{suffix}");
        let (status, headers, body) = send(&app, "PROPFIND", &path, None, None, vec![]).await;
        assert_eq!(status, StatusCode::MULTI_STATUS);
        assert_eq!(headers["content-type"], "application/xml");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            format!(
                "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getlastmodified>Thu, 02 Jan 2020 03:04:05 GMT</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
            )
        );
        assert_eq!(
            send(&app, "MKCOL", &path, Some(&write), None, vec![])
                .await
                .0,
            StatusCode::CREATED
        );
        for method in ["GET", "HEAD", "PUT"] {
            assert_eq!(
                send(&app, method, &path, Some(&write), Some("0"), vec![])
                    .await
                    .0,
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
    }
    let private = "/_api/v1/sccache/alpha/vault/a/";
    assert_eq!(
        send(&app, "PROPFIND", private, None, None, vec![]).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, "PROPFIND", private, Some(&read), None, vec![])
            .await
            .0,
        StatusCode::MULTI_STATUS
    );
    assert_eq!(
        send(&app, "MKCOL", private, Some(&read), None, vec![])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let probe = "/_api/v1/sccache/alpha/public/.sccache_check";
    for size in [0, 1, 1024] {
        let (status, headers, _) = send(
            &app,
            "PUT",
            probe,
            Some(&write),
            Some(&size.to_string()),
            vec![7; size],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(headers["cache-control"], "no-store");
    }
    assert_eq!(
        send(&app, "PUT", probe, Some(&write), Some("1025"), vec![])
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for method in ["GET", "HEAD"] {
        assert_eq!(
            send(&app, method, probe, None, None, vec![]).await.0,
            StatusCode::NOT_FOUND
        );
    }
    for method in ["PROPFIND", "MKCOL"] {
        assert_eq!(
            send(&app, method, probe, Some(&write), None, vec![])
                .await
                .0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    for suffix in [
        "a",
        "a/b",
        "a/b/c/d/",
        "g/",
        "A/",
        "a//",
        ".sccache_check/",
        "a/b/c/abc",
        &format!("a/b/c/{}", "d".repeat(64)),
        &format!("a/a/a/{}", "A".repeat(64)),
    ] {
        let path = format!("/_api/v1/sccache/alpha/public/{suffix}");
        assert_eq!(
            send(&app, "GET", &path, None, None, vec![]).await.0,
            StatusCode::NOT_FOUND,
            "{suffix}"
        );
    }
    for path in [
        "/_api/v1/sccache/alpha/public",
        "/_api/v1/sccache/Alpha/public/",
        "/_api/v1/sccache/alpha/pub_lic/",
    ] {
        assert_eq!(
            send(&app, "GET", path, None, None, vec![]).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let (status, headers, _) =
        send(&app, "DELETE", &archive("public", 'a'), None, None, vec![]).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers["allow"], "GET, HEAD, PUT, PROPFIND, MKCOL");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sccache_entries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    // Virtual operations must not create marker or probe objects.
    for store in stores {
        assert!(
            store
                .list(None)
                .try_collect::<Vec<_>>()
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn archives_are_immutable_and_reset_expiry_and_slug_changes_hide_them(pool: PgPool) {
    let (app, _stores) = fixture(&pool).await;
    let credential = token(&pool, "org_a", "*", &["sccache:read", "sccache:write"]).await;
    for cache in ["public", "vault"] {
        let path = archive(cache, 'b');
        assert_eq!(
            send(
                &app,
                "PUT",
                &path,
                Some(&credential),
                Some("5"),
                b"first".to_vec()
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            send(
                &app,
                "PUT",
                &path,
                Some(&credential),
                Some("11"),
                b"replacement".to_vec()
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        let read = if cache == "public" {
            None
        } else {
            Some(credential.as_str())
        };
        let (status, headers, body) = send(&app, "GET", &path, read, None, vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"first");
        assert_eq!(headers["content-length"], "5");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-snowstead-cache"], "MISS");
        assert!(headers.contains_key("etag"));
        let (status, head, body) = send(&app, "HEAD", &path, read, None, vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty());
        assert_eq!(head["content-length"], "5");
        assert_eq!(head["etag"], headers["etag"]);
    }
    assert_eq!(
        send(
            &app,
            "GET",
            &archive("vault", 'b').replace("/alpha/", "/beta/"),
            Some(&token(&pool, "org_b", "*", &["sccache:read"]).await),
            None,
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let metered: i64 = sqlx::query_scalar(
        "SELECT sum(bytes)::bigint FROM bandwidth_daily WHERE org_id='org_a' AND product='sccache'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(metered, 10);
    sqlx::raw_sql("UPDATE sccache_entries SET expires_at=now()-interval '1 second' WHERE cache_id IN (SELECT id FROM caches WHERE name='public'); UPDATE caches SET sccache_generation='reset' WHERE org_id='org_a' AND name='vault';").execute(&pool).await.unwrap();
    for cache in ["public", "vault"] {
        let path = archive(cache, 'b');
        for method in ["GET", "HEAD"] {
            assert_eq!(
                send(&app, method, &path, Some(&credential), None, vec![])
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            send(
                &app,
                "PUT",
                &path,
                Some(&credential),
                Some("3"),
                b"new".to_vec()
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            send(&app, "GET", &path, Some(&credential), None, vec![])
                .await
                .2,
            b"new"
        );
    }
    sqlx::query("UPDATE orgs SET slug='renamed' WHERE id='org_a'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, "GET", &archive("public", 'b'), None, None, vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &archive("public", 'b').replace("/alpha/", "/renamed/"),
            None,
            None,
            vec![]
        )
        .await
        .2,
        b"new"
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn lengths_zero_and_size_boundaries(pool: PgPool) {
    let (app, _stores) = fixture(&pool).await;
    let credential = token(&pool, "org_a", "*", &["sccache:write"]).await;
    let path = archive("public", 'c');
    let probe = "/_api/v1/sccache/alpha/public/.sccache_check";
    for path in [path.as_str(), probe] {
        for length in [
            None,
            Some(""),
            Some("-1"),
            Some("+1"),
            Some("1.0"),
            Some("1, 1"),
        ] {
            assert_eq!(
                send(&app, "PUT", path, Some(&credential), length, vec![])
                    .await
                    .0,
                StatusCode::LENGTH_REQUIRED
            );
        }
        for length in ["18446744073709551616", "9007199254740992"] {
            assert_eq!(
                send(&app, "PUT", path, Some(&credential), Some(length), vec![])
                    .await
                    .0,
                StatusCode::PAYLOAD_TOO_LARGE
            );
        }
        for (digit, length, body) in [
            ('1', "1", vec![]),
            ('2', "0", vec![1]),
            ('3', "1", vec![1, 2]),
        ] {
            // Failed attempts retain their shared reservation until expiry;
            // use independent actions to exercise each malformed body.
            let malformed_path = if path == probe {
                probe.to_owned()
            } else {
                archive("public", digit)
            };
            let (status, _, bytes) = send(
                &app,
                "PUT",
                &malformed_path,
                Some(&credential),
                Some(length),
                body,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{}",
                String::from_utf8_lossy(&bytes)
            );
            assert!(String::from_utf8_lossy(&bytes).contains("Content length mismatch"));
        }
    }
    assert_eq!(
        send(&app, "PUT", &path, Some(&credential), Some("0"), vec![])
            .await
            .0,
        StatusCode::CREATED
    );
    let (status, headers, bytes) = send(&app, "GET", &path, None, None, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-length"], "0");
    assert!(bytes.is_empty());
    // Duplicate bodies must be drained and checked, not silently discarded.
    assert_eq!(
        send(&app, "PUT", &path, Some(&credential), Some("2"), vec![1])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let large = archive("public", 'd');
    assert_eq!(
        send(
            &app,
            "PUT",
            &large,
            Some(&credential),
            Some("67108865"),
            vec![]
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        send(
            &app,
            "PUT",
            &large,
            Some(&credential),
            Some("67108864"),
            vec![42; 64 * 1024 * 1024]
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let (status, headers, bytes) = send(&app, "GET", &large, None, None, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-length"], "67108864");
    assert_eq!(bytes.len(), 64 * 1024 * 1024);
    assert!(bytes.iter().all(|b| *b == 42));
}
