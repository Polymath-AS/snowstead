mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config};
use sqlx::PgPool;
use tower::ServiceExt;

fn jwt(org: &str, cache: &str, perms: &[&str]) -> String {
    let claims = json!({"jti":format!("compiler-{org}-{cache}-{}", perms.join("+")),"sub":"compiler","iss":"snowstead","aud":"snowstead","iat":1,"org":org,"caches":[cache],"perms":perms});
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

#[path = "support/tokens.rs"]
mod tokens;

/// A listed JWT-era token, which works with the scope its row records.
async fn token(pool: &PgPool, org: &str, cache: &str, perms: &[&str]) -> String {
    tokens::register(pool, jwt(org, cache, perms)).await
}

fn config(suffix: &str) -> Config {
    Config {
        jwt_secret: "fixture-jwt".into(),
        cache_host_suffix: suffix.into(),
        cache_canonical_hosts: "api.snowstead.com".into(),
        ..Default::default()
    }
}

async fn seed(pool: &PgPool) {
    sqlx::raw_sql(
        "INSERT INTO orgs(id,slug) VALUES ('org_a','alpha'),('org_b','beta');
         INSERT INTO caches(name,org_id,is_public,created_at) VALUES
           ('team','org_a',false,'2020-01-02 03:04:05+00'),
           ('team','org_b',false,'2020-01-02 03:04:05+00'),
           ('go','org_a',true,'2020-01-02 03:04:05+00'),
           ('sccache','org_a',true,'2020-01-02 03:04:05+00');
         INSERT INTO cache_protocols(cache_id,protocol)
           SELECT id,kind FROM caches CROSS JOIN (VALUES ('go'),('sccache'),('nix')) p(kind);
         INSERT INTO caches(name,org_id,is_public,created_at) VALUES
           ('bazel','org_a',true,'2020-01-02 03:04:05+00');
         INSERT INTO cache_protocols(cache_id,protocol)
           SELECT id,kind FROM caches CROSS JOIN (VALUES ('bazel'),('nix')) p(kind) WHERE caches.name='bazel';
         INSERT INTO cache_protocols(cache_id,protocol)
           SELECT id,'bazel' FROM caches WHERE name='team';
         INSERT INTO bazel_caches(cache_id,generation,capacity)
           SELECT id,'generation-' || id,33554432 FROM caches WHERE name IN ('team','bazel');",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn app(pool: &PgPool, suffix: &str) -> Router {
    let state = AppState::new(
        pool.clone(),
        config(suffix),
        common::storage(),
        reqwest::Client::new(),
    )
    .unwrap();
    common::router(state)
}

async fn send(
    app: &Router,
    method: &str,
    host: Option<&str>,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    bytes: &[u8],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(host) = host {
        req = req.header("host", host);
    }
    if let Some(token) = token {
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

/// A Go action upload: the body commits to its own SHA-256 output ID.
async fn put_go(
    app: &Router,
    host: &str,
    path: &str,
    token: &str,
    bytes: &[u8],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let length = bytes.len().to_string();
    let output = hex::encode(Sha256::digest(bytes));
    send(
        app,
        "PUT",
        Some(host),
        path,
        Some(token),
        &[
            ("content-length", length.as_str()),
            ("x-snowstead-output-id", output.as_str()),
        ],
        bytes,
    )
    .await
}

async fn put_bytes(
    app: &Router,
    host: &str,
    path: &str,
    token: &str,
    bytes: &[u8],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let length = bytes.len().to_string();
    send(
        app,
        "PUT",
        Some(host),
        path,
        Some(token),
        &[("content-length", length.as_str())],
        bytes,
    )
    .await
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn go_reads_and_writes_through_the_organization_host(pool: PgPool) {
    seed(&pool).await;
    let app = app(&pool, "snowstead.com").await;
    let token = token(&pool, "org_a", "team", &["go:read", "go:write"]).await;
    let first = "a".repeat(64);
    let second = "b".repeat(64);
    let org_path = format!("/team/go/v1/actions/{first}");
    let legacy_path = format!("/_api/v1/go/alpha/team/v1/actions/{first}");
    let body: &[u8] = b"go action output";
    let second_body: &[u8] = b"second go action output";

    let (status, headers, _) = send(
        &app,
        "GET",
        Some("alpha.snowstead.com"),
        &org_path,
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");

    let (status, headers, _) = put_go(&app, "alpha.snowstead.com", &org_path, &token, body).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");

    let (status, headers, bytes) = send(
        &app,
        "GET",
        Some("alpha.snowstead.com"),
        &org_path,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");
    assert_eq!(bytes, body);

    let (status, _, bytes) = send(
        &app,
        "HEAD",
        Some("alpha.snowstead.com"),
        &org_path,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());

    let with_query = format!("{org_path}?x=1");
    let (status, _, bytes) = send(
        &app,
        "GET",
        Some("alpha.snowstead.com"),
        &with_query,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, body);

    let (status, _, bytes) = send(
        &app,
        "GET",
        Some("api.snowstead.com"),
        &legacy_path,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, body);

    let legacy_second = format!("/_api/v1/go/alpha/team/v1/actions/{second}");
    let (status, _, _) = put_go(
        &app,
        "api.snowstead.com",
        &legacy_second,
        &token,
        second_body,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let org_second = format!("/team/go/v1/actions/{second}");
    let (status, _, bytes) = send(
        &app,
        "GET",
        Some("alpha.snowstead.com"),
        &org_second,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, second_body);

    let (status, headers, _) = send(
        &app,
        "GET",
        Some("beta.snowstead.com"),
        &org_path,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");

    let (status, _, _) = send(
        &app,
        "GET",
        Some("api.snowstead.com"),
        &org_path,
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(&app, "GET", None, &org_path, None, &[], b"").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, headers, _) = send(
        &app,
        "DELETE",
        Some("alpha.snowstead.com"),
        &org_path,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers["allow"], "GET, HEAD, PUT");

    for path in [
        "/team/go".to_owned(),
        "/team/go/".to_owned(),
        "/team/go/v1/actions/short".to_owned(),
        format!("/te%61m/go/v1/actions/{first}"),
    ] {
        let (status, _, _) = send(
            &app,
            "GET",
            Some("alpha.snowstead.com"),
            &path,
            None,
            &[],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }

    let (status, headers, _) = send(
        &app,
        "GET",
        Some("a.b.snowstead.com"),
        &org_path,
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn sccache_webdav_through_the_organization_host(pool: PgPool) {
    seed(&pool).await;
    let app = app(&pool, "snowstead.com").await;
    let read = token(&pool, "org_a", "team", &["sccache:read"]).await;
    let write = token(&pool, "org_a", "team", &["sccache:read", "sccache:write"]).await;
    let artifact = "a".repeat(64);
    let artifact_path = format!("/a/a/a/{artifact}");
    let org_artifact = format!("/team/sccache{artifact_path}");
    let legacy_artifact = format!("/_api/v1/sccache/alpha/team{artifact_path}");
    let bytes: &[u8] = b"sccache artifact bytes";
    let org = "alpha.snowstead.com";
    let api = "api.snowstead.com";

    let (status, _, body) = send(
        &app,
        "PROPFIND",
        Some(org),
        "/team/sccache/",
        Some(&read),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("<d:href>/team/sccache/</d:href>")
    );

    let (status, _, body) = send(
        &app,
        "PROPFIND",
        Some(api),
        "/_api/v1/sccache/alpha/team/",
        Some(&read),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("<d:href>/_api/v1/sccache/alpha/team/</d:href>")
    );

    let (status, _, _) = send(
        &app,
        "MKCOL",
        Some(org),
        "/team/sccache/a/",
        Some(&write),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, _) = put_bytes(&app, org, "/team/sccache/.sccache_check", &write, b"x").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = put_bytes(&app, org, &org_artifact, &write, bytes).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, body) =
        send(&app, "GET", Some(org), &org_artifact, Some(&read), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes);

    let (status, _, body) = send(
        &app,
        "GET",
        Some(api),
        &legacy_artifact,
        Some(&read),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes);

    let (status, _, _) = send(
        &app,
        "GET",
        Some(org),
        "/team/sccache",
        Some(&read),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &app,
        "PROPFIND",
        Some(org),
        "/team/sccache//a/",
        Some(&read),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);

    let (status, _, _) = send(
        &app,
        "MKCOL",
        Some(org),
        "/team/sccache/a/b/",
        Some(&write),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, body) = send(
        &app,
        "PROPFIND",
        Some(org),
        "/team/sccache/a/b/",
        Some(&read),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("<d:href>/team/sccache/a/b/</d:href>")
    );

    let (status, _, _) = send(
        &app,
        "GET",
        Some("beta.snowstead.com"),
        &org_artifact,
        Some(&read),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn bazel_http_through_the_organization_host(pool: PgPool) {
    seed(&pool).await;
    let app = app(&pool, "snowstead.com").await;
    let token = token(&pool, "org_a", "team", &["bazel:read", "bazel:write"]).await;
    let bytes: &[u8] = b"build output";
    let hash = hex::encode(Sha256::digest(bytes));
    let second_bytes: &[u8] = b"second build output";
    let second_hash = hex::encode(Sha256::digest(second_bytes));
    let org = "alpha.snowstead.com";
    let api = "api.snowstead.com";
    let org_path = format!("/team/bazel/cas/{hash}");
    let legacy_path = format!("/_api/v1/bazel/alpha/team/cas/{hash}");

    let (status, _, _) = send(&app, "PUT", Some(org), &org_path, None, &[], bytes).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, headers, _) = put_bytes(&app, org, &org_path, &token, bytes).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");

    let (status, headers, body) =
        send(&app, "GET", Some(org), &org_path, Some(&token), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");
    assert_eq!(body, bytes);

    let (status, _, body) = send(&app, "HEAD", Some(org), &org_path, Some(&token), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());

    let (status, _, body) =
        send(&app, "GET", Some(api), &legacy_path, Some(&token), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes);

    let legacy_second = format!("/_api/v1/bazel/alpha/team/cas/{second_hash}");
    let (status, _, _) = put_bytes(&app, api, &legacy_second, &token, second_bytes).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let org_second = format!("/team/bazel/cas/{second_hash}");
    let (status, _, body) = send(&app, "GET", Some(org), &org_second, Some(&token), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, second_bytes);

    for path in [
        "/team/bazel".to_owned(),
        "/team/bazel/".to_owned(),
        format!("/team/bazel/xx/{hash}"),
    ] {
        let (status, _, _) = send(&app, "GET", Some(org), &path, Some(&token), &[], b"").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }

    let (status, _, _) = send(
        &app,
        "GET",
        Some("beta.snowstead.com"),
        &org_path,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The public cache is where the CDN-facing headers are observable: the
    // organization host must stay uncacheable at the edge, while the shared
    // host's CAS reads keep their public revalidation policy.
    let public_token = crate::token(&pool, "org_a", "bazel", &["bazel:read", "bazel:write"]).await;
    let public_bytes: &[u8] = b"public build output";
    let public_hash = hex::encode(Sha256::digest(public_bytes));
    let public_path = format!("/bazel/bazel/cas/{public_hash}");
    let (status, _, _) = put_bytes(&app, org, &public_path, &public_token, public_bytes).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, headers, body) = send(&app, "GET", Some(org), &public_path, None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, public_bytes);
    assert_eq!(headers["cloudflare-cdn-cache-control"], "no-store");
    assert_eq!(
        headers["cache-control"],
        "public, no-cache, must-revalidate, no-transform"
    );
    let shared_public = format!("/_api/v1/bazel/alpha/bazel/cas/{public_hash}");
    let (status, headers, body) =
        send(&app, "GET", Some(api), &shared_public, None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, public_bytes);
    assert_eq!(
        headers["cloudflare-cdn-cache-control"],
        "public, no-cache, must-revalidate, no-transform"
    );

    // Isolation: nothing else on the organization host reaches Bazel.
    let (status, headers, _) = send(
        &app,
        "POST",
        Some(org),
        "/build.bazel.remote.execution.v2.Capabilities/GetCapabilities",
        None,
        &[("content-type", "application/grpc")],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers["allow"], "GET, HEAD");

    // The go cache has no Bazel protocol, so its Bazel address does not exist.
    let go_token = crate::token(&pool, "org_a", "go", &["bazel:read"]).await;
    let (status, _, _) = send(
        &app,
        "GET",
        Some(org),
        &format!("/go/bazel/cas/{hash}"),
        Some(&go_token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &app,
        "GET",
        Some(org),
        &format!("/team/bazel/cas/{}", hash.to_uppercase()),
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &app,
        "GET",
        Some(org),
        &format!("/te%61m/bazel/cas/{hash}"),
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, headers, _) =
        send(&app, "DELETE", Some(org), &org_path, Some(&token), &[], b"").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers["allow"], "GET,HEAD,PUT");

    // A body that does not hash to its path is refused and never stored.
    let mismatched_path = format!("/team/bazel/cas/{}", "c".repeat(64));
    let (status, _, _) = put_bytes(&app, org, &mismatched_path, &token, b"twelve bytes").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &app,
        "GET",
        Some(org),
        &mismatched_path,
        Some(&token),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn caches_named_after_products_keep_their_nix_addresses(pool: PgPool) {
    seed(&pool).await;
    let plain = app(&pool, "").await;
    let app = app(&pool, "snowstead.com").await;
    let go_write = token(&pool, "org_a", "go", &["go:read", "go:write"]).await;
    let action = "a".repeat(64);

    for name in ["go", "sccache", "bazel"] {
        let nix = format!("/{name}/nix-cache-info");
        let (status, headers, _) = send(
            &app,
            "GET",
            Some("alpha.snowstead.com"),
            &nix,
            None,
            &[],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_eq!(headers["content-type"], "text/x-nix-cache-info", "{name}");

        let shared = format!("/alpha/{name}/nix-cache-info");
        for (router, host) in [
            (&app, Some("api.snowstead.com")),
            (&app, None),
            (&plain, Some("api.snowstead.com")),
            (&plain, None),
        ] {
            let (status, _, _) = send(router, "GET", host, &shared, None, &[], b"").await;
            assert_eq!(status, StatusCode::OK, "{name} {host:?}");
        }

        let (status, headers, _) = send(
            &app,
            "PUT",
            Some("api.snowstead.com"),
            &shared,
            None,
            &[],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{name}");
        assert_eq!(headers["allow"], "GET, HEAD", "{name}");
    }

    let (status, _, _) = put_go(
        &app,
        "alpha.snowstead.com",
        &format!("/go/go/v1/actions/{action}"),
        &go_write,
        b"go cache named go",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, body) = send(
        &app,
        "GET",
        Some("alpha.snowstead.com"),
        &format!("/go/go/v1/actions/{action}"),
        Some(&go_write),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"go cache named go");
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn other_organization_host_paths_stay_nix_reads(pool: PgPool) {
    seed(&pool).await;
    let app = app(&pool, "snowstead.com").await;
    let action = "a".repeat(64);

    let (status, headers, _) = send(
        &app,
        "PUT",
        Some("alpha.snowstead.com"),
        "/team/zig/x",
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers["allow"], "GET, HEAD");

    let (status, headers, _) = send(
        &app,
        "PUT",
        Some("alpha.snowstead.com"),
        "/team/nix-cache-info",
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers["allow"], "GET, HEAD");

    let (status, _, _) = send(
        &app,
        "GET",
        Some("alpha.snowstead.com"),
        &format!("/_api/v1/go/alpha/team/v1/actions/{action}"),
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
