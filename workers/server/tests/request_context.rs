mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use snowstead_server::{AppState, config::Config, router, serve};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;

#[sqlx::test(migrations = false)]
async fn health_rejects_database_without_application_schema(pool: PgPool) {
    let state = AppState::new(
        pool,
        Config::default(),
        common::storage(),
        reqwest::Client::new(),
    )
    .unwrap();
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn tcp_audit_uses_peer_address_unless_proxy_is_explicitly_trusted(pool: PgPool) {
    for (index, trusted, cf, forwarded, expected) in [
        (0, "", "198.51.100.7", "203.0.113.8", "127.0.0.1"),
        (
            1,
            "127.0.0.1",
            "198.51.100.7",
            "203.0.113.8",
            "198.51.100.7",
        ),
        (
            2,
            "127.0.0.1",
            "198.51.100.7, 192.0.2.9",
            "203.0.113.8",
            "203.0.113.8",
        ),
        (
            3,
            "127.0.0.1",
            "invalid",
            "203.0.113.8, 192.0.2.9",
            "127.0.0.1",
        ),
    ] {
        let server_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let state = AppState::new(
            server_pool.clone(),
            Config {
                admin_secret: "context-test-operator".into(),
                trusted_proxy_ips: trusted.into(),
                ..Default::default()
            },
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve(listener, state, async {
            let _ = stopped.await;
        }));
        let name = format!("context-{index}");
        let response = reqwest::Client::new()
            .post(format!("http://{address}/_api/v1/admin/caches"))
            .bearer_auth("context-test-operator")
            .header("cf-connecting-ip", cf)
            .header("x-forwarded-for", forwarded)
            .json(&json!({"name":name,"protocols":["nix"]}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let ip: Option<String> = sqlx::query_scalar(
            "SELECT ip FROM audit_logs WHERE action='cache.create' AND cache_name=$1",
        )
        .bind(name)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ip.as_deref(), Some(expected));
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        assert!(server_pool.is_closed());
    }
}
