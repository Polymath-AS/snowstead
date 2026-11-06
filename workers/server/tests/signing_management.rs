//! Real management router + disposable Postgres. Run via scripts/with-postgres.sh.
mod common;

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::FutureExt;
use serde_json::{Value, json};
use snowstead_server::{
    AppState,
    config::Config,
    migrations, router,
    signing::{self, Narinfo},
};
use sqlx::{Connection, Executor, PgConnection, PgPool, Row, postgres::PgConnectOptions};
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};
use tower::ServiceExt;

const SECRET: &str =
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8DoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuA==";
const PUBLIC: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
const PATH: &str = "/_api/v1/orgs/org_alpha/caches/main/signing-keys";

async fn isolated<F, Fut>(test: F) -> Result<()>
where
    F: FnOnce(PgPool) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let url = std::env::var("SNOWSTEAD_TEST_DATABASE_URL")
        .context("run via scripts/with-postgres.sh; requires disposable Postgres")?;
    let options = PgConnectOptions::from_str(&url)?;
    let mut admin = PgConnection::connect_with(&options).await?;
    let name = format!(
        "snowstead_signing_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    admin
        .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .await?;
    let pool = PgPool::connect_with(options.database(&name)).await?;
    let outcome = AssertUnwindSafe(async {
        migrations::run(&pool).await?;
        test(pool.clone()).await
    })
    .catch_unwind()
    .await;
    pool.close().await;
    admin
        .execute(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .await?;
    admin.close().await?;
    match outcome {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn config() -> Config {
    Config {
        admin_secret: "operator-secret".into(),
        signing_master_key: STANDARD.encode([42; 32]),
        signing_key_name: "shared".into(),
        signing_private_key: SECRET.into(),
        ..Default::default()
    }
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(credential) = credential {
        builder = builder.header("authorization", format!("Bearer {credential}"));
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn call(app: &Router, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    send(app, method, path, Some("operator-secret"), body).await
}

async fn seed(pool: &PgPool) -> Result<()> {
    pool.execute("INSERT INTO orgs (id, slug) VALUES ('org_alpha', 'alpha'), ('org_beta', 'beta'); INSERT INTO caches (org_id,name) VALUES ('org_alpha','main'), ('org_beta','main');").await?;
    Ok(())
}

async fn verify_render(pool: &PgPool, cfg: &Config, id: i32, public: &str) {
    let nar = Narinfo {
        store_path: "/nix/store/00000000000000000000000000000000-example".into(),
        store_path_hash: "0".repeat(32),
        nar_hash: format!("sha256:{}", "0".repeat(64)),
        nar_size: 42,
        references: vec![],
        deriver: None,
        system: None,
        signatures: vec![],
        file_hash: "a".repeat(64),
        file_size: 10,
        compression: "zstd".into(),
    };
    let text = signing::render(pool, cfg, id, "alpha/main", false, &nar)
        .await
        .unwrap();
    let (name, bytes) = public.split_once(':').unwrap();
    let signature = text
        .lines()
        .find_map(|l| l.strip_prefix(&format!("Sig: {name}:")))
        .unwrap();
    let key =
        VerifyingKey::from_bytes(&STANDARD.decode(bytes).unwrap().try_into().unwrap()).unwrap();
    let signature = Signature::from_slice(&STANDARD.decode(signature).unwrap()).unwrap();
    let fingerprint = format!("1;{};sha256:{};42;", nar.store_path, "0".repeat(52));
    key.verify_strict(fingerprint.as_bytes(), &signature)
        .unwrap();
}

#[tokio::test]
async fn generated_lifecycle_trust_retirement_and_identity_binding() -> Result<()> {
    isolated(|pool| async move {
        seed(&pool).await?;
        let cfg = config();
        let app = router(AppState::new(pool.clone(), cfg.clone(), common::storage(), reqwest::Client::new())?);
        let (_, initial) = call(&app, "GET", PATH, json!({})).await;
        let shared = format!("shared:{PUBLIC}");
        assert_eq!(initial, json!({"activePublicKey": shared, "shared": true, "keys": [{"id":null,"publicKey":shared,"state":"active"}]}));
        assert_eq!(send(&app,"POST",PATH,None,json!({})).await.0, StatusCode::UNAUTHORIZED);
        let (status, first) = call(&app,"POST",PATH,json!({})).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, second) = call(&app,"POST",PATH,json!({})).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_ne!(first["publicKey"], second["publicKey"]);
        let activate = format!("{PATH}/{}/activate", first["id"].as_str().unwrap());
        for trusted in [Value::Null, json!([shared, first["publicKey"]]), json!([shared, first["publicKey"], 1])] {
            assert_eq!(call(&app,"POST",&activate,json!({"trustedPublicKeys":trusted})).await.0, StatusCode::CONFLICT);
        }
        let trusted = json!([shared, first["publicKey"], second["publicKey"]]);
        let (a, b) = tokio::join!(call(&app,"POST",&activate,json!({"trustedPublicKeys":trusted})), call(&app,"POST",&activate,json!({"trustedPublicKeys":trusted})));
        assert!((a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT) || (b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT));
        let id: i32 = sqlx::query_scalar("SELECT id FROM caches WHERE org_id='org_alpha'").fetch_one(&pool).await?;
        verify_render(&pool,&cfg,id,first["publicKey"].as_str().unwrap()).await;
        let activate_second = format!("{PATH}/{}/activate",second["id"].as_str().unwrap());
        assert_eq!(call(&app,"POST",&activate_second,json!({"trustedPublicKeys":trusted})).await.0, StatusCode::OK);
        verify_render(&pool,&cfg,id,second["publicKey"].as_str().unwrap()).await;
        let rows: Vec<(String,Option<String>)> = sqlx::query_as("SELECT state, signing_key_sealed FROM cache_signing_keys WHERE cache_id=$1").bind(id).fetch_all(&pool).await?;
        assert_eq!(rows.iter().filter(|(s,_)| s=="active").count(),1);
        assert!(rows.iter().filter(|(s,_)| s=="retired").all(|(_,secret)|secret.is_none()));
        let (_, list) = call(&app,"GET",PATH,json!({})).await;
        assert_eq!(list["shared"],false);
        assert!(!list.to_string().contains("v2:"));
        assert!(list["keys"].as_array().unwrap().iter().all(|k| k["createdAt"].as_str().is_some_and(|s| s.ends_with('Z'))));
        let other_path = activate_second.replace("org_alpha","org_beta");
        assert_eq!(call(&app,"POST",&other_path,json!({"trustedPublicKeys":trusted})).await.0,StatusCode::NOT_FOUND);
        sqlx::query("UPDATE caches SET signing_key_name='renamed', signing_public_key=replace(signing_public_key,signing_key_name,'renamed') WHERE id=$1").bind(id).execute(&pool).await?;
        let nar = Narinfo {store_path:"/nix/store/example".into(),store_path_hash:"0".repeat(32),nar_hash:format!("sha256:{}","0".repeat(64)),nar_size:1,references:vec![],deriver:None,system:None,signatures:vec![],file_hash:"a".repeat(64),file_size:1,compression:"zstd".into()};
        assert!(signing::render(&pool,&cfg,id,"alpha/main",false,&nar).await.is_err());
        Ok(())
    }).await
}

#[tokio::test]
async fn imports_permission_pair_validation_duplicate_names_and_downgrade() -> Result<()> {
    isolated(|pool| async move {
        seed(&pool).await?;
        let cfg = config();
        let app = router(AppState::new(
            pool.clone(),
            cfg.clone(),
            common::storage(),
            reqwest::Client::new(),
        )?);
        let body = json!({"secretKey":format!("customer:{SECRET}")});
        assert_eq!(
            call(&app, "POST", PATH, body.clone()).await.0,
            StatusCode::FORBIDDEN
        );
        pool.execute("UPDATE orgs SET custom_signing_keys=true")
            .await?;
        for value in [
            json!(null),
            json!(42),
            json!("bad"),
            json!(format!("-bad:{SECRET}")),
            json!(format!("customer:{}", STANDARD.encode([0; 64]))),
        ] {
            assert_eq!(
                call(&app, "POST", PATH, json!({"secretKey":value})).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        let (a, b) = tokio::join!(
            call(&app, "POST", PATH, body.clone()),
            call(&app, "POST", PATH, body.clone())
        );
        assert!(
            (a.0 == StatusCode::CREATED && b.0 == StatusCode::CONFLICT)
                || (b.0 == StatusCode::CREATED && a.0 == StatusCode::CONFLICT)
        );
        let key = if a.0 == StatusCode::CREATED { a.1 } else { b.1 };
        assert_eq!(key["publicKey"], format!("customer:{PUBLIC}"));
        let other = PATH.replace("org_alpha", "org_beta");
        assert_eq!(
            call(&app, "POST", &other, body).await.0,
            StatusCode::CREATED,
            "customer public material may be reused"
        );
        let activate = format!("{PATH}/{}/activate", key["id"].as_str().unwrap());
        let trusted = json!({"trustedPublicKeys":[format!("shared:{PUBLIC}"),key["publicKey"]]});
        pool.execute("UPDATE orgs SET custom_signing_keys=false")
            .await?;
        assert_eq!(
            call(&app, "POST", &activate, trusted.clone()).await.0,
            StatusCode::FORBIDDEN
        );
        pool.execute("UPDATE orgs SET custom_signing_keys=true")
            .await?;
        assert_eq!(
            call(&app, "POST", &activate, trusted).await.0,
            StatusCode::OK
        );
        let id: i32 = sqlx::query_scalar("SELECT id FROM caches WHERE org_id='org_alpha'")
            .fetch_one(&pool)
            .await?;
        verify_render(&pool, &cfg, id, key["publicKey"].as_str().unwrap()).await;
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT managed_public_key IS NULL FROM cache_signing_keys WHERE id=$1"
            )
            .bind(key["id"].as_str().unwrap())
            .fetch_one(&pool)
            .await?
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cache_creation_records_active_key_and_missing_master_refuses_stage() -> Result<()> {
    isolated(|pool| async move {
        seed(&pool).await?;
        let cfg=config();
        let app=router(AppState::new(pool.clone(),cfg.clone(),common::storage(),reqwest::Client::new())?);
        assert_eq!(call(&app,"POST","/_api/v1/orgs/org_alpha/caches",json!({"name":"fresh","protocols":["nix"]})).await.0,StatusCode::CREATED);
        let (id,public,sealed):(i32,String,String)=sqlx::query_as("SELECT id,signing_public_key,signing_key_sealed FROM caches WHERE name='fresh'").fetch_one(&pool).await?;
        assert!(sealed.starts_with("v2:"));
        let history = sqlx::query("SELECT id,state,signing_public_key,signing_key_sealed,managed_public_key FROM cache_signing_keys WHERE cache_id=$1").bind(id).fetch_all(&pool).await?;
        assert_eq!(history.len(),1);
        let row=&history[0];
        let key_id: &str = row.get("id");
        assert_eq!(row.get::<&str,_>("state"),"active");
        assert_eq!(row.get::<&str,_>("signing_public_key"),public);
        assert_eq!(row.get::<Option<&str>,_>("signing_key_sealed"),Some(sealed.as_str()));
        assert_eq!(row.get::<Option<&str>,_>("managed_public_key"),public.split_once(':').map(|(_,bytes)| bytes));
        assert_eq!(sealed.split(':').nth(1),Some(key_id));
        verify_render(&pool,&cfg,id,&public).await;
        let fresh=PATH.replace("/main/","/fresh/");
        let (_,list)=call(&app,"GET",&fresh,json!({})).await;
        assert_eq!(list["activePublicKey"],public);
        assert_eq!(list["shared"],false);
        assert_eq!(list["keys"].as_array().unwrap().len(),1);
        assert_eq!(list["keys"][0]["id"],key_id);
        assert_eq!(list["keys"][0]["publicKey"],public);
        assert_eq!(list["keys"][0]["state"],"active");
        assert!(list["keys"][0]["createdAt"].as_str().is_some_and(|at| at.ends_with('Z')));
        let mut no_master=cfg.clone(); no_master.signing_master_key.clear();
        let app=router(AppState::new(pool.clone(),no_master,common::storage(),reqwest::Client::new())?);
        assert_eq!(call(&app,"POST",PATH,json!({})).await,(StatusCode::CONFLICT,json!({"error":"managed signing requires SIGNING_MASTER_KEY"})));
        Ok(())
    }).await
}
