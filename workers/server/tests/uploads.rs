mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config, router};
use sqlx::PgPool;
use tower::ServiceExt;

fn token(org: &str, cache: &str) -> String {
    let claims = json!({"jti":format!("{org}-{cache}"),"sub":"cli","iss":"snowstead","aud":"snowstead","iat":1,"org":org,"caches":[cache],"perms":["push","pull"]});
    signed_token(claims)
}

fn signed_token(claims: Value) -> String {
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
    headers: &[(&str, &str)],
    bytes: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "backend.local");
    if let Some(token) = credential {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    (
        status,
        headers,
        to_bytes(response.into_body(), 32 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}

async fn post(app: &Router, path: &str, credential: &str, body: Value) -> (StatusCode, Value) {
    let (status, _, bytes) = send(
        app,
        "POST",
        path,
        Some(credential),
        &[("content-type", "application/json")],
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))),
    )
}

// Independent encoder for a regular-file NAR, including the eight-byte framing.
fn nar(contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for word in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
        contents,
        b")",
    ] {
        out.extend_from_slice(&(word.len() as u64).to_le_bytes());
        out.extend_from_slice(word);
        out.resize(out.len() + ((8 - word.len() % 8) % 8), 0);
    }
    out
}

fn path_input(hash: &str, raw: &[u8], inline: bool) -> Value {
    json!({"storePath":format!("/nix/store/{hash}-fixture"),"storePathHash":hash,
        "narHash":format!("sha256-{}",STANDARD.encode(Sha256::digest(raw))),"narSize":raw.len(),
        "compression":"zstd","references":[],"inline":inline})
}

async fn create(app: &Router, cache: &str, credential: &str, input: Value) -> Value {
    let (status, result) = post(
        app,
        &format!("/_api/v1/caches/{cache}/upload-streams/batch"),
        credential,
        json!({"paths":[input]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    result["sessions"][0].clone()
}

async fn put_manifest(
    app: &Router,
    job: &str,
    index: usize,
    credential: &str,
    members: Value,
) -> StatusCode {
    send(
        app,
        "PUT",
        &format!("{job}/manifest/{index}"),
        Some(credential),
        &[("content-type", "application/json")],
        serde_json::to_vec(&json!({"members":members})).unwrap(),
    )
    .await
    .0
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn durable_manifest_replay_normalization_and_pagination(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true),('other',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let mut config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    config.push_jobs.members = 3;
    config.push_jobs.chunk_members = 2;
    let storage = common::storage();
    let fresh = || {
        router(
            AppState::new(
                pool.clone(),
                config.clone(),
                storage.clone(),
                reqwest::Client::new(),
            )
            .unwrap(),
        )
    };
    let app = fresh();
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let raw = nar(b"manifest bytes are not an upload");
    let mut x = path_input(&"0".repeat(32), &raw, false);
    let y = path_input(&"1".repeat(32), &raw, false);
    let z = path_input(&"2".repeat(32), &raw, false);
    let x_name = x["storePath"]
        .as_str()
        .unwrap()
        .strip_prefix("/nix/store/")
        .unwrap()
        .to_owned();
    let y_name = y["storePath"]
        .as_str()
        .unwrap()
        .strip_prefix("/nix/store/")
        .unwrap()
        .to_owned();
    x["references"] = json!([y_name, x_name, y_name]);
    let identity = json!({"idempotencyKey":"build-1","mode":"closure","roots":[z["storePath"],x["storePath"]]});
    let (status, created) = post(&app, base, &auth, identity.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        created["capabilities"],
        json!(["manifest", "prepareOnly", "completion", "readiness"])
    );
    let job = format!("{base}/{}", created["job"]["id"].as_str().unwrap());
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([y, x])).await,
        StatusCode::OK
    );
    // Another process reconstructs the builder entirely from durable rows.
    let app = fresh();
    let (_, replay) = post(&app, base, &auth, identity.clone()).await;
    assert_eq!(replay["job"]["id"], created["job"]["id"]);
    assert_eq!(replay["job"]["revision"], 1);
    let mut normalized = x.clone();
    normalized["references"] = json!([x_name, y_name]);
    normalized["inline"] = json!(true);
    normalized["narHash"] = json!(format!("sha256:{}", hex::encode(Sha256::digest(&raw))));
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([normalized, y])).await,
        StatusCode::OK
    );
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([z])).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put_manifest(&app, &job, 1, &auth, json!([z])).await,
        StatusCode::OK
    );
    assert_eq!(
        put_manifest(&app, &job, 2, &auth, json!([x, y])).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let (status, sealed) = post(&app, &format!("{job}/seal"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    assert_eq!(sealed["job"]["state"], "sealed");
    assert_eq!(sealed["job"]["revision"], 2);
    assert_eq!(sealed["job"]["manifestDigest"].as_str().unwrap().len(), 64);
    assert_eq!(
        put_manifest(&app, &job, 2, &auth, json!([x])).await,
        StatusCode::CONFLICT
    );
    let app = fresh();
    let (status, replay) = post(&app, &format!("{job}/seal"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["job"], sealed["job"]);
    let (status, _, bytes) = send(&app, "GET", &job, Some(&auth), &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let page: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(page["chunks"], json!([0, 1]));
    assert_eq!(page["members"].as_array().unwrap().len(), 2);
    assert_eq!(page["members"][0]["storePath"], x["storePath"]);
    assert_eq!(page["members"][1]["storePath"], y["storePath"]);
    let (status, _, bytes) = send(
        &app,
        "GET",
        &format!("{job}?after={}", page["next"].as_str().unwrap()),
        Some(&auth),
        &[],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(page["members"].as_array().unwrap().len(), 1);
    assert_eq!(page["members"][0]["storePath"], z["storePath"]);
    assert!(page["next"].is_null());
    // Chunk partition and arrival order do not change the sealed identity.
    let mut identity2 = identity.clone();
    identity2["idempotencyKey"] = json!("build-2");
    identity2["roots"] = json!([x["storePath"], z["storePath"], x["storePath"]]);
    let (_, second) = post(&app, base, &auth, identity2).await;
    let second = format!("{base}/{}", second["job"]["id"].as_str().unwrap());
    assert_eq!(
        put_manifest(&app, &second, 1, &auth, json!([x, z])).await,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{second}/seal"), &auth, json!({}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put_manifest(&app, &second, 0, &auth, json!([y])).await,
        StatusCode::OK
    );
    let (status, second) = post(&app, &format!("{second}/seal"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        second["job"]["manifestDigest"],
        sealed["job"]["manifestDigest"]
    );
    let mut conflict = identity;
    conflict["mode"] = json!("selected");
    assert_eq!(
        post(&app, base, &auth, conflict).await.0,
        StatusCode::CONFLICT
    );
    // A sealed manifest is not an upload, does not reserve quota, and cannot
    // expose private or other-cache manifests to a different token actor.
    assert_eq!(
        send(
            &app,
            "GET",
            &job,
            Some(&token("default", "manifest")),
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &job.replace("caches/manifest", "caches/other"),
            Some(&auth),
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM upload_sessions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_authorization_is_bounded_and_cancellation_is_terminal(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let mut config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    config.push_jobs.active_per_org = 1;
    let fresh = || {
        router(
            AppState::new(
                pool.clone(),
                config.clone(),
                common::storage(),
                reqwest::Client::new(),
            )
            .unwrap(),
        )
    };
    let app = fresh();
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let input = path_input(&"0".repeat(32), &nar(b"authorization"), false);
    let identity = json!({"idempotencyKey":"lease","mode":"selected","roots":[input["storePath"]]});
    let (_, created) = post(&app, base, &auth, identity.clone()).await;
    let id = created["job"]["id"].as_str().unwrap();
    let job = format!("{base}/{id}");
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([input])).await,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{job}/seal"), &auth, json!({})).await.0,
        StatusCode::OK
    );
    // Signed but unregistered JWTs retain legacy upload access, not delegation.
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    pool_execute(
        &pool,
        "INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) VALUES('default-*','cli','default','[\"push\"]','fixture');",
    )
    .await;
    let now: i64 = sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM NOW()))::bigint")
        .fetch_one(&pool)
        .await
        .unwrap();
    let short = signed_token(
        json!({"jti":"default-*","sub":"cli","iss":"snowstead","aud":"snowstead","iat":1,
        "exp":now+120,"org":"default","caches":["*"],"perms":["push"]}),
    );
    let (status, leased) = post(&app, &format!("{job}/resume"), &short, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{leased}");
    assert_eq!(leased["job"]["authorizationExpiresAt"], now + 120);
    assert_eq!(leased["job"]["grantGeneration"], 1);
    assert_eq!(
        leased["capabilities"],
        json!(["manifest", "prepareOnly", "completion", "readiness"])
    );
    // Request authentication tolerates clock skew; delegation does not extend
    // an already expired credential into a fresh background lease.
    let expired = signed_token(
        json!({"jti":"default-*","sub":"cli","iss":"snowstead","aud":"snowstead","iat":1,
        "exp":now-1,"org":"default","caches":["*"],"perms":["push"]}),
    );
    assert_eq!(
        post(&app, &format!("{job}/resume"), &expired, json!({}))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, idle) = post(&app, &format!("{job}/resume"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{idle}");
    assert_eq!(
        idle["job"]["authorizationExpiresAt"],
        idle["job"]["expiresAt"]
    );
    assert!(
        idle["job"]["authorizationExpiresAt"].as_i64().unwrap()
            < idle["job"]["hardExpiresAt"].as_i64().unwrap()
    );
    sqlx::query("UPDATE push_jobs SET hard_expires_at=to_timestamp($2::bigint::double precision) WHERE id=$1")
        .bind(id).bind(now+600).execute(&pool).await.unwrap();
    let restarted = fresh();
    let (status, renewed) = post(&restarted, &format!("{job}/resume"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{renewed}");
    assert_eq!(renewed["job"]["authorizationExpiresAt"], now + 600);
    assert_eq!(renewed["job"]["grantGeneration"], 3);
    // Cancellation remains possible after policy removes permission to upload.
    pool_execute(&pool,"UPDATE caches SET is_public=false; UPDATE orgs SET private_caches=false WHERE id='default'; DELETE FROM cache_protocols;").await;
    assert_eq!(
        post(&restarted, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, cancelled) = post(&restarted, &format!("{job}/cancel"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["job"]["state"], "cancelled");
    assert_eq!(cancelled["job"]["grantGeneration"], 4);
    assert!(cancelled["job"]["authorizationExpiresAt"].is_null());
    assert_eq!(
        post(&fresh(), &format!("{job}/cancel"), &auth, json!({}))
            .await
            .1,
        cancelled
    );
    pool_execute(&pool,"UPDATE caches SET is_public=true; INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    for action in ["resume", "seal"] {
        assert_eq!(
            post(&app, &format!("{job}/{action}"), &auth, json!({}))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([input])).await,
        StatusCode::CONFLICT
    );
    let replay = post(&app, base, &auth, identity).await;
    assert_eq!(replay.0, StatusCode::OK);
    assert_eq!(replay.1["job"]["state"], "cancelled");
    let (_, next) = post(
        &app,
        base,
        &auth,
        json!({"idempotencyKey":"next","mode":"selected","roots":[input["storePath"]]}),
    )
    .await;
    let next_id = next["job"]["id"].as_str().unwrap();
    sqlx::query("UPDATE push_jobs SET idle_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(next_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        post(&app, &format!("{base}/{next_id}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::GONE
    );
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_token_revocation_fences_authorization(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) VALUES('default-*','cli','default','[\"push\"]','fixture');",
    )
    .await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        admin_secret: "operator-secret".into(),
        ..Default::default()
    };
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let input = path_input(&"0".repeat(32), &nar(b"revocation"), false);
    let (_, created) = post(
        &app,
        base,
        &auth,
        json!({"idempotencyKey":"revoke","mode":"selected","roots":[input["storePath"]]}),
    )
    .await;
    let id = created["job"]["id"].as_str().unwrap();
    let job = format!("{base}/{id}");
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([input])).await,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{job}/seal"), &auth, json!({})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    let revoke = "/_api/v1/orgs/default/tokens/default-*/revoke";
    let mut fence = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('org:default',0))")
        .execute(&mut *fence)
        .await
        .unwrap();
    assert_eq!(
        post(
            &app,
            revoke,
            "operator-secret",
            json!({"reason":"test revocation"})
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fence.rollback().await.unwrap();
    let resume = format!("{job}/resume");
    let (revoked, renewed) = tokio::join!(
        post(
            &app,
            revoke,
            "operator-secret",
            json!({"reason":"test revocation"})
        ),
        post(&app, &resume, &auth, json!({}))
    );
    let revoked = if revoked.0 == StatusCode::SERVICE_UNAVAILABLE {
        post(
            &app,
            revoke,
            "operator-secret",
            json!({"reason":"test revocation"}),
        )
        .await
    } else {
        revoked
    };
    assert_eq!(revoked.0, StatusCode::OK, "{revoked:?}");
    assert!(
        matches!(
            renewed.0,
            StatusCode::OK | StatusCode::UNAUTHORIZED | StatusCode::SERVICE_UNAVAILABLE
        ),
        "{renewed:?}"
    );
    assert_eq!(
        post(&app, &resume, &auth, json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    let revoked:bool=sqlx::query_scalar("SELECT authorization_jti IS NULL AND authorization_expires_at IS NULL AND grant_generation>=2 FROM push_jobs WHERE id=$1")
        .bind(id).fetch_one(&pool).await.unwrap();
    assert!(
        revoked,
        "revocation must invalidate the durable grant, regardless of the race winner"
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_protection_matches_metadata_and_withdrawal_cancels_overlapping_jobs(
    pool: PgPool,
) {
    pool_execute(&pool,"INSERT INTO caches(name,is_public) VALUES('manifest',true),('other',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) VALUES('default-*','cli','default','[\"push\"]','fixture');").await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        admin_secret: "operator-secret".into(),
        ..Default::default()
    };
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let raw = nar(b"protected");
    let mut x = path_input(&"0".repeat(32), &raw, false);
    let y = path_input(&"1".repeat(32), &raw, false);
    let z = path_input(&"2".repeat(32), &raw, false);
    x["references"] = json!([
        format!("{}-fixture", "2".repeat(32)),
        format!("{}-fixture", "1".repeat(32))
    ]);
    let mut jobs = Vec::new();
    for (index, member) in [x.clone(), x.clone(), y.clone(), z.clone()]
        .iter()
        .enumerate()
    {
        let (status,created)=post(&app,base,&auth,json!({"idempotencyKey":format!("protect-{index}"),"mode":"selected","roots":[member["storePath"]]})).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let job = format!("{base}/{}", created["job"]["id"].as_str().unwrap());
        assert_eq!(
            put_manifest(&app, &job, 0, &auth, json!([member])).await,
            StatusCode::OK
        );
        assert_eq!(
            post(&app, &format!("{job}/seal"), &auth, json!({})).await.0,
            StatusCode::OK
        );
        assert_eq!(
            post(&app, &format!("{job}/resume"), &auth, json!({}))
                .await
                .0,
            StatusCode::OK
        );
        jobs.push(job);
    }
    // A member published later by a legacy writer also inherits protection.
    // Its reference order/duplicates do not alter content identity.
    sqlx::query("WITH b AS (INSERT INTO blob_objects(file_hash,compression,r2_key,file_size) VALUES('protected','zstd','protected',12) RETURNING id)
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,references_json)
        SELECT j.cache_id,m.store_path_hash,m.metadata->>'storePath',m.metadata->>'narHash',(m.metadata->>'narSize')::bigint,b.id,$1
        FROM push_jobs j JOIN push_job_members m ON m.job_id=j.id CROSS JOIN b WHERE j.idempotency_key='protect-0'")
        .bind(json!([x["references"][0],x["references"][1],x["references"][0]]).to_string()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,references_json)
        SELECT c.id,p.store_path_hash,p.store_path,p.nar_hash,p.nar_size,p.blob_object_id,p.references_json
        FROM published_paths p CROSS JOIN caches c WHERE c.name='other'").execute(&pool).await.unwrap();
    let eviction = "/_api/v1/orgs/default/eviction";
    let inventory = || send(&app, "GET", eviction, Some("operator-secret"), &[], vec![]);
    let (status, _, bytes) = inventory().await;
    assert_eq!(status, StatusCode::OK);
    let visible = serde_json::from_slice::<Value>(&bytes).unwrap();
    assert_eq!(visible["next"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        visible["next"]["items"][0]["cache"], "other",
        "protection must not cross cache boundaries even for shared bytes"
    );
    sqlx::query("UPDATE published_paths SET nar_size=nar_size+1")
        .execute(&pool)
        .await
        .unwrap();
    let (_, _, bytes) = inventory().await;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["next"]["items"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "a hash match alone must not protect conflicting metadata"
    );
    sqlx::query("UPDATE published_paths SET nar_size=nar_size-1")
        .execute(&pool)
        .await
        .unwrap();
    // One cancelled job cannot release another job's overlapping protection.
    assert_eq!(
        post(&app, &format!("{}/cancel", jobs[0]), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    let (_, _, bytes) = inventory().await;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["next"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Explicit deletion wins over temporary protection, including absent names.
    let (status, result) = post(
        &app,
        "/_api/v1/orgs/default/caches/manifest/paths/delete",
        "operator-secret",
        json!({"storePathHashes":[x["storePathHash"],z["storePathHash"]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    for index in [0, 1, 3] {
        assert_eq!(
            post(&app, &format!("{}/resume", jobs[index]), &auth, json!({}))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        post(&app, &format!("{}/resume", jobs[2]), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        post(
            &app,
            "/_api/v1/orgs/default/caches/manifest/evict",
            "operator-secret",
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{}/resume", jobs[2]), &auth, json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_completion_checks_current_members_and_preserves_history(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) \
        VALUES('default-*','cli','default','[\"push\"]','fixture');",
    )
    .await;
    let mut config = Config {
        jwt_secret: "test-jwt".into(),
        admin_secret: "operator-secret".into(),
        ..Default::default()
    };
    config.push_jobs.active_per_org = 1;
    config.push_jobs.members = 1;
    config.push_jobs.chunk_members = 1;
    config.push_jobs.protected_members_per_org = 130;
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let raw = nar(b"already cached completion");
    let mut member = path_input(&"0".repeat(32), &raw, false);
    // Selected mode does not require an external reference to be present.
    member["references"] = json!([format!("{}-external", "1".repeat(32))]);
    let identity =
        json!({"idempotencyKey":"completion","mode":"selected","roots":[member["storePath"]]});
    let (status, created) = post(&app, base, &auth, identity.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["job"]["id"].as_str().unwrap();
    let job = format!("{base}/{id}");
    assert_eq!(
        post(&app, &format!("{job}/complete"), &auth, json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([member])).await,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{job}/seal"), &auth, json!({})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    let missing = post(&app, &format!("{job}/complete"), &auth, json!({})).await;
    assert_eq!(missing.0, StatusCode::CONFLICT, "{}", missing.1);
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    sqlx::query("WITH b AS (INSERT INTO blob_objects(file_hash,compression,r2_key,file_size) VALUES($2,'zstd','completion',$3) RETURNING id) \
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,references_json) \
        SELECT j.cache_id,m.store_path_hash,m.metadata->>'storePath',m.metadata->>'narHash', \
        (m.metadata->>'narSize')::bigint+1,b.id,(m.metadata->'references')::text \
        FROM push_jobs j JOIN push_job_members m ON m.job_id=j.id CROSS JOIN b WHERE j.id=$1")
        .bind(id).bind(hex::encode(Sha256::digest(&compressed))).bind(compressed.len() as i64)
        .execute(&pool).await.unwrap();
    assert_eq!(
        post(&app, &format!("{job}/complete"), &auth, json!({}))
            .await
            .0,
        StatusCode::CONFLICT,
        "a conflicting cached entry is not completion"
    );
    let (status, _, summary) = send(
        &app,
        "GET",
        &format!("{job}?summary=true"),
        Some(&auth),
        &[],
        vec![],
    )
    .await;
    let summary: Value = serde_json::from_slice(&summary).unwrap();
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(
        summary["available"], false,
        "metadata must match, not merely exist"
    );
    assert_eq!(summary["blocked"], false);
    assert_eq!(summary["members"], json!([]));
    assert!(summary["next"].is_null());
    sqlx::query("UPDATE published_paths SET nar_size=nar_size-1")
        .execute(&pool)
        .await
        .unwrap();
    let (status, _, summary) = send(
        &app,
        "GET",
        &format!("{job}?summary=true"),
        Some(&auth),
        &[],
        vec![],
    )
    .await;
    let summary: Value = serde_json::from_slice(&summary).unwrap();
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["available"], true);
    assert_eq!(
        summary["job"]["state"], "sealed",
        "readiness must not complete the job"
    );
    // No linked upload session is needed when the complete set already exists.
    let (status, completed) = post(&app, &format!("{job}/complete"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{completed}");
    assert_eq!(completed["job"]["state"], "completed");
    let receipt = completed["job"].clone();
    assert_eq!(
        receipt["protectionExpiresAt"].as_i64().unwrap() - receipt["completedAt"].as_i64().unwrap(),
        300
    );
    for operation in ["complete", "cancel", "seal"] {
        let (status, replay) = post(&app, &format!("{job}/{operation}"), &auth, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(
            replay["job"], receipt,
            "{operation} must not mutate a completed receipt"
        );
    }
    let (status, replay) = post(&app, base, &auth, identity).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["job"], receipt);
    let (status, resumed) = post(&app, &format!("{job}/resume"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    assert_eq!(resumed["job"], receipt);
    assert_eq!(resumed["available"], true);
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        post(
            &app,
            "/_api/v1/caches/manifest/upload-streams/batch",
            &auth,
            json!({"jobId":id,"paths":[member]})
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "completion must not issue more upload grants"
    );
    let inventory = || {
        send(
            &app,
            "GET",
            "/_api/v1/orgs/default/eviction",
            Some("operator-secret"),
            &[],
            vec![],
        )
    };
    let (_, _, bytes) = inventory().await;
    assert!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["next"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let next = json!({"idempotencyKey":"next","mode":"selected","roots":[member["storePath"]]});
    let mut completed_ids = vec![id.to_owned()];
    // Cross the former 128-job cap without expiring or revoking any grace.
    for index in 0..129 {
        let during_grace = json!({"idempotencyKey":format!("during-grace-{index}"),"mode":"selected","roots":[member["storePath"]]});
        let (status, additional) = post(&app, base, &auth, during_grace.clone()).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "completion frees the active slot: {additional}"
        );
        assert_eq!(
            post(&app, base, &auth, next.clone()).await.0,
            StatusCode::TOO_MANY_REQUESTS,
            "unfinished jobs still consume the active slot"
        );
        let additional_id = additional["job"]["id"].as_str().unwrap();
        let additional_job = format!("{base}/{additional_id}");
        assert_eq!(
            put_manifest(&app, &additional_job, 0, &auth, json!([member])).await,
            StatusCode::OK
        );
        for operation in ["seal", "resume", "complete"] {
            let (status, result) = post(
                &app,
                &format!("{additional_job}/{operation}"),
                &auth,
                json!({}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{result}");
        }
        assert_eq!(
            post(&app, base, &auth, during_grace).await.0,
            StatusCode::OK,
            "replay needs no new budget"
        );
        completed_ids.push(additional_id.to_owned());
    }
    assert_eq!(
        post(&app, base, &auth, next.clone()).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "completion protection has a separate bounded budget"
    );
    // No maintenance run: the query alone releases grace and its budget.
    sqlx::query(
        "UPDATE push_jobs SET protection_expires_at=NOW()-INTERVAL '1 second' WHERE id=ANY($1)",
    )
    .bind(&completed_ids[..completed_ids.len() - 1])
    .execute(&pool)
    .await
    .unwrap();
    let (_, _, bytes) = inventory().await;
    assert!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["next"]["items"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the last completed job still protects the shared path"
    );
    sqlx::query("UPDATE push_jobs SET protection_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(completed_ids.last().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let (_, _, bytes) = inventory().await;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["next"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (status, next) = post(&app, base, &auth, next).await;
    assert_eq!(status, StatusCode::CREATED);
    let next_id = next["job"]["id"].as_str().unwrap();
    let next_job = format!("{base}/{next_id}");
    assert_eq!(
        put_manifest(&app, &next_job, 0, &auth, json!([member])).await,
        StatusCode::OK
    );
    for operation in ["seal", "resume"] {
        assert_eq!(
            post(&app, &format!("{next_job}/{operation}"), &auth, json!({}))
                .await
                .0,
            StatusCode::OK
        );
    }
    let mut pending_member = member.clone();
    pending_member["inline"] = json!(true);
    let (status, pending) = post(
        &app,
        "/_api/v1/caches/manifest/upload-streams/batch",
        &auth,
        json!({"jobId":next_id,"paths":[pending_member]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{pending}");
    let session = pending["sessions"][0]["sessionId"].as_str().unwrap();
    assert_eq!(
        post(&app, &format!("{next_job}/complete"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    let (_, replay) = post(&app, &format!("{next_job}/resume"), &auth, json!({})).await;
    assert_eq!(replay["available"], true);
    assert_eq!(
        send(
            &app,
            "POST",
            &format!(
                "/_api/v1/uploads/{session}/inline?fileHash={}",
                "0".repeat(64)
            ),
            Some(&auth),
            &[("content-length", "0")],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND,
        "completion must expire unfinished grants even when another writer supplied the path"
    );
    let (status, deleted) = post(
        &app,
        "/_api/v1/orgs/default/caches/manifest/paths/delete",
        "operator-secret",
        json!({"storePathHashes":[member["storePathHash"]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    let (status, resumed) = post(&app, &format!("{job}/resume"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    assert_eq!(resumed["job"]["state"], "completed");
    assert_eq!(resumed["job"]["completedAt"], receipt["completedAt"]);
    assert_eq!(resumed["available"], false);
    assert_eq!(
        post(&app, &format!("{job}/complete"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND,
        "historical completion must not recreate a withdrawn path"
    );
    // A reclaimed manifest has unknown availability, not a vacuous success.
    sqlx::query("WITH expired AS (UPDATE push_jobs SET manifest_bytes=0,idle_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1 RETURNING id), \
        chunks AS (DELETE FROM push_manifest_chunks WHERE job_id IN (SELECT id FROM expired)) \
        DELETE FROM push_job_members WHERE job_id IN (SELECT id FROM expired)")
        .bind(id).execute(&pool).await.unwrap();
    let (status, resumed) = post(&app, &format!("{job}/resume"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    assert_eq!(resumed["job"]["state"], "completed");
    assert_eq!(resumed["job"]["completedAt"], receipt["completedAt"]);
    assert!(resumed["available"].is_null());
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_uploads_reuse_sessions_and_fence_dependency_publication(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) VALUES('default-*','cli','default','[\"push\"]','fixture');").await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        admin_secret: "operator-secret".into(),
        ..Default::default()
    };
    let storage = common::storage();
    let fresh = || {
        router(
            AppState::new(
                pool.clone(),
                config.clone(),
                storage.clone(),
                reqwest::Client::new(),
            )
            .unwrap(),
        )
    };
    let app = fresh();
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let allocate = "/_api/v1/caches/manifest/upload-streams/batch";
    let raw = nar(b"parent bytes");
    let child_raw = nar(b"different prerequisite bytes");
    let mut parent = path_input(&"0".repeat(32), &raw, false);
    let child = path_input(&"1".repeat(32), &child_raw, true);
    let spare = path_input(&"2".repeat(32), &raw, true);
    parent["references"] = json!([
        format!("{}-fixture", "1".repeat(32)),
        format!("{}-fixture", "0".repeat(32)),
        format!("{}-fixture", "1".repeat(32))
    ]);
    let (status, created) = post(
        &app,
        base,
        &auth,
        json!({"idempotencyKey":"uploads","mode":"closure","roots":[parent["storePath"]]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["job"]["id"].as_str().unwrap();
    let job = format!("{base}/{id}");
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([parent, child, spare])).await,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, &format!("{job}/seal"), &auth, json!({})).await.0,
        StatusCode::OK
    );
    let request = json!({"jobId":id,"paths":[parent,child,spare]});
    assert_eq!(
        post(&app, allocate, &auth, request.clone()).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    let mut wrong = child.clone();
    wrong["narSize"] = json!(child_raw.len() + 1);
    for paths in [
        json!([parent, wrong]),
        json!([path_input(&"3".repeat(32), &raw, true)]),
        json!([child, child]),
    ] {
        assert_ne!(
            post(&app, allocate, &auth, json!({"jobId":id,"paths":paths}))
                .await
                .0,
            StatusCode::CREATED
        );
    }
    let (status, allocated) = post(&app, allocate, &auth, request.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{allocated}");
    let parent_id = allocated["sessions"][0]["sessionId"].as_str().unwrap();
    let child_id = allocated["sessions"][1]["sessionId"].as_str().unwrap();
    let spare_id = allocated["sessions"][2]["sessionId"].as_str().unwrap();
    // A restarted server returns the same sessions in the new request order.
    // Inline is a hint on first allocation, not permission to replace a receipt.
    let mut changed_hint = child.clone();
    changed_hint["inline"] = json!(false);
    let restarted = fresh();
    let (status, replay) = post(
        &restarted,
        allocate,
        &auth,
        json!({"jobId":id,"paths":[changed_hint,parent]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert_eq!(replay["sessions"][0]["sessionId"], child_id);
    assert_eq!(replay["sessions"][0]["inline"], true);
    assert_eq!(replay["sessions"][1]["sessionId"], parent_id);
    assert_eq!(
        post(
            &app,
            allocate,
            &token("default", "manifest"),
            request.clone()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{parent_id}/parts"),
            &token("default", "manifest"),
            json!({"parts":[{"partNumber":1,"size":1}]})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let file_hash = hex::encode(Sha256::digest(&compressed));
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{parent_id}/parts"),
            &auth,
            json!({"parts":[{"partNumber":1,"size":compressed.len()}]})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, _, uploaded) = send(
        &app,
        "PUT",
        &format!("/_api/v1/uploads/{parent_id}/part/1"),
        Some(&auth),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&uploaded)
    );
    let receipt = json!({"uploads":[{"sessionId":parent_id,"narHash":parent["narHash"],"narSize":raw.len(),"fileHash":file_hash,"fileSize":compressed.len(),"parts":[{"partNumber":1,"etag":serde_json::from_slice::<Value>(&uploaded).unwrap()["etag"]}]}]});
    // Interrupt after the immutable receipt commits, before a candidate can
    // start. A restarted caller must recover without rewriting sealed parts.
    pool_execute(&pool, "CREATE FUNCTION reject_preparation_start() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'injected preparation startup failure'; END $$;
        CREATE TRIGGER reject_preparation_start BEFORE INSERT ON nar_installations FOR EACH ROW EXECUTE FUNCTION reject_preparation_start();").await;
    let (_, interrupted) = post(
        &app,
        "/_api/v1/uploads/finalize?prepareOnly=true",
        &auth,
        receipt.clone(),
    )
    .await;
    assert_eq!(
        interrupted["results"][0]["published"], false,
        "{interrupted}"
    );
    assert_eq!(interrupted["results"][0]["status"], 500);
    pool_execute(&pool, "DROP TRIGGER reject_preparation_start ON nar_installations; DROP FUNCTION reject_preparation_start();").await;
    let (_, recovery) = post(&fresh(), allocate, &auth, request.clone()).await;
    assert_eq!(recovery["sessions"][0]["status"], "finalizing");
    assert_eq!(recovery["sessions"][0]["prepared"], false);
    let mut recovered_receipt = recovery["sessions"][0]["receipt"].clone();
    // The server canonicalizes equivalent NAR hash encodings. Successful
    // finalization below also checks that the returned hash is equivalent.
    recovered_receipt["narHash"] = parent["narHash"].clone();
    assert_eq!(recovered_receipt, receipt["uploads"][0]);
    assert!(recovery["sessions"][1]["receipt"].is_null());
    let (status, prepared) = post(
        &app,
        "/_api/v1/uploads/finalize?prepareOnly=true",
        &auth,
        json!({"uploads":[recovery["sessions"][0]["receipt"]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{prepared}");
    assert_eq!(prepared["results"][0]["prepared"], true, "{prepared}");
    assert_eq!(prepared["results"][0]["published"], false);
    assert_eq!(prepared["results"][0]["status"], 202);
    let (_, reused) = post(&fresh(), allocate, &auth, request.clone()).await;
    assert_eq!(reused["sessions"][0]["sessionId"], parent_id);
    assert_eq!(reused["sessions"][0]["prepared"], true, "{reused}");
    assert_eq!(reused["sessions"][1]["prepared"], false, "{reused}");
    let (status, _, progress) = send(&fresh(), "GET", &job, Some(&auth), &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let progress: Value = serde_json::from_slice(&progress).unwrap();
    assert_eq!(
        progress["members"][0]["session"]["prepared"], true,
        "{progress}"
    );
    assert_eq!(progress["members"][0]["available"], false);
    let (status, blocked) = post(&app, "/_api/v1/uploads/finalize", &auth, receipt.clone()).await;
    assert_eq!(status, StatusCode::OK, "{blocked}");
    assert_eq!(blocked["results"][0]["status"], 409, "{blocked}");
    assert!(
        blocked["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("prerequisites missing"),
        "{blocked}"
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    sqlx::query(
        "UPDATE push_jobs SET authorization_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    let (_, expired) = post(&app, "/_api/v1/uploads/finalize", &auth, receipt.clone()).await;
    assert_eq!(expired["results"][0]["status"], 409, "{expired}");
    assert_eq!(
        post(&app, allocate, &auth, request.clone()).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );

    let child_compressed = zstd::stream::encode_all(child_raw.as_slice(), 3).unwrap();
    let child_hash = hex::encode(Sha256::digest(&child_compressed));
    let frame = inline_frame(
        &json!([{"sessionId":child_id,"fileHash":child_hash,"fileSize":child_compressed.len()}]),
        &[child_compressed],
    );
    let (status, _, prepared) = send(
        &app,
        "POST",
        "/_api/v1/uploads/inline/batch?prepareOnly=true",
        Some(&auth),
        &[
            ("content-type", "application/octet-stream"),
            ("content-length", &frame.len().to_string()),
        ],
        frame,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let prepared: Value = serde_json::from_slice(&prepared).unwrap();
    assert_eq!(prepared["results"][0]["published"], false, "{prepared}");
    assert_eq!(prepared["results"][0]["prepared"], true, "{prepared}");
    // Two restarted processes recover prepared work without a client finalize
    // retry. A crashed worker's live claim must not be stolen before expiry.
    sqlx::query("UPDATE push_jobs SET work_id='crashed-worker',work_expires_at=NOW()+INTERVAL '1 minute' WHERE id=$1")
        .bind(id).execute(&pool).await.unwrap();
    let mut workers = Vec::new();
    let mut stops = Vec::new();
    for _ in 0..2 {
        let worker_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let mut worker_config = config.clone();
        worker_config.push_jobs.publication_workers = 1;
        let worker = AppState::new(
            worker_pool,
            worker_config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        stops.push(stop);
        workers.push(tokio::spawn(snowstead_server::serve(
            listener,
            worker,
            async move {
                let _ = stopped.await;
            },
        )));
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // Reclaiming execution is not renewed publication authority.
    sqlx::query("UPDATE push_jobs SET work_expires_at=NOW()-INTERVAL '1 second',authorization_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if send(
                &app,
                "GET",
                &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
                None,
                &[],
                vec![],
            )
            .await
            .0 == StatusCode::OK
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("restarted workers must publish the prepared root without another client request");
    for stop in stops {
        stop.send(()).unwrap();
    }
    for worker in workers {
        worker.await.unwrap().unwrap();
    }
    // Receipt replay observes background publication, without another byte upload.
    let restarted = fresh();
    let (_, completed) = post(
        &restarted,
        "/_api/v1/uploads/finalize?prepareOnly=true",
        &auth,
        receipt,
    )
    .await;
    assert_eq!(completed["results"][0]["published"], true, "{completed}");
    let (_, _, progress) = send(&restarted, "GET", &job, Some(&auth), &[], vec![]).await;
    let progress: Value = serde_json::from_slice(&progress).unwrap();
    assert_eq!(progress["members"][0]["available"], true, "{progress}");
    assert_eq!(progress["members"][0]["session"]["status"], "completed");
    let (_, replay) = post(&restarted, allocate, &auth, request.clone()).await;
    assert_eq!(replay["sessions"][0]["sessionId"], parent_id);
    assert_eq!(replay["sessions"][0]["status"], "completed");
    assert_eq!(
        replay["sessions"][0]["publicationResult"]["published"],
        true
    );
    let (status, _, downloaded) = send(
        &restarted,
        "GET",
        &format!("/default/manifest/nar/{file_hash}/zstd.nar"),
        None,
        &[],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(downloaded, compressed);

    // A legacy writer can win a path first, but different metadata is not a
    // successful job skip. Keep its bytes and report the conflict explicitly.
    let other_raw = nar(b"legacy won with other content");
    let other = create(
        &app,
        "manifest",
        &auth,
        path_input(&"2".repeat(32), &other_raw, true),
    )
    .await;
    let other_compressed = zstd::stream::encode_all(other_raw.as_slice(), 3).unwrap();
    let other_hash = hex::encode(Sha256::digest(&other_compressed));
    let (_, _, published) = send(
        &app,
        "POST",
        &format!(
            "/_api/v1/uploads/{}/inline?fileHash={other_hash}",
            other["sessionId"].as_str().unwrap()
        ),
        Some(&auth),
        &[("content-length", &other_compressed.len().to_string())],
        other_compressed,
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&published).unwrap()["published"],
        true
    );
    let (_, _, conflict) = send(
        &app,
        "POST",
        &format!("/_api/v1/uploads/{spare_id}/inline?fileHash={file_hash}"),
        Some(&auth),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    let conflict: Value = serde_json::from_slice(&conflict).unwrap();
    assert_eq!(conflict["published"], false, "{conflict}");
    assert_eq!(conflict["status"], 409, "{conflict}");
    assert!(
        conflict["error"]
            .as_str()
            .unwrap()
            .contains("metadata conflict")
    );
    assert_eq!(
        post(&app, &format!("{job}/cancel"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        post(&app, allocate, &auth, request).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            &app,
            "POST",
            &format!("/_api/v1/uploads/{spare_id}/inline?fileHash={file_hash}"),
            Some(&auth),
            &[("content-length", &compressed.len().to_string())],
            compressed
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_worker_splits_capacity_and_resumes_blocked_members(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO orgs(id,slug) VALUES('org_z','zeta'); \
        INSERT INTO caches(name,is_public,org_id) VALUES('manifest',true,'default'),('manifest',true,'org_z'); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) VALUES \
        ('default-*','cli','default','[\"push\"]','fixture'),('org_z-*','cli','org_z','[\"push\"]','fixture');").await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    let storage = common::storage();
    let app = router(
        AppState::new(
            pool.clone(),
            config.clone(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    // Incompressible enough to exceed the entire default org's retained quota.
    let mut random = 7u32;
    let large: Vec<u8> = (0..4096)
        .map(|_| {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            (random >> 24) as u8
        })
        .collect();
    let raw = [
        nar(&large),
        nar(b"first small member"),
        nar(b"second small member"),
        nar(b"prerequisite"),
    ];
    let bytes: Vec<_> = raw
        .iter()
        .map(|n| zstd::stream::encode_all(n.as_slice(), 3).unwrap())
        .collect();
    let limit = bytes[3].len() + bytes[1].len().max(bytes[2].len());
    assert!(bytes[0].len() > limit);
    let base = "/_api/v1/caches/manifest/push-jobs";
    let allocate = "/_api/v1/caches/manifest/upload-streams/batch";
    let mut jobs = Vec::new();
    for org in ["default", "org_z"] {
        let auth = token(org, "*");
        let indices: Vec<usize> = if org == "default" {
            vec![0, 1, 2, 3]
        } else {
            vec![2, 3]
        };
        let members: Vec<_> = indices
            .iter()
            .map(|&i| {
                let mut member = path_input(&i.to_string().repeat(32), &raw[i], true);
                if i != 3 {
                    member["references"] = json!([format!("{}-fixture", "3".repeat(32))]);
                }
                member
            })
            .collect();
        let (_,created)=post(&app,base,&auth,json!({"idempotencyKey":"capacity-worker","mode":"closure","roots":[members[0]["storePath"]]})).await;
        let id = created["job"]["id"].as_str().unwrap().to_owned();
        let job = format!("{base}/{id}");
        assert_eq!(
            put_manifest(&app, &job, 0, &auth, json!(members)).await,
            StatusCode::OK
        );
        for action in ["seal", "resume"] {
            assert_eq!(
                post(&app, &format!("{job}/{action}"), &auth, json!({}))
                    .await
                    .0,
                StatusCode::OK
            );
        }
        let (status, sessions) =
            post(&app, allocate, &auth, json!({"jobId":id,"paths":members})).await;
        assert_eq!(status, StatusCode::CREATED, "{sessions}");
        // Prepare every parent before publishing the leaf. No parent can be
        // published by request-driven fallback; only the worker can finish it.
        for (ordinal, &index) in indices.iter().enumerate() {
            let session = sessions["sessions"][ordinal]["sessionId"].as_str().unwrap();
            let hash = hex::encode(Sha256::digest(&bytes[index]));
            let (status, _, out) = send(
                &app,
                "POST",
                &format!("/_api/v1/uploads/{session}/inline?fileHash={hash}"),
                Some(&auth),
                &[("content-length", &bytes[index].len().to_string())],
                bytes[index].clone(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let out: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(out["published"], index == 3, "{out}");
            if index != 3 {
                assert_eq!(out["status"], 409, "{out}");
            }
        }
        jobs.push((org, id, members));
    }
    // A downgrade after preparation tests publication admission, not the
    // earlier per-object transfer size check.
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(limit as i64)
        .execute(&pool)
        .await
        .unwrap();
    let worker_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let mut worker_config = config;
    worker_config.push_jobs.publication_workers = 1;
    let worker =
        AppState::new(worker_pool, worker_config, storage, reqwest::Client::new()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(snowstead_server::serve(listener, worker, async move {
        let _ = stopped.await;
    }));
    let (org, id, members) = &jobs[0];
    let auth = token(org, "*");
    let job = format!("{base}/{id}");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (_, _, out) = send(&app, "GET", &job, Some(&auth), &[], vec![]).await;
            let progress: Value = serde_json::from_slice(&out).unwrap();
            let blocked = progress["members"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m["publicationError"] == "capacity_blocked")
                .count();
            let other = send(
                &app,
                "GET",
                &format!("/zeta/manifest/{}.narinfo", "2".repeat(32)),
                None,
                &[],
                vec![],
            )
            .await
            .0;
            if blocked == 2 && other == StatusCode::OK {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("an oversized member must not stop smaller members or another org");
    for (i, expected) in [
        (0, StatusCode::NOT_FOUND),
        (1, StatusCode::OK),
        (2, StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/default/manifest/{}.narinfo", i.to_string().repeat(32)),
                None,
                &[],
                vec![]
            )
            .await
            .0,
            expected
        );
    }
    // A direct client retry must also clear its blocked status, without a new
    // authorization generation. The oversized member stays prepared for resume.
    pool_execute(
        &pool,
        "UPDATE orgs SET storage_limit=NULL WHERE id='default'",
    )
    .await;
    let (status, pending) = post(&app, allocate, &auth, json!({"jobId":id,"paths":members})).await;
    assert_eq!(status, StatusCode::CREATED, "{pending}");
    let session = pending["sessions"][2]["sessionId"].as_str().unwrap();
    let hash = hex::encode(Sha256::digest(&bytes[2]));
    let (status, _, out) = send(
        &app,
        "POST",
        &format!("/_api/v1/uploads/{session}/inline?fileHash={hash}"),
        Some(&auth),
        &[("content-length", &bytes[2].len().to_string())],
        bytes[2].clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&out).unwrap()["published"],
        true
    );
    let (_, _, out) = send(&app, "GET", &job, Some(&auth), &[], vec![]).await;
    let progress: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        progress["members"][0]["publicationError"],
        "capacity_blocked"
    );
    assert!(progress["members"][2].get("publicationError").is_none());
    let (status, _, summary) = send(
        &app,
        "GET",
        &format!("{job}?summary=true"),
        Some(&auth),
        &[],
        vec![],
    )
    .await;
    let summary: Value = serde_json::from_slice(&summary).unwrap();
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["available"], false);
    assert_eq!(summary["blocked"], true);
    assert_eq!(summary["members"], json!([]));
    // Resume now publishes the retained oversized candidate without another
    // client upload or finalize request for that object.
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let mut visible = true;
            for index in 0..4 {
                visible &= send(
                    &app,
                    "GET",
                    &format!("/default/manifest/{}.narinfo", index.to_string().repeat(32)),
                    None,
                    &[],
                    vec![],
                )
                .await
                .0 == StatusCode::OK;
            }
            if visible {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("resume must publish retained candidates without another upload");
    let (status, replay) = post(&app, allocate, &auth, json!({"jobId":id,"paths":members})).await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert!(
        replay["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["status"] == "completed")
    );
    let (_, _, out) = send(&app, "GET", &job, Some(&auth), &[], vec![]).await;
    let progress: Value = serde_json::from_slice(&out).unwrap();
    assert!(
        progress["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m.get("publicationError").is_none())
    );
    for data in &bytes {
        let hash = hex::encode(Sha256::digest(data));
        let (status, _, download) = send(
            &app,
            "GET",
            &format!("/default/manifest/nar/{hash}/zstd.nar"),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&download, data);
    }
    stop.send(()).unwrap();
    serving.await.unwrap().unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_worker_batches_dependencies_without_adopting_unprepared_members(pool: PgPool) {
    check_manifest_worker_dependencies(pool, 0).await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_worker_progresses_beyond_a_blocked_candidate_window(pool: PgPool) {
    check_manifest_worker_dependencies(pool, 20).await;
}

async fn check_manifest_worker_dependencies(pool: PgPool, blocked: usize) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true);
        INSERT INTO cache_protocols SELECT id,'nix' FROM caches;
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by)
        VALUES('default-*','cli','default','[\"push\"]','fixture');",
    )
    .await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    let storage = common::storage();
    let app = router(
        AppState::new(
            pool.clone(),
            config.clone(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let mut raw: Vec<_> = [
        b"root".as_slice(),
        b"middle bytes",
        b"leaf",
        b"blocked branch",
        b"not uploaded",
    ]
    .into_iter()
    .map(nar)
    .collect();
    raw.extend(std::iter::repeat_n(raw[3].clone(), blocked));
    let bytes: Vec<_> = raw
        .iter()
        .map(|r| zstd::stream::encode_all(r.as_slice(), 3).unwrap())
        .collect();
    let mut members: Vec<_> = raw
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let hash = if i < 5 {
                i.to_string().repeat(32)
            } else {
                format!("5{:031}", i - 5)
            };
            path_input(&hash, r, true)
        })
        .collect();
    members[0]["references"] = json!([
        format!("{}-fixture", "1".repeat(32)),
        format!("{}-external", "9".repeat(32))
    ]);
    members[1]["references"] = json!([
        format!("{}-fixture", "2".repeat(32)),
        format!("{}-fixture", "1".repeat(32))
    ]);
    members[3]["references"] = json!([format!("{}-fixture", "4".repeat(32))]);
    for member in &mut members[5..] {
        member["references"] = json!([format!("{}-fixture", "4".repeat(32))]);
    }
    let base = "/_api/v1/caches/manifest/push-jobs";
    let (status, created) = post(
        &app,
        base,
        &auth,
        json!({"idempotencyKey":"closed-batch","mode":"selected","roots":[members[0]["storePath"]]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["job"]["id"].as_str().unwrap();
    let job = format!("{base}/{id}");
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!(members)).await,
        StatusCode::OK
    );
    for action in ["seal", "resume"] {
        assert_eq!(
            post(&app, &format!("{job}/{action}"), &auth, json!({}))
                .await
                .0,
            StatusCode::OK
        );
    }
    let allocate = "/_api/v1/caches/manifest/upload-streams/batch";
    let (status, sessions) = post(&app, allocate, &auth, json!({"jobId":id,"paths":members})).await;
    assert_eq!(status, StatusCode::CREATED, "{sessions}");
    // A valid compressed checksum is not proof of the declared NAR content.
    // This member must remain unavailable and must not unblock its dependents.
    let invalid_session = sessions["sessions"][4]["sessionId"].as_str().unwrap();
    let wrong_hash = hex::encode(Sha256::digest(&bytes[0]));
    let (status, _, rejected) = send(
        &app,
        "POST",
        &format!(
            "/_api/v1/uploads/{invalid_session}/inline?fileHash={wrong_hash}&prepareOnly=true"
        ),
        Some(&auth),
        &[("content-length", &bytes[0].len().to_string())],
        bytes[0].clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rejected: Value = serde_json::from_slice(&rejected).unwrap();
    assert_eq!(rejected["status"], 400, "{rejected}");
    assert_eq!(rejected["published"], false);
    assert_ne!(rejected["prepared"], true);
    for i in [0, 1, 3].into_iter().chain(5..members.len()).chain([2]) {
        let session = sessions["sessions"][i]["sessionId"].as_str().unwrap();
        let hash = hex::encode(Sha256::digest(&bytes[i]));
        let prepare_only = i != 2;
        let (status, _, result) = send(
            &app,
            "POST",
            &format!(
                "/_api/v1/uploads/{session}/inline?fileHash={hash}&prepareOnly={prepare_only}"
            ),
            Some(&auth),
            &[("content-length", &bytes[i].len().to_string())],
            bytes[i].clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let result: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(result["published"], i == 2, "{result}");
        if prepare_only {
            assert_eq!(result["prepared"], true, "{result}");
            assert_eq!(result["status"], 202, "{result}");
        }
    }
    // Observe real publication statements, not a helper or a fallback path.
    pool_execute(&pool,"CREATE TABLE closed_batches (members integer NOT NULL);
        CREATE FUNCTION closed_batches() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            INSERT INTO closed_batches SELECT count(*) FROM inserted HAVING count(*)>0;
            RETURN NULL; END $$;
        CREATE TRIGGER closed_batches AFTER INSERT ON published_paths REFERENCING NEW TABLE AS inserted
            FOR EACH STATEMENT EXECUTE FUNCTION closed_batches();").await;
    let worker_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let mut config = config;
    config.push_jobs.publication_workers = 1;
    let state = AppState::new(worker_pool, config, storage, reqwest::Client::new()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(snowstead_server::serve(listener, state, async move {
        let _ = stopped.await;
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if send(
                &app,
                "GET",
                &format!("/default/manifest/{}.narinfo", "0".repeat(32)),
                None,
                &[],
                vec![],
            )
            .await
            .0 == StatusCode::OK
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    serving.await.unwrap().unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT members FROM closed_batches")
            .fetch_all(&pool)
            .await
            .unwrap(),
        if blocked == 0 { vec![2] } else { vec![1, 1] }
    );
    for i in 0..5 {
        let (status, _, info) = send(
            &app,
            "GET",
            &format!("/default/manifest/{}.narinfo", i.to_string().repeat(32)),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(
            status,
            if i < 3 {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        );
        if i < 3 {
            assert!(
                String::from_utf8(info)
                    .unwrap()
                    .contains(&format!("NarSize: {}", raw[i].len()))
            );
            let hash = hex::encode(Sha256::digest(&bytes[i]));
            let (status, _, download) = send(
                &app,
                "GET",
                &format!("/default/manifest/nar/{hash}/zstd.nar"),
                None,
                &[],
                vec![],
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(download, bytes[i]);
        }
    }
    let (count, size): (i64, i64) =
        sqlx::query_as("SELECT path_count,size FROM caches WHERE name='manifest'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 3);
    assert_eq!(size, bytes[..3].iter().map(|b| b.len() as i64).sum::<i64>());
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_stale_worker_cannot_publish_or_release_a_replacement(pool: PgPool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Hold the first live claim's COMMIT response, after PostgreSQL releases
    // its locks. Each server has one connection, so this is its claim commit.
    let paused_worker = async |job: String| {
        let observer = pool.clone();
        let upstream = format!(
            "{}:{}",
            pool.connect_options().get_host(),
            pool.connect_options().get_port()
        );
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        let (seen, observed) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (busy, refused) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (client, _) = proxy.accept().await.unwrap();
            let backend = tokio::net::TcpStream::connect(upstream).await.unwrap();
            client.set_nodelay(true).unwrap();
            backend.set_nodelay(true).unwrap();
            let (mut client_read, mut client_write) = client.into_split();
            let (mut backend_read, mut backend_write) = backend.into_split();
            let responses = async move {
                let mut barrier = Some((seen, released));
                let mut busy = Some(busy);
                let mut refusals = 0;
                loop {
                    let mut header = [0u8; 5];
                    if backend_read.read_exact(&mut header).await.is_err() {
                        break;
                    }
                    let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
                    let mut body = vec![0u8; length - 4];
                    backend_read.read_exact(&mut body).await.unwrap();
                    if barrier.is_some() && header[0] == b'C' && body == b"COMMIT\0" {
                        let claim: Option<String> = sqlx::query_scalar(
                            "SELECT work_id FROM push_jobs WHERE id=$1 AND work_expires_at>clock_timestamp()",
                        ).bind(&job).fetch_optional(&observer).await.unwrap();
                        if let Some(claim) = claim {
                            let (seen, released) = barrier.take().unwrap();
                            seen.send(claim).unwrap();
                            released.await.unwrap();
                        }
                    }
                    // After claim acknowledgement, two failed boolean lock
                    // results identify publication and its first release.
                    if barrier.is_none()
                        && header[0] == b'D'
                        && body.len() == 7
                        && body[..6] == [0, 1, 0, 0, 0, 1]
                        && matches!(body[6], 0 | b'f')
                    {
                        refusals += 1;
                        if refusals == 2 {
                            let _ = busy.take().unwrap().send(());
                        }
                    }
                    if client_write.write_all(&header).await.is_err()
                        || client_write.write_all(&body).await.is_err()
                    {
                        break;
                    }
                }
            };
            let _ = tokio::join!(
                tokio::io::copy(&mut client_read, &mut backend_write),
                responses
            );
        });
        let worker_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(
                (*pool.connect_options())
                    .clone()
                    .host("127.0.0.1")
                    .port(port)
                    .ssl_mode(sqlx::postgres::PgSslMode::Disable),
            )
            .await
            .unwrap();
        (worker_pool, observed, release, refused)
    };
    pool_execute(&pool,"INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) VALUES('default-*','cli','default','[\"push\"]','fixture');").await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    let storage = common::storage();
    let app = router(
        AppState::new(
            pool.clone(),
            config.clone(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    // Change grants, lifetimes, and policy after the claim commits but before
    // publication. No product-only barrier or shorter lease is required.
    for scenario in 0..10 {
        let resume = scenario == 1;
        let raw = nar(if resume { b"new grant" } else { b"same grant" });
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let file_hash = hex::encode(Sha256::digest(&compressed));
        let parent_hash = format!("{:032}", scenario * 2);
        let child_hash = format!("{:032}", scenario * 2 + 1);
        let mut parent = path_input(&parent_hash, &raw, true);
        let child = path_input(&child_hash, &raw, true);
        parent["references"] = json!([format!("{child_hash}-fixture")]);
        let (status, created) = post(&app,base,&auth,json!({"idempotencyKey":format!("stale-{scenario}"),"mode":"closure","roots":[parent["storePath"]]})).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["job"]["id"].as_str().unwrap();
        let job = format!("{base}/{id}");
        assert_eq!(
            put_manifest(&app, &job, 0, &auth, json!([parent, child])).await,
            StatusCode::OK
        );
        for action in ["seal", "resume"] {
            assert_eq!(
                post(&app, &format!("{job}/{action}"), &auth, json!({}))
                    .await
                    .0,
                StatusCode::OK
            );
        }
        let (status, sessions) = post(
            &app,
            "/_api/v1/caches/manifest/upload-streams/batch",
            &auth,
            json!({"jobId":id,"paths":[parent,child]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{sessions}");
        for (index, session) in sessions["sessions"].as_array().unwrap().iter().enumerate() {
            let session = session["sessionId"].as_str().unwrap();
            let (status, _, result) = send(
                &app,
                "POST",
                &format!("/_api/v1/uploads/{session}/inline?fileHash={file_hash}"),
                Some(&auth),
                &[("content-length", &compressed.len().to_string())],
                compressed.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let result: Value = serde_json::from_slice(&result).unwrap();
            assert_eq!(result["published"], index == 1, "{result}");
        }
        let session = sessions["sessions"][0]["sessionId"].as_str().unwrap();
        let candidate: (String, String) =
            sqlx::query_as("SELECT key,phase FROM nar_installations WHERE session_id=$1")
                .bind(session)
                .fetch_one(&pool)
                .await
                .unwrap();
        let mut worker_config = config.clone();
        worker_config.push_jobs.publication_workers = 1;
        let start = async |worker_pool: PgPool| {
            let state = AppState::new(
                worker_pool,
                worker_config.clone(),
                storage.clone(),
                reqwest::Client::new(),
            )
            .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let serving = tokio::spawn(snowstead_server::serve(listener, state, async move {
                let _ = stopped.await;
            }));
            (stop, serving)
        };
        let (old_pool, old_seen, old_release, old_refused) = paused_worker(id.into()).await;
        let (old_stop, old_server) = start(old_pool).await;
        let old_id = tokio::time::timeout(std::time::Duration::from_secs(5), old_seen)
            .await
            .unwrap()
            .unwrap();
        if (3..=8).contains(&scenario) {
            match scenario {
                3..=5 => {
                    let change = [
                        "UPDATE push_jobs SET idle_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1",
                        "UPDATE push_jobs SET hard_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1",
                        "UPDATE push_jobs SET authorization_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1",
                    ][scenario - 3];
                    sqlx::query(change).bind(id).execute(&pool).await.unwrap();
                }
                6 => pool_execute(&pool, "DELETE FROM cache_protocols WHERE protocol='nix'").await,
                7 => pool_execute(&pool, "UPDATE caches SET is_public=false").await,
                8 => {
                    pool_execute(&pool, "UPDATE orgs SET storage_limit=0 WHERE id='default'").await
                }
                _ => unreachable!(),
            }
            old_release.send(()).unwrap();
            old_stop.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), old_server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if scenario == 8 {
                let (status, _, bytes) = send(&app, "GET", &job, Some(&auth), &[], vec![]).await;
                assert_eq!(status, StatusCode::OK);
                let progress: Value = serde_json::from_slice(&bytes).unwrap();
                assert!(
                    progress["members"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|m| m["storePathHash"] == parent_hash
                            && m["publicationError"] == "capacity_blocked")
                );
            } else {
                let failures: i32 =
                    sqlx::query_scalar("SELECT work_failures FROM push_jobs WHERE id=$1")
                        .bind(id)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                assert!(
                    failures > 0,
                    "scenario {scenario} must exercise a rejected publication turn"
                );
            }
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM published_paths WHERE store_path_hash=$1",
                )
                .bind(&parent_hash)
                .fetch_one(&pool)
                .await
                .unwrap(),
                0,
                "scenario {scenario}"
            );
            assert_eq!(
                sqlx::query_as::<_, (String, String)>(
                    "SELECT key,phase FROM nar_installations WHERE session_id=$1",
                )
                .bind(session)
                .fetch_one(&pool)
                .await
                .unwrap(),
                candidate,
                "scenario {scenario}"
            );
            if scenario <= 5 {
                let protected: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM nix_job_protected_paths('default',clock_timestamp()) WHERE store_path_hash=$1)",
                ).bind(&child_hash).fetch_one(&pool).await.unwrap();
                assert!(
                    !protected,
                    "scenario {scenario}: expiry must release protection without maintenance"
                );
            }
            // Policy denial must not prevent cancellation. Expired jobs need
            // no renewal: discovery must continue to exclude them.
            if scenario >= 6 {
                assert_eq!(
                    post(&app, &format!("{job}/cancel"), &auth, json!({}))
                        .await
                        .0,
                    StatusCode::OK
                );
            }
            pool_execute(&pool, "INSERT INTO cache_protocols SELECT id,'nix' FROM caches ON CONFLICT DO NOTHING;
                UPDATE caches SET is_public=true; UPDATE orgs SET storage_limit=NULL WHERE id='default';").await;
            assert_eq!(
                send(
                    &app,
                    "GET",
                    &format!("/default/manifest/{parent_hash}.narinfo"),
                    None,
                    &[],
                    vec![]
                )
                .await
                .0,
                StatusCode::NOT_FOUND,
                "scenario {scenario}"
            );
            continue;
        }
        if scenario == 9 {
            // An ordinary, non-job client wins the same path while the job's
            // claim acknowledgement is delayed. The worker must reuse that
            // publication, complete its receipt, and avoid a second charge.
            let legacy = create(&app, "manifest", &auth, parent.clone()).await;
            let legacy = legacy["sessionId"].as_str().unwrap();
            let (status, _, result) = send(
                &app,
                "POST",
                &format!("/_api/v1/uploads/{legacy}/inline?fileHash={file_hash}"),
                Some(&auth),
                &[("content-length", &compressed.len().to_string())],
                compressed.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                serde_json::from_slice::<Value>(&result).unwrap()["published"],
                true
            );
            let totals: (i64, i64) =
                sqlx::query_as("SELECT path_count,size FROM caches WHERE name='manifest'")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            old_release.send(()).unwrap();
            old_stop.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), old_server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                sqlx::query_as::<_, (i64, i64)>(
                    "SELECT path_count,size FROM caches WHERE name='manifest'"
                )
                .fetch_one(&pool)
                .await
                .unwrap(),
                totals
            );
            let outcome: Value =
                sqlx::query_scalar("SELECT publication_result FROM upload_sessions WHERE id=$1")
                    .bind(session)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(outcome["alreadyExisted"], true, "{outcome}");
        } else if scenario == 2 {
            let mut blocker = pool.begin().await.unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('org:default',0))")
                .execute(&mut *blocker)
                .await
                .unwrap();
            old_release.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), old_refused)
                .await
                .unwrap()
                .unwrap();
            blocker.rollback().await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if send(
                        &app,
                        "GET",
                        &format!("/default/manifest/{parent_hash}.narinfo"),
                        None,
                        &[],
                        vec![],
                    )
                    .await
                    .0 == StatusCode::OK
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("a busy release must not strand the job until its execution lease expires");
            old_stop.send(()).unwrap();
            old_server.await.unwrap().unwrap();
        } else {
            if resume {
                assert_eq!(
                    post(&app, &format!("{job}/resume"), &auth, json!({}))
                        .await
                        .0,
                    StatusCode::OK
                );
            } else {
                sqlx::query("UPDATE push_jobs SET work_expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1").bind(id).execute(&pool).await.unwrap();
            }
            let (new_pool, new_seen, new_release, _new_refused) = paused_worker(id.into()).await;
            let (new_stop, new_server) = start(new_pool).await;
            let new_id = tokio::time::timeout(std::time::Duration::from_secs(5), new_seen)
                .await
                .unwrap()
                .unwrap();
            assert_ne!(old_id, new_id);
            old_release.send(()).unwrap();
            old_stop.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), old_server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, Option<String>>(
                    "SELECT work_id FROM push_jobs WHERE id=$1"
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap(),
                Some(new_id),
                "scenario {scenario}, old claim {old_id}"
            );
            assert_eq!(
                sqlx::query_as::<_, (String, String)>(
                    "SELECT key,phase FROM nar_installations WHERE session_id=$1"
                )
                .bind(session)
                .fetch_one(&pool)
                .await
                .unwrap(),
                candidate
            );
            assert_eq!(
                send(
                    &app,
                    "GET",
                    &format!("/default/manifest/{parent_hash}.narinfo"),
                    None,
                    &[],
                    vec![]
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
            new_release.send(()).unwrap();
            new_stop.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), new_server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/default/manifest/{parent_hash}.narinfo"),
                None,
                &[],
                vec![]
            )
            .await
            .0,
            StatusCode::OK
        );
        let (status, replay) = post(
            &app,
            "/_api/v1/caches/manifest/upload-streams/batch",
            &auth,
            json!({"jobId":id,"paths":[parent,child]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{replay}");
        assert!(
            replay["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["status"] == "completed")
        );
        let (status, _, bytes) = send(
            &app,
            "GET",
            &format!("/default/manifest/nar/{file_hash}/zstd.nar"),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, compressed);
        assert_eq!(
            post(&app, &format!("{job}/cancel"), &auth, json!({}))
                .await
                .0,
            StatusCode::OK
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_batch_publication_and_withdrawal_preserve_job_fences(pool: PgPool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Make a dropped transaction retain its server-side locks long enough
    // to expose a fallback that starts before ROLLBACK has finished.
    let options = pool.connect_options();
    let upstream = format!("{}:{}", options.get_host(), options.get_port());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut proxy = tokio::task::JoinSet::new();
    proxy.spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (client, _) = listener.accept().await.unwrap();
            let server = tokio::net::TcpStream::connect(&upstream).await.unwrap();
            client.set_nodelay(true).unwrap();
            server.set_nodelay(true).unwrap();
            connections.spawn(async move {
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                let requests = async {
                    // SSL is disabled below. The startup packet has no type byte.
                    let length = client_read.read_u32().await?;
                    let mut body = vec![0; length as usize - 4];
                    client_read.read_exact(&mut body).await?;
                    server_write.write_u32(length).await?;
                    server_write.write_all(&body).await?;
                    while let Ok(kind) = client_read.read_u8().await {
                        let length = client_read.read_u32().await?;
                        let mut body = vec![0; length as usize - 4];
                        client_read.read_exact(&mut body).await?;
                        if kind == b'Q' && body.starts_with(b"ROLLBACK") {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        server_write.write_u8(kind).await?;
                        server_write.write_u32(length).await?;
                        server_write.write_all(&body).await?;
                    }
                    Ok::<_, std::io::Error>(())
                };
                let _ = tokio::join!(
                    requests,
                    tokio::io::copy(&mut server_read, &mut client_write)
                );
            });
        }
    });
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(
            (*options)
                .clone()
                .host("127.0.0.1")
                .port(port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable),
        )
        .await
        .unwrap();
    pool_execute(&pool,"INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) VALUES('default-*','cli','default','[\"push\"]','fixture');").await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        admin_secret: "operator-secret".into(),
        ..Default::default()
    };
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let raws = [nar(b"batch root"), nar(b"batch dependency")];
    let payloads: Vec<_> = raws
        .iter()
        .map(|raw| zstd::stream::encode_all(raw.as_slice(), 3).unwrap())
        .collect();
    for case in [4, 0, 1, 2, 3] {
        let root_hash = (case * 2).to_string().repeat(32);
        let child_hash = (case * 2 + 1).to_string().repeat(32);
        let mut root = path_input(&root_hash, &raws[0], true);
        root["references"] = json!([format!("{child_hash}-fixture")]);
        let child = path_input(&child_hash, &raws[1], true);
        let (_, created) = post(&app, base, &auth, json!({"idempotencyKey":format!("batch-{case}"),"mode":"closure","roots":[root["storePath"]]})).await;
        let id = created["job"]["id"].as_str().unwrap();
        let job = format!("{base}/{id}");
        assert_eq!(
            put_manifest(&app, &job, 0, &auth, json!([root, child])).await,
            StatusCode::OK
        );
        assert_eq!(
            post(&app, &format!("{job}/seal"), &auth, json!({})).await.0,
            StatusCode::OK
        );
        assert_eq!(
            post(&app, &format!("{job}/resume"), &auth, json!({}))
                .await
                .0,
            StatusCode::OK
        );
        let (status, sessions) = post(
            &app,
            "/_api/v1/caches/manifest/upload-streams/batch",
            &auth,
            json!({"jobId":id,"paths":[root,child]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{sessions}");
        let uploads: Vec<_> = payloads.iter().enumerate().map(|(i, bytes)| json!({"sessionId":sessions["sessions"][i]["sessionId"],"fileHash":hex::encode(Sha256::digest(bytes)),"fileSize":bytes.len()})).collect();
        if case == 4 {
            // An ordinary path wins before a conflicting job member. The
            // losing member must not satisfy its job's dependent publication.
            let ordinary = create(
                &app,
                "manifest",
                &auth,
                path_input(&child_hash, &raws[0], true),
            )
            .await;
            let mut mixed = vec![json!({"sessionId":ordinary["sessionId"],
                "fileHash":hex::encode(Sha256::digest(&payloads[0])),"fileSize":payloads[0].len()})];
            mixed.extend(uploads);
            let frame = inline_frame(
                &json!(mixed),
                &[
                    payloads[0].clone(),
                    payloads[0].clone(),
                    payloads[1].clone(),
                ],
            );
            let (status, _, result) = send(
                &app,
                "POST",
                "/_api/v1/uploads/inline/batch",
                Some(&auth),
                &[
                    ("content-type", "application/octet-stream"),
                    ("content-length", &frame.len().to_string()),
                ],
                frame,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let result: Value = serde_json::from_slice(&result).unwrap();
            assert_eq!(result["results"][0]["published"], true, "{result}");
            for item in &result["results"].as_array().unwrap()[1..] {
                assert_eq!(item["published"], false, "{result}");
                assert_eq!(item["status"], 409, "{result}");
            }
            assert_eq!(
                send(
                    &app,
                    "GET",
                    &format!("/default/manifest/{root_hash}.narinfo"),
                    None,
                    &[],
                    vec![]
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
            let (_, _, progress) = send(&app, "GET", &job, Some(&auth), &[], vec![]).await;
            let progress: Value = serde_json::from_slice(&progress).unwrap();
            for member in progress["members"].as_array().unwrap() {
                assert_ne!(member["session"]["status"], "completed", "{progress}");
            }
            continue;
        }
        let frame = inline_frame(&json!(uploads), &payloads);
        // A root-first batch cannot pass solely through singleton fallback:
        // its prerequisite is absent until the dependency-closed group commits.
        if case == 0 {
            let (status, _, result) = send(
                &app,
                "POST",
                "/_api/v1/uploads/inline/batch",
                Some(&auth),
                &[
                    ("content-type", "application/octet-stream"),
                    ("content-length", &frame.len().to_string()),
                ],
                frame.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let result: Value = serde_json::from_slice(&result).unwrap();
            assert_eq!(result["results"].as_array().unwrap().len(), 2);
            for item in result["results"].as_array().unwrap() {
                assert_eq!(item["published"], true, "{result}");
            }
            for hash in [&root_hash, &child_hash] {
                assert_eq!(
                    send(
                        &app,
                        "GET",
                        &format!("/default/manifest/{hash}.narinfo"),
                        None,
                        &[],
                        vec![]
                    )
                    .await
                    .0,
                    StatusCode::OK
                );
            }
        }
        match case {
            0 | 1 => {
                // Case 1 withdraws an absent root, cancelling its whole job.
                assert_eq!(
                    post(
                        &app,
                        "/_api/v1/orgs/default/caches/manifest/paths/delete",
                        "operator-secret",
                        json!({"storePathHashes":[root_hash]})
                    )
                    .await
                    .0,
                    StatusCode::OK
                );
            }
            2 => {
                // A reclaimed job identity cannot leave unrestricted sessions.
                sqlx::query("DELETE FROM push_jobs WHERE id=$1")
                    .bind(id)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            _ => {
                assert_eq!(
                    post(
                        &app,
                        "/_api/v1/orgs/default/tokens/default-*/revoke",
                        "operator-secret",
                        json!({"reason":"job upload fence test"})
                    )
                    .await
                    .0,
                    StatusCode::OK
                );
            }
        }
        let (status, _, result) = send(
            &app,
            "POST",
            "/_api/v1/uploads/inline/batch",
            Some(&auth),
            &[
                ("content-type", "application/octet-stream"),
                ("content-length", &frame.len().to_string()),
            ],
            frame,
        )
        .await;
        if case == 3 {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(status, StatusCode::OK);
            let result: Value = serde_json::from_slice(&result).unwrap();
            assert_eq!(result["results"].as_array().unwrap().len(), 2);
            for item in result["results"].as_array().unwrap() {
                assert_eq!(item["published"], false, "{result}");
                assert_eq!(item["status"], 409, "{result}");
            }
        }
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/default/manifest/{root_hash}.narinfo"),
                None,
                &[],
                vec![]
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_graph_boundaries_and_identity_conflicts(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let mut config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    config.push_jobs.active_per_org = 16;
    let app =
        router(AppState::new(pool, config, common::storage(), reqwest::Client::new()).unwrap());
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let raw = nar(b"graph");
    let mut x = path_input(&"0".repeat(32), &raw, false);
    let mut y = path_input(&"1".repeat(32), &raw, false);
    let z = path_input(&"2".repeat(32), &raw, false);
    x["references"] = json!([format!("{}-fixture", "1".repeat(32))]);
    y["references"] = json!([format!("{}-fixture", "0".repeat(32))]);
    let mut self_edge = x.clone();
    self_edge["references"] = json!([format!("{}-fixture", "0".repeat(32))]);
    let mut conflict = self_edge.clone();
    conflict["narSize"] = json!(raw.len() + 8);
    let cases = [
        (
            "closure",
            x["storePath"].clone(),
            json!([x]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "selected",
            x["storePath"].clone(),
            json!([x]),
            StatusCode::OK,
        ),
        (
            "closure",
            x["storePath"].clone(),
            json!([x, y]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "selected",
            x["storePath"].clone(),
            json!([x, y]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "closure",
            x["storePath"].clone(),
            json!([self_edge, self_edge]),
            StatusCode::OK,
        ),
        (
            "closure",
            x["storePath"].clone(),
            json!([self_edge, conflict]),
            StatusCode::CONFLICT,
        ),
        (
            "selected",
            z["storePath"].clone(),
            json!([self_edge]),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (i, (mode, root, members, expected)) in cases.into_iter().enumerate() {
        let (status, created) = post(
            &app,
            base,
            &auth,
            json!({"idempotencyKey":format!("graph-{i}"),"mode":mode,"roots":[root]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let job = format!("{base}/{}", created["job"]["id"].as_str().unwrap());
        assert_eq!(
            put_manifest(&app, &job, 0, &auth, members).await,
            StatusCode::OK
        );
        let (status, result) = post(&app, &format!("{job}/seal"), &auth, json!({})).await;
        assert_eq!(status, expected, "case {i}: {result}");
        if expected == StatusCode::OK {
            let (_, _, bytes) = send(&app, "GET", &job, Some(&auth), &[], vec![]).await;
            let page: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(page["members"].as_array().unwrap().len(), 1);
        }
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_admission_bounds_bodies_without_blocking_uploads(pool: PgPool) {
    use std::{sync::Arc, task::Poll, time::Duration};
    use tokio::sync::Notify;

    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    let app = router(
        AppState::new(
            single.clone(),
            config,
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let mut pending = Vec::new();
    for _ in 0..4 {
        let reached = Arc::new(Notify::new());
        let signal = reached.clone();
        let stream = futures_util::stream::poll_fn(move |_| {
            signal.notify_one();
            Poll::<Option<Result<axum::body::Bytes, std::io::Error>>>::Pending
        });
        let request = Request::builder()
            .method("POST")
            .uri(base)
            .header("authorization", format!("Bearer {auth}"))
            .body(Body::from_stream(stream))
            .unwrap();
        pending.push(tokio::spawn(app.clone().oneshot(request)));
        tokio::time::timeout(Duration::from_secs(5), reached.notified())
            .await
            .unwrap();
    }
    assert_eq!(
        send(&app, "POST", base, None, &[], b"not JSON".to_vec())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, _) =
        send(&app, "POST", base, Some(&auth), &[], b"not JSON".to_vec()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers["retry-after"], "1");
    let raw = nar(b"uploads have independent admission");
    let session = tokio::time::timeout(
        Duration::from_secs(5),
        create(
            &app,
            "manifest",
            &auth,
            path_input(&"0".repeat(32), &raw, false),
        ),
    )
    .await
    .unwrap();
    assert!(session["sessionId"].is_string());
    for task in pending {
        let response = tokio::time::timeout(Duration::from_secs(35), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }
    let (status,created) = post(&app,base,&auth,json!({"idempotencyKey":"after-timeout","mode":"selected","roots":[format!("/nix/store/{}-fixture","0".repeat(32))]})).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    single.close().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_default_limit_accepts_a_deep_closure_without_recursion(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; \
        INSERT INTO api_tokens(jti,subject,org_id,perms_json,created_by) \
        VALUES('default-*','cli','default','[\"push\"]','fixture');",
    )
    .await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    let root = format!("/nix/store/{:032b}-fixture", 9999);
    let (status, created) = post(
        &app,
        base,
        &auth,
        json!({"idempotencyKey":"deep","mode":"closure","roots":[root]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let job = format!("{base}/{}", created["job"]["id"].as_str().unwrap());
    let raw = nar(b"deep manifest");
    for ordinal in 0..100 {
        let members: Vec<_> = (ordinal * 100..(ordinal + 1) * 100)
            .map(|n| {
                let mut member = path_input(&format!("{n:032b}"), &raw, false);
                if n > 0 {
                    member["references"] = json!([format!("{:032b}-fixture", n - 1)]);
                }
                member
            })
            .collect();
        assert_eq!(
            put_manifest(&app, &job, ordinal, &auth, json!(members)).await,
            StatusCode::OK
        );
    }
    let (status, sealed) = post(&app, &format!("{job}/seal"), &auth, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    assert_eq!(sealed["job"]["inputMembers"], 10_000);
    assert_eq!(sealed["job"]["state"], "sealed");
    let mut count = 0;
    let mut cursor = String::new();
    loop {
        let (status, _, bytes) = send(
            &app,
            "GET",
            &format!("{job}?after={cursor}"),
            Some(&auth),
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: Value = serde_json::from_slice(&bytes).unwrap();
        let members = page["members"].as_array().unwrap();
        assert!(members.len() <= 100);
        for member in members {
            assert_eq!(member["storePathHash"], format!("{count:032b}"));
            count += 1;
        }
        match page["next"].as_str() {
            Some(next) => cursor = next.to_owned(),
            None => break,
        }
    }
    assert_eq!(count, 10_000);
    let id = sealed["job"]["id"].as_str().unwrap();
    assert_eq!(
        post(&app, &format!("{job}/resume"), &auth, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    sqlx::query("WITH b AS (INSERT INTO blob_objects(file_hash,compression,r2_key,file_size) VALUES('deep','zstd','deep',12) RETURNING id) \
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,references_json) \
        SELECT j.cache_id,m.store_path_hash,m.metadata->>'storePath',m.metadata->>'narHash', \
        (m.metadata->>'narSize')::bigint,b.id,(m.metadata->'references')::text \
        FROM push_jobs j JOIN push_job_members m ON m.job_id=j.id CROSS JOIN b WHERE j.id=$1")
        .bind(id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE published_paths SET nar_size=nar_size+1 WHERE store_path_hash=$1")
        .bind(format!("{:032b}", 9999))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        post(&app, &format!("{job}/complete"), &auth, json!({}))
            .await
            .0,
        StatusCode::CONFLICT,
        "a matching prefix cannot complete a 10,000-member manifest"
    );
    sqlx::query("UPDATE published_paths SET nar_size=nar_size-1 WHERE store_path_hash=$1")
        .bind(format!("{:032b}", 9999))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE push_jobs SET hard_expires_at=NOW()+INTERVAL '1 minute' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let start = std::time::Instant::now();
    let (status, completed) = post(&app, &format!("{job}/complete"), &auth, json!({})).await;
    eprintln!(
        "10,000-member completion HTTP elapsed: {:?}",
        start.elapsed()
    );
    assert_eq!(status, StatusCode::OK, "{completed}");
    assert_eq!(completed["job"]["state"], "completed");
    assert_eq!(
        completed["job"]["protectionExpiresAt"], completed["job"]["hardExpiresAt"],
        "grace cannot extend the hard deadline"
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_limits_auth_policy_and_expiry(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO orgs(id,slug) VALUES('org_b','beta'); \
        INSERT INTO caches(name,is_public) VALUES('manifest',true),('other',true); \
        INSERT INTO caches(name,is_public,org_id) VALUES('manifest',true,'org_b'); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let mut config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    config.push_jobs.members = 2;
    config.push_jobs.chunk_members = 1;
    config.push_jobs.active_per_org = 1;
    config.push_jobs.manifest_bytes = 1024;
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let auth = token("default", "*");
    let base = "/_api/v1/caches/manifest/push-jobs";
    assert_eq!(
        send(&app, "POST", base, None, &[], b"not JSON".to_vec())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let raw = nar(b"limits");
    let x = path_input(&"0".repeat(32), &raw, false);
    let y = path_input(&"1".repeat(32), &raw, false);
    let create = json!({"idempotencyKey":"limited","mode":"selected","roots":[x["storePath"]]});
    assert_eq!(
        post(&app, base, &token("default", "other"), create.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, created) = post(&app, base, &auth, create.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["job"]["id"].as_str().unwrap();
    let job = format!("{base}/{id}");
    assert_eq!(
        send(&app, "GET", &job, Some(&token("org_b", "*")), &[], vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([x, y])).await,
        StatusCode::BAD_REQUEST
    );
    let mut invalid = x.clone();
    invalid["storePathHash"] = json!("invalid");
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([invalid])).await,
        StatusCode::BAD_REQUEST
    );
    let mut oversized = x.clone();
    oversized["deriver"] = json!("a".repeat(1200));
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([oversized])).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        put_manifest(&app, &job, 0, &auth, json!([x])).await,
        StatusCode::OK
    );
    // This chunk fits the request limit but not the remaining job budget.
    let mut too_much = y.clone();
    too_much["deriver"] = json!("a".repeat(450));
    assert_eq!(
        put_manifest(&app, &job, 1, &auth, json!([too_much])).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        put_manifest(&app, &job, 1, &auth, json!([y])).await,
        StatusCode::OK
    );
    assert_eq!(
        put_manifest(&app, &job, 2, &auth, json!([x])).await,
        StatusCode::BAD_REQUEST
    );
    let mut another = create.clone();
    another["idempotencyKey"] = json!("second");
    assert_eq!(
        post(
            &app,
            "/_api/v1/caches/other/push-jobs",
            &auth,
            another.clone()
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Replays do not consume another job slot or extend the hard lifetime.
    assert_eq!(
        post(&app, base, &auth, create.clone()).await.0,
        StatusCode::OK
    );
    sqlx::query("UPDATE orgs SET private_caches=false WHERE id='default'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE caches SET is_public=false WHERE org_id='default' AND name='manifest'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        post(&app, &format!("{job}/seal"), &auth, json!({})).await.0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE caches SET is_public=true WHERE org_id='default'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cache_protocols WHERE cache_id=(SELECT id FROM caches WHERE org_id='default' AND name='manifest')").execute(&pool).await.unwrap();
    assert_eq!(
        send(&app, "GET", &job, Some(&auth), &[], vec![]).await.0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches WHERE org_id='default' AND name='manifest'").execute(&pool).await.unwrap();
    sqlx::query("UPDATE push_jobs SET hard_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, "GET", &job, Some(&auth), &[], vec![]).await.0,
        StatusCode::GONE
    );
    assert_eq!(post(&app, base, &auth, create).await.0, StatusCode::GONE);
    assert_eq!(
        post(&app, base, &auth, another).await.0,
        StatusCode::CREATED
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn manifest_protection_budget_bounds_chunks_across_caches(pool: PgPool) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('manifest',true),('other',true); \
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let auth = token("default", "*");
    let raw = nar(b"aggregate protection budgets");
    let x = path_input(&"0".repeat(32), &raw, false);
    let y = path_input(&"1".repeat(32), &raw, false);
    for (case, members, bytes) in [("members", 2, 4096), ("bytes", 4, 1024)] {
        let mut y = y.clone();
        if case == "bytes" {
            y["deriver"] = json!("a".repeat(250));
        }
        let mut config = Config {
            jwt_secret: "test-jwt".into(),
            ..Default::default()
        };
        config.push_jobs.members = 2;
        config.push_jobs.chunk_members = 1;
        config.push_jobs.manifest_bytes = 1024;
        config.push_jobs.active_per_org = 4;
        config.push_jobs.protected_members_per_org = members;
        config.push_jobs.protected_manifest_bytes_per_org = bytes;
        let app = router(
            AppState::new(
                pool.clone(),
                config,
                common::storage(),
                reqwest::Client::new(),
            )
            .unwrap(),
        );
        let mut jobs = vec![];
        for cache in ["manifest", "other"] {
            let base = format!("/_api/v1/caches/{cache}/push-jobs");
            let (status, created) = post(
                &app,
                &base,
                &auth,
                json!({"idempotencyKey":case,"mode":"selected","roots":[x["storePath"]]}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{case}: {created}");
            let job = format!("{base}/{}", created["job"]["id"].as_str().unwrap());
            jobs.push(job);
        }
        if case == "members" {
            assert_eq!(post(&app, "/_api/v1/caches/manifest/push-jobs", &auth,
                json!({"idempotencyKey":"empty-third","mode":"selected","roots":[x["storePath"]]})).await.0,
                StatusCode::TOO_MANY_REQUESTS,
                "empty builders reserve members before their first chunk");
        }
        for job in &jobs {
            assert_eq!(
                put_manifest(&app, job, 0, &auth, json!([x])).await,
                StatusCode::OK,
                "{case}"
            );
        }
        assert_eq!(
            put_manifest(&app, &jobs[1], 1, &auth, json!([y])).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{case}: aggregate, not per-job, limit"
        );
        assert_eq!(
            put_manifest(&app, &jobs[1], 0, &auth, json!([x])).await,
            StatusCode::OK,
            "{case}: replay does not reserve twice"
        );
        let (_, _, body) = send(&app, "GET", &jobs[1], Some(&auth), &[], vec![]).await;
        let progress: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            progress["job"]["revision"], 1,
            "rejected chunk must not change progress"
        );
        assert_eq!(
            post(&app, &format!("{}/cancel", jobs[0]), &auth, json!({}))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            put_manifest(&app, &jobs[1], 1, &auth, json!([y])).await,
            StatusCode::OK,
            "{case}: cancellation releases budget without maintenance"
        );
        assert_eq!(
            post(&app, &format!("{}/cancel", jobs[1]), &auth, json!({}))
                .await
                .0,
            StatusCode::OK
        );
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn inline_private_publication_and_read_isolation(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO orgs(id,slug) VALUES ('org_a','alpha'),('org_b','beta');
        INSERT INTO caches(name,org_id,is_public) VALUES ('vault','org_a',false),('empty','org_a',false),('vault','org_b',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        signing_key_name: "fixture".into(),
        signing_private_key: STANDARD.encode([7u8; 32]),
        ..Default::default()
    };
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        config.clone(),
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let a = token("org_a", "*");
    let b = token("org_b", "*");
    let hash = "0".repeat(32);
    let raw = nar(b"private bytes, not a digest possession proof");
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let file_hash = hex::encode(Sha256::digest(&compressed));
    let session = create(&app, "vault", &a, path_input(&hash, &raw, true)).await;
    let id = session["sessionId"].as_str().unwrap();
    let inline = format!("/_api/v1/uploads/{id}/inline?fileHash={file_hash}");
    assert_eq!(
        send(
            &app,
            "POST",
            &inline,
            Some(&b),
            &[("content-length", &compressed.len().to_string())],
            compressed.clone()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, _, result) = send(
        &app,
        "POST",
        &inline,
        Some(&a),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&result).unwrap()["published"],
        true
    );
    // A new state uses only durable SQL rows and objects, not per-process grants.
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let (_, _, replay) = send(
        &app,
        "POST",
        &inline,
        Some(&a),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&replay).unwrap()["published"],
        true
    );
    let path = format!("/alpha/vault/{hash}.narinfo");
    let (status, headers, _) = send(&app, "GET", &path, None, &[], vec![]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers[header::WWW_AUTHENTICATE],
        "Basic realm=\"snowstead\""
    );
    assert_eq!(
        send(&app, "GET", &path, Some(&b), &[], vec![]).await.0,
        StatusCode::FORBIDDEN
    );
    let basic = format!("Basic {}", STANDARD.encode(format!("user:{a}")));
    let (status, headers, body) = send(
        &app,
        "GET",
        &path,
        None,
        &[("authorization", &basic)],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-cache");
    let text = String::from_utf8(body.clone()).unwrap();
    assert!(text.contains(&format!("URL: nar/{file_hash}/zstd.nar\n")));
    assert!(text.contains("Sig: fixture:"));
    assert!(!headers.contains_key(header::LAST_MODIFIED));
    let (status, head, bytes) = send(&app, "HEAD", &path, Some(&a), &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());
    assert_eq!(head[header::CONTENT_LENGTH], body.len().to_string());
    let download = format!("/private/alpha/vault/nar/{file_hash}/zstd.nar");
    assert_eq!(
        send(&app, "HEAD", &download, Some(&a), &[], vec![]).await.0,
        StatusCode::OK
    );
    let (status, _, bytes) = send(&app, "GET", &download, Some(&a), &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, compressed);
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/alpha/empty/nar/{file_hash}/zstd.nar"),
            Some(&a),
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/nar/{file_hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let metered: i64 = sqlx::query_scalar("SELECT bytes FROM bandwidth_daily WHERE org_id='org_a'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(metered, compressed.len() as i64);
    pool_execute(
        &pool,
        "UPDATE caches SET is_public=true WHERE org_id='org_a' AND name='vault'",
    )
    .await;
    // SQL membership renders metadata under the current visibility policy.
    // Changing visibility alone must not expose bytes from the private bucket.
    assert_eq!(
        send(&app, "GET", &path, None, &[], vec![]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/alpha/vault/nar/{file_hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    state.finish_background().await;
}

async fn pool_execute(pool: &PgPool, sql: &'static str) {
    sqlx::raw_sql(sql).execute(pool).await.unwrap();
}

// Matches the incoming CLI's inline_frames: one header frame, then payload frames.
fn inline_frame(uploads: &Value, payloads: &[Vec<u8>]) -> Vec<u8> {
    let manifest = serde_json::to_vec(&json!({"uploads":uploads})).unwrap();
    let mut frame = (manifest.len() as u32).to_be_bytes().to_vec();
    frame.extend(manifest);
    for bytes in payloads {
        frame.extend(bytes);
    }
    frame
}

async fn send_inline_batch(app: &Router, frame: Vec<u8>) -> (StatusCode, Value) {
    let (status, _, bytes) = send(
        app,
        "POST",
        "/_api/v1/uploads/inline/batch",
        Some("legacy"),
        &[
            ("content-type", "application/octet-stream"),
            ("content-length", &frame.len().to_string()),
        ],
        frame,
    )
    .await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn inline_batch_cli_contract_validates_before_work_and_protects_capacity(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let config = Config {
        auth_token: "legacy".into(),
        ..Default::default()
    };
    let storage = if std::env::var_os("SNOWSTEAD_TEST_R2_ENDPOINT").is_some() {
        snowstead_server::storage::Storage::new(&Config::from_env()).unwrap()
    } else {
        common::storage()
    };
    let state = AppState::new(
        pool.clone(),
        config,
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let mut uploads = Vec::new();
    let mut payloads = Vec::new();
    for (hash, contents) in [
        ("2".repeat(32), b"batch first".as_slice()),
        ("3".repeat(32), b"longer batch second member".as_slice()),
    ] {
        let raw = nar(contents);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let session = create(&app, "main", "legacy", path_input(&hash, &raw, true)).await;
        uploads.push(json!({"sessionId":session["sessionId"],"fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len()}));
        payloads.push(compressed);
    }
    let uploads = json!(uploads);
    let frame = inline_frame(&uploads, &payloads);
    // Preparation-only is job-scoped. Reject it before mutating legacy sessions.
    let (status, _, rejected) = send(
        &app,
        "POST",
        "/_api/v1/uploads/inline/batch?prepareOnly=true",
        Some("legacy"),
        &[
            ("content-type", "application/octet-stream"),
            ("content-length", &frame.len().to_string()),
        ],
        frame.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rejected: Value = serde_json::from_slice(&rejected).unwrap();
    for row in rejected["results"].as_array().unwrap() {
        assert_eq!(row["status"], 409, "{rejected}");
        assert_eq!(row["published"], false);
    }
    let changed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM upload_sessions WHERE status<>'streaming' OR file_size<>0",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(changed, 0);
    for (headers, expected) in [
        (vec![], StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            vec![("content-type", "application/octet-stream")],
            StatusCode::LENGTH_REQUIRED,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "0"),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "8404997"),
            ],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "5"),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "9999"),
            ],
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            send(
                &app,
                "POST",
                "/_api/v1/uploads/inline/batch",
                Some("legacy"),
                &headers,
                frame.clone()
            )
            .await
            .0,
            expected
        );
    }
    // A bad later checksum must not seal or stage the valid first member.
    let mut bad_checksum = frame.clone();
    *bad_checksum.last_mut().unwrap() ^= 1;
    let mut duplicate = uploads.clone();
    duplicate[1]["sessionId"] = duplicate[0]["sessionId"].clone();
    let mut invalid_hash = uploads.clone();
    invalid_hash[1]["fileHash"] = json!("A".repeat(64));
    let mut oversized = uploads.clone();
    oversized[1]["fileSize"] = json!(1024 * 1024 + 1);
    let mut trailing = frame.clone();
    trailing.push(0);
    for invalid in [
        bad_checksum,
        inline_frame(&duplicate, &payloads),
        inline_frame(&invalid_hash, &payloads),
        inline_frame(&oversized, &payloads),
        inline_frame(&json!([]), &[]),
        inline_frame(&json!(vec![uploads[0].clone(); 9]), &[]),
        frame[..frame.len() - 1].to_vec(),
        trailing,
        vec![0, 0, 0, 0, 0],
        vec![0, 0, 64, 1, 0],
    ] {
        let (status, result) = send_inline_batch(&app, invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM upload_sessions WHERE status<>'streaming' OR file_size<>0",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0);
        for input in uploads.as_array().unwrap() {
            let prefix = format!("staging/{}", input["sessionId"].as_str().unwrap());
            assert!(
                storage
                    .list(true, &prefix, None, 1)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
    // Both inclusive wire bounds: eight 1 MiB payloads pass envelope validation
    // and produce ordered item-level missing-session results, not HTTP errors.
    let maximum_payloads = vec![vec![0; 1024 * 1024]; 8];
    let maximum = json!((0..8).map(|index| json!({"sessionId":format!("missing-{index}"),"fileHash":hex::encode(Sha256::digest(&maximum_payloads[index])),"fileSize":1024*1024})).collect::<Vec<_>>());
    let (status, result) = send_inline_batch(&app, inline_frame(&maximum, &maximum_payloads)).await;
    assert_eq!(status, StatusCode::OK);
    for (index, row) in result["results"].as_array().unwrap().iter().enumerate() {
        assert_eq!(row["sessionId"], maximum[index]["sessionId"]);
        assert_eq!(row["status"], 404);
    }
    let total: usize = payloads.iter().map(Vec::len).sum();
    for (limit, admitted) in [(total - 1, false), (total, true), (total, true)] {
        sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
            .bind(limit as i64)
            .execute(&pool)
            .await
            .unwrap();
        let (status, result) = send_inline_batch(&app, frame.clone()).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        for (index, row) in result["results"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["sessionId"], uploads[index]["sessionId"]);
            assert_eq!(row["published"], admitted, "{result}");
            if !admitted {
                assert_eq!(row["status"], 413, "{result}");
            }
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, if admitted { 2 } else { 0 });
    }
    let mixed = json!([{"sessionId":"missing","fileHash":uploads[0]["fileHash"],"fileSize":payloads[0].len()}, uploads[1]]);
    let (_, result) = send_inline_batch(&app, inline_frame(&mixed, &payloads)).await;
    assert_eq!(result["results"][0]["sessionId"], "missing");
    assert_eq!(result["results"][0]["status"], 404);
    assert_eq!(result["results"][1]["published"], true);
    // A real compressed NAR that expands beyond the declared size is an item
    // failure, never a publication, even though its compressed checksum matches.
    let expanded = nar(&vec![b'x'; 256 * 1024]);
    let compressed = zstd::stream::encode_all(expanded.as_slice(), 3).unwrap();
    let mut input = path_input(&"4".repeat(32), &expanded, true);
    input["narSize"] = json!(expanded.len() - 1);
    let session = create(&app, "main", "legacy", input).await;
    let rejected = json!([{"sessionId":session["sessionId"],"fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len()}]);
    let (status, result) = send_inline_batch(&app, inline_frame(&rejected, &[compressed])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["results"][0]["published"], false);
    assert_eq!(result["results"][0]["status"], 400, "{result}");
    assert_eq!(result["results"][0]["error"], "Invalid NAR");
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{}.narinfo", "4".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let audit: (String, i32, String) = sqlx::query_as(
        "SELECT action, status, detail::jsonb->>'endpoint' FROM audit_logs ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit, ("push".into(), 200, "inline-upload-batch".into()));
    state.finish_background().await;
}

async fn upload_inline(app: &Router, cache: &str, input: Value, compressed: &[u8]) -> Value {
    let session = create(app, cache, "legacy", input).await;
    let id = session["sessionId"].as_str().unwrap();
    let path = format!(
        "/_api/v1/uploads/{id}/inline?fileHash={}",
        hex::encode(Sha256::digest(compressed))
    );
    let (status, _, bytes) = send(
        app,
        "POST",
        &path,
        Some("legacy"),
        &[("content-length", &compressed.len().to_string())],
        compressed.to_vec(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn capacity_pins_and_corrupt_uploads_fail_without_exposure(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        Config {
            auth_token: "legacy".into(),
            ..Default::default()
        },
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let raw_pinned = nar(b"pinned oldest artifact");
    let raw_evict = nar(b"evictable artifact");
    let raw_new = nar(b"newly retained replacement with different compressed size");
    let pin = zstd::stream::encode_all(raw_pinned.as_slice(), 3).unwrap();
    let evict = zstd::stream::encode_all(raw_evict.as_slice(), 3).unwrap();
    let new = zstd::stream::encode_all(raw_new.as_slice(), 3).unwrap();
    let pinned_hash = "2".repeat(32);
    let evict_hash = "3".repeat(32);
    let new_hash = "4".repeat(32);
    assert_eq!(
        upload_inline(
            &app,
            "main",
            path_input(&pinned_hash, &raw_pinned, true),
            &pin
        )
        .await["published"],
        true
    );
    assert_eq!(
        upload_inline(
            &app,
            "main",
            path_input(&evict_hash, &raw_evict, true),
            &evict
        )
        .await["published"],
        true
    );
    pool_execute(&pool,"UPDATE published_paths SET last_pushed_at='2000-01-01',last_accessed_at=NULL;
        INSERT INTO pins(id,cache_id,name,keep_kind,current_revision) SELECT 'pin',id,'keep','forever',1 FROM caches;
        INSERT INTO pin_revisions(id,pin_id,revision,store_path) VALUES ('rev','pin',1,'/nix/store/pinned');").await;
    sqlx::query("INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) SELECT 'rev',id,$1 FROM caches").bind(&pinned_hash).execute(&pool).await.unwrap();
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind((pin.len() + new.len()) as i64)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        upload_inline(&app, "main", path_input(&new_hash, &raw_new, true), &new).await["published"],
        true
    );
    let kept: Vec<String> =
        sqlx::query_scalar("SELECT store_path_hash FROM published_paths ORDER BY store_path_hash")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(kept, [pinned_hash.clone(), new_hash.clone()]);
    assert_eq!(
        storage
            .head(false, &format!("main/{evict_hash}.narinfo"))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    for hash in [&pinned_hash, &new_hash] {
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/main/{hash}.narinfo"),
                None,
                &[],
                vec![]
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    // Capacity withdraws SQL membership, not the committed immutable NAR.
    let evicted_key: String =
        sqlx::query_scalar("SELECT public_key FROM blob_objects WHERE file_hash=$1")
            .bind(hex::encode(Sha256::digest(&evict)))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(storage.head(false, &evicted_key).await.is_ok());
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{evict_hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let reason: String =
        sqlx::query_scalar("SELECT reason FROM eviction_logs WHERE key LIKE '%fixture'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason, "capacity");
    sqlx::query("INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) SELECT 'rev',id,$1 FROM caches").bind(&new_hash).execute(&pool).await.unwrap();
    let denied = upload_inline(
        &app,
        "main",
        path_input(&"5".repeat(32), &raw_new, true),
        &new,
    )
    .await;
    assert_eq!(denied["published"], false);
    assert_eq!(denied["status"], 413);
    let mut corrupt = path_input(&"6".repeat(32), &raw_new, true);
    corrupt["narHash"] = json!(format!("sha256:{}", "0".repeat(64)));
    let denied = upload_inline(&app, "main", corrupt, &new).await;
    assert_eq!(denied["published"], false);
    assert_eq!(denied["status"], 400);
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{}.narinfo", "6".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // Neither a digest nor already-stored bytes substitutes for proof of possession.
    let fake = create(
        &app,
        "main",
        "legacy",
        path_input(&"7".repeat(32), &raw_new, false),
    )
    .await;
    let (status,result)=post(&app,"/_api/v1/uploads/finalize","legacy",json!({"uploads":[{"sessionId":fake["sessionId"],"narHash":path_input("",&raw_new,false)["narHash"],"narSize":raw_new.len(),"fileHash":hex::encode(Sha256::digest(&new)),"fileSize":new.len(),"parts":[{"partNumber":1,"etag":hex::encode(Sha256::digest(&new))}]}]})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["results"][0]["published"], false);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    // Abort is idempotent, but expiry is checked at request time even without GC.
    let id = fake["sessionId"].as_str().unwrap();
    for _ in 0..2 {
        assert_eq!(
            post(
                &app,
                &format!("/_api/v1/uploads/{id}/abort"),
                "legacy",
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    sqlx::query("UPDATE upload_sessions SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{id}/abort"),
            "legacy",
            json!({})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn multipart_survives_restart_and_preserves_immutable_receipts(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let config = Config {
        auth_token: "legacy".into(),
        admin_secret: "admin".into(),
        public_url: "https://cache.example.test".into(),
        ..Default::default()
    };
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        config.clone(),
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let mut seed = 0x12345678u32;
    let contents: Vec<u8> = (0..9 * 1024 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let raw = nar(&contents);
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let hash = "1".repeat(32);
    let input = path_input(&hash, &raw, false);
    let session = create(&app, "main", "legacy", input.clone()).await;
    let id = session["sessionId"].as_str().unwrap();
    let size = session["partSize"].as_u64().unwrap() as usize;
    assert!(compressed.len() > size);
    let reservations: Vec<_> = compressed
        .chunks(size)
        .enumerate()
        .map(|(i, bytes)| json!({"partNumber":i+1,"size":bytes.len()}))
        .collect();
    let (status, grants) = post(
        &app,
        "/_api/v1/uploads/parts",
        "legacy",
        json!({"uploads":[{"sessionId":id,"parts":reservations}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let grants = grants["results"][0]["parts"].as_array().unwrap();
    assert_eq!(grants.len(), 2);
    let mut receipts = Vec::new();
    for (i, (grant, bytes)) in grants.iter().zip(compressed.chunks(size)).enumerate() {
        let url = reqwest::Url::parse(grant["url"].as_str().unwrap()).unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://cache.example.test"
        );
        assert_eq!(grant["headers"]["authorization"], "Bearer legacy");
        let (status, headers, result) = send(
            &app,
            "PUT",
            url.path(),
            Some("legacy"),
            &[("content-length", &bytes.len().to_string())],
            bytes.to_vec(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&result)
        );
        let result: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(
            headers[header::ETAG],
            format!("\"{}\"", result["etag"].as_str().unwrap())
        );
        receipts.push(json!({"partNumber":i+1,"etag":result["etag"]}));
        let mut changed = bytes.to_vec();
        changed[0] ^= 1;
        assert_eq!(
            send(
                &app,
                "PUT",
                url.path(),
                Some("legacy"),
                &[("content-length", &bytes.len().to_string())],
                changed
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{id}/parts"),
            "legacy",
            json!({"parts":[{"partNumber":1,"size":size-1}]})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let receipt = json!({"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),"fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len(),"parts":receipts});
    let staging_keys: Vec<String> =
        sqlx::query_scalar("SELECT storage_key FROM upload_parts WHERE session_id=$1")
            .bind(id)
            .fetch_all(&pool)
            .await
            .unwrap();
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let envelope = json!({"uploads":[receipt.clone()]});
    // A failed ownership insert must not poison the connection or lose parts.
    // The same immutable receipt must still finalize after the fault clears.
    pool_execute(&pool, "CREATE FUNCTION fail_candidate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected candidate allocation failure'; END $$;
        CREATE TRIGGER fail_candidate BEFORE INSERT ON nar_installations FOR EACH ROW EXECUTE FUNCTION fail_candidate();").await;
    let (_, failed) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        envelope.clone(),
    )
    .await;
    assert_eq!(failed["results"][0]["published"], false, "{failed}");
    assert_eq!(failed["results"][0]["status"], 500, "{failed}");
    pool_execute(
        &pool,
        "DROP TRIGGER fail_candidate ON nar_installations; DROP FUNCTION fail_candidate();",
    )
    .await;
    // Publication and staging retirement must commit together. A cleanup
    // queue failure cannot publish the path or discard its reusable sources.
    pool_execute(&pool, "CREATE FUNCTION fail_staging_retirement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF starts_with(NEW.key,'staging/') THEN RAISE EXCEPTION 'injected staging retirement failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER fail_staging_retirement BEFORE INSERT ON object_cleanup FOR EACH ROW EXECUTE FUNCTION fail_staging_retirement();").await;
    let (_, failed) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        envelope.clone(),
    )
    .await;
    assert_eq!(failed["results"][0]["published"], false, "{failed}");
    assert_eq!(failed["results"][0]["status"], 500, "{failed}");
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for key in &staging_keys {
        assert!(storage.head(true, key).await.is_ok());
    }
    pool_execute(&pool, "DROP TRIGGER fail_staging_retirement ON object_cleanup; DROP FUNCTION fail_staging_retirement();").await;
    let (first, second) = tokio::join!(
        post(
            &app,
            "/_api/v1/uploads/finalize",
            "legacy",
            envelope.clone()
        ),
        post(&app, "/_api/v1/uploads/finalize", "legacy", envelope),
    );
    assert!(
        first.1["results"][0]["published"] == true || second.1["results"][0]["published"] == true
    );
    for (status, result) in [first, second] {
        assert_eq!(status, StatusCode::OK);
        let result = &result["results"][0];
        // A stale snapshot may ask the existing CLI to retry, never overwrite
        // a competing publication or produce an integrity error.
        assert!(
            result["published"] == true || result["status"] == 503,
            "{result}"
        );
    }
    let retired: Vec<String> =
        sqlx::query_scalar("SELECT key FROM object_cleanup WHERE is_private AND key=ANY($1)")
            .bind(&staging_keys)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(retired.len(), staging_keys.len());
    // Run the queued deletes without relying on global maintenance timing.
    // Replays below must still validate receipts and serve the final object.
    for key in retired {
        storage.delete(true, &key).await.unwrap();
        assert_eq!(
            storage.head(true, &key).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    for _ in 0..2 {
        let (status, result) = post(
            &app,
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":[receipt.clone()]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["results"][0]["published"], true, "{result}");
    }
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{id}/abort"),
            "legacy",
            json!({})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, _, bytes) = send(
        &app,
        "GET",
        &format!("/main/{hash}.narinfo"),
        None,
        &[],
        vec![],
    )
    .await;
    let text = String::from_utf8(bytes).unwrap();
    let url = text
        .lines()
        .find_map(|line| line.strip_prefix("URL: "))
        .unwrap();
    assert!(url.starts_with("nar/"));
    let download = reqwest::Url::parse("http://backend.local/main/")
        .unwrap()
        .join(url)
        .unwrap();
    let (status, _, downloaded) = send(&app, "GET", download.path(), None, &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(downloaded, compressed);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let (_, completed) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipt.clone()]}),
    )
    .await;
    let (status, _) = post(
        &app,
        "/_api/v1/orgs/default/caches/main/paths/delete",
        "admin",
        json!({"storePathHashes":[hash]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // A completed result survives withdrawal and a later quota change. It
    // reports the original outcome, not a new publication or capacity charge.
    pool_execute(&pool, "UPDATE orgs SET storage_limit=0 WHERE id='default'").await;
    let (status, replay) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipt.clone()]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, completed);
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let mut changed = receipt;
    changed["fileHash"] = json!("f".repeat(64));
    let (_, rejected) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[changed]}),
    )
    .await;
    assert_eq!(rejected["results"][0]["status"], 409);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn final_nar_digest_failure_cannot_complete_a_multipart_destination(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let mut config = Config::from_env();
    config.auth_token = "legacy".into();
    let storage = snowstead_server::storage::Storage::new(&config).unwrap();
    let state = AppState::new(
        pool.clone(),
        config,
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let mut seed = 0x76543210u32;
    let contents: Vec<u8> = (0..9 * 1024 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let raw = nar(&contents);
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    assert!(compressed.len() > 8 * 1024 * 1024);
    let hash = "d".repeat(32);
    let mut input = path_input(&hash, &raw, false);
    // A syntactically valid stream with matching compressed hash and sizes,
    // but the wrong final NAR digest. Failure occurs after the entire stream.
    input["narHash"] = json!(format!("sha256-{}", STANDARD.encode([0u8; 32])));
    let session = create(&app, "main", "legacy", input.clone()).await;
    let id = session["sessionId"].as_str().unwrap();
    let part_size = session["partSize"].as_u64().unwrap() as usize;
    let reservations: Vec<_> = compressed
        .chunks(part_size)
        .enumerate()
        .map(|(i, bytes)| json!({"partNumber":i+1,"size":bytes.len()}))
        .collect();
    let (status, reserved) = post(
        &app,
        &format!("/_api/v1/uploads/{id}/parts"),
        "legacy",
        json!({"parts":reservations}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reserved}");
    let mut receipts = Vec::new();
    for (i, bytes) in compressed.chunks(part_size).enumerate() {
        let (status, _, body) = send(
            &app,
            "PUT",
            &format!("/_api/v1/uploads/{id}/part/{}", i + 1),
            Some("legacy"),
            &[("content-length", &bytes.len().to_string())],
            bytes.to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let uploaded: Value = serde_json::from_slice(&body).unwrap();
        receipts.push(json!({"partNumber":i+1,"etag":uploaded["etag"]}));
    }
    let file_hash = hex::encode(Sha256::digest(&compressed));
    let (status, result) = tokio::time::timeout(std::time::Duration::from_secs(30), post(
        &app, "/_api/v1/uploads/finalize", "legacy",
        json!({"uploads":[{"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),"fileHash":file_hash,"fileSize":compressed.len(),"parts":receipts}]}),
    )).await.expect("failed verification must close both sides of the pipe");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["results"][0]["status"], 400, "{result}");
    assert_eq!(result["results"][0]["published"], false);
    state.finish_background().await;
    let key: String = sqlx::query_scalar("SELECT key FROM object_cleanup WHERE key LIKE $1")
        .bind(format!("nar/objects/%/{file_hash}/zstd.nar"))
        .fetch_one(&pool)
        .await
        .unwrap();
    // Retirement only queued deletion. No maintenance has run, so absence
    // proves the failed digest never completed the provider object.
    assert!(
        storage
            .head(false, &key)
            .await
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn batch_capacity_rejects_the_whole_incoming_set_and_retries_at_the_boundary(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let app = router(
        AppState::new(
            pool.clone(),
            Config {
                auth_token: "legacy".into(),
                ..Default::default()
            },
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let mut receipts = Vec::new();
    let mut total = 0i64;
    for (hash, contents) in [
        ("8".repeat(32), b"first batch member".as_slice()),
        (
            "9".repeat(32),
            b"asymmetric second member with more bytes".as_slice(),
        ),
    ] {
        let raw = nar(contents);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let input = path_input(&hash, &raw, false);
        let session = create(&app, "main", "legacy", input.clone()).await;
        let id = session["sessionId"].as_str().unwrap();
        let (status, _) = post(
            &app,
            &format!("/_api/v1/uploads/{id}/parts"),
            "legacy",
            json!({"parts":[{"partNumber":1,"size":compressed.len()}]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, bytes) = send(
            &app,
            "PUT",
            &format!("/_api/v1/uploads/{id}/part/1"),
            Some("legacy"),
            &[("content-length", &compressed.len().to_string())],
            compressed.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        receipts.push(
            json!({"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),
            "fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len(),
            "parts":[{"partNumber":1,"etag":result["etag"]}]}),
        );
        total += compressed.len() as i64;
    }
    for (limit, admitted) in [(total - 1, false), (total, true)] {
        sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
            .bind(limit)
            .execute(&pool)
            .await
            .unwrap();
        let (status, result) = post(
            &app,
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":receipts}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for row in result["results"].as_array().unwrap() {
            assert_eq!(row["published"], admitted, "{result}");
            if !admitted {
                assert_eq!(row["status"], 413, "{result}");
            }
        }
        for hash in ["8".repeat(32), "9".repeat(32)] {
            assert_eq!(
                send(
                    &app,
                    "GET",
                    &format!("/main/{hash}.narinfo"),
                    None,
                    &[],
                    vec![]
                )
                .await
                .0,
                if admitted {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, if admitted { 2 } else { 0 });
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn unresolved_canonical_writers_do_not_block_immutable_publication(pool: PgPool) {
    let storage = common::storage();
    let app = router(
        AppState::new(
            pool.clone(),
            Config {
                auth_token: "legacy".into(),
                jwt_secret: "test-jwt".into(),
                ..Default::default()
            },
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    for private in [false, true] {
        let name = if private { "secret" } else { "main" };
        let cache: i32 =
            sqlx::query_scalar("INSERT INTO caches(name,is_public) VALUES($1,$2) RETURNING id")
                .bind(name)
                .bind(!private)
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) VALUES($1,'nix')")
            .bind(cache)
            .execute(&pool)
            .await
            .unwrap();
        for tombstone in [false, true] {
            let raw = nar(format!("canonical writer {private} {tombstone}").as_bytes());
            let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
            let hash = hex::encode(Sha256::digest(&compressed));
            let key = format!(
                "{}/{hash}/zstd.nar",
                if private { "nars/sha256" } else { "nar" }
            );
            storage
                .put(private, &key, b"old canonical bytes")
                .await
                .unwrap();
            if tombstone {
                sqlx::query("INSERT INTO nar_installations(key,operation_id,source_key,upload_id,file_hash,compression,is_private,file_size,phase) VALUES($1,'old',$1,'provider-upload',$2,'zstd',$3,$4,'legacy-unresolved')")
                    .bind(&key).bind(&hash).bind(private).bind(compressed.len() as i64).execute(&pool).await.unwrap();
            } else {
                sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at) VALUES($1,$2,repeat('z',32),'/nix/store/old','sha256:test',1,$1,$3,'zstd','aborted',$4,'provider-upload',now()-interval '1 day')")
                    .bind(&hash).bind(cache).bind(compressed.len() as i64).bind(&key).execute(&pool).await.unwrap();
            }
            let store_hash = if tombstone { "a" } else { "b" }.repeat(32);
            let input = path_input(&store_hash, &raw, true);
            let published = upload_inline(&app, name, input.clone(), &compressed).await;
            assert_eq!(published["published"], true, "{published}");
            let mut bytes = Vec::new();
            use tokio::io::AsyncReadExt;
            storage
                .open(private, &key)
                .await
                .unwrap()
                .reader
                .read_to_end(&mut bytes)
                .await
                .unwrap();
            assert_eq!(bytes, b"old canonical bytes");
            assert_eq!(
                send(
                    &app,
                    "GET",
                    &format!("/{name}/{store_hash}.narinfo"),
                    Some(&token("default", name)),
                    &[],
                    vec![]
                )
                .await
                .0,
                StatusCode::OK
            );
            // Immutable publication must not reconcile or retire legacy ownership.
            let retained: i64 = if tombstone {
                sqlx::query_scalar("SELECT count(*) FROM nar_installations WHERE key=$1 AND operation_id='old' AND phase='legacy-unresolved'")
                .bind(&key)
                .fetch_one(&pool).await.unwrap()
            } else {
                sqlx::query_scalar("SELECT count(*) FROM upload_sessions WHERE id=$1 AND status='aborted' AND r2_upload_id='provider-upload'")
                .bind(&hash)
                .fetch_one(&pool).await.unwrap()
            };
            assert_eq!(retained, 1);
            let committed: String = sqlx::query_scalar(if private {
                "SELECT private_key FROM blob_objects WHERE file_hash=$1"
            } else {
                "SELECT public_key FROM blob_objects WHERE file_hash=$1"
            })
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_ne!(committed, key);
            assert!(committed.starts_with(if private {
                "nars/objects/"
            } else {
                "nar/objects/"
            }));
        }
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn batch_shared_bytes_preserve_public_and_private_delivery_after_queued_cleanup(
    pool: PgPool,
) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('main',true),('secret',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        Config {
            auth_token: "legacy".into(),
            admin_secret: "admin".into(),
            jwt_secret: "test-jwt".into(),
            ..Default::default()
        },
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let raw = nar(b"shared bytes in two independently authorized buckets");
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let hash = hex::encode(Sha256::digest(&compressed));
    let mut uploads = Vec::new();
    for (index, cache) in ["main", "secret", "main", "secret"].iter().enumerate() {
        let session = create(
            &app,
            cache,
            "legacy",
            path_input(&index.to_string().repeat(32), &raw, true),
        )
        .await;
        uploads.push(
            json!({"sessionId":session["sessionId"],"fileHash":hash,"fileSize":compressed.len()}),
        );
    }
    let (_, result) = send_inline_batch(
        &app,
        inline_frame(&json!(uploads), &vec![compressed.clone(); 4]),
    )
    .await;
    assert!(
        result["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["published"] == true),
        "{result}"
    );
    let (status, deleted) = post(
        &app,
        "/_api/v1/orgs/default/caches/main/paths/delete",
        "admin",
        json!({"storePathHashes":["0".repeat(32)]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    // Execute every queued deletion, including the unadopted group candidates.
    // Do not depend on the process-global maintenance scheduler in parallel tests.
    let retired: Vec<(bool, String)> = sqlx::query_as("SELECT is_private,key FROM object_cleanup")
        .fetch_all(&pool)
        .await
        .unwrap();
    for (private, key) in retired {
        storage.delete(private, &key).await.unwrap();
    }
    let credential = token("default", "*");
    for url in [
        format!("/nar/{hash}/zstd.nar"),
        format!("/private/secret/nar/{hash}/zstd.nar"),
    ] {
        let (status, _, bytes) = send(&app, "GET", &url, Some(&credential), &[], vec![]).await;
        assert_eq!(status, StatusCode::OK, "{url}");
        assert_eq!(bytes, compressed);
    }
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/private/secret/nar/{hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn independent_publishers_recheck_quota_and_reuse_candidates_after_rollback(pool: PgPool) {
    use std::time::Duration;

    pool_execute(
        &pool,
        "INSERT INTO caches(name) VALUES('main'),('other');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let storage = common::storage();
    let mut apps = Vec::new();
    let mut pools = Vec::new();
    for _ in 0..2 {
        let independent = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        apps.push(router(
            AppState::new(
                independent.clone(),
                Config {
                    auth_token: "legacy".into(),
                    admin_secret: "admin".into(),
                    ..Default::default()
                },
                storage.clone(),
                reqwest::Client::new(),
            )
            .unwrap(),
        ));
        pools.push(independent);
    }
    let mut receipts = Vec::new();
    let mut files = Vec::new();
    for (index, contents) in [
        b"first independent publisher".as_slice(),
        b"second independent publisher with asymmetric content and size".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let raw = nar(contents);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let input = path_input(&if index == 0 { "a" } else { "b" }.repeat(32), &raw, false);
        let cache = if index == 0 { "main" } else { "other" };
        let session = create(&apps[index], cache, "legacy", input.clone()).await;
        let id = session["sessionId"].as_str().unwrap();
        let (status, result) = post(
            &apps[index],
            &format!("/_api/v1/uploads/{id}/parts"),
            "legacy",
            json!({"parts":[{"partNumber":1,"size":compressed.len()}]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        let (status, _, bytes) = send(
            &apps[index],
            "PUT",
            &format!("/_api/v1/uploads/{id}/part/1"),
            Some("legacy"),
            &[("content-length", &compressed.len().to_string())],
            compressed.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let part: Value = serde_json::from_slice(&bytes).unwrap();
        receipts.push(
            json!({"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),
            "fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len(),
            "parts":[{"partNumber":1,"etag":part["etag"]}]}),
        );
        files.push(compressed);
    }
    let limit = files.iter().map(Vec::len).max().unwrap() as i64;
    let total = files.iter().map(|file| file.len() as i64).sum::<i64>();
    assert!(total > limit);
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(limit)
        .execute(&pool)
        .await
        .unwrap();

    // NAR fences reject publication, but permit both servers to finish storage
    // preparation. Each server has its own pool and local admission gates.
    let mut blocked = pool.begin().await.unwrap();
    for receipt in &receipts {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "nar:{}:zstd",
                receipt["fileHash"].as_str().unwrap()
            ))
            .execute(&mut *blocked)
            .await
            .unwrap();
    }
    for (app, receipt) in apps.iter().zip(&receipts) {
        let (status, result) = post(
            app,
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":[receipt]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["results"][0]["status"], 503, "{result}");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations WHERE phase='ready'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    // A repeated preparation would now fail: its original byte sources are gone.
    let sources: Vec<String> = sqlx::query_scalar("SELECT storage_key FROM upload_parts")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(sources.len(), 2);
    for key in sources {
        storage.delete(true, &key).await.unwrap();
        assert!(storage.head(true, &key).await.is_err());
    }
    blocked.rollback().await.unwrap();

    // Pause A after capacity admission, while it still owns the org fence.
    // Disable only this test trigger's lock timeout, so the barrier does not
    // depend on the host completing an assertion within the production timeout.
    pool_execute(
        &pool,
        "CREATE FUNCTION pause_publication() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.store_path_hash=repeat('a',32) THEN
            PERFORM set_config('lock_timeout','0',true);
            PERFORM pg_advisory_xact_lock(78431::bigint);
        END IF; RETURN NEW; END $$;
        CREATE TRIGGER pause_publication BEFORE INSERT ON published_paths
        FOR EACH ROW EXECUTE FUNCTION pause_publication();",
    )
    .await;
    let mut barrier = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(78431::bigint)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    let mut first = tokio::spawn({
        let app = apps[0].clone();
        let receipt = receipts[0].clone();
        async move {
            post(
                &app,
                "/_api/v1/uploads/finalize",
                "legacy",
                json!({"uploads":[receipt]}),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if first.is_finished() {
                panic!(
                    "publisher returned before the barrier: {:?}",
                    (&mut first).await.unwrap()
                );
            }
            if sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT FROM pg_locks
                WHERE locktype='advisory' AND classid=0 AND objid=78431 AND NOT granted)",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first publisher must reach the SQL barrier");
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["status"], 503, "{result}");
    barrier.rollback().await.unwrap();
    let (status, result) = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["published"], true, "{result}");

    // B needs to evict A. A later SQL error must roll back that eviction and
    // preserve B's ready candidate, not merely return a failed item result.
    pool_execute(
        &pool,
        "DROP TRIGGER pause_publication ON published_paths;
        CREATE FUNCTION fail_publication() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected publication failure'; END $$;
        CREATE TRIGGER fail_publication BEFORE INSERT ON published_paths
        FOR EACH ROW EXECUTE FUNCTION fail_publication();",
    )
    .await;
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["status"], 500, "{result}");
    assert_eq!(
        send(
            &apps[0],
            "GET",
            &format!("/main/{}.narinfo", "a".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::OK
    );
    let retained: (i64, i64) =
        sqlx::query_as("SELECT sum(path_count)::bigint,sum(size)::bigint FROM caches")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, (1, files[0].len() as i64));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations WHERE phase='ready'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    pool_execute(&pool, "DROP TRIGGER fail_publication ON published_paths;").await;

    // Pinning A makes B inadmissible. Raising the limit to the exact combined
    // size then admits B, still without its deleted staging bytes.
    let (status, result) = post(&apps[0], "/_api/v1/orgs/default/caches/main/pins", "admin",
        json!({"name":"release","storePath":format!("/nix/store/{}-fixture", "a".repeat(32)),"keep":"forever"})).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["status"], 413, "{result}");
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(total)
        .execute(&pool)
        .await
        .unwrap();
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["published"], true, "{result}");
    for (index, receipt) in receipts.iter().enumerate() {
        // Replay through the other instance must not charge or prepare again.
        let (status, result) = post(
            &apps[1 - index],
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":[receipt]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["results"][0]["published"], true, "{result}");
        let cache = if index == 0 { "main" } else { "other" };
        let hash = if index == 0 { "a" } else { "b" }.repeat(32);
        let (status, _, metadata) = send(
            &apps[index],
            "GET",
            &format!("/{cache}/{hash}.narinfo"),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8(metadata).unwrap().contains(&format!(
            "FileHash: sha256:{}",
            receipt["fileHash"].as_str().unwrap()
        )));
        let (status, _, bytes) = send(
            &apps[index],
            "GET",
            &format!("/nar/{}/zstd.nar", receipt["fileHash"].as_str().unwrap()),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, files[index]);
    }
    let retained: (i64, i64) =
        sqlx::query_as("SELECT sum(path_count)::bigint,sum(size)::bigint FROM caches")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, (2, total));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    for independent in pools {
        independent.close().await;
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn failed_publication_retains_candidate_until_session_expiry(pool: PgPool) {
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        Config {
            auth_token: "legacy".into(),
            ..Default::default()
        },
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    pool_execute(&pool, "INSERT INTO caches(name,is_public) VALUES('main',true),('secret',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;
        CREATE FUNCTION fail_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected publication failure'; END $$;
        CREATE TRIGGER fail_publication BEFORE INSERT ON published_paths FOR EACH ROW EXECUTE FUNCTION fail_publication();").await;
    let mut keys = Vec::new();
    for private in [false, true] {
        let raw = nar(format!("failed canonical publication {private}").as_bytes());
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let hash = hex::encode(Sha256::digest(&compressed));
        let result = upload_inline(
            &app,
            if private { "secret" } else { "main" },
            path_input(&"c".repeat(32), &raw, true),
            &compressed,
        )
        .await;
        assert_eq!(result["published"], false, "{result}");
        assert_eq!(result["status"], 500, "{result}");
        let key: String = sqlx::query_scalar(
            "SELECT key FROM nar_installations WHERE is_private=$1 AND key LIKE $2 AND phase='ready'",
        )
        .bind(private)
        .bind(format!("%/{hash}/zstd.nar"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(key.starts_with(if private {
            "nars/objects/"
        } else {
            "nar/objects/"
        }));
        assert!(storage.head(private, &key).await.is_ok());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM blob_objects WHERE file_hash=$1")
                .bind(&hash)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        // SQL failure keeps confirmed bytes reusable until session expiry.
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM nar_installations WHERE file_hash=$1"
            )
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM object_cleanup WHERE key=$1")
                .bind(&key)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        keys.push((private, key));
    }
    pool_execute(
        &pool,
        "DROP TRIGGER fail_publication ON published_paths;
        UPDATE upload_sessions SET expires_at=now()-interval '1 day';",
    )
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(snowstead_server::serve(listener, state, async {
        let _ = stopped.await;
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if sqlx::query_scalar::<_, i64>(
                "SELECT (SELECT count(*) FROM object_cleanup) + (SELECT count(*) FROM nar_installations)",
            )
                .fetch_one(&pool)
                .await
                .unwrap()
                == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for (private, key) in keys {
        assert_eq!(
            storage.head(private, &key).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn uncertain_immutable_completion_does_not_poison_retries_across_restart(pool: PgPool) {
    use axum::{extract::Request as AxumRequest, response::IntoResponse, routing::any};
    use snowstead_server::storage::Storage;
    let r2 = Config::from_env();
    let upstream = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
    assert_eq!(r2.r2_endpoint, upstream);
    assert!(upstream.starts_with("http://127.0.0.1:"));
    let config = Config {
        auth_token: "legacy".into(),
        ..Default::default()
    };
    let storage = Storage::new(&r2).unwrap();
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let proxy_app = Router::new().fallback(any(move |request: AxumRequest| {
        let upstream = upstream.clone();
        async move {
            let (parts, body) = request.into_parts();
            let canonical = parts.uri.path().contains("/nar/objects/");
            let completion = (parts.method == "PUT" && parts.uri.query().is_none())
                || (parts.method == "POST"
                    && parts.uri.query().is_some_and(|q| q.contains("uploadId=")));
            let response = reqwest::Client::new()
                .request(parts.method, format!("{upstream}{}", parts.uri))
                .headers(parts.headers)
                .body(to_bytes(body, 32 * 1024 * 1024).await.unwrap())
                .send()
                .await
                .unwrap();
            // The provider completes the write, but the caller receives an
            // error instead of confirmation. Abort cannot prove it never ran.
            if canonical && completion && response.status().is_success() {
                return (
                    StatusCode::FORBIDDEN,
                    "<Error><Code>AccessDenied</Code></Error>",
                )
                    .into_response();
            }
            let status = response.status();
            let headers = response.headers().clone();
            (status, headers, response.bytes().await.unwrap()).into_response()
        }
    }));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async {
        axum::serve(proxy, proxy_app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let mut interrupted = r2;
    interrupted.r2_endpoint = proxy_url;
    pool_execute(&pool,"INSERT INTO caches(name,is_public) VALUES('main',true); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let app = router(
        AppState::new(
            pool.clone(),
            config.clone(),
            Storage::new(&interrupted).unwrap(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let raw = nar(b"ambiguous completion must remain protected");
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let healthy = router(
        AppState::new(
            pool.clone(),
            config.clone(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let retained_raw = nar(b"keep this published path if the next storage copy fails");
    let retained = zstd::stream::encode_all(retained_raw.as_slice(), 3).unwrap();
    let retained_hash = "a".repeat(32);
    assert_eq!(
        upload_inline(
            &healthy,
            "main",
            path_input(&retained_hash, &retained_raw, true),
            &retained
        )
        .await["published"],
        true
    );
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(compressed.len() as i64)
        .execute(&pool)
        .await
        .unwrap();
    let hash = hex::encode(Sha256::digest(&compressed));
    let input = path_input(&"d".repeat(32), &raw, true);
    let failed = upload_inline(&app, "main", input.clone(), &compressed).await;
    assert_eq!(failed["published"], false, "{failed}");
    assert_eq!(failed["status"], 500, "{failed}");
    // Preparing bytes admits no retained capacity. Even an ambiguous provider
    // completion cannot withdraw an existing path before SQL publication.
    assert_eq!(
        send(
            &healthy,
            "GET",
            &format!("/main/{retained_hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM eviction_logs")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let uncertain: String = sqlx::query_scalar("SELECT key FROM object_cleanup WHERE key LIKE $1")
        .bind(format!("nar/objects/%/{hash}/zstd.nar"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(storage.head(false, &uncertain).await.is_ok());
    let source: Option<String> = sqlx::query_scalar(
        "SELECT storage_key FROM upload_parts WHERE session_id=$1 AND part_number=1",
    )
    .bind(failed["sessionId"].as_str().unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        source.is_none(),
        "inline bytes must not create a staged source"
    );
    assert!(
        storage
            .list(
                true,
                &format!("staging/{}", failed["sessionId"].as_str().unwrap()),
                None,
                1
            )
            .await
            .unwrap()
            .is_empty()
    );
    let restarted = router(
        AppState::new(
            pool.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    // Replay the same sealed session after recreating application state.
    let (status, _, retry) = send(
        &restarted,
        "POST",
        &format!(
            "/_api/v1/uploads/{}/inline?fileHash={hash}",
            failed["sessionId"].as_str().unwrap()
        ),
        Some("legacy"),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let retry: Value = serde_json::from_slice(&retry).unwrap();
    assert_eq!(retry["published"], true, "{retry}");
    let committed: String =
        sqlx::query_scalar("SELECT public_key FROM blob_objects WHERE file_hash=$1")
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(committed, uncertain);
    assert!(storage.head(false, &uncertain).await.is_ok());
    assert_eq!(
        send(
            &restarted,
            "GET",
            &format!("/nar/{hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .2,
        compressed
    );
    stop.send(()).unwrap();
    proxy_task.await.unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn ordered_batch_preparation_with_duplicate_paths_and_partial_failures_pool_one(
    pool: PgPool,
) {
    use axum::{extract::Request as AxumRequest, response::IntoResponse, routing::any};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('inline'),('multipart'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; UPDATE orgs SET storage_limit=1073741824 WHERE id='default';").await;
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    for inline in [true, false] {
        let upstream = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
        assert!(upstream.starts_with("http://127.0.0.1:"));
        let ids = Arc::new(Mutex::new((String::new(), String::new())));
        let overtaken = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let fast = Arc::new(tokio::sync::Notify::new());
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let delayed = Arc::new(AtomicBool::new(false));
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::from_env();
        config.r2_endpoint = format!("http://{}", proxy.local_addr().unwrap());
        let proxy_app = Router::new().fallback(any({
            let ids = ids.clone();
            let overtaken = overtaken.clone();
            let reads = reads.clone();
            let writes = writes.clone();
            let reached = reached.clone();
            let release = release.clone();
            move |request: AxumRequest| {
                let upstream = upstream.clone();
                let ids = ids.clone();
                let overtaken = overtaken.clone();
                let reads = reads.clone();
                let writes = writes.clone();
                let fast = fast.clone();
                let reached = reached.clone();
                let release = release.clone();
                let delayed = delayed.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let (slow_id, fast_id) = ids.lock().unwrap().clone();
                    if parts.method == "PUT" && parts.uri.path().contains("/objects/") {
                        writes.fetch_add(1, Ordering::SeqCst);
                    }
                    if parts.method == "GET" && !slow_id.is_empty() {
                        reads.fetch_add(1, Ordering::SeqCst);
                        if parts.uri.path().contains(&fast_id) {
                            fast.notify_one();
                        }
                        if parts.uri.path().contains(&slow_id)
                            && !delayed.swap(true, Ordering::SeqCst)
                        {
                            reached.notify_one();
                            // No DB connection may be held here: another preparation
                            // must reach storage even though the pool has one slot.
                            let concurrent =
                                tokio::time::timeout(Duration::from_secs(5), fast.notified())
                                    .await
                                    .is_ok();
                            overtaken.store(concurrent, Ordering::SeqCst);
                            release.notified().await;
                        }
                    }
                    let response = reqwest::Client::new()
                        .request(parts.method, format!("{upstream}{}", parts.uri))
                        .headers(parts.headers)
                        .body(to_bytes(body, 32 * 1024 * 1024).await.unwrap())
                        .send()
                        .await
                        .unwrap();
                    (
                        response.status(),
                        response.headers().clone(),
                        response.bytes().await.unwrap(),
                    )
                        .into_response()
                }
            }
        }));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let proxy_task = tokio::spawn(async {
            axum::serve(proxy, proxy_app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let storage = snowstead_server::storage::Storage::new(&config).unwrap();
        config.auth_token = "legacy".into();
        config.admin_secret = "admin".into();
        let state = AppState::new(single.clone(), config, storage, reqwest::Client::new()).unwrap();
        let app = router(state.clone());
        let cache = if inline { "inline" } else { "multipart" };
        let mut inputs = Vec::new();
        let mut payloads = Vec::new();
        // The first two sessions target the same path with different metadata.
        // A third path shares the winner's bytes: blob and path deduplication
        // must remain independent, including within one SQL statement.
        for index in 0..8 {
            let contents = if index == 2 {
                if inline { 0 } else { 1 }
            } else {
                index
            };
            let raw = nar(format!("{cache} different content {contents}").as_bytes());
            let mut input = path_input(
                &format!("{:032}", if index == 1 { 0 } else { index }),
                &raw,
                inline,
            );
            input["references"] = json!([format!("{}-reference-{index}", "f".repeat(32))]);
            input["deriver"] = json!(format!("derivation-{index}.drv"));
            payloads.push(zstd::stream::encode_all(raw.as_slice(), 3).unwrap());
            inputs.push(input);
        }
        let (status, created) = post(
            &app,
            &format!("/_api/v1/caches/{cache}/upload-streams/batch"),
            "legacy",
            json!({"paths":inputs}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let sessions = created["sessions"].as_array().unwrap();
        let mut uploads = Vec::new();
        for (index, (session, bytes)) in sessions.iter().zip(&payloads).enumerate() {
            let id = session["sessionId"].as_str().unwrap();
            let mut item = json!({"sessionId":id,"fileHash":hex::encode(Sha256::digest(bytes)),"fileSize":bytes.len()});
            if !inline {
                let (status, reserved) = post(
                    &app,
                    &format!("/_api/v1/uploads/{id}/parts"),
                    "legacy",
                    json!({"parts":[{"partNumber":1,"size":bytes.len()}]}),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{reserved}");
                let (status, _, uploaded) = send(
                    &app,
                    "PUT",
                    &format!("/_api/v1/uploads/{id}/part/1"),
                    Some("legacy"),
                    &[("content-length", &bytes.len().to_string())],
                    bytes.clone(),
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                let uploaded: Value = serde_json::from_slice(&uploaded).unwrap();
                item["narHash"] = inputs[index]["narHash"].clone();
                item["narSize"] = inputs[index]["narSize"].clone();
                item["parts"] = json!([{"partNumber":1,"etag":uploaded["etag"]}]);
            }
            uploads.push(item);
        }
        // Eight actual preparations, plus an independent missing-session item
        // for finalize. Inline has an eight-item wire cap, so corrupt metadata
        // in the last real session instead (checksum/envelope remain valid).
        if inline {
            sqlx::query("UPDATE upload_sessions SET nar_size=nar_size-1 WHERE id=$1")
                .bind(sessions[7]["sessionId"].as_str().unwrap())
                .execute(&pool)
                .await
                .unwrap();
        } else {
            // Reverse the duplicate sessions relative to creation order too.
            uploads.swap(0, 1);
            let mut missing = uploads[7].clone();
            missing["sessionId"] = json!("missing");
            uploads.insert(3, missing);
            // A SQL failure in one member must roll back the group, then let
            // independent members publish in input order without new byte I/O.
            pool_execute(&pool, "CREATE FUNCTION reject_batch_member() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                IF NEW.store_path_hash=repeat('0',31)||'6' THEN RAISE EXCEPTION 'injected member failure'; END IF;
                RETURN NEW; END $$;
                CREATE TRIGGER reject_batch_member BEFORE INSERT ON published_paths FOR EACH ROW EXECUTE FUNCTION reject_batch_member();").await;
        }
        *ids.lock().unwrap() = (
            uploads[0]["sessionId"].as_str().unwrap().to_owned(),
            uploads[1]["sessionId"].as_str().unwrap().to_owned(),
        );
        let (status, result) = tokio::time::timeout(Duration::from_secs(30), async {
            if inline {
                send_inline_batch(&app, inline_frame(&json!(uploads), &payloads)).await
            } else {
                let pending = tokio::spawn({
                    let app = app.clone();
                    let uploads = uploads.clone();
                    async move {
                        post(
                            &app,
                            "/_api/v1/uploads/finalize",
                            "legacy",
                            json!({"uploads":uploads}),
                        )
                        .await
                    }
                });
                tokio::time::timeout(Duration::from_secs(10), reached.notified())
                    .await
                    .unwrap();
                // Simulate expiration of execution leases while the ordered
                // buffer is held by its first member. Queued work has not
                // started and must not lose a lease before it runs.
                let queued: Vec<_> = uploads[5..].iter()
                    .map(|item| item["sessionId"].as_str().unwrap()).collect();
                sqlx::query("UPDATE nar_installations SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE session_id=ANY($1)")
                    .bind(&queued).execute(&pool).await.unwrap();
                // Disconnect with some batch members not yet streamed. The
                // owned batch must finish every reservation, not strand them.
                pending.abort();
                assert!(pending.await.unwrap_err().is_cancelled());
                release.notify_one();
                state.finish_background().await;
                post(
                    &app,
                    "/_api/v1/uploads/finalize",
                    "legacy",
                    json!({"uploads":uploads}),
                )
                .await
            }
        })
        .await
        .expect("batch must not deadlock with pool one");
        assert_eq!(status, StatusCode::OK, "{result}");
        if inline {
            assert_eq!(
                reads.load(Ordering::SeqCst),
                0,
                "inline preparation must not read storage"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                7,
                "each valid inline input gets one PUT; invalid NARs get none"
            );
        } else {
            assert!(
                overtaken.load(Ordering::SeqCst),
                "later preparation must overtake blocked first source read"
            );
            assert_eq!(
                reads.load(Ordering::SeqCst),
                8,
                "each sealed part is read once"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                8,
                "each input gets one final PUT"
            );
        }
        for (index, row) in result["results"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["sessionId"], uploads[index]["sessionId"]);
            if inline && index == 7 {
                assert_eq!(row["status"], 400, "{result}");
            } else if !inline && index == 3 {
                assert_eq!(row["status"], 404, "{result}");
            } else if !inline && index == 7 {
                assert_eq!(row["status"], 500, "{result}");
                assert_eq!(row["published"], false, "{result}");
            } else {
                assert_eq!(row["published"], true, "{result}");
            }
        }
        assert_eq!(result["results"][1]["alreadyExisted"], true);
        assert!(result["results"][0].get("alreadyExisted").is_none());
        let (stored_hash, references, deriver): (String, String, Option<String>) = sqlx::query_as("SELECT b.file_hash,p.references_json,p.deriver FROM published_paths p JOIN caches c ON c.id=p.cache_id JOIN blob_objects b ON b.id=p.blob_object_id WHERE c.name=$1 AND p.store_path_hash=$2")
            .bind(cache).bind("0".repeat(32)).fetch_one(&pool).await.unwrap();
        let winner = if inline { 0 } else { 1 };
        assert_eq!(stored_hash, hex::encode(Sha256::digest(&payloads[winner])));
        assert_eq!(
            serde_json::from_str::<Value>(&references).unwrap(),
            inputs[winner]["references"]
        );
        assert_eq!(deriver.as_deref(), inputs[winner]["deriver"].as_str());
        let (status, _, rendered) = send(
            &app,
            "GET",
            &format!("/{cache}/{}.narinfo", "0".repeat(32)),
            Some("legacy"),
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains(&format!("FileHash: sha256:{stored_hash}")));
        assert!(rendered.contains(&format!("Deriver: derivation-{winner}.drv")));
        let (status, _, detail) = send(
            &app,
            "GET",
            &format!("/_api/v1/orgs/default/caches/{cache}"),
            Some("admin"),
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let detail: Value = serde_json::from_slice(&detail).unwrap();
        let expected_bytes: usize = payloads
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 1 - winner && *index != if inline { 7 } else { 6 })
            .map(|(_, bytes)| bytes.len())
            .sum();
        assert_eq!(detail["paths"], 6);
        assert_eq!(
            detail["size"], expected_bytes,
            "logical bytes count shared blobs once per path"
        );
        // A completed replay must not resurrect a withdrawn duplicate path,
        // and withdrawing it must not remove the other path's shared bytes.
        let (status, deleted) = post(
            &app,
            &format!("/_api/v1/orgs/default/caches/{cache}/paths/delete"),
            "admin",
            json!({"storePathHashes":["0".repeat(32)]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        let (status, replay) = if inline {
            send_inline_batch(&app, inline_frame(&json!(uploads), &payloads)).await
        } else {
            post(
                &app,
                "/_api/v1/uploads/finalize",
                "legacy",
                json!({"uploads":uploads}),
            )
            .await
        };
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["results"][0], result["results"][0]);
        assert_eq!(replay["results"][1], result["results"][1]);
        for (hash, expected) in [
            ("0".repeat(32), StatusCode::NOT_FOUND),
            (format!("{:032}", 2), StatusCode::OK),
        ] {
            let (status, _, body) = send(
                &app,
                "GET",
                &format!("/{cache}/{hash}.narinfo"),
                Some("legacy"),
                &[],
                vec![],
            )
            .await;
            assert_eq!(status, expected);
            if status == StatusCode::OK {
                assert!(
                    String::from_utf8(body)
                        .unwrap()
                        .contains(&format!("FileHash: sha256:{stored_hash}"))
                );
            }
        }
        let (status, _, bytes) = send(
            &app,
            "GET",
            &format!("/nar/{stored_hash}/zstd.nar"),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, payloads[winner]);
        stop.send(()).unwrap();
        proxy_task.await.unwrap();
    }
    single.close().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn paused_immutable_copy_releases_pool_without_reserving_quota_or_publishing_stale_data(
    pool: PgPool,
) {
    use axum::{extract::Request as AxumRequest, response::IntoResponse, routing::any};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    let old_raw = nar(b"paused older immutable upload");
    let new_raw = nar(b"newer publication must survive the late old copy");
    let old = zstd::stream::encode_all(old_raw.as_slice(), 3).unwrap();
    let new = zstd::stream::encode_all(new_raw.as_slice(), 3).unwrap();
    pool_execute(&pool, "INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind((old.len() + new.len() - 1) as i64)
        .execute(&pool)
        .await
        .unwrap();
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let upstream = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
    assert!(upstream.starts_with("http://127.0.0.1:"));
    let reached = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let paused = Arc::new(AtomicBool::new(false));
    let storage_work = Arc::new(AtomicUsize::new(0));
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::from_env();
    config.r2_endpoint = format!("http://{}", proxy.local_addr().unwrap());
    config.auth_token = "legacy".into();
    config.admin_secret = "admin".into();
    let proxy_app = Router::new().fallback(any({
        let reached = reached.clone();
        let release = release.clone();
        let paused = paused.clone();
        let storage_work = storage_work.clone();
        move |request: AxumRequest| {
            let upstream = upstream.clone();
            let reached = reached.clone();
            let release = release.clone();
            let paused = paused.clone();
            let storage_work = storage_work.clone();
            async move {
                let (parts, body) = request.into_parts();
                // S3 uses POST ?delete for source cleanup after publication;
                // count byte reads/writes, not that expected cleanup request.
                if matches!(parts.method.as_str(), "GET" | "PUT" | "POST")
                    && parts.uri.query() != Some("delete")
                {
                    storage_work.fetch_add(1, Ordering::SeqCst);
                }
                if (parts.method == "POST" || parts.method == "PUT")
                    && parts.uri.path().contains("/nar/objects/")
                    && !paused.swap(true, Ordering::SeqCst)
                {
                    reached.notify_one();
                    release.notified().await;
                }
                let response = reqwest::Client::new()
                    .request(parts.method, format!("{upstream}{}", parts.uri))
                    .headers(parts.headers)
                    .body(to_bytes(body, 32 * 1024 * 1024).await.unwrap())
                    .send()
                    .await
                    .unwrap();
                (
                    response.status(),
                    response.headers().clone(),
                    response.bytes().await.unwrap(),
                )
                    .into_response()
            }
        }
    }));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async {
        axum::serve(proxy, proxy_app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let storage = snowstead_server::storage::Storage::new(&config).unwrap();
    let app = router(
        AppState::new(
            single.clone(),
            config.clone(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let hash = "a".repeat(32);
    let pending = tokio::spawn({
        let app = app.clone();
        let input = path_input(&hash, &old_raw, true);
        let old = old.clone();
        async move { upload_inline(&app, "main", input, &old).await }
    });
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .expect("immutable copy must reach barrier");
    // The first provider request is the final immutable PUT. Inline NAR
    // verification must not stage, assemble, or read bytes from storage.
    assert_eq!(storage_work.load(Ordering::SeqCst), 1);
    // Every operation below uses the same one-slot application pool, with the
    // storage barrier still closed. No sleep or scheduler ordering is required.
    let stale_key = tokio::time::timeout(Duration::from_secs(10), async {
        let key: String =
            sqlx::query_scalar("SELECT key FROM nar_installations WHERE session_id IS NOT NULL")
                .fetch_one(&single)
                .await
                .unwrap();
        assert!(key.starts_with("nar/objects/"));
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT source_key IS NULL FROM nar_installations WHERE key=$1"
            )
            .bind(&key)
            .fetch_one(&single)
            .await
            .unwrap()
        );
        assert_eq!(
            send(&app, "GET", "/main/nix-cache-info", None, &[], vec![])
                .await
                .0,
            StatusCode::OK
        );
        let independent = upload_inline(
            &app,
            "main",
            path_input(&"f".repeat(32), &new_raw, true),
            &new,
        )
        .await;
        assert_eq!(independent["published"], true, "{independent}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
                .fetch_one(&single)
                .await
                .unwrap(),
            1
        );
        // Even deletion of an absent path invalidates its in-flight admission.
        let (status, deleted) = post(
            &app,
            "/_api/v1/orgs/default/caches/main/paths/delete",
            "admin",
            json!({"storePathHashes":[hash]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        let (status, _, body) = send(
            &app,
            "PUT",
            "/_api/v1/orgs/default",
            Some("admin"),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"storageLimit":2*new.len()})).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let newer = upload_inline(&app, "main", path_input(&hash, &new_raw, true), &new).await;
        assert_eq!(newer["published"], true, "{newer}");
        key
    })
    .await
    .expect("SQL, management and independent uploads must progress while copy is paused");
    release.notify_one();
    let stale = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale["published"], false, "{stale}");
    assert_eq!(stale["status"], 409, "{stale}");
    assert!(storage.head(false, &stale_key).await.is_ok());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM object_cleanup WHERE key=$1 AND NOT is_private"
        )
        .bind(&stale_key)
        .fetch_one(&single)
        .await
        .unwrap(),
        1
    );
    let new_hash = hex::encode(Sha256::digest(&new));
    let (status, _, bytes) = send(
        &app,
        "GET",
        &format!("/nar/{new_hash}/zstd.nar"),
        None,
        &[],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, new);
    let (status, _, metadata) = send(
        &app,
        "GET",
        &format!("/main/{hash}.narinfo"),
        None,
        &[],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8(metadata)
            .unwrap()
            .contains(&format!("FileHash: sha256:{new_hash}"))
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
            .fetch_one(&single)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM nar_installations WHERE session_id IS NOT NULL"
        )
        .fetch_one(&single)
        .await
        .unwrap(),
        0
    );
    // A transient org conflict must retain the verified immutable candidate.
    // A fresh server retries publication without reading or writing any bytes.
    paused.store(false, Ordering::SeqCst);
    let pending = tokio::spawn({
        let app = app.clone();
        let input = path_input(&"b".repeat(32), &new_raw, true);
        let new = new.clone();
        async move { upload_inline(&app, "main", input, &new).await }
    });
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .unwrap();
    let mut competing = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('org:default', 0))")
        .execute(&mut *competing)
        .await
        .unwrap();
    release.notify_one();
    let busy = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(busy["status"], 503, "{busy}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM nar_installations WHERE session_id=$1 AND phase='ready'"
        )
        .bind(busy["sessionId"].as_str().unwrap())
        .fetch_one(&single)
        .await
        .unwrap(),
        1
    );
    competing.rollback().await.unwrap();
    let before_replay = storage_work.load(Ordering::SeqCst);
    let restarted = router(
        AppState::new(
            single.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let uploads = json!([{
        "sessionId": busy["sessionId"],
        "fileHash": new_hash,
        "fileSize": new.len()
    }]);
    let (status, replay) = send_inline_batch(&restarted, inline_frame(&uploads, &[new])).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["results"][0]["published"], true, "{replay}");
    assert_eq!(storage_work.load(Ordering::SeqCst), before_replay);
    stop.send(()).unwrap();
    proxy_task.await.unwrap();
    single.close().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn sealed_sessions_can_be_aborted_without_racing_publication(pool: PgPool) {
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        Config {
            auth_token: "legacy".into(),
            ..Default::default()
        },
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    pool_execute(&pool, "INSERT INTO caches(name) VALUES('main');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;
        CREATE FUNCTION fail_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected publication failure'; END $$;
        CREATE TRIGGER fail_publication BEFORE INSERT ON published_paths FOR EACH ROW EXECUTE FUNCTION fail_publication();").await;
    let abort = |id: String| {
        let app = app.clone();
        async move {
            post(
                &app,
                &format!("/_api/v1/uploads/{id}/abort"),
                "legacy",
                json!({}),
            )
            .await
            .0
        }
    };
    let status = |id: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT status FROM upload_sessions WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };

    // Sealed, then failed: verification rejects one, publication the other.
    let raw = nar(b"sealed but never published");
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let mut corrupt = path_input(&"a".repeat(32), &raw, true);
    corrupt["narHash"] = json!(format!("sha256:{}", "0".repeat(64)));
    let unverified = upload_inline(&app, "main", corrupt, &compressed).await;
    assert_eq!(unverified["status"], 400, "{unverified}");
    let unpublished = upload_inline(
        &app,
        "main",
        path_input(&"b".repeat(32), &raw, true),
        &compressed,
    )
    .await;
    assert_eq!(unpublished["status"], 500, "{unpublished}");
    let unverified = unverified["sessionId"].as_str().unwrap().to_owned();
    let unpublished = unpublished["sessionId"].as_str().unwrap().to_owned();
    // The failed publication keeps its verified candidate reserved for a retry.
    let reserved: String =
        sqlx::query_scalar("SELECT key FROM nar_installations WHERE session_id=$1")
            .bind(&unpublished)
            .fetch_one(&pool)
            .await
            .unwrap();
    for id in [&unverified, &unpublished] {
        assert_eq!(status(id.clone()).await, "finalizing");
        // Idempotent, like an abort while streaming.
        for _ in 0..2 {
            assert_eq!(abort(id.clone()).await, StatusCode::OK);
        }
        assert_eq!(status(id.clone()).await, "aborted");
    }
    // The reservation is released as expiry releases it: gone, and its exact
    // key handed to cleanup rather than left adoptable.
    let reservations: i64 = sqlx::query_scalar("SELECT count(*) FROM nar_installations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reservations, 0);
    let queued: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM object_cleanup WHERE key=$1)")
            .bind(&reserved)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(queued);
    // Aborted is final: the same bytes cannot be sealed or published again.
    pool_execute(&pool, "DROP TRIGGER fail_publication ON published_paths").await;
    let hash = hex::encode(Sha256::digest(&compressed));
    let (code, _, bytes) = send(
        &app,
        "POST",
        &format!("/_api/v1/uploads/{unpublished}/inline?fileHash={hash}"),
        Some("legacy"),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let replay: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(replay["status"], 409, "{replay}");
    assert_eq!(replay["published"], false);

    // Abort and publication fence each other: whatever the interleaving,
    // exactly one outcome is recorded and no reservation outlives it.
    for round in 0..12u8 {
        let raw = nar(&[b'r', round]);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let store_hash = format!(
            "{}{}",
            "c".repeat(31),
            b"0123456789ab"[round as usize] as char
        );
        let session = create(&app, "main", "legacy", path_input(&store_hash, &raw, true)).await;
        let id = session["sessionId"].as_str().unwrap().to_owned();
        let path = format!(
            "/_api/v1/uploads/{id}/inline?fileHash={}",
            hex::encode(Sha256::digest(&compressed))
        );
        let length = compressed.len().to_string();
        let headers = [("content-length", length.as_str())];
        let upload = send(&app, "POST", &path, Some("legacy"), &headers, compressed);
        let racing = async {
            // Let the upload reach a different point each round.
            for _ in 0..round * 3 {
                tokio::task::yield_now().await;
            }
            abort(id.clone()).await
        };
        let ((_, _, bytes), aborted) = tokio::join!(upload, racing);
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        let published: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM published_paths WHERE store_path_hash=$1)",
        )
        .bind(&store_hash)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(result["published"] == true, published, "{result}");
        let recorded = status(id.clone()).await;
        if aborted == StatusCode::OK {
            assert!(!published, "round {round}: aborted and published");
            assert_eq!(recorded, "aborted");
        } else {
            // Refused by the fence or by the completed publication.
            assert!(
                aborted == StatusCode::CONFLICT || aborted == StatusCode::SERVICE_UNAVAILABLE,
                "round {round}: {aborted}"
            );
        }
        if published {
            assert_eq!(recorded, "completed");
        }
        let reservations: i64 = sqlx::query_scalar("SELECT count(*) FROM nar_installations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(reservations, 0, "round {round}");
    }
}
