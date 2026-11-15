mod common;

use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use snowstead_server::{AppState, capacity, config::Config, router};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

async fn fixture(pool: &PgPool) -> AppState {
    sqlx::raw_sql(
        "INSERT INTO caches(name) VALUES ('main');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .execute(pool)
    .await
    .unwrap();
    AppState::new(
        pool.clone(),
        Config {
            shared_auth_token: Some("shared-token".into()),
            ..Default::default()
        },
        common::storage(),
        reqwest::Client::new(),
    )
    .unwrap()
}

async fn limit(pool: &PgPool, bytes: Option<i64>) {
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(bytes)
        .execute(pool)
        .await
        .unwrap();
}

/// A published path of `size` retained bytes, last pushed on that day of
/// January 2000. Its store path hash and file hash repeat `digit`.
async fn retain(pool: &PgPool, digit: char, size: i64, day: i32) {
    sqlx::query(
        "WITH blob AS (INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) \
         VALUES(repeat($1,64),$2,'zstd','nar/'||$1) RETURNING id) \
         INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,last_pushed_at) \
         SELECT c.id,repeat($1,32),'/nix/store/'||repeat($1,32)||'-fixture','sha256:'||repeat('0',64),$2,blob.id,make_date(2000,1,$3) \
         FROM caches c,blob WHERE c.name='main'",
    )
    .bind(digit.to_string())
    .bind(size)
    .bind(day)
    .execute(pool)
    .await
    .unwrap();
}

/// The retained paths, as the digits they were created with.
async fn kept(pool: &PgPool) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(string_agg(left(store_path_hash,1),'' ORDER BY store_path_hash),'') FROM published_paths",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn pin(pool: &PgPool, digit: char) {
    sqlx::query(
        "WITH pin AS (INSERT INTO pins(id,cache_id,name,keep_kind,current_revision) \
         SELECT 'pin-'||$1,id,'keep-'||$1,'forever',1 FROM caches RETURNING id,cache_id), \
         revision AS (INSERT INTO pin_revisions(id,pin_id,revision,store_path) \
         SELECT 'rev-'||$1,id,1,'/nix/store/pinned' FROM pin RETURNING id) \
         INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) \
         SELECT revision.id,pin.cache_id,repeat($1,32) FROM pin,revision",
    )
    .bind(digit.to_string())
    .execute(pool)
    .await
    .unwrap();
}

/// Start one inline upload session for a new path through the public route.
async fn start(app: &Router, digit: char) -> (StatusCode, Value) {
    let hash = digit.to_string().repeat(32);
    let body = json!({"paths":[{
        "storePath":format!("/nix/store/{hash}-new"),"storePathHash":hash,
        "narHash":format!("sha256:{}","0".repeat(64)),"narSize":128,
        "compression":"zstd","references":[],"inline":true
    }]});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_api/v1/caches/main/upload-streams/batch")
                .header(
                    snowstead_protocol::PROTOCOL_VERSION_HEADER,
                    snowstead_protocol::PROTOCOL_VERSION,
                )
                .header("authorization", "Bearer shared-token")
                .header("host", "backend.local")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn sessions(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM upload_sessions")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn evictor_frees_least_recently_used_first_and_stops_at_the_limit(pool: PgPool) {
    let state = fixture(&pool).await;
    for (digit, day) in [('1', 3), ('2', 1), ('3', 4), ('4', 2)] {
        retain(&pool, digit, 40, day).await;
    }
    // No limit, a limit above usage, and a limit met exactly all leave the
    // organization alone.
    for bytes in [None, Some(161), Some(160)] {
        limit(&pool, bytes).await;
        assert_eq!(capacity::evict(&state, "default").await.unwrap(), 0);
        assert_eq!(kept(&pool).await, "1234");
    }
    // 160 bytes against 100: the two oldest go, by last use and not by id.
    // 80 bytes is under the limit, so the third oldest stays.
    limit(&pool, Some(100)).await;
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 80);
    assert_eq!(kept(&pool).await, "13");
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 0);
    let logged: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT reason,right(key,10),size FROM eviction_logs ORDER BY key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        logged,
        [
            ("capacity".into(), "22-fixture".into(), 40),
            ("capacity".into(), "44-fixture".into(), 40)
        ]
    );
    // An access makes the older push the more recently used of the two.
    sqlx::query(
        "UPDATE published_paths SET last_accessed_at=NOW() WHERE store_path_hash=repeat('1',32)",
    )
    .execute(&pool)
    .await
    .unwrap();
    limit(&pool, Some(40)).await;
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 40);
    assert_eq!(kept(&pool).await, "1");
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn evictor_keeps_the_newest_path_while_older_ones_can_go(pool: PgPool) {
    let state = fixture(&pool).await;
    retain(&pool, '1', 40, 1).await;
    retain(&pool, '2', 40, 2).await;
    retain(&pool, '3', 40, 3).await;
    sqlx::query(
        "UPDATE published_paths SET last_pushed_at=NOW() WHERE store_path_hash=repeat('2',32)",
    )
    .execute(&pool)
    .await
    .unwrap();
    // Room for one path only. The one just pushed is the one that stays.
    limit(&pool, Some(40)).await;
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 80);
    assert_eq!(kept(&pool).await, "2");
    // More than one bounded pass: 300 older one-byte paths go, and no more.
    sqlx::query(
        "WITH blob AS (INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) \
         VALUES(repeat('f',64),1,'zstd','nar/f') RETURNING id) \
         INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id,last_pushed_at) \
         SELECT c.id,lpad(n::text,32,'a'),'/nix/store/'||lpad(n::text,32,'a')||'-many','sha256:'||repeat('0',64),1,blob.id,make_date(1999,1,1) \
         FROM caches c,blob,generate_series(1,300) n",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 300);
    assert_eq!(kept(&pool).await, "2");
    let left: Vec<i64> = sqlx::query_scalar(
        "SELECT b.file_size FROM published_paths p JOIN blob_objects b ON b.id=p.blob_object_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(left, [40]);
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn evictor_spares_protected_paths_and_returns_when_only_they_remain(pool: PgPool) {
    let state = fixture(&pool).await;
    for (digit, day) in [('1', 1), ('2', 2), ('3', 3), ('4', 4), ('5', 5)] {
        retain(&pool, digit, 40, day).await;
    }
    // 1 is pinned, 2 belongs to a sealed push job, 3 has an upload in flight,
    // and 4's bytes have a publication attempt in flight. 5 is the newest and
    // the only one with no protection.
    pin(&pool, '1').await;
    sqlx::raw_sql(
        "INSERT INTO api_tokens(jti,subject,perms_json,created_by,org_id) VALUES('job-token','test','[\"push\"]','test','default');
        INSERT INTO push_jobs(id,cache_id,creator,idempotency_key,mode,roots,state,manifest_bytes,authorization_jti,authorization_expires_at)
        SELECT 'job',id,'job-token','job','selected','[]','sealed',1,'job-token',now()+interval '30 minutes' FROM caches;
        INSERT INTO push_job_members(job_id,store_path_hash,metadata)
        SELECT 'job',store_path_hash,jsonb_build_object('storePath',store_path,'narHash',nar_hash,'narSize',nar_size,'references',references_json::jsonb,'deriver',deriver)
        FROM published_paths WHERE store_path_hash=repeat('2',32);
        INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_size,compression,status,expires_at)
        SELECT 'uploading',cache_id,store_path_hash,store_path,nar_hash,nar_size,0,'zstd','streaming',now()+interval '1 hour'
        FROM published_paths WHERE store_path_hash=repeat('3',32);
        INSERT INTO nar_installations(key,operation_id,source_key,file_hash,compression,is_private,file_size,cache_id,expires_at)
        SELECT 'attempt','operation','staging',repeat('4',64),'zstd',false,40,id,now()+interval '1 hour' FROM caches;",
    )
    .execute(&pool)
    .await
    .unwrap();
    limit(&pool, Some(10)).await;
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 40);
    assert_eq!(kept(&pool).await, "1234");
    // Still 160 bytes against 10, and that is not an error.
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 0);
    assert_eq!(kept(&pool).await, "1234");
    // Each protection is released on its own, and only then does its path go.
    for (release, left) in [
        ("DELETE FROM nar_installations", "123"),
        ("UPDATE upload_sessions SET status='aborted'", "12"),
        (
            "UPDATE push_jobs SET authorization_expires_at=now()-interval '1 second'",
            "1",
        ),
        ("DELETE FROM pin_paths", ""),
    ] {
        sqlx::query(release).execute(&pool).await.unwrap();
        assert_eq!(capacity::evict(&state, "default").await.unwrap(), 40);
        assert_eq!(kept(&pool).await, left);
    }
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn upload_start_accepts_at_109_percent_and_asks_to_retry_from_110(pool: PgPool) {
    let state = fixture(&pool).await;
    let app = router(state.clone());
    limit(&pool, Some(100)).await;
    retain(&pool, '1', 109, 1).await;
    let (status, created) = start(&app, 'a').await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    retain(&pool, '2', 1, 2).await;
    let (status, refused) = start(&app, 'b').await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refused}");
    assert_eq!(
        refused,
        json!({"error":"Storage is over its limit while older data is evicted; retry"})
    );
    assert_eq!(sessions(&pool).await, 1);
    // A limit whose tenth is not a whole number: 15 * 1.1 = 16.5, so 16 bytes
    // are still under it and 17 are not.
    sqlx::raw_sql(
        "DELETE FROM upload_sessions; DELETE FROM published_paths; DELETE FROM blob_objects",
    )
    .execute(&pool)
    .await
    .unwrap();
    limit(&pool, Some(15)).await;
    retain(&pool, '3', 16, 1).await;
    assert_eq!(start(&app, 'c').await.0, StatusCode::CREATED);
    retain(&pool, '4', 1, 2).await;
    assert_eq!(start(&app, 'd').await.0, StatusCode::SERVICE_UNAVAILABLE);
    // A limit of zero retains nothing and leaves nothing to evict, so the
    // refusal is final. No limit, no rule.
    limit(&pool, Some(0)).await;
    assert_eq!(start(&app, 'g').await.0, StatusCode::PAYLOAD_TOO_LARGE);
    limit(&pool, None).await;
    assert_eq!(start(&app, 'f').await.0, StatusCode::CREATED);
    // After eviction the same organization starts uploads again.
    limit(&pool, Some(15)).await;
    assert_eq!(start(&app, 'd').await.0, StatusCode::SERVICE_UNAVAILABLE);
    sqlx::query("DELETE FROM upload_sessions")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 16);
    assert_eq!(start(&app, 'd').await.0, StatusCode::CREATED);
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn upload_start_over_the_limit_depends_on_evictable_bytes(pool: PgPool) {
    let state = fixture(&pool).await;
    let app = router(state.clone());
    limit(&pool, Some(100)).await;
    retain(&pool, '1', 99, 1).await;
    retain(&pool, '2', 6, 2).await;
    pin(&pool, '1').await;
    // A second pin keeps one revision: the current one, which is empty. Its
    // superseded revision named path 2, and no longer protects it.
    sqlx::raw_sql(
        "INSERT INTO pins(id,cache_id,name,keep_kind,keep_value,current_revision) SELECT 'old',id,'old','revisions',1,2 FROM caches;
        INSERT INTO pin_revisions(id,pin_id,revision,store_path,superseded_at) VALUES ('old-1','old',1,'/nix/store/old',now()),('old-2','old',2,'/nix/store/new',NULL);
        INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) SELECT 'old-1',id,repeat('2',32) FROM caches;
        INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) SELECT 'old-1',id,repeat('1',32) FROM caches;",
    )
    .execute(&pool)
    .await
    .unwrap();
    // 105 bytes are over the limit but under 110% of it, and only 99 of them
    // are protected: eviction can make room, so the upload starts.
    let (status, created) = start(&app, 'a').await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    // Keeping two revisions protects path 2 as well. Path 1 is now pinned
    // twice and still counts once: 105 protected bytes meet the limit.
    sqlx::query("UPDATE pins SET keep_value=2 WHERE id='old'")
        .execute(&pool)
        .await
        .unwrap();
    let (status, refused) = start(&app, 'b').await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{refused}");
    assert_eq!(
        refused,
        json!({"error":"Insufficient evictable capacity; delete retained paths first"})
    );
    assert_eq!(sessions(&pool).await, 1);
    // The evictor agrees with that count: it finds nothing it may remove.
    assert_eq!(capacity::evict(&state, "default").await.unwrap(), 0);
    assert_eq!(kept(&pool).await, "12");
    // A pin kept by age follows the same rule as `nix_path_pinned`.
    sqlx::raw_sql(
        "UPDATE pins SET keep_kind='days',keep_value=1 WHERE id='old';
        UPDATE pin_revisions SET superseded_at=now()-interval '2 days' WHERE id='old-1';",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(start(&app, 'b').await.0, StatusCode::CREATED);
    sqlx::query(
        "UPDATE pin_revisions SET superseded_at=now()-interval '23 hours' WHERE id='old-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(start(&app, 'c').await.0, StatusCode::PAYLOAD_TOO_LARGE);
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn worker_evicts_on_its_timer_and_survives_a_failed_eviction(pool: PgPool) {
    let state = fixture(&pool).await;
    retain(&pool, '1', 40, 1).await;
    retain(&pool, '2', 40, 2).await;
    limit(&pool, Some(40)).await;
    // Another writer holds the organization fence: eviction fails, retryably.
    let mut fence = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('org:default',0))")
        .execute(&mut *fence)
        .await
        .unwrap();
    assert!(capacity::evict(&state, "default").await.is_err());
    let stop = CancellationToken::new();
    let worker = tokio::spawn(capacity::run(
        state.clone(),
        stop.clone(),
        Duration::from_millis(20),
    ));
    // Several ticks fail against the fence. The worker neither evicts nor ends.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!worker.is_finished());
    assert_eq!(kept(&pool).await, "12");
    sqlx::query("SELECT pg_advisory_unlock(hashtextextended('org:default',0))")
        .execute(&mut *fence)
        .await
        .unwrap();
    drop(fence);
    tokio::time::timeout(Duration::from_secs(5), async {
        while kept(&pool).await != "2" {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the worker must retry on a later tick");
    // A limit lowered by management wakes nobody. The timer still finds it.
    limit(&pool, Some(0)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !kept(&pool).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the timer must find an organization nobody woke the worker for");
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("cancellation must stop the worker")
        .unwrap();
    state.finish_background().await;
}
