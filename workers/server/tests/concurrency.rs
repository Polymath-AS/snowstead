//! Writers in one organization run concurrently. Each test here overlaps real
//! requests on a multi-thread runtime, with a pool sized like production's,
//! and asserts an invariant that must hold whichever writer wins. A 503 is a
//! request to retry, and is retried; an invariant is never retried.
mod common;
#[path = "support/tokens.rs"]
mod tokens;
#[path = "support/web.rs"]
mod web;

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, capacity, config::Config};
use sqlx::PgPool;
use tokio::sync::Barrier;
use tower::ServiceExt;

/// The shared upload credential, and the dashboard as the default org's owner.
const SHARED: &str = "legacy";
const OWNER: &str = "dashboard-owner";
const ALLOCATE: &str = "/_api/v1/caches/main/upload-streams/batch";
const JOBS: &str = "/_api/v1/caches/main/push-jobs";

/// Run `body` on a multi-thread runtime, on this test's database, with a pool
/// of its own. `sqlx::test` drives a current-thread runtime, where requests
/// only interleave at their await points.
fn threaded<F, Fut>(pool: &PgPool, body: F)
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let options = (*pool.connect_options()).clone();
    let outcome = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(8)
                    .connect_with(options)
                    .await
                    .unwrap();
                body(pool.clone()).await;
                pool.close().await;
            })
    })
    .join();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// A server on `pool` with the caches named, all public Nix caches.
async fn server(pool: &PgPool, caches: &[&str]) -> (AppState, Router) {
    server_with(pool, caches, common::storage()).await
}

async fn server_with(
    pool: &PgPool,
    caches: &[&str],
    storage: snowstead_server::storage::Storage,
) -> (AppState, Router) {
    for name in caches {
        sqlx::query("INSERT INTO caches(name) VALUES ($1)")
            .bind(name)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches")
        .execute(pool)
        .await
        .unwrap();
    let state = AppState::new(
        pool.clone(),
        Config {
            shared_auth_token: Some(SHARED.into()),
            jwt_secret: "test-jwt".into(),
            admin_secret: "operator".into(),
            ..Default::default()
        },
        storage,
        reqwest::Client::new(),
    )
    .unwrap();
    let app = common::router(state.clone());
    (state, app)
}

/// Which side of a race came first, round by round. A race test that only
/// ever saw one order proved nothing about the other: it fails as
/// inconclusive instead of passing.
#[derive(Default)]
struct Orders {
    one: usize,
    other: usize,
}

impl Orders {
    fn note(&mut self, one: bool) {
        if one {
            self.one += 1;
        } else {
            self.other += 1;
        }
    }

    /// Enough rounds, and both orders seen. A test runs further rounds, up
    /// to five times as many, until then.
    fn settled(&self, round: usize, rounds: usize) -> bool {
        round >= rounds && self.one > 0 && self.other > 0
    }

    fn conclusive(&self, what: &str) {
        assert!(
            self.one > 0 && self.other > 0,
            "inconclusive: {what} only ever ran in one order ({} against {} rounds)",
            self.one,
            self.other
        );
    }
}

/// Record, at commit, every session that completes for a job already
/// cancelled or with a token already revoked. The check runs in a deferred
/// trigger of the publishing transaction itself, on a fresh snapshot, so it
/// sees exactly the cancellations and revocations that committed before the
/// publication did. Reading a count after a response cannot tell those apart
/// from a publication that committed in between.
async fn watch(pool: &PgPool) {
    sqlx::raw_sql(
        "CREATE TABLE race_tokens(session_id text PRIMARY KEY, jti text NOT NULL);
         CREATE TABLE race_violations(session_id text NOT NULL, what text NOT NULL);
         CREATE FUNCTION race_check() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
             IF EXISTS (SELECT 1 FROM push_jobs j WHERE j.id=NEW.push_job_id AND j.state='cancelled') THEN
                 INSERT INTO race_violations VALUES (NEW.id,'published for a cancelled job');
             END IF;
             IF EXISTS (SELECT 1 FROM race_tokens r JOIN api_tokens t ON t.jti=r.jti
                 WHERE r.session_id=NEW.id AND t.revoked_at IS NOT NULL) THEN
                 INSERT INTO race_violations VALUES (NEW.id,'published with a revoked token');
             END IF;
             RETURN NULL;
         END $$;
         CREATE CONSTRAINT TRIGGER race_check AFTER UPDATE ON upload_sessions
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
             WHEN (NEW.status='completed' AND OLD.status IS DISTINCT FROM 'completed')
             EXECUTE FUNCTION race_check();",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn violations(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT session_id,what FROM race_violations")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    credential: &str,
    headers: &[(&str, &str)],
    bytes: Vec<u8>,
) -> (StatusCode, Value) {
    let (path, credential) = if credential == OWNER {
        web::dashboard(method, path, "operator", None)
    } else {
        (path.to_owned(), web::Credential::Bearer(credential.into()))
    };
    let mut request = credential
        .apply(Request::builder().method(method).uri(path.as_str()))
        .header(
            snowstead_protocol::PROTOCOL_VERSION_HEADER,
            snowstead_protocol::PROTOCOL_VERSION,
        )
        .header("host", "backend.local");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))),
    )
}

/// One JSON request, repeated while the server answers 503. `retries` counts
/// those answers.
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    credential: &str,
    body: &Value,
    retries: &AtomicUsize,
) -> (StatusCode, Value) {
    for _ in 0..400 {
        let (status, value) = send(
            app,
            method,
            path,
            credential,
            &[("content-type", "application/json")],
            serde_json::to_vec(body).unwrap(),
        )
        .await;
        if status != StatusCode::SERVICE_UNAVAILABLE {
            return (status, value);
        }
        retries.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("{method} {path} stayed busy");
}

/// Wait without the timer's millisecond granularity, so that a racing request
/// lands at a different point of its opponent each round.
async fn pause(micros: usize) {
    let until = Instant::now() + Duration::from_micros(micros as u64);
    while Instant::now() < until {
        tokio::task::yield_now().await;
    }
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

/// A distinct small path: its creation input and its compressed bytes.
struct Upload {
    hash: String,
    input: Value,
    compressed: Vec<u8>,
}

fn upload(number: usize) -> Upload {
    let hash = format!("{number:032}");
    let raw = nar(format!("concurrent path {number}").as_bytes());
    Upload {
        input: json!({"storePath":format!("/nix/store/{hash}-fixture"),"storePathHash":hash,
            "narHash":format!("sha256-{}",STANDARD.encode(Sha256::digest(&raw))),"narSize":raw.len(),
            "compression":"zstd","references":[],"inline":true}),
        compressed: zstd::stream::encode_all(raw.as_slice(), 3).unwrap(),
        hash,
    }
}

/// Start one session, retrying 503.
async fn start(
    app: &Router,
    cache: &str,
    credential: &str,
    upload: &Upload,
    retries: &AtomicUsize,
) -> String {
    let (status, created) = call(
        app,
        "POST",
        &format!("/_api/v1/caches/{cache}/upload-streams/batch"),
        credential,
        &json!({"paths":[upload.input]}),
        retries,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["sessions"][0]["sessionId"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Send a session's bytes and publish it. The result row is the session's
/// outcome; a row or a response with status 503 is retried. A refused request
/// is reported as a row with its status.
async fn finish(
    app: &Router,
    credential: &str,
    session: &str,
    upload: &Upload,
    retries: &AtomicUsize,
) -> Value {
    let path = format!(
        "/_api/v1/uploads/{session}/inline?fileHash={}",
        hex::encode(Sha256::digest(&upload.compressed))
    );
    for _ in 0..400 {
        let (status, row) = send(
            app,
            "POST",
            &path,
            credential,
            &[("content-length", &upload.compressed.len().to_string())],
            upload.compressed.clone(),
        )
        .await;
        let row = if status == StatusCode::OK {
            row
        } else {
            json!({"status":status.as_u16(),"error":row})
        };
        if row["status"] != 503 {
            return row;
        }
        retries.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("session {session} stayed busy");
}

/// What a cache's totals say, and what its published paths add up to.
async fn totals(pool: &PgPool, cache: &str) -> ((i64, i64), (i64, i64)) {
    let (count, size, paths, bytes): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT c.path_count,c.size, \
         (SELECT count(*) FROM published_paths p WHERE p.cache_id=c.id), \
         (SELECT COALESCE(sum(b.file_size),0)::bigint FROM published_paths p \
          JOIN blob_objects b ON b.id=p.blob_object_id WHERE p.cache_id=c.id) \
         FROM caches c WHERE c.name=$1",
    )
    .bind(cache)
    .fetch_one(pool)
    .await
    .unwrap();
    ((count, size), (paths, bytes))
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

/// A registered API token for the default org, allowed to push everywhere.
async fn token(pool: &PgPool, jti: &str) -> String {
    let claims = json!({"jti":jti,"sub":"cli","iss":"snowstead","aud":"snowstead","iat":1,
        "org":"default","caches":["*"],"perms":["push","pull","go:read","go:write"]});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"test-jwt").unwrap();
    mac.update(input.as_bytes());
    let signed = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    tokens::register(pool, signed).await
}

/// A sealed, authorized push job over `members`, each independent of the
/// others, and its path.
async fn job(app: &Router, auth: &str, key: &str, members: &[Upload]) -> String {
    let none = AtomicUsize::new(0);
    let inputs: Vec<_> = members.iter().map(|m| m.input.clone()).collect();
    let (status, created) = call(
        app,
        "POST",
        JOBS,
        auth,
        &json!({"idempotencyKey":key,"mode":"selected","roots":[inputs[0]["storePath"]]}),
        &none,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let job = format!("{JOBS}/{}", created["job"]["id"].as_str().unwrap());
    let (status, chunk) = call(
        app,
        "PUT",
        &format!("{job}/manifest/0"),
        auth,
        &json!({"members":inputs}),
        &none,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{chunk}");
    for action in ["seal", "resume"] {
        let (status, body) = call(
            app,
            "POST",
            &format!("{job}/{action}"),
            auth,
            &json!({}),
            &none,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    job
}

/// Publishers into one cache wait for each other only on the cache's totals.
/// All of them commit, and the totals are exactly what was published.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn publishers_into_one_cache_all_commit_with_exact_totals(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const PUBLISHERS: usize = 32;
        let (state, app) = server(&pool, &["main"]).await;
        let barrier = Arc::new(Barrier::new(PUBLISHERS));
        let retries = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..PUBLISHERS)
            .map(|number| {
                let (app, barrier, retries) = (app.clone(), barrier.clone(), retries.clone());
                tokio::spawn(async move {
                    let upload = upload(number);
                    barrier.wait().await;
                    let session = start(&app, "main", SHARED, &upload, &retries).await;
                    finish(&app, SHARED, &session, &upload, &retries).await
                })
            })
            .collect();
        for task in tasks {
            let row = task.await.unwrap();
            assert_eq!(row["published"], true, "{row}");
        }
        let (recorded, actual) = totals(&pool, "main").await;
        assert_eq!(recorded, actual);
        assert_eq!(actual.0, PUBLISHERS as i64);
        let retries = retries.load(Ordering::Relaxed);
        eprintln!("one cache: {PUBLISHERS} publishers, {retries} retried 503s");
        assert!(
            retries <= PUBLISHERS / 4,
            "{retries} publishers were told to retry"
        );
        drop(app);
        state.finish_background().await;
    });
}

/// Publishers into different caches of one organization share only its policy.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn publishers_into_different_caches_of_one_org_all_commit(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const CACHES: [&str; 4] = ["one", "two", "three", "four"];
        const PUBLISHERS: usize = 32;
        let (state, app) = server(&pool, &CACHES).await;
        let barrier = Arc::new(Barrier::new(PUBLISHERS));
        let retries = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..PUBLISHERS)
            .map(|number| {
                let (app, barrier, retries) = (app.clone(), barrier.clone(), retries.clone());
                tokio::spawn(async move {
                    let cache = CACHES[number % CACHES.len()];
                    let upload = upload(number);
                    barrier.wait().await;
                    let session = start(&app, cache, SHARED, &upload, &retries).await;
                    finish(&app, SHARED, &session, &upload, &retries).await
                })
            })
            .collect();
        for task in tasks {
            let row = task.await.unwrap();
            assert_eq!(row["published"], true, "{row}");
        }
        for cache in CACHES {
            let (recorded, actual) = totals(&pool, cache).await;
            assert_eq!(recorded, actual, "{cache}");
            assert_eq!(actual.0, (PUBLISHERS / CACHES.len()) as i64, "{cache}");
        }
        let retries = retries.load(Ordering::Relaxed);
        eprintln!("four caches: {PUBLISHERS} publishers, {retries} retried 503s");
        assert!(
            retries <= PUBLISHERS / 4,
            "{retries} publishers were told to retry"
        );
        drop(app);
        state.finish_background().await;
    });
}

/// A session races the deletion of its own path, from seal to publication.
/// Either the path was published first and the deletion removed it, or the
/// deletion aborted the session. The path is never there afterwards.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_session_racing_its_paths_deletion_never_republishes_it(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 40;
        let (state, app) = server(&pool, &["main"]).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let (mut published_first, mut aborted) = (0, 0);
        for round in 0..ROUNDS * 5 {
            if round >= ROUNDS && published_first > 0 && aborted > 0 {
                break;
            }
            let upload = Arc::new(upload(round));
            let session = start(&app, "main", SHARED, &upload, &retries).await;
            let barrier = Arc::new(Barrier::new(2));
            let publisher = tokio::spawn({
                let (app, barrier, retries, upload, session) = (
                    app.clone(),
                    barrier.clone(),
                    retries.clone(),
                    upload.clone(),
                    session.clone(),
                );
                async move {
                    barrier.wait().await;
                    finish(&app, SHARED, &session, &upload, &retries).await
                }
            });
            let deleter = tokio::spawn({
                let (app, barrier, retries, upload) = (
                    app.clone(),
                    barrier.clone(),
                    retries.clone(),
                    upload.clone(),
                );
                async move {
                    barrier.wait().await;
                    // Land the deletion at a different point of the upload's
                    // seal, preparation, and publication each round.
                    pause(round % 20 * 400).await;
                    call(
                        &app,
                        "POST",
                        "/_api/v1/orgs/default/caches/main/paths/delete",
                        OWNER,
                        &json!({"storePathHashes":[upload.hash]}),
                        &retries,
                    )
                    .await
                }
            });
            let row = publisher.await.unwrap();
            let (status, deletion) = deleter.await.unwrap();
            assert_eq!(status, StatusCode::OK, "{deletion}");
            let present: i64 =
                sqlx::query_scalar("SELECT count(*) FROM published_paths WHERE store_path_hash=$1")
                    .bind(&upload.hash)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(
                present, 0,
                "round {round}: a withdrawn path is published: {row} after {deletion}"
            );
            let status: String =
                sqlx::query_scalar("SELECT status FROM upload_sessions WHERE id=$1")
                    .bind(&session)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            let deleted = deletion["deleted"]
                .as_array()
                .unwrap()
                .contains(&json!(upload.hash));
            if row["published"] == true {
                // It can only have been published before the deletion ran.
                assert!(deleted, "round {round}: {row} but {deletion}");
                assert_eq!(status, "completed", "round {round}");
                published_first += 1;
            } else {
                assert!(!deleted, "round {round}: {row} but {deletion}");
                assert_eq!(status, "aborted", "round {round}: {row}");
                aborted += 1;
            }
        }
        eprintln!(
            "seal against deletion: {published_first} published first, {aborted} aborted, \
             {} retried 503s",
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        assert!(
            published_first > 0 && aborted > 0,
            "inconclusive: the deletion only ever ran on one side of the publication"
        );
    });
}

/// A client publishes its job's members while the job is cancelled. Whatever
/// was published by the time the cancellation returns is all that ever is.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn nothing_is_published_after_a_job_cancellation_returns(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 30;
        const MEMBERS: usize = 6;
        let (state, app) = server(&pool, &["main"]).await;
        watch(&pool).await;
        let auth = token(&pool, "job-owner").await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut seen: Vec<i64> = Vec::new();
        for round in 0..ROUNDS * 5 {
            if round >= ROUNDS && seen.iter().any(|n| *n > 0 && *n < MEMBERS as i64) {
                break;
            }
            let members: Vec<_> = (0..MEMBERS).map(|m| upload(round * 100 + m)).collect();
            let job = job(&app, &auth, &format!("cancel-{round}"), &members).await;
            let id = job.rsplit('/').next().unwrap().to_owned();
            let inputs: Vec<_> = members.iter().map(|m| m.input.clone()).collect();
            let (status, allocated) = call(
                &app,
                "POST",
                ALLOCATE,
                &auth,
                &json!({"jobId":id,"paths":inputs}),
                &retries,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{allocated}");
            let barrier = Arc::new(Barrier::new(MEMBERS + 1));
            let publishers: Vec<_> = members
                .into_iter()
                .enumerate()
                .map(|(index, upload)| {
                    let session = allocated["sessions"][index]["sessionId"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    let (app, auth, barrier, retries) =
                        (app.clone(), auth.clone(), barrier.clone(), retries.clone());
                    tokio::spawn(async move {
                        barrier.wait().await;
                        // Spread the publications out, so the other request
                        // can land between two of them.
                        pause(index * 2000).await;
                        finish(&app, &auth, &session, &upload, &retries).await
                    })
                })
                .collect();
            let cancellation = tokio::spawn({
                let (app, auth, barrier, retries, pool, job) = (
                    app.clone(),
                    auth.clone(),
                    barrier.clone(),
                    retries.clone(),
                    pool.clone(),
                    job.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(500 + round % 30 * 400).await;
                    let (status, body) = call(
                        &app,
                        "POST",
                        &format!("{job}/cancel"),
                        &auth,
                        &json!({}),
                        &retries,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["job"]["state"], "cancelled", "{body}");
                    // What had been published when the cancellation returned.
                    count(&pool, "SELECT count(*) FROM published_paths").await
                }
            });
            let at_cancellation = cancellation.await.unwrap();
            let mut published = 0;
            for publisher in publishers {
                let row = publisher.await.unwrap();
                published += i64::from(row["published"] == true);
            }
            let afterwards = count(&pool, "SELECT count(*) FROM published_paths").await;
            assert_eq!(
                afterwards, at_cancellation,
                "round {round}: a member was published after its job was cancelled"
            );
            let open: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM upload_sessions WHERE push_job_id=$1 \
                 AND status NOT IN ('completed','aborted')",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(open, 0, "round {round}");
            let completed: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM upload_sessions WHERE push_job_id=$1 AND status='completed'",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(completed, published, "round {round}");
            seen.push(published);
        }
        eprintln!(
            "publication against cancellation: members published per round {seen:?}, \
             {} retried 503s",
            retries.load(Ordering::Relaxed)
        );
        let late = violations(&pool).await;
        drop(app);
        state.finish_background().await;
        assert!(
            late.is_empty(),
            "committed after the cancellation: {late:?}"
        );
        assert!(
            seen.iter().any(|n| *n > 0 && *n < MEMBERS as i64),
            "inconclusive: no cancellation landed between two publications: {seen:?}"
        );
    });
}

/// A token publishes while it is revoked. Whatever it had published by the
/// time the revocation returns is all it ever publishes.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn nothing_is_published_after_a_token_revocation_returns(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 30;
        const UPLOADS: usize = 6;
        let (state, app) = server(&pool, &["main"]).await;
        watch(&pool).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut seen: Vec<i64> = Vec::new();
        for round in 0..ROUNDS * 5 {
            if round >= ROUNDS && seen.iter().any(|n| *n > 0 && *n < UPLOADS as i64) {
                break;
            }
            let jti = format!("revoked-{round}");
            let auth = token(&pool, &jti).await;
            let mut sessions = Vec::new();
            for number in 0..UPLOADS {
                let upload = upload(round * 100 + number);
                let session = start(&app, "main", &auth, &upload, &retries).await;
                sqlx::query("INSERT INTO race_tokens VALUES ($1,$2)")
                    .bind(&session)
                    .bind(&jti)
                    .execute(&pool)
                    .await
                    .unwrap();
                sessions.push((session, upload));
            }
            let barrier = Arc::new(Barrier::new(UPLOADS + 1));
            let publishers: Vec<_> = sessions
                .into_iter()
                .enumerate()
                .map(|(index, (session, upload))| {
                    let (app, auth, barrier, retries) =
                        (app.clone(), auth.clone(), barrier.clone(), retries.clone());
                    tokio::spawn(async move {
                        barrier.wait().await;
                        // Spread the publications out, so the other request
                        // can land between two of them.
                        pause(index * 2000).await;
                        finish(&app, &auth, &session, &upload, &retries).await
                    })
                })
                .collect();
            let revocation = tokio::spawn({
                let (app, barrier, retries, pool) =
                    (app.clone(), barrier.clone(), retries.clone(), pool.clone());
                async move {
                    barrier.wait().await;
                    pause(500 + round % 30 * 400).await;
                    let (status, body) = call(
                        &app,
                        "POST",
                        &format!("/_api/v1/orgs/default/tokens/{jti}/revoke"),
                        OWNER,
                        &json!({"reason":"raced"}),
                        &retries,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{body}");
                    count(&pool, "SELECT count(*) FROM published_paths").await
                }
            });
            let at_revocation = revocation.await.unwrap();
            let mut published = 0;
            for publisher in publishers {
                let row = publisher.await.unwrap();
                published += i64::from(row["published"] == true);
            }
            let afterwards = count(&pool, "SELECT count(*) FROM published_paths").await;
            assert_eq!(
                afterwards, at_revocation,
                "round {round}: a revoked token published a path"
            );
            seen.push(published);
        }
        eprintln!(
            "publication against revocation: paths published per round {seen:?}, \
             {} retried 503s",
            retries.load(Ordering::Relaxed)
        );
        let late = violations(&pool).await;
        drop(app);
        state.finish_background().await;
        assert!(late.is_empty(), "committed after the revocation: {late:?}");
        assert!(
            seen.iter().any(|n| *n > 0 && *n < UPLOADS as i64),
            "inconclusive: no revocation landed between two publications: {seen:?}"
        );
    });
}

/// A closure is pinned while the evictor wants every path of it. Either the
/// pin is refused because a member is already gone, or it commits and every
/// member stays.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_committed_pins_closure_survives_concurrent_eviction(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 40;
        const CLOSURE: usize = 4;
        let (state, app) = server(&pool, &["main"]).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let (mut pinned, mut refused) = (0, 0);
        for round in 0..ROUNDS * 5 {
            if round >= ROUNDS && pinned > 0 && refused > 0 {
                break;
            }
            sqlx::raw_sql(
                "DELETE FROM pins; DELETE FROM published_paths; DELETE FROM blob_objects; \
                 UPDATE orgs SET storage_limit=NULL WHERE id='default';",
            )
            .execute(&pool)
            .await
            .unwrap();
            // A root that references three dependencies, all published.
            let hashes: Vec<_> = (0..CLOSURE)
                .map(|n| format!("{:032}", round * 10 + n))
                .collect();
            for (index, hash) in hashes.iter().enumerate() {
                let references: Vec<_> = if index == 0 {
                    hashes[1..].iter().map(|h| format!("{h}-fixture")).collect()
                } else {
                    Vec::new()
                };
                sqlx::query(
                    "WITH blob AS (INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) \
                     VALUES($1||$1,40,'zstd','nar/'||$1) RETURNING id) \
                     INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size, \
                         blob_object_id,references_json,last_pushed_at) \
                     SELECT c.id,$1,'/nix/store/'||$1||'-fixture','sha256:'||repeat('0',64),40, \
                         blob.id,$2,make_date(2000,1,1) FROM caches c,blob",
                )
                .bind(hash)
                .bind(json!(references).to_string())
                .execute(&pool)
                .await
                .unwrap();
            }
            // Over its limit by everything it holds.
            sqlx::query("UPDATE orgs SET storage_limit=0 WHERE id='default'")
                .execute(&pool)
                .await
                .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let pin = tokio::spawn({
                let (app, barrier, retries, root) = (
                    app.clone(),
                    barrier.clone(),
                    retries.clone(),
                    format!("/nix/store/{}-fixture", hashes[0]),
                );
                async move {
                    barrier.wait().await;
                    pause(round % 4 * 700).await;
                    call(
                        &app,
                        "POST",
                        "/_api/v1/orgs/default/caches/main/pins",
                        OWNER,
                        &json!({"name":format!("keep-{round}"),"storePath":root,"keep":"forever"}),
                        &retries,
                    )
                    .await
                }
            });
            let eviction = tokio::spawn({
                let (state, barrier) = (state.clone(), barrier.clone());
                async move {
                    barrier.wait().await;
                    pause(round / 4 % 4 * 700).await;
                    // A pass that times out on the pin's cache row is retried.
                    for _ in 0..100 {
                        if capacity::evict(&state, "default").await.is_ok() {
                            return;
                        }
                    }
                    panic!("eviction stayed busy");
                }
            });
            let (status, body) = pin.await.unwrap();
            eviction.await.unwrap();
            // Whatever the first eviction saw, a later one sees the pin.
            capacity::evict(&state, "default").await.unwrap();
            let kept = count(&pool, "SELECT count(*) FROM published_paths").await;
            let missing = count(
                &pool,
                "SELECT count(*) FROM pin_paths m WHERE NOT EXISTS (SELECT 1 FROM published_paths e \
                 WHERE e.cache_id=m.cache_id AND e.store_path_hash=m.store_path_hash)",
            )
            .await;
            assert_eq!(missing, 0, "round {round}: a pinned path was evicted");
            if status == StatusCode::CREATED {
                assert_eq!(kept, CLOSURE as i64, "round {round}: {body}");
                assert_eq!(
                    count(&pool, "SELECT count(*) FROM pin_paths").await,
                    CLOSURE as i64
                );
                pinned += 1;
            } else {
                // The evictor got there first: nothing is left to pin.
                assert_eq!(status, StatusCode::CONFLICT, "round {round}: {body}");
                assert_eq!(kept, 0, "round {round}");
                assert_eq!(count(&pool, "SELECT count(*) FROM pins").await, 0);
                refused += 1;
            }
        }
        eprintln!(
            "pin against eviction: {pinned} pinned, {refused} refused, {} retried 503s",
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        assert!(
            pinned > 0 && refused > 0,
            "inconclusive: the pin only ever ran on one side of the eviction"
        );
    });
}

/// Two allocations of one job member at once end with one session, linked to
/// the member and returned to both.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn concurrent_allocations_of_a_job_member_share_one_session(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 20;
        let (state, app) = server(&pool, &["main"]).await;
        let auth = token(&pool, "job-owner").await;
        let retries = Arc::new(AtomicUsize::new(0));
        for round in 0..ROUNDS {
            let member = upload(round);
            let job = job(
                &app,
                &auth,
                &format!("allocate-{round}"),
                std::slice::from_ref(&member),
            )
            .await;
            let id = job.rsplit('/').next().unwrap().to_owned();
            let request = Arc::new(json!({"jobId":id,"paths":[member.input]}));
            let barrier = Arc::new(Barrier::new(2));
            let allocations: Vec<_> = (0..2)
                .map(|_| {
                    let (app, auth, barrier, retries, request) = (
                        app.clone(),
                        auth.clone(),
                        barrier.clone(),
                        retries.clone(),
                        request.clone(),
                    );
                    tokio::spawn(async move {
                        barrier.wait().await;
                        call(&app, "POST", ALLOCATE, &auth, &request, &retries).await
                    })
                })
                .collect();
            let mut sessions = Vec::new();
            for allocation in allocations {
                let (status, body) = allocation.await.unwrap();
                assert_eq!(status, StatusCode::CREATED, "round {round}: {body}");
                sessions.push(
                    body["sessions"][0]["sessionId"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                );
            }
            assert_eq!(sessions[0], sessions[1], "round {round}");
            let linked: Vec<(String, Option<String>)> = sqlx::query_as(
                "SELECT u.id,(SELECT m.session_id FROM push_job_members m WHERE m.job_id=u.push_job_id) \
                 FROM upload_sessions u WHERE u.push_job_id=$1",
            )
            .bind(&id)
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(
                linked,
                vec![(sessions[0].clone(), Some(sessions[0].clone()))],
                "round {round}"
            );
            // Only a few jobs may be active in an organization at once.
            let (status, body) = call(
                &app,
                "POST",
                &format!("{job}/cancel"),
                &auth,
                &json!({}),
                &retries,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        eprintln!(
            "concurrent allocation: {} retried 503s",
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
    });
}

/// Registrations of one organization's limits arrive at once and out of
/// order. The newest version's policy is what remains.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn concurrent_org_limits_end_on_the_newest_version(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: i64 = 12;
        const WRITERS: i64 = 8;
        let (state, app) = server(&pool, &[]).await;
        sqlx::query("INSERT INTO orgs(id,slug) VALUES ('org_race','race')")
            .execute(&pool)
            .await
            .unwrap();
        let retries = Arc::new(AtomicUsize::new(0));
        for round in 0..ROUNDS {
            let barrier = Arc::new(Barrier::new(WRITERS as usize));
            let writers: Vec<_> = (1..=WRITERS)
                .map(|writer| {
                    let version = round * WRITERS + writer;
                    let (app, barrier, retries) = (app.clone(), barrier.clone(), retries.clone());
                    tokio::spawn(async move {
                        barrier.wait().await;
                        let (status, body) = call(
                            &app,
                            "PUT",
                            "/_api/v1/orgs/org_race",
                            OWNER,
                            &json!({"storageLimit":version * 100,"privateCaches":version % 2 == 0,
                                "customSigningKeys":false,"limitsVersion":version.to_string()}),
                            &retries,
                        )
                        .await;
                        assert_eq!(status, StatusCode::OK, "version {version}: {body}");
                    })
                })
                .collect();
            for writer in writers {
                writer.await.unwrap();
            }
            let newest = (round + 1) * WRITERS;
            let stored: (Option<i64>, Option<i64>, bool) = sqlx::query_as(
                "SELECT limits_version,storage_limit,private_caches FROM orgs WHERE id='org_race'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                stored,
                (Some(newest), Some(newest * 100), newest % 2 == 0),
                "round {round}"
            );
        }
        eprintln!(
            "concurrent limits: {} retried 503s",
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
    });
}

/// Ten paths of 40 bytes, pushed on consecutive days, in an organization
/// allowed to keep five of them.
async fn overage(pool: &PgPool) {
    sqlx::raw_sql(
        "DELETE FROM published_paths; DELETE FROM blob_objects; \
         UPDATE orgs SET storage_limit=NULL WHERE id='default';",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "WITH blobs AS (INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) \
         SELECT repeat(n::text,64),40,'zstd','nar/'||n FROM generate_series(0,9) n \
         RETURNING id,left(file_hash,1) AS digit) \
         INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size, \
             blob_object_id,last_pushed_at) \
         SELECT c.id,repeat(digit,32),'/nix/store/'||repeat(digit,32)||'-fixture', \
             'sha256:'||repeat('0',64),40,blobs.id,make_date(2000,1,digit::integer+1) \
         FROM caches c,blobs",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("UPDATE orgs SET storage_limit=200 WHERE id='default'")
        .execute(pool)
        .await
        .unwrap();
}

async fn kept(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT COALESCE(string_agg(left(store_path_hash,1),'' ORDER BY store_path_hash),'') \
         FROM published_paths",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Whether some transaction in this database holds an advisory lock.
async fn leased(pool: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND granted \
         AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// One evictor works on an organization at a time. A second one that arrives
/// while the first is inside its pass leaves without evicting, and two that
/// start together remove the overage once: the least recently used half.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn two_evictors_remove_an_overage_once(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 30;
        let (state, app) = server(&pool, &["main"]).await;
        // Proven overlap: keep the first evictor inside its pass, in a slow
        // delete, and run the second meanwhile.
        sqlx::raw_sql(
            "CREATE FUNCTION slow_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
             PERFORM pg_sleep(0.5); RETURN NULL; END $$; \
             CREATE TRIGGER slow_delete BEFORE DELETE ON published_paths \
             FOR EACH STATEMENT EXECUTE FUNCTION slow_delete();",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut proven = false;
        for _ in 0..20 {
            overage(&pool).await;
            let first = tokio::spawn({
                let state = state.clone();
                async move { capacity::evict(&state, "default").await.unwrap() }
            });
            while !leased(&pool).await && !first.is_finished() {
                tokio::task::yield_now().await;
            }
            let second = capacity::evict(&state, "default").await.unwrap();
            // The first was still inside its pass when the second returned.
            let overlapped = leased(&pool).await && !first.is_finished();
            let freed = first.await.unwrap();
            assert_eq!(kept(&pool).await, "56789", "freed {freed} and {second}");
            if overlapped {
                assert_eq!(second, 0, "the second evictor did not yield");
                assert_eq!(freed, 200);
                proven = true;
                break;
            }
        }
        sqlx::raw_sql("DROP TRIGGER slow_delete ON published_paths; DROP FUNCTION slow_delete();")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            proven,
            "inconclusive: the second evictor never ran inside the first's pass"
        );
        let mut idle = 0;
        for round in 0..ROUNDS {
            overage(&pool).await;
            let barrier = Arc::new(Barrier::new(2));
            let evictors: Vec<_> = (0..2)
                .map(|_| {
                    let (state, barrier) = (state.clone(), barrier.clone());
                    tokio::spawn(async move {
                        barrier.wait().await;
                        capacity::evict(&state, "default").await.unwrap()
                    })
                })
                .collect();
            let mut freed = Vec::new();
            for evictor in evictors {
                freed.push(evictor.await.unwrap());
            }
            assert_eq!(kept(&pool).await, "56789", "round {round}: freed {freed:?}");
            assert_eq!(freed.iter().sum::<u64>(), 200, "round {round}");
            idle += freed.iter().filter(|bytes| **bytes == 0).count();
            let (recorded, actual) = totals(&pool, "main").await;
            assert_eq!(recorded, actual, "round {round}");
        }
        eprintln!("two evictors: one of them found nothing to do in {idle} of {ROUNDS} rounds");
        drop(app);
        state.finish_background().await;
    });
}

/// `fillers` old 40-byte paths in the only cache, inserted directly.
async fn fill(pool: &PgPool, fillers: usize) {
    sqlx::query(
        "WITH blobs AS (INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) \
         SELECT 'f'||lpad(n::text,63,'0'),40,'zstd','nar/filler/'||n FROM generate_series(1,$1) n \
         RETURNING id,right(file_hash,31) AS digits) \
         INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size, \
             blob_object_id,last_pushed_at) \
         SELECT c.id,'f'||digits,'/nix/store/f'||digits||'-filler', \
             'sha256:'||repeat('0',64),40,blobs.id,make_date(2000,1,1) \
         FROM caches c,blobs",
    )
    .bind(fillers as i32)
    .execute(pool)
    .await
    .unwrap();
}

/// The evictor reads the limit without sharing the org row. A limit raised
/// while a pass is in flight must not be acted on after the raise returned.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_limit_raised_before_eviction_is_what_the_evictor_obeys(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 60;
        const FILLERS: usize = 200;
        let (state, app) = server(&pool, &["main"]).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut violations = Vec::new();
        let mut orders = Orders::default();
        for round in 0..ROUNDS * 5 {
            if orders.settled(round, ROUNDS) {
                break;
            }
            sqlx::raw_sql(
                "DELETE FROM published_paths; DELETE FROM blob_objects; \
                 UPDATE orgs SET storage_limit=NULL WHERE id='default';",
            )
            .execute(&pool)
            .await
            .unwrap();
            fill(&pool, FILLERS).await;
            sqlx::query("UPDATE orgs SET storage_limit=0 WHERE id='default'")
                .execute(&pool)
                .await
                .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let raise = tokio::spawn({
                let (app, barrier, retries, pool) =
                    (app.clone(), barrier.clone(), retries.clone(), pool.clone());
                async move {
                    barrier.wait().await;
                    pause(round % 20 * 300).await;
                    let (status, body) = call(
                        &app,
                        "PUT",
                        "/_api/v1/orgs/default",
                        OWNER,
                        &json!({"storageLimit":1_000_000_000i64,"privateCaches":true,
                            "customSigningKeys":false,"limitsVersion":(round + 1).to_string()}),
                        &retries,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["storageLimit"], 1_000_000_000i64, "{body}");
                    // What was still published once the raise had returned.
                    count(&pool, "SELECT count(*) FROM published_paths").await
                }
            });
            let eviction = tokio::spawn({
                let (state, barrier) = (state.clone(), barrier.clone());
                async move {
                    barrier.wait().await;
                    for _ in 0..100 {
                        if capacity::evict(&state, "default").await.is_ok() {
                            return;
                        }
                    }
                    panic!("eviction stayed busy");
                }
            });
            let at_raise = raise.await.unwrap();
            eviction.await.unwrap();
            let afterwards = count(&pool, "SELECT count(*) FROM published_paths").await;
            if afterwards < at_raise {
                violations.push((round, at_raise, afterwards));
            }
            orders.note(at_raise == FILLERS as i64);
        }
        eprintln!(
            "limit raise against eviction: (round, published when the raise returned, published afterwards) {violations:?}"
        );
        drop(app);
        state.finish_background().await;
        assert!(
            violations.is_empty(),
            "paths were evicted under the old limit after the raise returned: {violations:?}"
        );
        orders.conclusive("the limit raise against the eviction");
    });
}

/// A sealed job is authorized while the evictor wants its already published
/// member. Once the authorization has returned and the member is still
/// published, it is job-protected and must stay.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_member_published_when_its_job_is_authorized_is_not_evicted(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 80;
        const FILLERS: usize = 200;
        let (state, app) = server(&pool, &["main"]).await;
        let auth = token(&pool, "job-owner").await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut violations = Vec::new();
        let mut orders = Orders::default();
        for round in 0..ROUNDS * 5 {
            if orders.settled(round, ROUNDS) {
                break;
            }
            sqlx::raw_sql(
                "DELETE FROM published_paths; DELETE FROM blob_objects; \
                 UPDATE orgs SET storage_limit=NULL WHERE id='default';",
            )
            .execute(&pool)
            .await
            .unwrap();
            // Publish the member for real, then age it.
            let member = upload(round);
            let session = start(&app, "main", &auth, &member, &retries).await;
            let row = finish(&app, &auth, &session, &member, &retries).await;
            assert_eq!(row["published"], true, "{row}");
            sqlx::query("UPDATE published_paths SET last_pushed_at=make_date(1999,1,1),last_accessed_at=NULL")
                .execute(&pool)
                .await
                .unwrap();
            fill(&pool, FILLERS).await;
            // A sealed, not yet authorized job naming the member.
            let (status, created) = call(
                &app,
                "POST",
                JOBS,
                &auth,
                &json!({"idempotencyKey":format!("protect-{round}"),"mode":"selected","roots":[member.input["storePath"]]}),
                &retries,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            let job = format!("{JOBS}/{}", created["job"]["id"].as_str().unwrap());
            let mut input = member.input.clone();
            input.as_object_mut().unwrap().remove("inline");
            let (status, chunk) = call(
                &app,
                "PUT",
                &format!("{job}/manifest/0"),
                &auth,
                &json!({"members":[member.input]}),
                &retries,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{chunk}");
            let (status, sealed) = call(
                &app,
                "POST",
                &format!("{job}/seal"),
                &auth,
                &json!({}),
                &retries,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{sealed}");
            sqlx::query("UPDATE orgs SET storage_limit=0 WHERE id='default'")
                .execute(&pool)
                .await
                .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let hash = member.hash.clone();
            let authorize = tokio::spawn({
                let (app, auth, barrier, retries, pool, job, hash) = (
                    app.clone(),
                    auth.clone(),
                    barrier.clone(),
                    retries.clone(),
                    pool.clone(),
                    job.clone(),
                    hash.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(round % 40 * 250).await;
                    let (status, body) = call(
                        &app,
                        "POST",
                        &format!("{job}/resume"),
                        &auth,
                        &json!({}),
                        &retries,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{body}");
                    // Is the member published now that the job protects it?
                    sqlx::query_scalar::<_, i64>(
                        "SELECT count(*) FROM published_paths WHERE store_path_hash=$1",
                    )
                    .bind(&hash)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
                }
            });
            let eviction = tokio::spawn({
                let (state, barrier) = (state.clone(), barrier.clone());
                async move {
                    barrier.wait().await;
                    for _ in 0..100 {
                        if capacity::evict(&state, "default").await.is_ok() {
                            return;
                        }
                    }
                    panic!("eviction stayed busy");
                }
            });
            let protected = authorize.await.unwrap();
            eviction.await.unwrap();
            orders.note(protected == 1);
            let afterwards: i64 =
                sqlx::query_scalar("SELECT count(*) FROM published_paths WHERE store_path_hash=$1")
                    .bind(&hash)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            if afterwards < protected {
                let (status, body) = call(
                    &app,
                    "POST",
                    &format!("{job}/complete"),
                    &auth,
                    &json!({}),
                    &retries,
                )
                .await;
                violations.push((round, status.as_u16(), body["error"].to_string()));
            }
            let (status, body) = call(
                &app,
                "POST",
                &format!("{job}/cancel"),
                &auth,
                &json!({}),
                &retries,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        eprintln!(
            "job authorization against eviction: (round, completion status, completion error) {violations:?}"
        );
        drop(app);
        state.finish_background().await;
        assert!(
            violations.is_empty(),
            "a member published when its job was authorized was evicted afterwards: {violations:?}"
        );
        orders.conclusive("the authorization against the eviction");
    });
}

/// Requests against a cache race its deletion. None may be answered 500, and
/// nothing may be left pointing at the deleted cache.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn requests_racing_a_cache_deletion_are_refused_cleanly(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 60;
        let (state, app) = server(&pool, &[]).await;
        let auth = token(&pool, "deleter").await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
        // Whether a kind of request has been seen on both sides of a deletion.
        let both = |outcomes: &std::collections::BTreeMap<String, usize>, who: &str| {
            ["201", "200"]
                .iter()
                .any(|ok| outcomes.contains_key(&format!("{who} -> {ok}")))
                && outcomes.contains_key(&format!("{who} -> 404"))
        };
        const REQUESTS: [&str; 3] = ["job create", "session create", "inline publish"];
        for round in 0..ROUNDS * 5 {
            if round >= ROUNDS && REQUESTS.iter().all(|who| both(&outcomes, who)) {
                break;
            }
            let name = format!("tmp{round}");
            sqlx::query("WITH c AS (INSERT INTO caches(name) VALUES ($1) RETURNING id) INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM c")
                .bind(&name).execute(&pool).await.unwrap();
            let first = Arc::new(upload(round * 10));
            let second = Arc::new(upload(round * 10 + 1));
            let session = start(&app, &name, &auth, &first, &retries).await;
            let barrier = Arc::new(Barrier::new(4));
            let deleter = tokio::spawn({
                let (app, barrier, retries, name) =
                    (app.clone(), barrier.clone(), retries.clone(), name.clone());
                async move {
                    barrier.wait().await;
                    pause(round % 20 * 150).await;
                    call(
                        &app,
                        "POST",
                        &format!("/_api/v1/orgs/default/caches/{name}/delete"),
                        OWNER,
                        &json!({}),
                        &retries,
                    )
                    .await
                    .0
                    .as_u16()
                }
            });
            let jobber = tokio::spawn({
                let (app, auth, barrier, retries, name, first) = (
                    app.clone(),
                    auth.clone(),
                    barrier.clone(),
                    retries.clone(),
                    name.clone(),
                    first.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(round % 5 * 500).await;
                    call(&app, "POST", &format!("/_api/v1/caches/{name}/push-jobs"), &auth,
                        &json!({"idempotencyKey":format!("k{round}"),"mode":"selected","roots":[first.input["storePath"]]}), &retries).await.0.as_u16()
                }
            });
            let allocator = tokio::spawn({
                let (app, auth, barrier, retries, name, second) = (
                    app.clone(),
                    auth.clone(),
                    barrier.clone(),
                    retries.clone(),
                    name.clone(),
                    second.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(round % 7 * 300).await;
                    call(
                        &app,
                        "POST",
                        &format!("/_api/v1/caches/{name}/upload-streams/batch"),
                        &auth,
                        &json!({"paths":[second.input]}),
                        &retries,
                    )
                    .await
                    .0
                    .as_u16()
                }
            });
            let publisher = tokio::spawn({
                let (app, auth, barrier, retries, first, session) = (
                    app.clone(),
                    auth.clone(),
                    barrier.clone(),
                    retries.clone(),
                    first.clone(),
                    session.clone(),
                );
                async move {
                    barrier.wait().await;
                    let row = finish(&app, &auth, &session, &first, &retries).await;
                    if row["published"] == true {
                        200
                    } else {
                        row["status"].as_u64().unwrap_or(0) as u16
                    }
                }
            });
            for (who, task) in [
                ("delete", deleter),
                ("job create", jobber),
                ("session create", allocator),
                ("inline publish", publisher),
            ] {
                let status = task.await.unwrap();
                *outcomes.entry(format!("{who} -> {status}")).or_default() += 1;
            }
        }
        eprintln!("requests against cache deletion: {outcomes:#?}");
        let orphans = count(&pool, "SELECT count(*) FROM nar_installations n WHERE NOT EXISTS (SELECT 1 FROM caches c WHERE c.id=n.cache_id)").await;
        let left = count(&pool, "SELECT (SELECT count(*) FROM caches)+(SELECT count(*) FROM upload_sessions)+(SELECT count(*) FROM published_paths)+(SELECT count(*) FROM push_jobs)").await;
        eprintln!(
            "left after all deletions: {left} rows in caches/sessions/paths/jobs, {orphans} candidates of deleted caches"
        );
        drop(app);
        state.finish_background().await;
        assert!(
            outcomes.keys().all(|k| !k.ends_with("500")),
            "{outcomes:#?}"
        );
        assert_eq!(left, 0);
        for who in REQUESTS {
            assert!(
                both(&outcomes, who),
                "inconclusive: {who} only ever ran on one side of the deletion: {outcomes:#?}"
            );
        }
    });
}

/// Publishers, an evictor, and path deletions in one cache at once. Totals
/// must stay exact and every session must end.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn mixed_writers_in_one_cache_keep_totals_exact(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const UPLOADS: usize = 160;
        const WORKERS: usize = 8;
        let (state, app) = server(&pool, &["main"]).await;
        sqlx::query("UPDATE orgs SET storage_limit=600 WHERE id='default'")
            .execute(&pool)
            .await
            .unwrap();
        let retries = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let evictor = tokio::spawn({
            let (state, done) = (state.clone(), done.clone());
            async move {
                let mut failed = 0;
                while !done.load(Ordering::Relaxed) {
                    if capacity::evict(&state, "default").await.is_err() {
                        failed += 1;
                    }
                    tokio::task::yield_now().await;
                }
                failed
            }
        });
        let deleter = tokio::spawn({
            let (app, done, retries) = (app.clone(), done.clone(), retries.clone());
            async move {
                let mut n = 0usize;
                let mut statuses = std::collections::BTreeMap::<u16, usize>::new();
                while !done.load(Ordering::Relaxed) {
                    let hashes: Vec<_> = (0..4)
                        .map(|k| format!("{:032}", (n * 7 + k) % UPLOADS))
                        .collect();
                    let (status, _) = call(
                        &app,
                        "POST",
                        "/_api/v1/orgs/default/caches/main/paths/delete",
                        OWNER,
                        &json!({"storePathHashes":hashes}),
                        &retries,
                    )
                    .await;
                    *statuses.entry(status.as_u16()).or_default() += 1;
                    n += 1;
                    pause(700).await;
                }
                statuses
            }
        });
        let next = Arc::new(AtomicUsize::new(0));
        let publishers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let (app, retries, next) = (app.clone(), retries.clone(), next.clone());
                tokio::spawn(async move {
                    let mut statuses = std::collections::BTreeMap::<String, usize>::new();
                    loop {
                        let number = next.fetch_add(1, Ordering::Relaxed);
                        if number >= UPLOADS {
                            return statuses;
                        }
                        let upload = upload(number);
                        let mut outcome = String::new();
                        for _ in 0..400 {
                            let (status, created) = send(
                                &app,
                                "POST",
                                ALLOCATE,
                                SHARED,
                                &[("content-type", "application/json")],
                                serde_json::to_vec(&json!({"paths":[upload.input]})).unwrap(),
                            )
                            .await;
                            if status == StatusCode::SERVICE_UNAVAILABLE {
                                tokio::time::sleep(Duration::from_millis(5)).await;
                                continue;
                            }
                            if status != StatusCode::CREATED {
                                outcome = format!("create {status}");
                                break;
                            }
                            let session = created["sessions"][0]["sessionId"]
                                .as_str()
                                .unwrap()
                                .to_owned();
                            let row = finish(&app, SHARED, &session, &upload, &retries).await;
                            outcome = if row["published"] == true {
                                "published".into()
                            } else {
                                format!("finish {} {}", row["status"], row["error"])
                            };
                            break;
                        }
                        *statuses.entry(outcome).or_default() += 1;
                    }
                })
            })
            .collect();
        let mut all = std::collections::BTreeMap::<String, usize>::new();
        for publisher in publishers {
            for (k, v) in publisher.await.unwrap() {
                *all.entry(k).or_default() += v;
            }
        }
        done.store(true, Ordering::Relaxed);
        let failed = evictor.await.unwrap();
        let deletions = deleter.await.unwrap();
        capacity::evict(&state, "default").await.unwrap();
        let (recorded, actual) = totals(&pool, "main").await;
        let open = count(
            &pool,
            "SELECT count(*) FROM upload_sessions WHERE status NOT IN ('completed','aborted')",
        )
        .await;
        let usage = count(&pool, "SELECT size::bigint FROM caches").await;
        eprintln!(
            "mixed writers: uploads {all:#?}, deletions {deletions:?}, {failed} busy eviction passes, {} retried 503s; totals {recorded:?} vs {actual:?}; {open} open sessions; usage {usage}",
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        assert_eq!(recorded, actual);
        assert_eq!(open, 0);
        assert!(all.keys().all(|k| !k.contains("500")), "{all:#?}");
    });
}

/// Clients push the same few paths again and again while the evictor keeps
/// the organization at its limit. Nobody deletes or cancels anything, so no
/// upload may be refused for good.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn eviction_does_not_refuse_a_new_upload_of_the_evicted_path(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const PUSHES: usize = 400;
        const PATHS: usize = 3;
        const WORKERS: usize = 6;
        let (state, app) = server(&pool, &["main"]).await;
        sqlx::query("UPDATE orgs SET storage_limit=150 WHERE id='default'")
            .execute(&pool)
            .await
            .unwrap();
        let retries = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let evictor = tokio::spawn({
            let (state, done) = (state.clone(), done.clone());
            async move {
                while !done.load(Ordering::Relaxed) {
                    let _ = capacity::evict(&state, "default").await;
                    tokio::task::yield_now().await;
                }
            }
        });
        let next = Arc::new(AtomicUsize::new(0));
        let pushers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let (app, retries, next) = (app.clone(), retries.clone(), next.clone());
                tokio::spawn(async move {
                    let mut statuses = std::collections::BTreeMap::<String, usize>::new();
                    loop {
                        let number = next.fetch_add(1, Ordering::Relaxed);
                        if number >= PUSHES {
                            return statuses;
                        }
                        let upload = upload(number % PATHS);
                        let mut outcome = String::from("create stayed busy");
                        for _ in 0..2000 {
                            let (status, created) = send(
                                &app,
                                "POST",
                                ALLOCATE,
                                SHARED,
                                &[("content-type", "application/json")],
                                serde_json::to_vec(&json!({"paths":[upload.input]})).unwrap(),
                            )
                            .await;
                            if status == StatusCode::SERVICE_UNAVAILABLE {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                                continue;
                            }
                            if status != StatusCode::CREATED {
                                outcome = format!("create {status} {created}");
                                break;
                            }
                            let session = created["sessions"][0]["sessionId"]
                                .as_str()
                                .unwrap()
                                .to_owned();
                            let row = finish(&app, SHARED, &session, &upload, &retries).await;
                            outcome = if row["published"] == true {
                                "published".into()
                            } else {
                                format!("finish {} {}", row["status"], row["error"])
                            };
                            break;
                        }
                        *statuses.entry(outcome).or_default() += 1;
                    }
                })
            })
            .collect();
        let mut all = std::collections::BTreeMap::<String, usize>::new();
        for pusher in pushers {
            for (k, v) in pusher.await.unwrap() {
                *all.entry(k).or_default() += v;
            }
        }
        done.store(true, Ordering::Relaxed);
        evictor.await.unwrap();
        let aborted = count(
            &pool,
            "SELECT count(*) FROM upload_sessions WHERE status='aborted'",
        )
        .await;
        let (recorded, actual) = totals(&pool, "main").await;
        eprintln!(
            "re-push against eviction: {all:#?}; {aborted} sessions aborted; totals {recorded:?} vs {actual:?}"
        );
        drop(app);
        state.finish_background().await;
        assert_eq!(recorded, actual);
        assert_eq!(all.len(), 1, "{all:#?}");
    });
}

/// An organization is over its limit by exactly the 100 paths an owner then
/// deletes. Once that deletion has returned the organization is at its limit,
/// so nothing else may be evicted.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn an_overage_already_deleted_is_not_evicted_again(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 60;
        let (state, app) = server(&pool, &["main"]).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut violations = Vec::new();
        let mut orders = Orders::default();
        let newest: Vec<_> = (101..=200).map(|n| format!("f{n:031}")).collect();
        for round in 0..ROUNDS * 5 {
            if orders.settled(round, ROUNDS) {
                break;
            }
            sqlx::raw_sql(
                "DELETE FROM published_paths; DELETE FROM blob_objects; \
                 UPDATE orgs SET storage_limit=NULL WHERE id='default';",
            )
            .execute(&pool)
            .await
            .unwrap();
            fill(&pool, 200).await;
            sqlx::query("UPDATE orgs SET storage_limit=4000 WHERE id='default'")
                .execute(&pool)
                .await
                .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let deletion = tokio::spawn({
                let (app, barrier, retries, pool, newest) = (
                    app.clone(),
                    barrier.clone(),
                    retries.clone(),
                    pool.clone(),
                    newest.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(round % 20 * 200).await;
                    let (status, body) = call(
                        &app,
                        "POST",
                        "/_api/v1/orgs/default/caches/main/paths/delete",
                        OWNER,
                        &json!({"storePathHashes":newest}),
                        &retries,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{body}");
                    (
                        body["deleted"].as_array().unwrap().len(),
                        count(&pool, "SELECT count(*) FROM published_paths").await,
                    )
                }
            });
            let eviction = tokio::spawn({
                let (state, barrier) = (state.clone(), barrier.clone());
                async move {
                    barrier.wait().await;
                    for _ in 0..100 {
                        if capacity::evict(&state, "default").await.is_ok() {
                            return;
                        }
                    }
                    panic!("eviction stayed busy");
                }
            });
            let (deleted, at_return) = deletion.await.unwrap();
            eviction.await.unwrap();
            let afterwards = count(&pool, "SELECT count(*) FROM published_paths").await;
            // 100 deleted by the owner and 100 left: exactly at the limit.
            if deleted == 100 && at_return == 100 && afterwards < 100 {
                violations.push((round, at_return, afterwards));
            }
            orders.note(deleted == 100 && at_return == 100);
        }
        eprintln!(
            "owner deletion against eviction: (round, left when the deletion returned, left afterwards) {violations:?}"
        );
        drop(app);
        state.finish_background().await;
        assert!(
            violations.is_empty(),
            "the evictor removed an overage that was already gone: {violations:?}"
        );
        orders.conclusive("the owner's deletion against the eviction");
    });
}

/// A job is completed while its only member is deleted. Completion first
/// leaves a completed job; deletion first cancels the job, and completion
/// then finds it cancelled. Completion never meets a job that is still sealed
/// with its member already gone.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn completion_racing_a_members_deletion_sees_the_job_cancelled(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 40;
        let (state, app) = server(&pool, &["main"]).await;
        let auth = token(&pool, "job-owner").await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut orders = Orders::default();
        for round in 0..ROUNDS * 5 {
            if orders.settled(round, ROUNDS) {
                break;
            }
            let member = upload(round);
            let job = job(
                &app,
                &auth,
                &format!("complete-{round}"),
                std::slice::from_ref(&member),
            )
            .await;
            let id = job.rsplit('/').next().unwrap().to_owned();
            let (status, allocated) = call(
                &app,
                "POST",
                ALLOCATE,
                &auth,
                &json!({"jobId":id,"paths":[member.input]}),
                &retries,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{allocated}");
            let session = allocated["sessions"][0]["sessionId"].as_str().unwrap();
            let row = finish(&app, &auth, session, &member, &retries).await;
            assert_eq!(row["published"], true, "{row}");
            let barrier = Arc::new(Barrier::new(2));
            let completion = tokio::spawn({
                let (app, auth, barrier, retries, job) = (
                    app.clone(),
                    auth.clone(),
                    barrier.clone(),
                    retries.clone(),
                    job.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(round % 8 * 250).await;
                    call(
                        &app,
                        "POST",
                        &format!("{job}/complete"),
                        &auth,
                        &json!({}),
                        &retries,
                    )
                    .await
                }
            });
            let deletion = tokio::spawn({
                let (app, barrier, retries, hash) = (
                    app.clone(),
                    barrier.clone(),
                    retries.clone(),
                    member.hash.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(round / 8 % 5 * 250).await;
                    call(
                        &app,
                        "POST",
                        "/_api/v1/orgs/default/caches/main/paths/delete",
                        OWNER,
                        &json!({"storePathHashes":[hash]}),
                        &retries,
                    )
                    .await
                }
            });
            let (completed, completion) = completion.await.unwrap();
            let (deleted, deletion) = deletion.await.unwrap();
            assert_eq!(deleted, StatusCode::OK, "{deletion}");
            let state: String = sqlx::query_scalar("SELECT state FROM push_jobs WHERE id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(
                count(&pool, "SELECT count(*) FROM published_paths").await,
                0,
                "round {round}"
            );
            if completed == StatusCode::OK {
                assert_eq!(state, "completed", "round {round}: {completion}");
            } else {
                assert_eq!(
                    completed,
                    StatusCode::CONFLICT,
                    "round {round}: {completion}"
                );
                assert_eq!(state, "cancelled", "round {round}: {completion}");
                assert_eq!(
                    completion["error"], "Only a sealed job can complete",
                    "round {round}"
                );
            }
            orders.note(completed == StatusCode::OK);
        }
        eprintln!(
            "completion against deletion: {} completed first, {} cancelled first, {} retried 503s",
            orders.one,
            orders.other,
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        orders.conclusive("the completion against the deletion");
    });
}

/// A job's authorization is renewed while its token is revoked. Whichever
/// runs first, the job ends without an authorization.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_resume_racing_its_tokens_revocation_leaves_no_authorization(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 40;
        let (state, app) = server(&pool, &["main"]).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut orders = Orders::default();
        for round in 0..ROUNDS * 5 {
            if orders.settled(round, ROUNDS) {
                break;
            }
            let jti = format!("resumed-{round}");
            let auth = token(&pool, &jti).await;
            let member = upload(round);
            let job = job(
                &app,
                &auth,
                &format!("resume-{round}"),
                std::slice::from_ref(&member),
            )
            .await;
            let id = job.rsplit('/').next().unwrap().to_owned();
            let barrier = Arc::new(Barrier::new(2));
            let resume = tokio::spawn({
                let (app, auth, barrier, retries, job) = (
                    app.clone(),
                    auth.clone(),
                    barrier.clone(),
                    retries.clone(),
                    job.clone(),
                );
                async move {
                    barrier.wait().await;
                    pause(round % 8 * 250).await;
                    call(
                        &app,
                        "POST",
                        &format!("{job}/resume"),
                        &auth,
                        &json!({}),
                        &retries,
                    )
                    .await
                }
            });
            let revocation = tokio::spawn({
                let (app, barrier, retries, jti) =
                    (app.clone(), barrier.clone(), retries.clone(), jti.clone());
                async move {
                    barrier.wait().await;
                    pause(round / 8 % 5 * 250).await;
                    call(
                        &app,
                        "POST",
                        &format!("/_api/v1/orgs/default/tokens/{jti}/revoke"),
                        OWNER,
                        &json!({"reason":"raced"}),
                        &retries,
                    )
                    .await
                }
            });
            let (resumed, body) = resume.await.unwrap();
            let (revoked, revocation) = revocation.await.unwrap();
            assert_eq!(revoked, StatusCode::OK, "{revocation}");
            assert!(
                resumed == StatusCode::OK || resumed == StatusCode::UNAUTHORIZED,
                "round {round}: {resumed} {body}"
            );
            let authorized: bool = sqlx::query_scalar(
                "SELECT authorization_jti IS NOT NULL FROM push_jobs WHERE id=$1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(!authorized, "round {round}: resumed {resumed}");
            orders.note(resumed == StatusCode::OK);
            // The revoked token cannot cancel its job; make room for the next.
            sqlx::query("UPDATE push_jobs SET state='cancelled' WHERE id=$1")
                .bind(&id)
                .execute(&pool)
                .await
                .unwrap();
        }
        eprintln!(
            "resume against revocation: {} resumed first, {} revoked first, {} retried 503s",
            orders.one,
            orders.other,
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        orders.conclusive("the resume against the revocation");
    });
}

/// A cache turns private while a session in it is published. Whatever is
/// published points at bytes in the bucket the cache's visibility names.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_publication_racing_a_visibility_change_lands_in_the_right_bucket(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 40;
        let (state, app) = server(&pool, &[]).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut orders = Orders::default();
        for round in 0..ROUNDS * 5 {
            if orders.settled(round, ROUNDS) {
                break;
            }
            let name = format!("vis{round}");
            sqlx::query(
                "WITH c AS (INSERT INTO caches(name) VALUES ($1) RETURNING id) \
                 INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM c",
            )
            .bind(&name)
            .execute(&pool)
            .await
            .unwrap();
            let upload = Arc::new(upload(round));
            let session = start(&app, &name, SHARED, &upload, &retries).await;
            let barrier = Arc::new(Barrier::new(2));
            let publisher = tokio::spawn({
                let (app, barrier, retries, upload) = (
                    app.clone(),
                    barrier.clone(),
                    retries.clone(),
                    upload.clone(),
                );
                async move {
                    barrier.wait().await;
                    finish(&app, SHARED, &session, &upload, &retries).await
                }
            });
            let change = tokio::spawn({
                let (app, barrier, retries, name) =
                    (app.clone(), barrier.clone(), retries.clone(), name.clone());
                async move {
                    barrier.wait().await;
                    pause(round % 20 * 400).await;
                    call(
                        &app,
                        "POST",
                        "/_api/v1/orgs/default/caches",
                        OWNER,
                        &json!({"name":name,"private":true}),
                        &retries,
                    )
                    .await
                }
            });
            let row = publisher.await.unwrap();
            let (changed, body) = change.await.unwrap();
            assert!(
                changed == StatusCode::OK || changed == StatusCode::CONFLICT,
                "round {round}: {changed} {body}"
            );
            let public: bool = sqlx::query_scalar("SELECT is_public FROM caches WHERE name=$1")
                .bind(&name)
                .fetch_one(&pool)
                .await
                .unwrap();
            // A change is refused exactly when a path was already published.
            assert_eq!(
                public,
                changed == StatusCode::CONFLICT,
                "round {round}: {body}"
            );
            let misplaced: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM published_paths p JOIN caches c ON c.id=p.cache_id \
                 JOIN blob_objects b ON b.id=p.blob_object_id WHERE c.name=$1 \
                 AND CASE WHEN c.is_public THEN b.public_key IS NULL ELSE b.private_key IS NULL END",
            )
            .bind(&name)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(misplaced, 0, "round {round}: {row} after {body}");
            if changed == StatusCode::CONFLICT {
                assert_eq!(row["published"], true, "round {round}: {row}");
            }
            orders.note(changed == StatusCode::OK);
        }
        eprintln!(
            "publication against a visibility change: {} changed first, {} published first, \
             {} retried 503s",
            orders.one,
            orders.other,
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        orders.conclusive("the visibility change against the publication");
    });
}

/// Go artifacts are uploaded while their cache's Go data is reset. A reset
/// logs every artifact it clears exactly once, and no transfer that started
/// before it becomes available in the generation it cleared.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn go_uploads_racing_a_reset_never_land_in_the_cleared_generation(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 25;
        const UPLOADS: usize = 6;
        let (state, app) = server(&pool, &["main"]).await;
        sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'go' FROM caches")
            .execute(&pool)
            .await
            .unwrap();
        let auth = token(&pool, "go-writer").await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut statuses = std::collections::BTreeMap::<u16, usize>::new();
        for round in 0..ROUNDS {
            let barrier = Arc::new(Barrier::new(UPLOADS + 1));
            let uploads: Vec<_> = (0..UPLOADS)
                .map(|index| {
                    let (app, auth, barrier, retries) =
                        (app.clone(), auth.clone(), barrier.clone(), retries.clone());
                    tokio::spawn(async move {
                        let bytes = format!("go artifact {round} {index}").into_bytes();
                        let action = hex::encode(Sha256::digest(format!("action {round} {index}")));
                        let path = format!("/_api/v1/go/default/main/v1/actions/{action}");
                        barrier.wait().await;
                        pause(index * 600).await;
                        for _ in 0..400 {
                            let (status, _) = send(
                                &app,
                                "PUT",
                                &path,
                                &auth,
                                &[
                                    ("content-length", &bytes.len().to_string()),
                                    (
                                        "x-snowstead-output-id",
                                        &hex::encode(Sha256::digest(&bytes)),
                                    ),
                                ],
                                bytes.clone(),
                            )
                            .await;
                            if status != StatusCode::SERVICE_UNAVAILABLE {
                                return status.as_u16();
                            }
                            retries.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                        panic!("{path} stayed busy");
                    })
                })
                .collect();
            let reset = tokio::spawn({
                let (app, barrier, retries) = (app.clone(), barrier.clone(), retries.clone());
                async move {
                    barrier.wait().await;
                    pause(500 + round * 150).await;
                    call(
                        &app,
                        "POST",
                        "/_api/v1/orgs/default/caches/main/go/reset",
                        OWNER,
                        &json!({}),
                        &retries,
                    )
                    .await
                }
            });
            for upload in uploads {
                *statuses.entry(upload.await.unwrap()).or_default() += 1;
            }
            let (status, body) = reset.await.unwrap();
            assert_eq!(status, StatusCode::OK, "{body}");
            // Available in a cleared generation means cleared by a reset,
            // which logged it once. Available now means never logged.
            let unaccounted = count(
                &pool,
                "SELECT count(*) FROM go_entries e JOIN caches c ON c.name='main' \
                 WHERE e.uploaded_at IS NOT NULL AND (SELECT count(*) FROM eviction_logs l \
                 WHERE l.product='go' AND l.key=e.action) \
                 <> CASE WHEN e.generation=c.go_generation THEN 0 ELSE 1 END",
            )
            .await;
            assert_eq!(unaccounted, 0, "round {round}: {statuses:?}");
        }
        eprintln!(
            "go uploads against reset: statuses {statuses:?}, {} retried 503s",
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        assert!(
            statuses
                .keys()
                .all(|status| [201, 204, 409].contains(status)),
            "{statuses:?}"
        );
        let cleared = count(
            &pool,
            "SELECT count(*) FROM eviction_logs WHERE product='go'",
        )
        .await;
        let live = count(
            &pool,
            "SELECT count(*) FROM go_entries e JOIN caches c ON c.id=e.cache_id \
             WHERE e.generation=c.go_generation AND e.uploaded_at IS NOT NULL",
        )
        .await;
        assert!(
            cleared > 0 && (live > 0 || statuses.contains_key(&409)),
            "inconclusive: every upload ran on one side of its reset \
             ({cleared} cleared, {live} live, {statuses:?})"
        );
    });
}

/// A multipart upload is initialized while its cache is deleted. A provider
/// upload the session adopted is always handed to the cleanup queue: by the
/// deletion that removes the session, never by nobody.
#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn an_upload_adopted_while_its_cache_is_deleted_is_queued_for_cleanup(pool: PgPool) {
    threaded(&pool, |pool| async move {
        const ROUNDS: usize = 40;
        let (state, app) = server_with(&pool, &[], common::s3_storage()).await;
        let retries = Arc::new(AtomicUsize::new(0));
        let mut orders = Orders::default();
        for round in 0..ROUNDS * 5 {
            if orders.settled(round, ROUNDS) {
                break;
            }
            let name = format!("adopt{round}");
            sqlx::query(
                "WITH c AS (INSERT INTO caches(name) VALUES ($1) RETURNING id) \
                 INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM c",
            )
            .bind(&name)
            .execute(&pool)
            .await
            .unwrap();
            let mut upload = upload(round);
            upload.input["inline"] = json!(false);
            let session = start(&app, &name, SHARED, &upload, &retries).await;
            let barrier = Arc::new(Barrier::new(2));
            let reservation = tokio::spawn({
                let (app, barrier, retries, session) = (
                    app.clone(),
                    barrier.clone(),
                    retries.clone(),
                    session.clone(),
                );
                async move {
                    barrier.wait().await;
                    call(
                        &app,
                        "POST",
                        &format!("/_api/v1/uploads/{session}/parts"),
                        SHARED,
                        &json!({"parts":[{"partNumber":1,"size":1024}]}),
                        &retries,
                    )
                    .await
                }
            });
            let deletion = tokio::spawn({
                let (app, barrier, retries, name) =
                    (app.clone(), barrier.clone(), retries.clone(), name.clone());
                async move {
                    barrier.wait().await;
                    pause(round % 20 * 500).await;
                    call(
                        &app,
                        "POST",
                        &format!("/_api/v1/orgs/default/caches/{name}/delete"),
                        OWNER,
                        &json!({}),
                        &retries,
                    )
                    .await
                }
            });
            let (reserved, grants) = reservation.await.unwrap();
            let (deleted, body) = deletion.await.unwrap();
            assert_eq!(deleted, StatusCode::OK, "{body}");
            let queued: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM object_cleanup WHERE upload_id IS NOT NULL \
                 AND starts_with(key,'staging/'||$1||'/')",
            )
            .bind(&session)
            .fetch_one(&pool)
            .await
            .unwrap();
            if reserved == StatusCode::OK {
                // The session adopted a provider upload before it was deleted.
                assert_eq!(queued, 1, "round {round}: {grants}");
            } else {
                assert!(
                    reserved == StatusCode::NOT_FOUND || reserved == StatusCode::CONFLICT,
                    "round {round}: {reserved} {grants}"
                );
                // An upload created but not adopted is queued by its creator.
                assert!(queued <= 1, "round {round}");
            }
            orders.note(reserved == StatusCode::OK);
        }
        eprintln!(
            "adoption against cache deletion: {} adopted first, {} deleted first, {} retried 503s",
            orders.one,
            orders.other,
            retries.load(Ordering::Relaxed)
        );
        drop(app);
        state.finish_background().await;
        orders.conclusive("the adoption against the cache deletion");
    });
}
