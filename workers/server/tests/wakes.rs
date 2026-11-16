//! Background workers wait for a wake, a known due time, or a slow fallback,
//! and no longer poll. Each test runs the real workers under `serve` and
//! sends requests through a router on the same state, as one process does.
//! Where a test must tell a wake or a due time from the fallback, the
//! fallback is an hour.
mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config, storage::Storage};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;

#[path = "support/tokens.rs"]
mod tokens;

const HOUR: Duration = Duration::from_secs(3600);
/// Far below the hour, and far above what a slow runner needs.
const PROMPT: Duration = Duration::from_secs(60);
const CACHE: &str = "/_api/v1/caches/wake";

struct Host {
    app: Router,
    auth: String,
    /// Connections the host's pool handed out: one for each statement sent
    /// to the pool, and one for each transaction. Counted in this process as
    /// they happen, so reading it waits for no statistics collector.
    checkouts: Arc<AtomicU64>,
    stop: tokio::sync::oneshot::Sender<()>,
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// The whole worker set on a pool of its own, which only it and requests to
/// `app` use. The test's assertions read through the `sqlx::test` pool.
async fn host(
    pool: &PgPool,
    storage: Storage,
    idle: Option<Duration>,
    finalizers: usize,
    publishers: usize,
) -> Host {
    sqlx::raw_sql(
        "INSERT INTO caches(name,is_public,org_id) VALUES('wake',true,'default'); \
         INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .execute(pool)
    .await
    .unwrap();
    let claims = json!({"jti":"wake-token","sub":"cli","iss":"snowstead","aud":"snowstead",
        "iat":1,"org":"default","caches":["*"],"perms":["push","pull"]});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"test-jwt").unwrap();
    mac.update(input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let auth = tokens::register(pool, format!("{input}.{signature}")).await;

    let checkouts = Arc::new(AtomicU64::new(0));
    let (opened, reused) = (checkouts.clone(), checkouts.clone());
    let workers = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |_, _| {
            opened.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        })
        .before_acquire(move |_, _| {
            reused.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(true) })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let mut config = Config {
        jwt_secret: "test-jwt".into(),
        ..Default::default()
    };
    config.resources.verifications = finalizers;
    config.push_jobs.publication_workers = publishers;
    let mut state = AppState::new(workers, config, storage, reqwest::Client::new()).unwrap();
    if let Some(idle) = idle {
        state = state.with_idle_period(idle);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(snowstead_server::serve(
        listener,
        state.clone(),
        async move {
            let _ = stopped.await;
        },
    ));
    Host {
        app: snowstead_server::router(state),
        auth,
        checkouts,
        stop,
        serving,
    }
}

impl Host {
    /// Wait until the workers have gone quiet: startup's sweeps are over and
    /// every worker has scanned, found nothing, and started to wait. A worker
    /// that polled would never let this return.
    async fn idle(&self) {
        tokio::time::timeout(Duration::from_secs(180), async {
            let mut seen = self.checkouts.load(Ordering::Relaxed);
            loop {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let now = self.checkouts.load(Ordering::Relaxed);
                if now == seen {
                    break;
                }
                seen = now;
            }
        })
        .await
        .expect("the workers never stopped issuing statements");
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(
                snowstead_protocol::PROTOCOL_VERSION_HEADER,
                snowstead_protocol::PROTOCOL_VERSION,
            )
            .header("host", "backend.local")
            .header("authorization", format!("Bearer {}", self.auth))
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))),
        )
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        let (status, value) = self
            .send(
                "POST",
                path,
                "application/json",
                serde_json::to_vec(&body).unwrap(),
            )
            .await;
        assert!(status.is_success(), "{path}: {status} {value}");
        value
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(PROMPT, self.serving)
            .await
            .expect("workers did not stop")
            .unwrap()
            .unwrap();
    }
}

/// One store path: its manifest entry and its compressed NAR.
struct Path {
    input: Value,
    raw: Vec<u8>,
    compressed: Vec<u8>,
}

fn path(digit: char, inline: bool) -> Path {
    // A regular-file NAR, with its eight-byte framing.
    let mut raw = Vec::new();
    let contents = format!("wake fixture {digit}");
    for word in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
        contents.as_bytes(),
        b")",
    ] {
        raw.extend_from_slice(&(word.len() as u64).to_le_bytes());
        raw.extend_from_slice(word);
        raw.resize(raw.len() + ((8 - word.len() % 8) % 8), 0);
    }
    let hash = digit.to_string().repeat(32);
    Path {
        input: json!({"storePath":format!("/nix/store/{hash}-fixture"),"storePathHash":hash,
            "narHash":format!("sha256-{}",STANDARD.encode(Sha256::digest(&raw))),"narSize":raw.len(),
            "compression":"zstd","references":[],"inline":inline}),
        compressed: zstd::stream::encode_all(raw.as_slice(), 3).unwrap(),
        raw,
    }
}

/// A sealed, authorized job for `paths` with a session for each. Nothing is
/// uploaded, so nothing is publishable. Returns the session IDs.
async fn job(host: &Host, key: &str, paths: &[&Path]) -> Vec<String> {
    let members: Vec<_> = paths.iter().map(|p| p.input.clone()).collect();
    let created = host
        .post(
            &format!("{CACHE}/push-jobs"),
            json!({"idempotencyKey":key,"mode":"closure","roots":[members[0]["storePath"]]}),
        )
        .await;
    let job = created["job"]["id"].as_str().unwrap();
    let (status, body) = host
        .send(
            "PUT",
            &format!("{CACHE}/push-jobs/{job}/manifest/0"),
            "application/json",
            serde_json::to_vec(&json!({"members":members})).unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for action in ["seal", "resume"] {
        host.post(&format!("{CACHE}/push-jobs/{job}/{action}"), json!({}))
            .await;
    }
    let sessions = host
        .post(
            &format!("{CACHE}/upload-streams/batch"),
            json!({"jobId":job,"paths":members}),
        )
        .await;
    sessions["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["sessionId"].as_str().unwrap().to_owned())
        .collect()
}

/// Upload a job member's bytes for its job's worker to publish. Returns once
/// the candidate is confirmed, which is what makes the job publishable.
async fn prepare(host: &Host, session: &str, path: &Path) {
    let hash = hex::encode(Sha256::digest(&path.compressed));
    let (status, out) = host
        .send(
            "POST",
            &format!("/_api/v1/uploads/{session}/inline?fileHash={hash}&prepareOnly=true"),
            "application/octet-stream",
            path.compressed.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["prepared"], true, "{out}");
    assert_eq!(out["published"], false, "{out}");
}

/// Upload one multipart session's bytes and return its receipt, ready to
/// finalize. Finalization is what queues it for a consumer.
async fn stage(host: &Host, path: &Path) -> Value {
    let created = host
        .post(
            &format!("{CACHE}/upload-streams/batch"),
            json!({"paths":[path.input]}),
        )
        .await;
    let id = created["sessions"][0]["sessionId"].as_str().unwrap();
    let grants = host
        .post(
            "/_api/v1/uploads/parts",
            json!({"uploads":[{"sessionId":id,
                "parts":[{"partNumber":1,"size":path.compressed.len()}]}]}),
        )
        .await;
    let grant = &grants["results"][0]["parts"][0];
    let mut upload = reqwest::Client::new().put(grant["url"].as_str().unwrap());
    for (name, value) in grant["headers"].as_object().unwrap() {
        upload = upload.header(name.as_str(), value.as_str().unwrap());
    }
    let response = upload.body(path.compressed.clone()).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_owned();
    json!({"sessionId":id,"narHash":path.input["narHash"],"narSize":path.raw.len(),
        "fileHash":hex::encode(Sha256::digest(&path.compressed)),
        "fileSize":path.compressed.len(),"parts":[{"partNumber":1,"etag":etag}]})
}

/// Queue receipts as one request, so one batch.
async fn finalize(host: &Host, receipts: Vec<Value>) {
    let (status, accepted) = host
        .send(
            "POST",
            "/_api/v1/uploads/finalize",
            "application/json",
            serde_json::to_vec(&json!({"uploads":receipts})).unwrap(),
        )
        .await;
    // Accepted, unless the consumer settled it before the reply was read.
    assert!(status.is_success(), "{accepted}");
}

async fn published(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM published_paths")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Wait for `count` published paths, which only a worker can produce here.
async fn publishes(pool: &PgPool, count: i64, why: &str) {
    tokio::time::timeout(PROMPT, async {
        while published(pool).await < count {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{why}"));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn idle_workers_issue_almost_no_statements(pool: PgPool) {
    // The shipped idle period, four consumers and two publishers.
    let host = host(&pool, common::storage(), None, 4, 2).await;
    host.idle().await;
    let before = host.checkouts.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let issued = host.checkouts.load(Ordering::Relaxed) - before;
    // Nothing, unless one fallback round falls in the window: two reads for
    // each of six workers and a drain pass. Polling every 100 ms, the same
    // six workers issued about 240 in four seconds.
    assert!(issued <= 40, "{issued} pool checkouts while idle");
    host.stop().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_prepared_job_member_is_published_at_its_commit(pool: PgPool) {
    let host = host(&pool, common::storage(), Some(HOUR), 1, 2).await;
    let member = path('1', true);
    let sessions = job(&host, "prompt", &[&member]).await;
    // Whatever resuming the job woke has looked, found nothing, and is
    // waiting again. Only the wake that follows preparation can end that.
    host.idle().await;
    assert_eq!(published(&pool).await, 0);
    prepare(&host, &sessions[0], &member).await;
    publishes(&pool, 1, "the prepared member waited for the fallback").await;
    host.stop().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn a_job_backed_off_into_the_future_is_published_when_due(pool: PgPool) {
    let host = host(&pool, common::storage(), Some(HOUR), 1, 1).await;
    let member = path('2', true);
    let sessions = job(&host, "due", &[&member]).await;
    host.idle().await;
    // As a failed turn's backoff leaves it. Nothing announces this change.
    sqlx::query("UPDATE push_jobs SET work_at=NOW()+INTERVAL '3 seconds'")
        .execute(&pool)
        .await
        .unwrap();
    // The wake finds the job not yet due. The worker has to read when it is
    // and wait for that, since no second wake comes.
    prepare(&host, &sessions[0], &member).await;
    publishes(&pool, 1, "the due job waited for the fallback").await;
    host.stop().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn a_finalization_batch_is_claimed_at_its_admission(pool: PgPool) {
    let host = host(&pool, common::s3_storage(), Some(HOUR), 1, 0).await;
    let receipt = stage(&host, &path('5', false)).await;
    host.idle().await;
    finalize(&host, vec![receipt]).await;
    publishes(&pool, 1, "the admitted batch waited for the fallback").await;
    host.stop().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn a_batch_with_a_future_retry_time_is_claimed_when_due(pool: PgPool) {
    let host = host(&pool, common::s3_storage(), Some(HOUR), 1, 0).await;
    let receipt = stage(&host, &path('6', false)).await;
    // Every batch starts as a failed turn would leave it: runnable later.
    sqlx::raw_sql(
        "CREATE FUNCTION defer_batch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         NEW.work_at := NOW()+INTERVAL '3 seconds'; RETURN NEW; END $$; \
         CREATE TRIGGER defer_batch BEFORE INSERT ON upload_finalization_batches \
         FOR EACH ROW EXECUTE FUNCTION defer_batch();",
    )
    .execute(&pool)
    .await
    .unwrap();
    host.idle().await;
    finalize(&host, vec![receipt]).await;
    publishes(&pool, 1, "the due batch waited for the fallback").await;
    host.stop().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn batches_admitted_while_the_only_consumer_is_busy_are_not_stranded(pool: PgPool) {
    let host = host(&pool, common::s3_storage(), Some(HOUR), 1, 0).await;
    let mut receipts = Vec::new();
    for digit in ['7', '8', '9'] {
        receipts.push(stage(&host, &path(digit, false)).await);
    }
    host.idle().await;
    // Three requests, so three batches and three wakes, for one consumer:
    // all but the first arrive while it is claiming or verifying another.
    for receipt in receipts {
        finalize(&host, vec![receipt]).await;
    }
    publishes(
        &pool,
        3,
        "a batch admitted during a turn waited for the fallback",
    )
    .await;
    host.stop().await;
}
