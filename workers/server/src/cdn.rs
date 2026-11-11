//! Public CDN invalidation. Jobs live in the private bucket, never SQL.
use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore},
    time::Instant,
};

use crate::{AppState, config::Config, error::ApiError};

const PREFIX: &str = "cdn-purges/";
const MAX_HASHES: usize = 10_000;
const MAX_JOB_BYTES: u64 = 1024 * 1024;
const INTERVAL: Duration = Duration::from_millis(125);
// One sweep reads at most this many queued jobs, and stops early once the
// provider itself has failed this many of them.
const SWEEP_PAGE: usize = 100;
const SWEEP_PAGES: usize = 10;
const SWEEP_PROVIDER_FAILURES: usize = 3;
static DISPATCH: Semaphore = Semaphore::const_new(4);
static SWEEP: Mutex<()> = Mutex::const_new(());
static LAST_REQUEST: Mutex<Option<Instant>> = Mutex::const_new(None);

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Job {
    #[serde(default)]
    cache_path: String,
    #[serde(default)]
    hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_at: Option<u64>,
    // Absent in existing TypeScript jobs, which always target narinfo URLs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    whole_cache: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    files: Option<Vec<String>>,
}

pub fn validate_config(config: &Config) -> anyhow::Result<()> {
    if !config.public_cache_origin.is_empty() {
        let cdn = origin(&config.public_cache_origin)?;
        if !config.public_url.is_empty() {
            let public = reqwest::Url::parse(&config.public_url)
                .map_err(|_| anyhow::anyhow!("Invalid public URL"))?;
            anyhow::ensure!(
                public.origin() != cdn.origin(),
                "Public URL and public cache origin must use different origins"
            );
        }
    }
    let zone = !config.cdn_zone_id.is_empty();
    let token = !config.cdn_purge_token.is_empty();
    anyhow::ensure!(
        zone == token,
        "CDN zone and purge token must be configured together"
    );
    anyhow::ensure!(
        !zone || !config.public_cache_origin.is_empty(),
        "CDN purging requires a public cache origin"
    );
    anyhow::ensure!(
        !zone
            || config
                .cdn_zone_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "Invalid CDN zone ID"
    );
    anyhow::ensure!(
        !token
            || reqwest::header::HeaderValue::from_str(&format!(
                "Bearer {}",
                config.cdn_purge_token
            ))
            .is_ok(),
        "Invalid CDN purge token"
    );
    Ok(())
}

fn origin(value: &str) -> anyhow::Result<reqwest::Url> {
    let invalid = || {
        anyhow::anyhow!(
            "Public cache origin must be HTTPS (or loopback HTTP), without credentials, path, query, or fragment"
        )
    };
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    let host = url.host_str().unwrap_or_default();
    let loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    // Check the raw path too: URL parsing normalizes dot segments away.
    let authority = value.split_once("://").ok_or_else(invalid)?.1;
    let raw_path = authority.find('/').map(|i| &authority[i..]).unwrap_or("");
    if host.is_empty()
        || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(raw_path, "" | "/")
        || value.contains('\\')
        || value.bytes().any(|b| b.is_ascii_whitespace())
        || authority.contains('@')
    {
        return Err(invalid());
    }
    Ok(url)
}

fn enabled(state: &AppState) -> bool {
    !state.config.cdn_zone_id.is_empty() && !state.config.cdn_purge_token.is_empty()
}

fn invalid_job() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "Invalid CDN purge input")
}
fn storage_error() -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "CDN purge queue operation failed",
    )
}
fn provider_error() -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, "CDN purge request failed")
}

fn job(path: &str, hashes: Option<&[String]>) -> Result<Job, ApiError> {
    if path.len() > 256
        || path.split('/').count() > 2
        || path.split('/').any(|s| {
            s.is_empty()
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    {
        return Err(invalid_job());
    }
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    if let Some(hashes) = hashes {
        if hashes.len() > MAX_HASHES {
            return Err(invalid_job());
        }
        for hash in hashes {
            if hash.len() != 32
                || !hash
                    .bytes()
                    .all(|b| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&b))
            {
                return Err(invalid_job());
            }
            if seen.insert(hash) {
                unique.push(hash.clone());
            }
        }
    }
    Ok(Job {
        cache_path: path.to_owned(),
        hashes: unique,
        retry_at: None,
        whole_cache: hashes.is_none(),
        files: None,
    })
}

fn files_job(keys: &[String]) -> Result<Job, ApiError> {
    if keys.len() > MAX_HASHES || keys.iter().map(String::len).sum::<usize>() > 512 * 1024 {
        return Err(invalid_job());
    }
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for key in keys {
        if key.len() > 1024
            || key.split('/').any(|s| {
                matches!(s, "" | "." | "..")
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
        {
            return Err(invalid_job());
        }
        if seen.insert(key) {
            files.push(key.clone());
        }
    }
    Ok(Job {
        cache_path: String::new(),
        hashes: Vec::new(),
        retry_at: None,
        whole_cache: false,
        files: Some(files),
    })
}

fn endpoint(config: &Config) -> String {
    format!(
        "https://api.cloudflare.com/client/v4/zones/{}/purge_cache",
        config.cdn_zone_id
    )
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn schedule_cache(state: &AppState, path: &str) -> Result<(), ApiError> {
    if !enabled(state) {
        return Ok(());
    }
    schedule(state, job(path, None)?).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn schedule(state: &AppState, job: Job) -> Result<(), ApiError> {
    let key = format!("{PREFIX}{:016}-{}", now(), uuid::Uuid::now_v7());
    save(state, &key, &job).await?;
    // Saturation leaves durable work for the next sweep instead of creating
    // unbounded tasks waiting for admission.
    if let Ok(permit) = DISPATCH.try_acquire() {
        let state = state.clone();
        state.tasks.clone().spawn(async move {
            let _permit = permit;
            if finish(&state, &key, job, &endpoint(&state.config))
                .await
                .is_err()
            {
                tracing::warn!("CDN purge queued for retry");
            }
        });
    }
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn purge(
    state: &AppState,
    path: &str,
    hashes: Option<&[String]>,
) -> Result<(), ApiError> {
    if !enabled(state) {
        return Ok(());
    }
    execute(state, &job(path, hashes)?, &endpoint(&state.config))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "the CDN refused the purge; try again shortly",
            )
        })
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn retry(state: &AppState) -> Result<usize, ApiError> {
    if !enabled(state) {
        return Ok(0);
    }
    retry_at_endpoint(state, &endpoint(&state.config)).await
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn retry_at_endpoint(state: &AppState, endpoint: &str) -> Result<usize, ApiError> {
    let Ok(_guard) = SWEEP.try_lock() else {
        return Ok(0);
    };
    let mut completed = 0;
    let mut budget = MAX_HASHES;
    // A job which cannot be read, parsed, or purged stays queued and fails the
    // sweep, but does not end it: the oldest key must never decide whether
    // newer purges run at all.
    let mut failure = None;
    let mut unhealthy = 0;
    let mut cursor: Option<String> = None;
    'sweep: for _ in 0..SWEEP_PAGES {
        let keys = state
            .storage
            .list(
                true,
                PREFIX.trim_end_matches('/'),
                cursor.as_deref(),
                SWEEP_PAGE,
            )
            .await
            .map_err(|_| storage_error())?;
        // Stuck jobs sort first. Read past a full page of them.
        let full = keys.len() == SWEEP_PAGE;
        cursor = keys.last().cloned();
        for key in keys {
            if !key.starts_with(PREFIX) {
                continue;
            }
            let valid = match pending(state, &key).await {
                Ok(Some(valid)) => valid,
                Ok(None) => continue,
                Err(error) => {
                    failure = Some(error);
                    continue;
                }
            };
            let cost = valid
                .files
                .as_ref()
                .map_or(valid.hashes.len(), Vec::len)
                .max(1);
            if cost > budget {
                break 'sweep;
            }
            budget -= cost;
            match dispatch(state, &key, valid, endpoint).await {
                Ok(()) => completed += 1,
                Err((error, retryable)) => {
                    failure = Some(error);
                    // A refused job stopped at its first refused request. Do
                    // not let it spend the budget of the jobs behind it.
                    budget += cost - cost.min(100);
                    // Rate limits and provider errors are not about one job:
                    // leave the rest of the backlog for the next sweep.
                    unhealthy += usize::from(retryable);
                    if unhealthy == SWEEP_PROVIDER_FAILURES {
                        break 'sweep;
                    }
                }
            }
        }
        if !full {
            break;
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(completed),
    }
}

/// A due, well-formed job; `None` when it is gone or not due yet.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn pending(state: &AppState, key: &str) -> Result<Option<Job>, ApiError> {
    let object = match state.storage.open(true, key).await {
        Ok(object) => object,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(storage_error()),
    };
    let mut bytes = Vec::new();
    object
        .reader
        .take(MAX_JOB_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| storage_error())?;
    if bytes.len() as u64 > MAX_JOB_BYTES {
        return Err(storage_error());
    }
    let pending: Job = serde_json::from_slice(&bytes).map_err(|_| storage_error())?;
    if pending.retry_at.is_some_and(|at| at > now()) {
        return Ok(None);
    }
    let mut valid = match &pending.files {
        Some(files) if !pending.whole_cache && pending.hashes.is_empty() => files_job(files)?,
        Some(_) => return Err(invalid_job()),
        None => job(
            &pending.cache_path,
            if pending.whole_cache {
                None
            } else {
                Some(&pending.hashes)
            },
        )?,
    };
    valid.retry_at = pending.retry_at;
    Ok(Some(valid))
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn save(state: &AppState, key: &str, job: &Job) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(job).map_err(|_| storage_error())?;
    state
        .storage
        .put(true, key, &bytes)
        .await
        .map_err(|_| storage_error())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn finish(state: &AppState, key: &str, job: Job, endpoint: &str) -> Result<(), ApiError> {
    dispatch(state, key, job, endpoint)
        .await
        .map_err(|(error, _)| error)
}

/// Purge and retire one durable job. The flag tells a failure the provider may
/// recover from (a rate limit, a server error, a timeout) from a refusal.
#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn dispatch(
    state: &AppState,
    key: &str,
    mut job: Job,
    endpoint: &str,
) -> Result<(), (ApiError, bool)> {
    match execute(state, &job, endpoint).await {
        Ok(()) => state
            .storage
            .delete(true, key)
            .await
            .map_err(|_| storage_error())
            .map_err(|error| (error, false)),
        Err(failure) => {
            if let Some(at) = failure.retry_at {
                job.retry_at = Some(at);
                save(state, key, &job)
                    .await
                    .map_err(|error| (error, false))?;
            }
            Err((provider_error(), failure.retry_at.is_some()))
        }
    }
}

#[derive(Debug)]
struct Failure {
    retry_at: Option<u64>,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn execute(state: &AppState, job: &Job, endpoint: &str) -> Result<(), Failure> {
    let base = origin(&state.config.public_cache_origin).map_err(|_| Failure { retry_at: None })?;
    if job.whole_cache {
        let host = base
            .as_str()
            .split_once("://")
            .expect("validated origin")
            .1
            .trim_end_matches('/');
        request(
            state,
            endpoint,
            &json!({"prefixes": [format!("{host}/{}/", job.cache_path)]}),
        )
        .await
    } else {
        let keys = job.files.clone().unwrap_or_else(|| {
            job.hashes
                .iter()
                .map(|hash| format!("{}/{}.narinfo", job.cache_path, hash))
                .collect()
        });
        for keys in keys.chunks(100) {
            let files: Vec<_> = keys
                .iter()
                .map(|key| format!("{}{key}", base.as_str()))
                .collect();
            request(state, endpoint, &json!({"files": files})).await?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "cdn.purge_request"
    )
)]
async fn request(state: &AppState, endpoint: &str, body: &Value) -> Result<(), Failure> {
    for attempt in 0..3 {
        {
            let mut last =
                crate::profile_future!(LAST_REQUEST.lock(), label = "cdn.request_lock_wait").await;
            if let Some(last) = *last {
                tokio::time::sleep_until(last + INTERVAL).await;
            }
            *last = Some(Instant::now());
        }
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut response = crate::profile_future!(
                state
                    .http
                    .post(endpoint)
                    .bearer_auth(&state.config.cdn_purge_token)
                    .json(body)
                    .send(),
                label = "cdn.purge_http"
            )
            .await?;
            let status = response.status();
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let mut bytes = Vec::new();
            while let Some(chunk) =
                crate::profile_future!(response.chunk(), label = "cdn.purge_body_chunk").await?
            {
                if bytes.len() + chunk.len() > 64 * 1024 {
                    break;
                }
                bytes.extend_from_slice(&chunk);
            }
            let success = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .is_some_and(|v| v.get("success") == Some(&Value::Bool(true)));
            Ok::<_, reqwest::Error>((status, success, retry_after))
        })
        .await;
        let fallback = 1000 * (attempt + 1);
        let (retryable, delay) = match result {
            Ok(Ok((status, true, _))) if status.is_success() => return Ok(()),
            Ok(Ok((status, _, header))) => (
                status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
                header.as_deref().and_then(retry_delay).unwrap_or(fallback),
            ),
            _ => (true, fallback),
        };
        let failure = Failure {
            retry_at: retryable.then(|| now().saturating_add(delay)),
        };
        if !retryable || attempt == 2 || delay > 2000 {
            return Err(failure);
        }
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    unreachable!()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn retry_delay(value: &str) -> Option<u64> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(seconds.saturating_mul(1000));
    }
    let at = httpdate::parse_http_date(value)
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .min(u64::MAX as u128) as u64;
    Some(at.saturating_sub(now()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    use object_store::memory::InMemory;
    use std::{collections::VecDeque, sync::Arc};

    #[derive(Clone)]
    struct Reply {
        status: StatusCode,
        retry: Option<String>,
        delay: Duration,
        body: Value,
    }

    impl Reply {
        fn status(status: StatusCode, retry: Option<&str>) -> Self {
            Self {
                status,
                retry: retry.map(str::to_owned),
                delay: Duration::ZERO,
                body: json!({"success": status.is_success()}),
            }
        }
    }

    #[derive(Default)]
    struct Mock {
        replies: Mutex<VecDeque<Reply>>,
        requests: Mutex<Vec<(Instant, Value)>>,
    }

    struct Server {
        endpoint: String,
        mock: Arc<Mock>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Server {
        async fn new() -> Self {
            async fn handle(
                State(mock): State<Arc<Mock>>,
                headers: HeaderMap,
                Json(body): Json<Value>,
            ) -> (StatusCode, HeaderMap, Json<Value>) {
                assert_eq!(
                    headers.get("authorization").unwrap(),
                    "Bearer secret-test-token"
                );
                mock.requests.lock().await.push((Instant::now(), body));
                let reply = mock
                    .replies
                    .lock()
                    .await
                    .pop_front()
                    .unwrap_or_else(|| Reply::status(StatusCode::OK, None));
                tokio::time::sleep(reply.delay).await;
                let mut headers = HeaderMap::new();
                if let Some(retry) = reply.retry {
                    headers.insert("retry-after", retry.parse().unwrap());
                }
                (reply.status, headers, Json(reply.body))
            }
            let mock = Arc::new(Mock::default());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/purge", listener.local_addr().unwrap());
            let app = Router::new()
                .route("/purge", post(handle))
                .with_state(mock.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                endpoint,
                mock,
                task,
            }
        }

        async fn replies(&self, replies: impl IntoIterator<Item = Reply>) {
            self.mock.requests.lock().await.clear();
            self.mock.replies.lock().await.extend(replies);
        }
    }

    fn config() -> Config {
        Config {
            public_cache_origin: "https://cdn.example.test".into(),
            cdn_zone_id: "zone".into(),
            cdn_purge_token: "secret-test-token".into(),
            ..Config::default()
        }
    }

    fn state(storage: Storage) -> AppState {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        AppState::new(pool, config(), storage, http).unwrap()
    }

    fn storage() -> Storage {
        Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new()))
    }

    fn hash(i: usize) -> String {
        format!("{:032x}", i).replace('e', "z")
    }

    async fn read_job(state: &AppState, key: &str) -> Job {
        let mut bytes = Vec::new();
        state
            .storage
            .open(true, key)
            .await
            .unwrap()
            .reader
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn config_and_path_validation() {
        assert!(validate_config(&Config::default()).is_ok());
        let mut config = config();
        assert!(validate_config(&config).is_ok());
        config.cdn_zone_id.clear();
        assert!(validate_config(&config).is_err());
        config.cdn_purge_token.clear();
        assert!(validate_config(&config).is_ok()); // Direct delivery alone.
        config.public_url = "https://CDN.example.test:443/".into();
        assert!(validate_config(&config).is_err());
        config.public_url = "https://api.example.test".into();
        assert!(validate_config(&config).is_ok());
        config.public_cache_origin.clear();
        config.cdn_zone_id = "zone".into();
        config.cdn_purge_token = "token".into();
        assert!(validate_config(&config).is_err());
        for value in [
            "https://cache.test",
            "https://cache.test/",
            "http://localhost:9000",
            "http://127.0.0.1:9000/",
            "http://[::1]:9000",
        ] {
            assert!(origin(value).is_ok(), "{value}");
        }
        for value in [
            "http://cache.test",
            "http://localhost.evil.test",
            "ftp://cache.test",
            "https://user:secret@cache.test",
            "https://@cache.test",
            "https://cache.test?key=secret",
            "https://cache.test#x",
            "https://cache.test/a",
            "https://cache.test/a/..",
            "https://cache.test\\evil",
            " https://cache.test",
        ] {
            assert!(origin(value).is_err(), "{value}");
        }
        for path in [
            "",
            "../evil",
            "org//cache",
            "org/cache/third",
            "org/%2e%2e",
            "org/cache?x=1",
            "org/cache#x",
        ] {
            assert!(job(path, None).is_err(), "{path}");
        }
        for key in [
            "",
            "/cache/info",
            "cache/../info",
            "cache/./info",
            "cache//info",
            "cache/%2finfo",
            "cache/info?x=1",
            "cache/info#x",
            "cache\\info",
        ] {
            assert!(files_job(&[key.into()]).is_err(), "{key}");
        }
        assert!(
            files_job(&[
                "org/cache/nix-cache-info".into(),
                "org/cache/a.narinfo".into()
            ])
            .is_ok()
        );
        assert!(job("cache", Some(&["../bad".into()])).is_err());
        assert!(job("cache", Some(&vec![hash(1); MAX_HASHES + 1])).is_err());
        assert_eq!(retry_delay("3600"), Some(3_600_000));
        let later = SystemTime::now() + Duration::from_secs(3600);
        assert!(retry_delay(&httpdate::fmt_http_date(later)).unwrap() > 3_598_000);
        assert_eq!(retry_delay("nonsense"), None);
        assert_eq!(
            endpoint(&config),
            "https://api.cloudflare.com/client/v4/zones/zone/purge_cache"
        );
    }

    // Pacing and sweep admission are process-wide: these tests take turns.
    static SERIAL: Mutex<()> = Mutex::const_new(());

    #[tokio::test]
    async fn durable_backlog_batches_retries_and_restart() {
        let _serial = SERIAL.lock().await;
        let server = Server::new().await;
        let storage = storage();
        let state = state(storage.clone());
        let mut hashes: Vec<_> = (0..205).map(hash).collect();
        hashes.push(hash(0));
        let pending = job("org/cache", Some(&hashes)).unwrap();
        assert_eq!(pending.hashes.len(), 205);
        let serialized = serde_json::to_value(&pending).unwrap();
        assert_eq!(
            serialized,
            json!({"cachePath": "org/cache", "hashes": &hashes[..205]})
        );
        execute(&state, &pending, &server.endpoint).await.unwrap();
        {
            let requests = server.mock.requests.lock().await;
            assert_eq!(requests.len(), 3);
            assert_eq!(
                requests
                    .iter()
                    .map(|(_, b)| b["files"].as_array().unwrap().len())
                    .collect::<Vec<_>>(),
                [100, 100, 5]
            );
            assert_eq!(
                requests[0].1["files"][0],
                format!("https://cdn.example.test/org/cache/{}.narinfo", hash(0))
            );
            assert!(
                requests
                    .windows(2)
                    .all(|r| r[1].0.duration_since(r[0].0) >= Duration::from_millis(100))
            );
        }

        server.replies([]).await;
        execute(&state, &job("org/cache", None).unwrap(), &server.endpoint)
            .await
            .unwrap();
        assert_eq!(
            server.mock.requests.lock().await[0].1,
            json!({"prefixes": ["cdn.example.test/org/cache/"]})
        );

        // Scheduling must persist before dispatch. Saturate dispatch so these
        // tests never reach the production endpoint, even in the background.
        let permits = DISPATCH.acquire_many(4).await.unwrap();
        schedule(&state, job("cache", Some(&[hash(1), hash(1)])).unwrap())
            .await
            .unwrap();
        schedule_cache(&state, "cache").await.unwrap();
        schedule(
            &state,
            files_job(&["cache/nix-cache-info".into(), "cache/nix-cache-info".into()]).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            state
                .storage
                .list(true, "cdn-purges", None, 100)
                .await
                .unwrap()
                .len(),
            3
        );
        assert!(
            state
                .storage
                .list(false, "cdn-purges", None, 100)
                .await
                .unwrap()
                .is_empty()
        );
        drop(permits);
        server.replies([]).await;
        assert_eq!(
            retry_at_endpoint(&state, &server.endpoint).await.unwrap(),
            3
        );
        assert!(server.mock.requests.lock().await.iter().any(
            |(_, b)| b == &json!({"files": ["https://cdn.example.test/cache/nix-cache-info"]})
        ));

        let key = "cdn-purges/0000000000000001-legacy";
        // Exact existing TS record shape, with no new discriminant required.
        state
            .storage
            .put(
                true,
                key,
                serde_json::to_string(
                    &json!({"cachePath": "cache", "hashes": [hash(1)], "retryAt": 1}),
                )
                .unwrap()
                .as_bytes(),
            )
            .await
            .unwrap();
        server
            .replies([Reply::status(StatusCode::TOO_MANY_REQUESTS, Some("3600"))])
            .await;
        let error = retry_at_endpoint(&state, &server.endpoint)
            .await
            .unwrap_err();
        assert_eq!(error.message, "CDN purge request failed");
        let retained = read_job(&state, key).await;
        assert!(retained.retry_at.unwrap() >= now() + 3_598_000);
        assert_eq!(server.mock.requests.lock().await.len(), 1);
        drop(state);
        let state = self::state(storage); // New process state, same private bucket.
        assert_eq!(
            retry_at_endpoint(&state, &server.endpoint).await.unwrap(),
            0
        );
        assert_eq!(server.mock.requests.lock().await.len(), 1); // Not early.
        let mut ready = retained;
        ready.retry_at = Some(1);
        save(&state, key, &ready).await.unwrap();
        server
            .replies([
                Reply::status(StatusCode::TOO_MANY_REQUESTS, Some("0")),
                Reply::status(StatusCode::INTERNAL_SERVER_ERROR, Some("0")),
                Reply::status(StatusCode::OK, None),
            ])
            .await;
        assert_eq!(
            retry_at_endpoint(&state, &server.endpoint).await.unwrap(),
            1
        );
        assert_eq!(server.mock.requests.lock().await.len(), 3);
        assert!(state.storage.head(true, key).await.is_err());

        // A failed purge never deletes its durable record, and never keeps the
        // record behind it from being purged.
        save(&state, key, &ready).await.unwrap();
        let next = "cdn-purges/0000000000000002-next";
        save(&state, next, &ready).await.unwrap();
        server
            .replies([Reply::status(StatusCode::FORBIDDEN, None)])
            .await;
        assert!(retry_at_endpoint(&state, &server.endpoint).await.is_err());
        assert_eq!(server.mock.requests.lock().await.len(), 2);
        assert!(state.storage.head(true, key).await.is_ok());
        assert!(state.storage.head(true, next).await.is_err());
        server
            .replies(vec![
                Reply::status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some("0")
                );
                3
            ])
            .await;
        assert!(retry_at_endpoint(&state, &server.endpoint).await.is_err());
        assert_eq!(server.mock.requests.lock().await.len(), 3);
        assert!(read_job(&state, key).await.retry_at.unwrap() >= now().saturating_sub(100));
        server.replies([]).await;
        assert_eq!(
            retry_at_endpoint(&state, &server.endpoint).await.unwrap(),
            1
        );

        // A stalled response and a transport error are retried, without
        // leaking provider details into externally returned errors.
        let mut slow = Reply::status(StatusCode::OK, None);
        slow.delay = Duration::from_secs(6);
        server
            .replies([slow, Reply::status(StatusCode::OK, None)])
            .await;
        execute(&state, &ready, &server.endpoint).await.unwrap();
        assert_eq!(server.mock.requests.lock().await.len(), 2);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = format!(
            "http://{}/secret-provider-url",
            listener.local_addr().unwrap()
        );
        drop(listener);
        save(&state, key, &ready).await.unwrap();
        let error = finish(&state, key, ready, &dead).await.unwrap_err();
        assert_eq!(error.message, "CDN purge request failed");
        assert!(read_job(&state, key).await.retry_at.is_some());
        server.replies([]).await;
        let mut ready = read_job(&state, key).await;
        ready.retry_at = None;
        save(&state, key, &ready).await.unwrap();
        assert_eq!(
            retry_at_endpoint(&state, &server.endpoint).await.unwrap(),
            1
        );
        // The public API keeps the original management error contract. An
        // explicit closed-loopback proxy prevents any production connection.
        let mut manual = state.clone();
        manual.http = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&dead).unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let error = purge(&manual, "cache", Some(&[hash(1)])).await.unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            error.message,
            "the CDN refused the purge; try again shortly"
        );
        state.tasks.close();
        state.tasks.wait().await;
    }

    #[tokio::test]
    async fn failing_jobs_do_not_block_later_jobs() {
        let _serial = SERIAL.lock().await;
        let server = Server::new().await;
        let state = state(storage());
        let one = job("cache", Some(&[hash(1)])).unwrap();
        // The oldest keys: unreadable, not a valid job, and refused for good.
        let malformed = "cdn-purges/0000000000000001-malformed";
        let invalid = "cdn-purges/0000000000000002-invalid";
        let refused = "cdn-purges/0000000000000003-refused";
        let later = "cdn-purges/0000000000000004-later";
        state.storage.put(true, malformed, b"{").await.unwrap();
        state
            .storage
            .put(true, invalid, br#"{"cachePath":"../escape","hashes":[]}"#)
            .await
            .unwrap();
        save(&state, refused, &one).await.unwrap();
        save(&state, later, &one).await.unwrap();
        server
            .replies([Reply::status(StatusCode::FORBIDDEN, None)])
            .await;
        // The sweep still reports the failure, but only after the later job ran.
        assert!(retry_at_endpoint(&state, &server.endpoint).await.is_err());
        assert_eq!(server.mock.requests.lock().await.len(), 2);
        assert!(state.storage.head(true, later).await.is_err());
        for kept in [malformed, invalid, refused] {
            assert!(state.storage.head(true, kept).await.is_ok(), "{kept}");
        }
        state.storage.delete(true, invalid).await.unwrap();
        state.storage.delete(true, refused).await.unwrap();

        // More stuck jobs than one listing page cannot hide the jobs after them.
        for i in 0..SWEEP_PAGE {
            let key = format!("cdn-purges/00000000000000010-stuck-{i:03}");
            state.storage.put(true, &key, b"{").await.unwrap();
        }
        let last = "cdn-purges/0000000000000002-last";
        save(&state, last, &one).await.unwrap();
        server.replies([]).await;
        assert!(retry_at_endpoint(&state, &server.endpoint).await.is_err());
        assert_eq!(server.mock.requests.lock().await.len(), 1);
        assert!(state.storage.head(true, last).await.is_err());
        for key in state
            .storage
            .list(true, "cdn-purges", None, 1000)
            .await
            .unwrap()
        {
            state.storage.delete(true, &key).await.unwrap();
        }

        // A failing provider is not asked about the whole backlog: the sweep
        // stops, and each job waits out its own Retry-After.
        let keys: Vec<_> = (0..5)
            .map(|i| format!("cdn-purges/000000000000000{i}-limited"))
            .collect();
        for key in &keys {
            save(&state, key, &one).await.unwrap();
        }
        server
            .replies(vec![
                Reply::status(
                    StatusCode::TOO_MANY_REQUESTS,
                    Some("3600")
                );
                SWEEP_PROVIDER_FAILURES
            ])
            .await;
        assert!(retry_at_endpoint(&state, &server.endpoint).await.is_err());
        assert_eq!(
            server.mock.requests.lock().await.len(),
            SWEEP_PROVIDER_FAILURES
        );
        server.replies([]).await;
        assert_eq!(
            retry_at_endpoint(&state, &server.endpoint).await.unwrap(),
            keys.len() - SWEEP_PROVIDER_FAILURES
        );
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                state.storage.head(true, key).await.is_ok(),
                i < SWEEP_PROVIDER_FAILURES,
                "{key}"
            );
        }
        state.tasks.close();
        state.tasks.wait().await;
    }
}
