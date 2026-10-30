//! Hosted v1 protocol. Errors deliberately omit URLs, credentials, and response bodies.
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail};
use futures_util::{StreamExt, TryStreamExt, stream};
use reqwest::{Method, Response, StatusCode, Url, header, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Semaphore,
};
use tokio_util::io::ReaderStream;

pub const MULTIPART_THRESHOLD: u64 = 90 * 1024 * 1024;
const PUT_ATTEMPTS: u32 = 4;
const PART_CONCURRENCY: usize = 4;

#[derive(Clone)]
pub struct Client {
    server: String,
    authorization: header::HeaderValue,
    http: reqwest::Client,
    upstream: reqwest::Client,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Missing {
    pub missing: Vec<String>,
    #[serde(default)]
    pub upstream: Vec<String>,
    #[serde(default)]
    pub unchecked: Vec<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
}

// Do not derive Debug: these instructions contain signed URLs and headers.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub session_id: String,
    pub r2_key: String,
    pub upload_method: String,
    #[serde(default)]
    pub upload_url: Option<String>,
    #[serde(default)]
    pub upload_headers: HashMap<String, String>,
    #[serde(default)]
    pub parts: Vec<PresignedPart>,
    #[serde(default)]
    pub part_size: Option<u64>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresignedPart {
    pub part_number: u32,
    pub url: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionParams {
    pub store_path: String,
    pub store_path_hash: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub file_hash: String,
    pub file_size: u64,
    pub compression: String,
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deriver: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitResult {
    pub session_id: String,
    #[serde(default)]
    pub published: bool,
    pub status: Option<u16>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadedPart {
    pub part_number: u32,
    pub etag: String,
}

fn status_ok(operation: &'static str, response: Response) -> Result<Response> {
    if response.status().is_success() {
        Ok(response)
    } else {
        bail!("{operation} failed (HTTP {})", response.status().as_u16())
    }
}

async fn decode<T: DeserializeOwned>(operation: &'static str, response: Response) -> Result<T> {
    status_ok(operation, response)?
        .json()
        .await
        .map_err(|_| anyhow!("{operation}: invalid response"))
}

impl Client {
    pub fn new(server: &crate::config::Server) -> Result<Self> {
        let url = Url::parse(&server.server).map_err(|_| anyhow!("invalid server URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("invalid server URL");
        }
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {}", server.token))
            .map_err(|_| anyhow!("invalid API token"))?;
        authorization.set_sensitive(true);
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(|_| anyhow!("could not initialize HTTP client"))?;
        let upstream = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| anyhow!("could not initialize upstream client"))?;
        Ok(Self {
            server: server.server.trim_end_matches('/').to_owned(),
            authorization,
            http,
            upstream,
        })
    }

    // Only internally constructed relative paths may use the authenticated client.
    async fn request(
        &self,
        operation: &'static str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Response> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.server))
            .header(header::AUTHORIZATION, self.authorization.clone());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| anyhow!("{operation}: HTTP transport failed"))?;
        tracing::debug!(
            operation,
            status = response.status().as_u16(),
            attempt = 1,
            "API response"
        );
        Ok(response)
    }

    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn missing(&self, cache: &str, hashes: &[String]) -> Result<Missing> {
        decode(
            "get-missing-paths",
            self.request(
                "get-missing-paths",
                Method::POST,
                "/_api/v1/get-missing-paths",
                Some(json!({"cache": cache, "storePathHashes": hashes})),
            )
            .await?,
        )
        .await
    }

    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn create_sessions(
        &self,
        cache: &str,
        paths: &[SessionParams],
    ) -> Result<Vec<Session>> {
        #[derive(Deserialize)]
        struct Sessions {
            sessions: Vec<Session>,
        }
        let path = format!("/_api/v1/caches/{}/upload-sessions/batch", segment(cache)?);
        let data: Sessions = decode(
            "create-sessions",
            self.request(
                "create-sessions",
                Method::POST,
                &path,
                Some(json!({"paths": paths})),
            )
            .await?,
        )
        .await?;
        Ok(data.sessions)
    }

    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn commit(
        &self,
        ids: &[String],
        parts: Option<&HashMap<String, Vec<UploadedPart>>>,
    ) -> Result<Vec<CommitResult>> {
        #[derive(Deserialize)]
        struct Results {
            results: Vec<CommitResult>,
        }
        let mut body = json!({"sessionIds": ids});
        if let Some(parts) = parts {
            body["parts"] = json!(parts);
        }
        let data: Results = decode(
            "commit",
            self.request(
                "commit",
                Method::POST,
                "/_api/v1/uploads/commit",
                Some(body),
            )
            .await?,
        )
        .await?;
        Ok(data.results)
    }

    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn complete(&self, session_id: &str) -> Result<()> {
        let path = format!("/_api/v1/uploads/{}/complete", segment(session_id)?);
        status_ok(
            "complete",
            self.request("complete", Method::POST, &path, Some(json!({})))
                .await?,
        )?;
        Ok(())
    }

    /// A canonical-key collision is reconciled with this session's proof, never another session.
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn upload_single(
        &self,
        session: &Session,
        path: &Path,
        limit: Arc<Semaphore>,
    ) -> Result<Option<CommitResult>> {
        let size = file_size(path).await?;
        let response = {
            let _permit = limit
                .acquire()
                .await
                .map_err(|_| anyhow!("upload limiter closed"))?;
            match session.upload_method.as_str() {
                "presigned" => {
                    let url = session
                        .upload_url
                        .as_deref()
                        .ok_or_else(|| anyhow!("missing upload URL"))?;
                    let mut headers = signed_headers(&session.upload_headers)?;
                    headers.insert(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/x-nix-nar"),
                    );
                    self.put_range("presigned upload", url, headers, path, 0, size)
                        .await?
                }
                "direct" => {
                    let url = format!(
                        "{}/_api/v1/uploads/{}/blob",
                        self.server,
                        segment(&session.session_id)?
                    );
                    self.put_range("blob upload", &url, self.upload_headers(), path, 0, size)
                        .await?
                }
                _ => bail!("invalid single upload method"),
            }
        };
        if response.status() != StatusCode::PRECONDITION_FAILED
            || session.r2_key.starts_with("staging/")
        {
            status_ok("single upload", response)?;
            return Ok(None);
        }
        drop(response);
        let results = self
            .commit(std::slice::from_ref(&session.session_id), None)
            .await?;
        let mut results = results.into_iter();
        let result = results
            .next()
            .ok_or_else(|| anyhow!("commit: missing reconciliation result"))?;
        if result.session_id != session.session_id || results.next().is_some() {
            bail!("commit: invalid reconciliation result");
        }
        if result.published
            || result.status != Some(400)
            || result.error.as_deref() != Some("Upload incomplete")
        {
            return Ok(Some(result));
        }
        self.upload_multipart(&session.session_id, path, limit)
            .await?;
        self.complete(&session.session_id).await?;
        Ok(None)
    }

    fn upload_headers(&self) -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, self.authorization.clone());
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/octet-stream"),
        );
        headers
    }

    /// Initiates the proxied multipart upload; callers subsequently complete or commit it.
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn upload_multipart(
        &self,
        session_id: &str,
        path: &Path,
        limit: Arc<Semaphore>,
    ) -> Result<()> {
        let size = file_size(path).await?;
        let id = segment(session_id)?;
        let endpoint = format!("/_api/v1/uploads/{id}/multipart");
        status_ok(
            "multipart initiation",
            self.request(
                "multipart initiation",
                Method::POST,
                &endpoint,
                Some(json!({})),
            )
            .await?,
        )?;
        let count = size.div_ceil(MULTIPART_THRESHOLD);
        if count > 10_000 {
            bail!("too many upload parts");
        }
        stream::iter(1..=count)
            .map(|number| {
                let limit = &limit;
                let id = &id;
                async move {
                    let _permit = limit
                        .acquire()
                        .await
                        .map_err(|_| anyhow!("upload limiter closed"))?;
                    let start = (number - 1) * MULTIPART_THRESHOLD;
                    let length = MULTIPART_THRESHOLD.min(size - start);
                    let url = format!("{}/_api/v1/uploads/{id}/part/{number}", self.server);
                    let response = self
                        .put_range(
                            "part upload",
                            &url,
                            self.upload_headers(),
                            path,
                            start,
                            length,
                        )
                        .await?;
                    // The proxied endpoint records its own ETags.
                    status_ok("part upload", response)?;
                    Ok::<_, anyhow::Error>(())
                }
            })
            .buffer_unordered(PART_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;
        Ok(())
    }

    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn upload_presigned_parts(
        &self,
        session: &Session,
        path: &Path,
        limit: Arc<Semaphore>,
    ) -> Result<Vec<UploadedPart>> {
        let size = file_size(path).await?;
        let part_size = session
            .part_size
            .filter(|n| *n > 0)
            .ok_or_else(|| anyhow!("invalid multipart part size"))?;
        if session.parts.len() as u64 != size.div_ceil(part_size) {
            bail!("invalid multipart instructions");
        }
        let mut seen = std::collections::HashSet::new();
        for part in &session.parts {
            if part.part_number == 0
                || u64::from(part.part_number) > size.div_ceil(part_size)
                || !seen.insert(part.part_number)
            {
                bail!("invalid multipart instructions");
            }
        }
        // buffer_unordered bounds live file streams; restore the instruction order afterward.
        let mut parts: Vec<(usize, UploadedPart)> = stream::iter(session.parts.iter().enumerate())
            .map(|(index, part)| {
                let limit = &limit;
                async move {
                    let _permit = limit
                        .acquire()
                        .await
                        .map_err(|_| anyhow!("upload limiter closed"))?;
                    let start = u64::from(part.part_number - 1) * part_size;
                    let length = part_size.min(size - start);
                    let response = self
                        .put_range(
                            "presigned part upload",
                            &part.url,
                            header::HeaderMap::new(),
                            path,
                            start,
                            length,
                        )
                        .await?;
                    let response = status_ok("presigned part upload", response)?;
                    let etag = response
                        .headers()
                        .get(header::ETAG)
                        .and_then(|v| v.to_str().ok())
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| anyhow!("part upload returned no ETag"))?
                        .to_owned();
                    Ok::<_, anyhow::Error>((
                        index,
                        UploadedPart {
                            part_number: part.part_number,
                            etag,
                        },
                    ))
                }
            })
            .buffer_unordered(PART_CONCURRENCY)
            .try_collect()
            .await?;
        parts.sort_by_key(|(index, _)| *index);
        Ok(parts.into_iter().map(|(_, part)| part).collect())
    }

    /// Every attempt reopens the exact range, holding the caller's upload slot throughout.
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    async fn put_range(
        &self,
        operation: &'static str,
        url: &str,
        mut headers: header::HeaderMap,
        path: &Path,
        start: u64,
        length: u64,
    ) -> Result<Response> {
        let url = Url::parse(url).map_err(|_| anyhow!("{operation}: invalid upload URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("{operation}: invalid upload URL");
        }
        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_str(&length.to_string())
                .map_err(|_| anyhow!("{operation}: invalid content length"))?,
        );
        for attempt in 1..=PUT_ATTEMPTS {
            let mut file = tokio::fs::File::open(path)
                .await
                .map_err(|_| anyhow!("{operation}: cannot open upload file"))?;
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|_| anyhow!("{operation}: cannot seek upload file"))?;
            let body = reqwest::Body::wrap_stream(ReaderStream::with_capacity(
                file.take(length),
                64 * 1024,
            ));
            let result = self
                .http
                .put(url.clone())
                .headers(headers.clone())
                .body(body)
                .send()
                .await;
            match result {
                Ok(response) => {
                    let status = response.status();
                    tracing::debug!(operation, status = status.as_u16(), attempt, "PUT response");
                    if attempt == PUT_ATTEMPTS || !matches!(status.as_u16(), 429 | 503) {
                        return Ok(response);
                    }
                    // Drop rather than buffer an untrusted response body.
                    drop(response);
                }
                Err(error) => {
                    tracing::debug!(operation, attempt, "PUT transport failed");
                    if attempt == PUT_ATTEMPTS
                        || !(error.is_connect()
                            || error.is_timeout()
                            || error.is_request()
                            || error.is_body())
                    {
                        bail!("{operation}: HTTP transport failed");
                    }
                }
            }
            let jitter = 0.5 + rand::random::<f64>();
            tokio::time::sleep(Duration::from_secs_f64(
                0.25 * 2_f64.powi(attempt as i32) * jitter,
            ))
            .await;
        }
        unreachable!("bounded PUT loop always returns")
    }

    pub async fn admin_get(&self, path: &str) -> Result<Value> {
        validate_admin_path(path)?;
        decode(
            "admin GET",
            self.request("admin GET", Method::GET, path, None).await?,
        )
        .await
    }

    pub async fn admin_post(&self, path: &str, body: Value) -> Result<Value> {
        validate_admin_path(path)?;
        decode(
            "admin POST",
            self.request("admin POST", Method::POST, path, Some(body))
                .await?,
        )
        .await
    }

    pub async fn upstream_has(&self, upstream: &str, hash: &str) -> bool {
        let Ok(hash) = segment(hash) else {
            return false;
        };
        let url = format!("{}/{hash}.narinfo", upstream.trim_end_matches('/'));
        let Ok(url) = Url::parse(&url) else {
            return false;
        };
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return false;
        }
        self.upstream
            .head(url)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }
}

fn segment(value: &str) -> Result<String> {
    // Hosted identifiers are simple names, hashes, or UUIDs. Reject path injection.
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("invalid API identifier");
    }
    Ok(value.to_owned())
}

fn validate_admin_path(path: &str) -> Result<()> {
    if !path.starts_with("/_api/v1/admin/")
        || path.contains(['?', '#', '\\', '%'])
        || path.split('/').any(|s| s == "." || s == "..")
    {
        bail!("invalid admin API path");
    }
    Ok(())
}

fn signed_headers(values: &HashMap<String, String>) -> Result<header::HeaderMap> {
    let mut headers = header::HeaderMap::new();
    for (name, value) in values {
        let name = header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("invalid upload header"))?;
        let mut value =
            header::HeaderValue::from_str(value).map_err(|_| anyhow!("invalid upload header"))?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    Ok(headers)
}

async fn file_size(path: &Path) -> Result<u64> {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.len())
        .map_err(|_| anyhow!("cannot stat upload file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

    #[derive(Debug)]
    struct Request {
        line: String,
        headers: String,
        body: Vec<u8>,
    }

    // Each response closes its connection so retries must provide a fresh stream.
    async fn server(responses: Vec<(u16, String, String)>) -> (String, JoinHandle<Vec<Request>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, extra, body) in responses {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(10), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    bytes.push(byte[0]);
                    if bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let headers = String::from_utf8(bytes).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut request_body = vec![0; length];
                socket.read_exact(&mut request_body).await.unwrap();
                requests.push(Request {
                    line: headers.lines().next().unwrap().into(),
                    headers: headers.to_lowercase(),
                    body: request_body,
                });
                if status == 0 {
                    continue;
                } // Simulate a lost response after receiving the body.
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{extra}\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (url, task)
    }

    fn response(status: u16, body: &str) -> (u16, String, String) {
        (status, String::new(), body.into())
    }

    fn client(url: &str) -> Client {
        Client::new(&crate::config::Server {
            server: url.into(),
            token: "secret-token".into(),
        })
        .unwrap()
    }

    fn session(url: &str, key: &str) -> Session {
        serde_json::from_value(json!({"sessionId":"s1", "r2Key":key, "uploadMethod":"presigned", "uploadUrl":url, "uploadHeaders":{"x-amz-meta-upload-session":"s1"}})).unwrap()
    }

    fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    #[tokio::test]
    async fn missing_defaults_and_wire_auth() {
        let (url, task) = server(vec![response(200, r#"{"missing":["hash"]}"#)]).await;
        let missing = client(&url)
            .missing("cache", &["hash".into()])
            .await
            .unwrap();
        assert_eq!(missing.missing, ["hash"]);
        assert!(
            missing.upstream.is_empty()
                && missing.unchecked.is_empty()
                && missing.upstreams.is_empty()
        );
        let requests = task.await.unwrap();
        assert_eq!(requests[0].line, "POST /_api/v1/get-missing-paths HTTP/1.1");
        assert!(
            requests[0]
                .headers
                .contains("authorization: bearer secret-token")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            json!({"cache":"cache","storePathHashes":["hash"]})
        );
    }

    #[tokio::test]
    async fn presigned_ranges_retry_and_keep_etags_without_auth() {
        let (url, task) = server(vec![
            response(503, ""),
            (200, "ETag: \"first\"\r\n".into(), String::new()),
            (200, "ETag: \"last\"\r\n".into(), String::new()),
        ])
        .await;
        let mut session = session(&url, "staging/s1");
        session.upload_method = "presigned-parts".into();
        session.part_size = Some(4);
        session.parts = vec![
            PresignedPart {
                part_number: 1,
                url: format!("{url}/one?signature=secret"),
            },
            PresignedPart {
                part_number: 2,
                url: format!("{url}/two?signature=secret"),
            },
        ];
        let file = file(b"abcdef");
        let parts = client(&url)
            .upload_presigned_parts(&session, file.path(), Arc::new(Semaphore::new(1)))
            .await
            .unwrap();
        assert_eq!(
            parts
                .iter()
                .map(|p| (p.part_number, p.etag.as_str()))
                .collect::<Vec<_>>(),
            [(1, "\"first\""), (2, "\"last\"")]
        );
        let requests = task.await.unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|r| r.body.as_slice())
                .collect::<Vec<_>>(),
            [b"abcd".as_slice(), b"abcd", b"ef"]
        );
        for request in &requests {
            assert!(!request.headers.contains("authorization:"));
        }
        assert!(requests[0].headers.contains("content-length: 4"));
        assert!(requests[2].headers.contains("content-length: 2"));
    }

    #[tokio::test]
    async fn canonical_412_reconciles_same_session_and_retargets_once() {
        let (url, task) = server(vec![
            response(412, "private failure"),
            response(
                200,
                r#"{"results":[{"sessionId":"s1","status":400,"error":"Upload incomplete"}]}"#,
            ),
            response(200, "{}"),
            response(200, "{}"),
            response(200, "{}"),
        ])
        .await;
        let file = file(b"nar bytes");
        let result = client(&url)
            .upload_single(
                &session(&format!("{url}/signed"), "nar/canonical"),
                file.path(),
                Arc::new(Semaphore::new(1)),
            )
            .await
            .unwrap();
        assert!(result.is_none());
        let requests = task.await.unwrap();
        assert_eq!(
            requests.iter().map(|r| r.line.as_str()).collect::<Vec<_>>(),
            [
                "PUT /signed HTTP/1.1",
                "POST /_api/v1/uploads/commit HTTP/1.1",
                "POST /_api/v1/uploads/s1/multipart HTTP/1.1",
                "PUT /_api/v1/uploads/s1/part/1 HTTP/1.1",
                "POST /_api/v1/uploads/s1/complete HTTP/1.1"
            ]
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[1].body).unwrap(),
            json!({"sessionIds":["s1"]})
        );
        assert_eq!(requests[0].body, requests[3].body);
        assert!(!requests[0].headers.contains("authorization:"));
        assert!(
            requests[0]
                .headers
                .contains("x-amz-meta-upload-session: s1")
        );
        assert!(
            requests[3]
                .headers
                .contains("authorization: bearer secret-token")
        );
    }

    #[tokio::test]
    async fn lost_success_412_returns_published_proof_without_retarget() {
        let (url, task) = server(vec![
            response(412, ""),
            response(200, r#"{"results":[{"sessionId":"s1","published":true}]}"#),
        ])
        .await;
        let file = file(b"nar");
        let result = client(&url)
            .upload_single(
                &session(&url, "nar/canonical"),
                file.path(),
                Arc::new(Semaphore::new(1)),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(result.published);
        assert_eq!(task.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn staged_412_is_not_reconciled_and_errors_are_redacted() {
        let (url, task) = server(vec![response(412, "secret-token private response")]).await;
        let file = file(b"nar");
        let error = client(&url)
            .upload_single(
                &session(&format!("{url}/signed?secret-signature"), "staging/s1"),
                file.path(),
                Arc::new(Semaphore::new(1)),
            )
            .await
            .unwrap_err();
        assert_eq!(format!("{error:#}"), "single upload failed (HTTP 412)");
        assert_eq!(task.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn posts_are_not_retried_and_redirects_are_not_followed() {
        let (url, task) = server(vec![
            response(503, "secret"),
            response(503, "secret"),
            (307, "Location: /leak\r\n".into(), String::new()),
        ])
        .await;
        let client = client(&url);
        assert!(client.create_sessions("cache", &[]).await.is_err());
        assert!(client.commit(&["s1".into()], None).await.is_err());
        let error = client.admin_get("/_api/v1/admin/tokens").await.unwrap_err();
        assert_eq!(format!("{error:#}"), "admin GET failed (HTTP 307)");
        assert_eq!(task.await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn upstream_head_does_not_authenticate() {
        let (url, task) = server(vec![response(200, "")]).await;
        assert!(client(&url).upstream_has(&url, "hash").await);
        let requests = task.await.unwrap();
        assert_eq!(requests[0].line, "HEAD /hash.narinfo HTTP/1.1");
        assert!(!requests[0].headers.contains("authorization:"));
    }

    #[tokio::test]
    async fn presigned_redirect_is_not_followed() {
        let (url, task) = server(vec![(307, "Location: /leak\r\n".into(), String::new())]).await;
        let file = file(b"nar");
        let error = client(&url)
            .upload_single(
                &session(&url, "staging/s1"),
                file.path(),
                Arc::new(Semaphore::new(1)),
            )
            .await
            .unwrap_err();
        assert_eq!(format!("{error:#}"), "single upload failed (HTTP 307)");
        assert_eq!(task.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn put_retry_budget_is_four_attempts() {
        let (url, task) = server((0..4).map(|_| response(429, "secret")).collect()).await;
        let file = file(b"nar");
        let error = client(&url)
            .upload_single(
                &session(&url, "staging/s1"),
                file.path(),
                Arc::new(Semaphore::new(1)),
            )
            .await
            .unwrap_err();
        assert_eq!(format!("{error:#}"), "single upload failed (HTTP 429)");
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests.iter().all(|r| r.body == b"nar"));
    }

    #[tokio::test]
    async fn put_reopens_body_after_lost_response() {
        let (url, task) = server(vec![response(0, ""), response(200, "")]).await;
        let file = file(b"replay me");
        assert!(
            client(&url)
                .upload_single(
                    &session(&url, "staging/s1"),
                    file.path(),
                    Arc::new(Semaphore::new(1))
                )
                .await
                .unwrap()
                .is_none()
        );
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.body == b"replay me"));
    }

    #[tokio::test]
    async fn direct_412_preserves_non_incomplete_commit_result() {
        let (url, task) = server(vec![
            response(412, ""),
            response(
                200,
                r#"{"results":[{"sessionId":"s1","status":403,"error":"Forbidden"}]}"#,
            ),
        ])
        .await;
        let file = file(b"nar");
        let mut session = session(&url, "nar/canonical");
        session.upload_method = "direct".into();
        let result = client(&url)
            .upload_single(&session, file.path(), Arc::new(Semaphore::new(1)))
            .await
            .unwrap()
            .unwrap();
        assert!(!result.published);
        assert_eq!(result.status, Some(403));
        let requests = task.await.unwrap();
        assert_eq!(requests[0].line, "PUT /_api/v1/uploads/s1/blob HTTP/1.1");
        assert!(
            requests[0]
                .headers
                .contains("authorization: bearer secret-token")
        );
    }

    #[tokio::test]
    async fn create_and_commit_use_hosted_wire_shapes() {
        let (url, task) = server(vec![
            response(
                200,
                r#"{"sessions":[{"sessionId":"s1","r2Key":"nar/key","uploadMethod":"direct"}]}"#,
            ),
            response(200, r#"{"results":[{"sessionId":"s1","published":true}]}"#),
        ])
        .await;
        let client = client(&url);
        let params = SessionParams {
            store_path: "/nix/store/hash-name".into(),
            store_path_hash: "hash".into(),
            nar_hash: "sha256:nar".into(),
            nar_size: 42,
            file_hash: "sha256:file".into(),
            file_size: 17,
            compression: "zstd".into(),
            references: vec![],
            deriver: None,
        };
        let sessions = client.create_sessions("cache", &[params]).await.unwrap();
        assert!(sessions[0].upload_url.is_none() && sessions[0].parts.is_empty());
        let parts = HashMap::from([(
            "s1".into(),
            vec![UploadedPart {
                part_number: 1,
                etag: "etag".into(),
            }],
        )]);
        assert!(client.commit(&["s1".into()], Some(&parts)).await.unwrap()[0].published);
        let requests = task.await.unwrap();
        assert_eq!(
            requests[0].line,
            "POST /_api/v1/caches/cache/upload-sessions/batch HTTP/1.1"
        );
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["paths"][0]["fileSize"], 17);
        assert_eq!(body["paths"][0]["storePathHash"], "hash");
        assert!(body["paths"][0].get("deriver").is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[1].body).unwrap(),
            json!({"sessionIds":["s1"],"parts":{"s1":[{"partNumber":1,"etag":"etag"}]}})
        );
    }
}
