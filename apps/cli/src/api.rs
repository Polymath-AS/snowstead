//! Hosted v1 protocol. Errors omit URLs, credentials, and response bodies.
use anyhow::{Result, anyhow, bail};
use reqwest::{Method, Response, Url, header, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::HashMap, time::Duration};

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
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub session_id: String,
    pub part_size: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionParams {
    pub store_path: String,
    pub store_path_hash: String,
    pub nar_hash: String,
    pub nar_size: u64,
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
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finalize {
    pub session_id: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub file_hash: String,
    pub file_size: u64,
    pub parts: Vec<UploadedPart>,
}
// Never log signed instructions.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Part {
    part_number: u32,
    url: String,
    headers: HashMap<String, String>,
}
fn status_ok(operation: &str, response: Response) -> Result<Response> {
    if response.status().is_success() {
        Ok(response)
    } else {
        bail!("{operation} failed (HTTP {})", response.status().as_u16())
    }
}
async fn decode<T: DeserializeOwned>(operation: &str, response: Response) -> Result<T> {
    status_ok(operation, response)?
        .json()
        .await
        .map_err(|_| anyhow!("{operation}: invalid response"))
}
fn transient(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}
async fn backoff(attempt: i32) {
    tokio::time::sleep(Duration::from_secs_f64(
        0.25 * 2_f64.powi(attempt) * (0.5 + rand::random::<f64>()),
    ))
    .await;
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
        Ok(Self {
            server: server.server.trim_end_matches('/').to_owned(),
            authorization,
            http: reqwest::Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(300))
                .build()?,
            upstream: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
        })
    }
    async fn request(
        &self,
        operation: &str,
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
            "API response"
        );
        Ok(response)
    }
    // One attempt only: callers share a four-attempt budget across HTTP and
    // per-upload failures. Never use this for non-idempotent session creation.
    async fn replayable_post<T: DeserializeOwned>(
        &self,
        operation: &str,
        path: &str,
        body: Value,
    ) -> Result<Option<T>> {
        let response = match self
            .request(operation, Method::POST, path, Some(body))
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if transient(response.status().as_u16()) {
            return Ok(None);
        }
        let response = status_ok(operation, response)?;
        match response.json().await {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.is_body() || error.is_timeout() => Ok(None),
            Err(_) => bail!("{operation}: invalid response"),
        }
    }
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn missing(&self, cache: &str, hashes: &[String]) -> Result<Missing> {
        decode(
            "get-missing-paths",
            self.request(
                "get-missing-paths",
                Method::POST,
                "/_api/v1/get-missing-paths",
                Some(json!({"cache":cache,"storePathHashes":hashes})),
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
        let path = format!("/_api/v1/caches/{}/upload-streams/batch", segment(cache)?);
        let data: Sessions = decode(
            "create-sessions",
            self.request(
                "create-sessions",
                Method::POST,
                &path,
                Some(json!({"paths":paths})),
            )
            .await?,
        )
        .await?;
        Ok(data.sessions)
    }
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn finalize(&self, uploads: &[Finalize]) -> Result<Vec<CommitResult>> {
        #[derive(Deserialize)]
        struct Results {
            results: Vec<CommitResult>,
        }
        let mut pending: Vec<_> = uploads.iter().enumerate().collect();
        let mut results = vec![None; uploads.len()];
        for attempt in 1..=4 {
            let paths: Vec<_> = pending.iter().map(|(_, upload)| *upload).collect();
            if let Some(data) = self
                .replayable_post::<Results>(
                    "finalize",
                    "/_api/v1/uploads/finalize",
                    json!({"uploads":paths}),
                )
                .await?
            {
                if data.results.len() != pending.len()
                    || data
                        .results
                        .iter()
                        .zip(&pending)
                        .any(|(row, (_, upload))| row.session_id != upload.session_id)
                {
                    bail!("finalize: response count or order differs from request");
                }
                let mut retry = Vec::new();
                for ((index, upload), row) in pending.into_iter().zip(data.results) {
                    if attempt < 4 && !row.published && row.status.is_some_and(transient) {
                        retry.push((index, upload));
                    } else {
                        results[index] = Some(row);
                    }
                }
                pending = retry;
                if pending.is_empty() {
                    return results
                        .into_iter()
                        .map(|row| row.ok_or_else(|| anyhow!("finalize: missing result")))
                        .collect();
                }
            }
            if attempt == 4 {
                bail!("finalize: transient HTTP failure after 4 attempts");
            }
            backoff(attempt).await;
        }
        unreachable!()
    }
    pub async fn abort(&self, id: &str) -> Result<()> {
        let path = format!("/_api/v1/uploads/{}/abort", segment(id)?);
        status_ok(
            "abort",
            self.request("abort", Method::POST, &path, Some(json!({})))
                .await?,
        )?;
        Ok(())
    }
    /// Reserve this exact part's quota before sending bytes. Retries retain the
    /// same immutable allocation and supplied headers, never the API credential.
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn upload_part(
        &self,
        id: &str,
        number: u32,
        bytes: bytes::Bytes,
    ) -> Result<UploadedPart> {
        if !(1..=10_000).contains(&number) || bytes.is_empty() {
            bail!("invalid upload part");
        }
        #[derive(Deserialize)]
        struct Parts {
            parts: Vec<Part>,
        }
        let path = format!("/_api/v1/uploads/{}/parts", segment(id)?);
        let mut reserved = None;
        for attempt in 1..=4 {
            reserved = self
                .replayable_post::<Parts>(
                    "reserve part",
                    &path,
                    json!({"parts":[{"partNumber":number,"size":bytes.len()}]}),
                )
                .await?;
            if reserved.is_some() {
                break;
            }
            if attempt == 4 {
                bail!("reserve part: transient HTTP failure after 4 attempts");
            }
            backoff(attempt).await;
        }
        let mut data = reserved.ok_or_else(|| anyhow!("reserve part: missing instructions"))?;
        if data.parts.len() != 1 || data.parts[0].part_number != number {
            bail!("invalid part instructions");
        }
        let part = data.parts.remove(0);
        let url = Url::parse(&part.url).map_err(|_| anyhow!("invalid upload URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("invalid upload URL");
        }
        let mut headers = header::HeaderMap::new();
        for (name, value) in part.headers {
            let name = header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow!("invalid upload header"))?;
            let mut value = header::HeaderValue::from_str(&value)
                .map_err(|_| anyhow!("invalid upload header"))?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_str(&bytes.len().to_string())?,
        );
        for attempt in 1..=4 {
            let body = reqwest::Body::from(bytes.clone());
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
                    tracing::debug!(status = status.as_u16(), attempt, "part PUT response");
                    if attempt == 4 || !transient(status.as_u16()) {
                        let response = status_ok("part upload", response)?;
                        let etag = response
                            .headers()
                            .get(header::ETAG)
                            .and_then(|v| v.to_str().ok())
                            .filter(|v| !v.is_empty())
                            .ok_or_else(|| anyhow!("part upload returned no ETag"))?
                            .to_owned();
                        return Ok(UploadedPart {
                            part_number: number,
                            etag,
                        });
                    }
                }
                Err(_) => {
                    tracing::debug!(attempt, "part PUT transport failed");
                    if attempt == 4 {
                        bail!("part upload: HTTP transport failed");
                    }
                }
            }
            backoff(attempt).await;
        }
        unreachable!()
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
        let Ok(url) = Url::parse(&format!(
            "{}/{hash}.narinfo",
            upstream.trim_end_matches('/')
        )) else {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    pub fn client(url: &str) -> Client {
        Client::new(&crate::config::Server {
            server: url.into(),
            token: "secret-token".into(),
        })
        .unwrap()
    }
    pub async fn read(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(socket.read_u8().await.unwrap());
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
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        (headers, body)
    }
    pub async fn reply(socket: &mut tokio::net::TcpStream, status: u16, body: &str, extra: &str) {
        socket.write_all(format!("HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}", body.len()).as_bytes()).await.unwrap();
    }
    #[tokio::test]
    async fn stream_wire_contract_retries_exact_bytes_and_only_supplied_headers() {
        for supplied_auth in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let origin = url.clone();
            let server = tokio::spawn(async move {
                for step in 0..8 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let (headers, body) = read(&mut socket).await;
                    if step == 0 {
                        assert!(
                            headers.starts_with("POST /_api/v1/caches/main/upload-streams/batch ")
                        );
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        assert!(body["paths"][0].get("fileHash").is_none());
                        assert!(body["paths"][0].get("fileSize").is_none());
                        reply(
                            &mut socket,
                            200,
                            r#"{"sessions":[{"sessionId":"s1","partSize":8388608}]}"#,
                            "",
                        )
                        .await;
                    } else if step <= 2 {
                        assert!(headers.starts_with("POST /_api/v1/uploads/s1/parts "));
                        assert_eq!(
                            serde_json::from_slice::<Value>(&body).unwrap(),
                            json!({"parts":[{"partNumber":1,"size":6}]})
                        );
                        if step == 1 {
                            reply(&mut socket, 429, "private queue full", "").await;
                            continue;
                        }
                        let supplied = if supplied_auth {
                            json!({"authorization":"Bearer proxy-token"})
                        } else {
                            json!({})
                        };
                        reply(&mut socket, 200, &json!({"parts":[{"partNumber":1,"url":format!("{origin}/signed?private-signature"),"headers":supplied}]}).to_string(), "").await;
                    } else if step <= 5 {
                        assert!(headers.starts_with("PUT /signed?private-signature "));
                        assert_eq!(body, b"abcdef");
                        assert!(!headers.contains("secret-token"));
                        assert_eq!(
                            headers
                                .to_lowercase()
                                .contains("authorization: bearer proxy-token"),
                            supplied_auth
                        );
                        assert!(headers.to_lowercase().contains("content-length: 6"));
                        match step {
                            3 => reply(&mut socket, 503, "private error", "").await,
                            4 => (), // Lost successful response must replay the same bytes.
                            _ => reply(&mut socket, 200, "", "ETag: \"part\"\r\n").await,
                        }
                    } else if step == 6 {
                        assert!(headers.starts_with("POST /_api/v1/uploads/finalize "));
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(
                            body["uploads"][0]["parts"],
                            json!([{"partNumber":1,"etag":"\"part\""}])
                        );
                        assert_eq!(body["uploads"][0]["fileSize"], 6);
                        reply(
                            &mut socket,
                            200,
                            r#"{"results":[{"sessionId":"s1","published":true}]}"#,
                            "",
                        )
                        .await;
                    } else {
                        assert!(headers.starts_with("POST /_api/v1/uploads/s1/abort "));
                        assert_eq!(body, b"{}");
                        reply(&mut socket, 200, "{}", "").await;
                    }
                }
            });
            let client = client(&url);
            let sessions = client
                .create_sessions(
                    "main",
                    &[SessionParams {
                        store_path: "/nix/store/hash-name".into(),
                        store_path_hash: "hash".into(),
                        nar_hash: "sha256:nar".into(),
                        nar_size: 42,
                        compression: "zstd".into(),
                        references: vec![],
                        deriver: None,
                    }],
                )
                .await
                .unwrap();
            assert_eq!(sessions[0].part_size, 8388608);
            let part = client
                .upload_part("s1", 1, bytes::Bytes::from_static(b"abcdef"))
                .await
                .unwrap();
            assert!(
                client
                    .finalize(&[Finalize {
                        session_id: "s1".into(),
                        nar_hash: "sha256:nar".into(),
                        nar_size: 42,
                        file_hash: "hash".into(),
                        file_size: 6,
                        parts: vec![part]
                    }])
                    .await
                    .unwrap()[0]
                    .published
            );
            client.abort("s1").await.unwrap();
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn missing_etag_and_redirect_fail_without_leaking_credentials() {
        for status in [200, 307, 403] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let origin = url.clone();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                read(&mut socket).await;
                reply(&mut socket, 200, &json!({"parts":[{"partNumber":1,"url":format!("{origin}/private-signature"),"headers":{}}]}).to_string(), "").await;
                let (mut socket, _) = listener.accept().await.unwrap();
                read(&mut socket).await;
                reply(
                    &mut socket,
                    status,
                    "private response secret-token",
                    "Location: /leak\r\n",
                )
                .await;
            });
            let error = client(&url)
                .upload_part("s1", 1, bytes::Bytes::from_static(b"abc"))
                .await
                .unwrap_err();
            let text = format!("{error:#}");
            for secret in ["private", "secret-token", &url] {
                assert!(!text.contains(secret));
            }
            server.await.unwrap();
        }
    }
    fn upload(id: &str) -> Finalize {
        Finalize {
            session_id: id.into(),
            nar_hash: "sha256:nar".into(),
            nar_size: 42,
            file_hash: "hash".into(),
            file_size: 6,
            parts: vec![UploadedPart {
                part_number: 1,
                etag: "etag".into(),
            }],
        }
    }
    async fn scripted(
        responses: Vec<(u16, Value)>,
    ) -> (Client, tokio::task::JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, response) in responses {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(10), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let (headers, body) = read(&mut socket).await;
                assert!(headers.starts_with("POST /_api/v1/"));
                requests.push(serde_json::from_slice(&body).unwrap());
                if status != 0 {
                    reply(&mut socket, status, &response.to_string(), "").await;
                }
            }
            requests
        });
        (client(&url), task)
    }
    #[tokio::test]
    async fn lost_finalize_response_replays_then_only_busy_rows_retry_in_original_order() {
        let (client, server) = scripted(vec![
            (0, Value::Null), // Published on the server, but its response was lost.
            (
                200,
                json!({"results":[
                    {"sessionId":"first","published":true},
                    {"sessionId":"busy","published":false,"status":503,"error":"Installation busy"},
                    {"sessionId":"bad","published":false,"status":400},
                    {"sessionId":"denied","published":false,"status":403},
                    {"sessionId":"full","published":false,"status":507}
                ]}),
            ),
            (503, json!({"error":"private queue full"})),
            (
                200,
                json!({"results":[{"sessionId":"busy","published":true}]}),
            ),
        ])
        .await;
        let uploads: Vec<_> = ["first", "busy", "bad", "denied", "full"]
            .into_iter()
            .map(upload)
            .collect();
        let results = client.finalize(&uploads).await.unwrap();
        assert_eq!(
            results
                .iter()
                .map(|row| row.session_id.as_str())
                .collect::<Vec<_>>(),
            ["first", "busy", "bad", "denied", "full"]
        );
        assert!(results[0].published && results[1].published);
        assert_eq!(
            results[2..]
                .iter()
                .map(|row| row.status)
                .collect::<Vec<_>>(),
            [Some(400), Some(403), Some(507)]
        );
        let requests = server.await.unwrap();
        assert_eq!(
            requests[0], requests[1],
            "lost responses replay identical metadata, not NAR bytes"
        );
        assert_eq!(requests[2], json!({"uploads":[uploads[1]]}));
        assert_eq!(requests[2], requests[3]);
    }
    #[tokio::test]
    async fn post_retries_are_bounded_and_integrity_and_create_fail_fast() {
        let mut scenarios = vec![
            ("reserve", vec![429, 502, 503, 504]),
            ("finalize", vec![429, 502, 503, 504]),
            ("busy", vec![200; 4]),
            ("create", vec![503]),
            ("create", vec![0]),
        ];
        for operation in ["reserve", "finalize"] {
            for status in [400, 403, 507] {
                scenarios.push((operation, vec![status]));
            }
        }
        futures_util::future::join_all(scenarios.into_iter().map(|(operation, statuses)| async move {
            let count = statuses.len();
            let response = if operation == "busy" {
                json!({"results":[{"sessionId":"s1","published":false,"status":503,"error":"Installation busy"}]})
            } else { json!({"error":"private secret-token"}) };
            let (client, server) = scripted(statuses.into_iter().map(|status| (status, response.clone())).collect()).await;
            let error = match operation {
                "reserve" => client.upload_part("s1", 1, bytes::Bytes::from_static(b"abcdef")).await.unwrap_err(),
                "finalize" => client.finalize(&[upload("s1")]).await.unwrap_err(),
                "busy" => {
                    let result = client.finalize(&[upload("s1")]).await.unwrap();
                    assert!(!result[0].published);
                    assert_eq!(result[0].status, Some(503));
                    assert_eq!(server.await.unwrap().len(), count);
                    return;
                }
                _ => client.create_sessions("main", &[]).await.err().unwrap(),
            };
            let text = format!("{error:#}");
            assert!(!text.contains("private") && !text.contains("secret-token"));
            if count == 4 { assert!(text.contains("4 attempts")); }
            assert_eq!(server.await.unwrap().len(), count);
        })).await;
    }
    #[tokio::test]
    async fn finalize_rejects_missing_extra_or_reordered_results_without_retry() {
        for rows in [
            json!([{"sessionId":"s1","published":true}]),
            json!([{"sessionId":"s2","published":true},{"sessionId":"s1","published":true}]),
            json!([{"sessionId":"s1","published":true},{"sessionId":"s2","published":true},{"sessionId":"s3","published":true}]),
        ] {
            let (client, server) = scripted(vec![(200, json!({"results":rows}))]).await;
            let error = client
                .finalize(&[upload("s1"), upload("s2")])
                .await
                .unwrap_err();
            assert!(error.to_string().contains("response count or order"));
            assert_eq!(server.await.unwrap().len(), 1);
        }
    }
}
