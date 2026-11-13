//! Hosted v1 protocol. Errors omit URLs, credentials, and response bodies.
//! The wire types and limits live in `snowstead-protocol`, shared with the server.
use anyhow::{Result, anyhow, bail};
use reqwest::{Method, Response, Url, header, redirect::Policy};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use snowstead_protocol::{
    self as protocol, CreateSessions, CreatedSessions, Empty, FinalizeBatch, InlineEntry,
    InlineManifest, MissingPaths, MissingPathsRequest, PartGrant, PartRequest, PathInput, Receipt,
    ReceiptPart, ReservationResults, ReservePartsBatch, SessionParts, UploadResults, UploadSession,
    UploadStage, UploadStatusRequest, limits, routes,
};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Client {
    server: String,
    authorization: header::HeaderValue,
    http: reqwest::Client,
    upstream: reqwest::Client,
    push_job: Option<String>,
    progress: Option<crate::progress::Progress>,
}

/// `snowstead-cli/<version>`, sent with every request.
pub(crate) fn user_agent() -> String {
    format!("{}/{}", protocol::CLI_PRODUCT, env!("CARGO_PKG_VERSION"))
}

/// Refuses a response from a server that cannot serve this CLI's protocol
/// version, with a message saying which side to upgrade. A server predating
/// versioning advertises nothing and is treated as version 1.
pub(crate) fn check_protocol(response: &Response) -> Result<()> {
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    protocol::check_server(
        header(protocol::PROTOCOL_VERSION_HEADER),
        header(protocol::MIN_PROTOCOL_VERSION_HEADER),
    )?;
    Ok(())
}

/// Serializes a request body. The protocol types always serialize.
pub(crate) fn body<T: Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| anyhow!("invalid request body"))
}
/// How the server left one row of a publication batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowOutcome {
    Published,
    /// Verified and stored for a push job, which publishes it later.
    Prepared,
    /// Refused with a status that retrying cannot change.
    Rejected {
        status: u16,
    },
    /// Still busy or unreachable when the retry budget ran out.
    TransientExhausted,
    /// The batch stopped on this error after other rows had resolved.
    Failed(String),
}
/// A part to reserve, on behalf of one waiting upload.
pub struct PartReservation {
    pub session_id: String,
    pub part_number: u32,
    pub size: usize,
}
pub struct InlineUpload {
    pub session_id: String,
    pub file_hash: String,
    pub bytes: bytes::Bytes,
}

// Only the small manifest is allocated afresh. Payload frames clone the
// permit-owned Bytes, retaining the global memory charge throughout a replay.
fn inline_frames(uploads: &[&InlineUpload]) -> Result<Vec<bytes::Bytes>> {
    let manifest = serde_json::to_vec(&body(&InlineManifest {
        uploads: uploads
            .iter()
            .map(|upload| InlineEntry {
                session_id: upload.session_id.clone(),
                file_hash: upload.file_hash.clone(),
                file_size: upload.bytes.len() as u64,
            })
            .collect(),
    })?)?;
    if manifest.len() > limits::INLINE_MANIFEST_MAX_BYTES {
        bail!("inline upload: manifest exceeds limit");
    }
    let mut header = Vec::with_capacity(4 + manifest.len());
    header.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    header.extend_from_slice(&manifest);
    Ok(std::iter::once(bytes::Bytes::from(header))
        .chain(uploads.iter().map(|upload| upload.bytes.clone()))
        .collect())
}
/// A non-success HTTP status. Typed so callers can classify a failure (for
/// example 401/403) without parsing its message.
#[derive(Debug)]
pub struct HttpError {
    operation: String,
    pub status: u16,
}
impl HttpError {
    pub(crate) fn new(operation: &str, status: u16) -> Self {
        Self {
            operation: operation.to_owned(),
            status,
        }
    }
}
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (HTTP {})", self.operation, self.status)?;
        match (self.operation.as_str(), self.status) {
            ("part upload", 401 | 403) => write!(
                f,
                ": upload URL rejected. Retry the push to request a new upload URL."
            ),
            (_, 401) => write!(
                f,
                ": authentication failed. Run `snowstead login` again. If SNOWSTEAD_TOKEN is set, replace it or unset it to use your saved login."
            ),
            (_, 403) => write!(
                f,
                ": permission denied. Check the token's permissions and access to this organization and cache. Confirm SNOWSTEAD_URL points to the intended server."
            ),
            _ => Ok(()),
        }
    }
}
impl std::error::Error for HttpError {}

fn status_ok(operation: &str, response: Response, versioned: bool) -> Result<Response> {
    if versioned {
        check_protocol(&response)?;
    }
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(HttpError::new(operation, response.status().as_u16()).into())
    }
}
async fn decode<T: DeserializeOwned>(operation: &str, response: Response) -> Result<T> {
    // Operator endpoints do not use the Nix upload protocol negotiation.
    status_ok(operation, response, false)?
        .json()
        .await
        .map_err(|_| anyhow!("{operation}: invalid response"))
}
fn transient(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

const ATTEMPTS: u32 = 4;
const RETRY_AFTER_CAP: Duration = Duration::from_secs(5);

/// What one attempt of a retried call came to.
enum Attempt<T> {
    Done(T),
    /// Transient: worth another attempt, after the server's Retry-After if sent.
    Retry {
        after: Option<Duration>,
    },
    Fatal(anyhow::Error),
}

/// Whether a request may be sent again once the server may have received it.
#[derive(Clone, Copy, PartialEq)]
enum Replay {
    /// Resend after transport failures, lost responses, and transient statuses.
    Idempotent,
    /// Resend only after 503, which the server returns before acting. Any
    /// other failure leaves the commit outcome unknown.
    RefusedOnly,
}

/// Seconds only; HTTP dates are ignored. Bounded so a server cannot stall a push.
fn retry_after(headers: &header::HeaderMap) -> Option<Duration> {
    let seconds = headers
        .get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(Duration::from_secs(seconds).min(RETRY_AFTER_CAP))
}

/// Sorts one HTTP exchange into done, retryable, or fatal for this call.
fn classify<E>(
    operation: &str,
    replay: Replay,
    versioned: bool,
    result: std::result::Result<Response, E>,
) -> Attempt<Response> {
    let response = match result {
        Ok(response) => response,
        Err(_) if replay == Replay::Idempotent => return Attempt::Retry { after: None },
        Err(_) => return Attempt::Fatal(anyhow!("{operation}: HTTP transport failed")),
    };
    // An incompatible server refuses every replay the same way.
    if versioned && let Err(error) = check_protocol(&response) {
        return Attempt::Fatal(error);
    }
    let status = response.status().as_u16();
    if match replay {
        Replay::Idempotent => transient(status),
        Replay::RefusedOnly => status == 503,
    } {
        return Attempt::Retry {
            after: retry_after(response.headers()),
        };
    }
    match status_ok(operation, response, versioned) {
        Ok(response) => Attempt::Done(response),
        Err(error) => Attempt::Fatal(error),
    }
}

impl Attempt<Response> {
    async fn json<T: DeserializeOwned>(self, operation: &str, replay: Replay) -> Attempt<T> {
        match self {
            Attempt::Done(response) => match response.json().await {
                Ok(data) => Attempt::Done(data),
                Err(error)
                    if replay == Replay::Idempotent && (error.is_body() || error.is_timeout()) =>
                {
                    Attempt::Retry { after: None }
                }
                Err(_) => Attempt::Fatal(anyhow!("{operation}: invalid response")),
            },
            Attempt::Retry { after } => Attempt::Retry { after },
            Attempt::Fatal(error) => Attempt::Fatal(error),
        }
    }
}

fn exhausted(operation: &str) -> anyhow::Error {
    anyhow!("{operation}: transient failure after {ATTEMPTS} attempts")
}

/// The retry budget every call shares: four attempts, with jittered
/// exponential backoff between them unless the server names a delay.
struct Budget {
    attempt: u32,
}
impl Budget {
    fn new() -> Self {
        Self { attempt: 1 }
    }
    /// Waits out a transient failure. False once the budget is spent.
    async fn wait(&mut self, after: Option<Duration>) -> bool {
        if self.attempt >= ATTEMPTS {
            return false;
        }
        tokio::time::sleep(after.unwrap_or_else(|| {
            Duration::from_secs_f64(
                0.25 * 2_f64.powi(self.attempt as i32) * (0.5 + rand::random::<f64>()),
            )
        }))
        .await;
        self.attempt += 1;
        true
    }
    /// For calls with a single result: `None` means send the request again.
    async fn settle<T>(&mut self, operation: &str, attempt: Attempt<T>) -> Result<Option<T>> {
        match attempt {
            Attempt::Done(value) => Ok(Some(value)),
            Attempt::Fatal(error) => Err(error),
            Attempt::Retry { after } if self.wait(after).await => Ok(None),
            Attempt::Retry { .. } => Err(exhausted(operation)),
        }
    }
}

trait Upload {
    fn session_id(&self) -> &str;
    fn inline_size(&self) -> Option<u64> {
        None
    }
}
impl Upload for Receipt {
    fn session_id(&self) -> &str {
        &self.session_id
    }
}
impl Upload for InlineUpload {
    fn session_id(&self) -> &str {
        &self.session_id
    }
    fn inline_size(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

/// One publication batch across its attempts. A row keeps the outcome it
/// resolved to, whatever later attempts do to the rows still pending.
struct Publication<'a, U> {
    operation: &'static str,
    /// A push job's client stores verified bytes and leaves publication to the job.
    prepares: bool,
    pending: Vec<(usize, &'a U)>,
    accepted: Vec<(usize, &'a U)>,
    polling: bool,
    poll_delay: Duration,
    outcomes: Vec<Option<RowOutcome>>,
    budget: Budget,
    progress: Option<crate::progress::Progress>,
}
impl<'a, U: Upload> Publication<'a, U> {
    fn new(
        operation: &'static str,
        prepares: bool,
        uploads: &'a [U],
        progress: Option<crate::progress::Progress>,
    ) -> Self {
        Self {
            operation,
            prepares,
            pending: uploads.iter().enumerate().collect(),
            accepted: Vec::new(),
            polling: false,
            poll_delay: Duration::from_millis(250),
            outcomes: vec![None; uploads.len()],
            budget: Budget::new(),
            progress,
        }
    }
    fn pending(&self) -> Vec<&'a U> {
        self.pending.iter().map(|(_, upload)| *upload).collect()
    }
    /// Folds in one attempt. `Some` ends the batch; `None` asks for another
    /// attempt with the rows still pending.
    async fn settle(&mut self, attempt: Attempt<UploadResults>) -> Option<Result<Vec<RowOutcome>>> {
        let after = match attempt {
            Attempt::Fatal(error) => return Some(self.finish(Err(error))),
            Attempt::Retry { after } => after,
            Attempt::Done(data) => {
                if data.results.len() != self.pending.len()
                    || data
                        .results
                        .iter()
                        .zip(&self.pending)
                        .any(|(row, (_, upload))| row.session_id != upload.session_id())
                {
                    return Some(self.finish(Err(anyhow!(
                        "{}: response count or order differs from request",
                        self.operation
                    ))));
                }
                let mut retry = Vec::new();
                for ((index, upload), row) in std::mem::take(&mut self.pending)
                    .into_iter()
                    .zip(data.results)
                {
                    if self.operation == "finalize"
                        && row.status == Some(202)
                        && !row.published
                        && !row.prepared
                        && row.error.is_none()
                        && let Some(stage) = row.stage
                    {
                        if let Some(path) = self
                            .progress
                            .as_ref()
                            .and_then(|p| p.path(upload.session_id()))
                        {
                            path.phase(match stage {
                                UploadStage::Queued => "Queued for verification",
                                UploadStage::Verifying => "Verifying",
                                UploadStage::Publishing => "Publishing",
                            });
                        }
                        self.accepted.push((index, upload));
                        continue;
                    }
                    let prepared = self.prepares
                        && row.prepared
                        && row.status == Some(202)
                        && row.error.is_none();
                    if (row.published || prepared)
                        && let Some(path) = self
                            .progress
                            .as_ref()
                            .and_then(|p| p.path(upload.session_id()))
                    {
                        path.published(upload.inline_size(), prepared);
                    }
                    self.outcomes[index] = Some(match (row.published, row.status) {
                        (true, _) => RowOutcome::Published,
                        _ if prepared => RowOutcome::Prepared,
                        (false, Some(status)) if transient(status) => {
                            retry.push((index, upload));
                            continue;
                        }
                        (false, Some(status)) => RowOutcome::Rejected { status },
                        (false, None) => {
                            RowOutcome::Failed(format!("{}: invalid result", self.operation))
                        }
                    });
                    // A resolved row must not remain live while its batch mates
                    // retry. The transfer collector still owns the final summary.
                    if let Some(progress) = &self.progress {
                        let error = match &self.outcomes[index] {
                            Some(RowOutcome::Rejected { status }) => {
                                Some(HttpError::new("publication", *status).to_string())
                            }
                            Some(RowOutcome::Failed(message)) => Some(message.clone()),
                            _ => None,
                        };
                        progress.finish_path(upload.session_id(), error.as_deref());
                    }
                }
                self.pending = retry;
                if self.pending.is_empty() {
                    return if self.poll_accepted().await {
                        None
                    } else {
                        Some(self.finish(Ok(())))
                    };
                }
                None
            }
        };
        if self.budget.attempt < ATTEMPTS {
            for (_, upload) in &self.pending {
                if let Some(path) = self
                    .progress
                    .as_ref()
                    .and_then(|p| p.path(upload.session_id()))
                {
                    let phase = if self.prepares {
                        "Preparing receipt"
                    } else if upload.inline_size().is_some() {
                        "Uploading and publishing"
                    } else {
                        "Publishing"
                    };
                    path.phase(&format!(
                        "{phase} · retry {}/{ATTEMPTS}",
                        self.budget.attempt + 1
                    ));
                }
            }
        }
        if self.budget.wait(after).await {
            None
        } else if !self.accepted.is_empty() {
            // Rejected admissions must not exhaust healthy, already accepted work.
            for (index, _) in self.pending.drain(..) {
                self.outcomes[index] = Some(RowOutcome::TransientExhausted);
            }
            self.poll_accepted().await;
            None
        } else {
            Some(self.finish(Ok(())))
        }
    }
    async fn poll_accepted(&mut self) -> bool {
        if self.accepted.is_empty() {
            return false;
        }
        self.pending = std::mem::take(&mut self.accepted);
        self.polling = true;
        // Successful status reads do not spend the transport-failure budget.
        self.budget = Budget::new();
        tokio::time::sleep(self.poll_delay).await;
        self.poll_delay = (self.poll_delay * 2).min(Duration::from_secs(2));
        true
    }
    /// The batch itself fails only when no row resolved. Otherwise the rows
    /// still pending take the reason the batch stopped.
    fn finish(&mut self, stopped: Result<()>) -> Result<Vec<RowOutcome>> {
        self.pending.append(&mut self.accepted);
        if self.outcomes.iter().all(Option::is_none) {
            match stopped {
                Err(error) => return Err(error),
                Ok(()) if !self.pending.is_empty() => return Err(exhausted(self.operation)),
                Ok(()) => (),
            }
        }
        let unresolved = match stopped {
            Ok(()) => RowOutcome::TransientExhausted,
            Err(error) => RowOutcome::Failed(format!("{error:#}")),
        };
        for (index, _) in self.pending.drain(..) {
            self.outcomes[index] = Some(unresolved.clone());
        }
        std::mem::take(&mut self.outcomes)
            .into_iter()
            .map(|row| row.ok_or_else(|| anyhow!("{}: missing result", self.operation)))
            .collect()
    }
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
            push_job: None,
            progress: None,
            http: reqwest::Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(300))
                .user_agent(user_agent())
                .build()?,
            upstream: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .user_agent(user_agent())
                .build()?,
        })
    }
    pub fn with_progress(&self, progress: &crate::progress::Progress) -> Self {
        let mut client = self.clone();
        client.progress = Some(progress.clone());
        client
    }

    /// An API request: credentials and this CLI's protocol version. Part
    /// uploads go to granted URLs with only the granted headers instead.
    fn api(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.server))
            .header(header::AUTHORIZATION, self.authorization.clone())
            .header(
                protocol::PROTOCOL_VERSION_HEADER,
                protocol::PROTOCOL_VERSION.to_string(),
            )
    }
    pub(crate) async fn request(
        &self,
        operation: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Response> {
        let mut request = self.api(method, path);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let started = Instant::now();
        let response = request
            .send()
            .await
            .map_err(|_| anyhow!("{operation}: HTTP transport failed"))?;
        tracing::debug!(
            operation,
            status = response.status().as_u16(),
            response_headers_ms = started.elapsed().as_millis(),
            "API response"
        );
        Ok(response)
    }
    /// One attempt only: the caller owns the retry budget and says whether
    /// this request may be replayed.
    async fn post<T: DeserializeOwned>(
        &self,
        operation: &str,
        replay: Replay,
        path: &str,
        body: &impl Serialize,
    ) -> Attempt<T> {
        let body = match self::body(body) {
            Ok(body) => body,
            Err(error) => return Attempt::Fatal(error),
        };
        let result = self
            .request(operation, Method::POST, path, Some(body))
            .await;
        classify(operation, replay, true, result)
            .json(operation, replay)
            .await
    }
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn missing(&self, cache: &str, hashes: &[String]) -> Result<MissingPaths> {
        let request = MissingPathsRequest {
            cache: cache.to_owned(),
            store_path_hashes: hashes.to_vec(),
        };
        let mut budget = Budget::new();
        loop {
            let attempt = self
                .post(
                    "get-missing-paths",
                    Replay::Idempotent,
                    routes::MISSING_PATHS,
                    &request,
                )
                .await;
            if let Some(missing) = budget.settle("get-missing-paths", attempt).await? {
                return Ok(missing);
            }
        }
    }
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn create_sessions(
        &self,
        cache: &str,
        paths: &[PathInput],
    ) -> Result<Vec<UploadSession>> {
        let path = routes::upload_streams(&segment(cache)?);
        let request = CreateSessions {
            paths: paths.to_vec(),
            job_id: self.push_job.clone(),
        };
        // The server returns busy before committing session creation.
        // Never replay transport failures or gateway errors: their commit
        // outcome is unknown and creation is not idempotent. A push job's
        // sessions are keyed by the job, so replaying them is safe.
        let replay = if self.push_job.is_some() {
            Replay::Idempotent
        } else {
            Replay::RefusedOnly
        };
        let mut budget = Budget::new();
        loop {
            let attempt = self
                .post::<CreatedSessions>("create-sessions", replay, &path, &request)
                .await;
            if let Some(data) = budget.settle("create-sessions", attempt).await? {
                return Ok(data.sessions);
            }
        }
    }
    fn prepare_only(&self, path: &str) -> String {
        if self.prepares_only() {
            format!("{path}?{}", routes::PREPARE_ONLY_QUERY)
        } else {
            path.to_owned()
        }
    }
    /// One outcome per upload, in request order. Rows that are still busy
    /// replay together; an error means no row resolved at all.
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn finalize(&self, uploads: &[Receipt]) -> Result<Vec<RowOutcome>> {
        let mut batch = Publication::new(
            "finalize",
            self.prepares_only(),
            uploads,
            self.progress.clone(),
        );
        let path = self.prepare_only(routes::FINALIZE);
        loop {
            let attempt = if batch.polling {
                let request = UploadStatusRequest {
                    sessions: batch
                        .pending()
                        .iter()
                        .map(|upload| upload.session_id.clone())
                        .collect(),
                };
                self.post(
                    "finalize status",
                    Replay::Idempotent,
                    routes::UPLOAD_STATUS,
                    &request,
                )
                .await
            } else {
                let request = FinalizeBatch {
                    uploads: batch.pending().into_iter().cloned().collect(),
                };
                self.post("finalize", Replay::Idempotent, &path, &request)
                    .await
            };
            if let Some(outcomes) = batch.settle(attempt).await {
                return outcomes;
            }
        }
    }
    /// Replays retain the same globally budgeted allocation, including after a
    /// lost publication acknowledgement. HTTP and item failures share a budget.
    /// Outcomes follow the same rules as `finalize`.
    pub async fn inline_batch(&self, uploads: &[InlineUpload]) -> Result<Vec<RowOutcome>> {
        if uploads.is_empty() || uploads.len() > limits::INLINE_BATCH_MAX {
            bail!("inline upload: invalid batch size");
        }
        for (index, upload) in uploads.iter().enumerate() {
            segment(&upload.session_id)?;
            if upload.bytes.is_empty()
                || upload.bytes.len() as u64 > limits::INLINE_MAX_BYTES
                || upload.file_hash.len() != 64
                || !upload
                    .file_hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || uploads[..index]
                    .iter()
                    .any(|other| other.session_id == upload.session_id)
            {
                bail!("inline upload: invalid bytes, hash, or duplicate session");
            }
        }
        let mut batch = Publication::new(
            "inline upload",
            self.prepares_only(),
            uploads,
            self.progress.clone(),
        );
        loop {
            let attempt = self.inline_attempt(&batch.pending()).await;
            if let Some(outcomes) = batch.settle(attempt).await {
                return outcomes;
            }
        }
    }
    async fn inline_attempt(&self, uploads: &[&InlineUpload]) -> Attempt<UploadResults> {
        let frames = match inline_frames(uploads) {
            Ok(frames) => frames,
            Err(error) => return Attempt::Fatal(error),
        };
        let length: usize = frames.iter().map(bytes::Bytes::len).sum();
        let body = reqwest::Body::wrap_stream(futures_util::stream::iter(
            frames.into_iter().map(Ok::<_, std::io::Error>),
        ));
        let result = self
            .api(Method::POST, &self.prepare_only(routes::INLINE_BATCH))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, length)
            .body(body)
            .send()
            .await;
        classify("inline upload", Replay::Idempotent, true, result)
            .json("inline upload", Replay::Idempotent)
            .await
    }
    pub async fn abort(&self, id: &str) -> Result<()> {
        let path = routes::abort(&segment(id)?);
        status_ok(
            "abort",
            self.request("abort", Method::POST, &path, Some(body(&Empty {})?))
                .await?,
            true,
        )?;
        Ok(())
    }
    /// Grants charge exact immutable lengths. Retry only transiently rejected
    /// sessions, preserving every successful grant and its original caller.
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn reserve_parts(
        &self,
        requests: &[PartReservation],
    ) -> Result<Vec<std::result::Result<PartGrant, String>>> {
        if requests.is_empty() || requests.len() > limits::BATCH_MAX {
            bail!("invalid part reservations");
        }
        let mut groups: Vec<(&str, Vec<(usize, &PartReservation)>)> = Vec::new();
        for (index, request) in requests.iter().enumerate() {
            if !(1..=limits::MAX_PARTS).contains(&request.part_number) || request.size == 0 {
                bail!("invalid part reservation");
            }
            if let Some((_, parts)) = groups.iter_mut().find(|(id, _)| *id == request.session_id) {
                if parts
                    .iter()
                    .any(|(_, p)| p.part_number == request.part_number)
                {
                    bail!("duplicate part reservation");
                }
                parts.push((index, request));
            } else {
                groups.push((&request.session_id, vec![(index, request)]));
            }
        }
        let mut pending: Vec<_> = groups.iter().collect();
        let mut results: Vec<_> = std::iter::repeat_with(|| None)
            .take(requests.len())
            .collect();
        let mut budget = Budget::new();
        loop {
            let request: ReservePartsBatch = ReservePartsBatch {
                uploads: pending
                    .iter()
                    .map(|(id, parts)| SessionParts {
                        session_id: (*id).to_owned(),
                        parts: parts
                            .iter()
                            .map(|(_, p)| PartRequest {
                                part_number: p.part_number,
                                size: p.size as u64,
                            })
                            .collect(),
                    })
                    .collect(),
            };
            let after = match self
                .post::<ReservationResults>(
                    "reserve parts",
                    Replay::Idempotent,
                    routes::UPLOAD_PARTS,
                    &request,
                )
                .await
            {
                Attempt::Fatal(error) => return Err(error),
                Attempt::Retry { after } => after,
                Attempt::Done(data) => {
                    if data.results.len() != pending.len()
                        || data
                            .results
                            .iter()
                            .zip(&pending)
                            .any(|(row, (id, _))| row.session_id != *id)
                    {
                        bail!("reserve parts: response count or order differs from request");
                    }
                    let mut retry = Vec::new();
                    for (group, row) in pending.into_iter().zip(data.results) {
                        if let Some(parts) = row.parts {
                            if row.status.is_some()
                                || parts.len() != group.1.len()
                                || parts.iter().zip(&group.1).any(|(part, (_, request))| {
                                    part.part_number != request.part_number
                                })
                            {
                                bail!("reserve parts: invalid part instructions");
                            }
                            for (part, (index, _)) in parts.into_iter().zip(&group.1) {
                                results[*index] = Some(Ok(part));
                            }
                        } else {
                            let status = row
                                .status
                                .ok_or_else(|| anyhow!("reserve parts: invalid result"))?;
                            if transient(status) {
                                retry.push(group);
                            } else {
                                for (index, _) in &group.1 {
                                    results[*index] =
                                        Some(Err(
                                            HttpError::new("reserve parts", status).to_string()
                                        ));
                                }
                            }
                        }
                    }
                    pending = retry;
                    if pending.is_empty() {
                        break;
                    }
                    None
                }
            };
            if !budget.wait(after).await {
                for (_, parts) in pending {
                    for (index, _) in parts {
                        results[*index] = Some(Err(exhausted("reserve parts").to_string()));
                    }
                }
                break;
            }
        }
        results
            .into_iter()
            .map(|result| result.ok_or_else(|| anyhow!("reserve parts: missing result")))
            .collect()
    }
    /// Send only the headers supplied with this grant. Retries retain the same
    /// immutable allocation, never copying the body or adding API credentials.
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    pub async fn upload_part(
        &self,
        id: &str,
        part: PartGrant,
        bytes: bytes::Bytes,
    ) -> Result<ReceiptPart> {
        let progress = self.progress.as_ref().and_then(|p| p.path(id));
        if !(1..=limits::MAX_PARTS).contains(&part.part_number) || bytes.is_empty() {
            bail!("invalid upload part");
        }
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
        // Not a granted header: the server stays free to retire old clients
        // on this route too. reqwest adds the User-Agent itself.
        headers.insert(
            protocol::PROTOCOL_VERSION_HEADER,
            header::HeaderValue::from(protocol::PROTOCOL_VERSION),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_str(&bytes.len().to_string())?,
        );
        let mut budget = Budget::new();
        loop {
            let result = self
                .http
                .put(url.clone())
                .headers(headers.clone())
                .body(reqwest::Body::from(bytes.clone()))
                .send()
                .await;
            match &result {
                Ok(response) => tracing::debug!(
                    status = response.status().as_u16(),
                    attempt = budget.attempt,
                    "part PUT response"
                ),
                Err(_) => tracing::debug!(attempt = budget.attempt, "part PUT transport failed"),
            }
            let attempt = classify("part upload", Replay::Idempotent, false, result);
            if matches!(attempt, Attempt::Retry { .. })
                && budget.attempt < ATTEMPTS
                && let Some(progress) = &progress
            {
                progress.retry_part(part.part_number, budget.attempt + 1, ATTEMPTS);
            }
            if let Some(response) = budget.settle("part upload", attempt).await? {
                let etag = response
                    .headers()
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| anyhow!("part upload returned no ETag"))?
                    .to_owned();
                if let Some(progress) = &progress {
                    progress.part_uploaded(part.part_number, bytes.len() as u64);
                }
                return Ok(ReceiptPart {
                    part_number: part.part_number,
                    etag,
                });
            }
        }
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
    pub fn for_job(&self, id: &str) -> Result<Self> {
        let mut client = self.clone();
        client.push_job = Some(segment(id)?);
        Ok(client)
    }

    pub fn prepares_only(&self) -> bool {
        self.push_job.is_some()
    }
}
pub(crate) fn segment(value: &str) -> Result<String> {
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
    use serde_json::json;
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
        socket.write_all(format!("HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSnowstead-Protocol-Version: {}\r\nSnowstead-Min-Protocol-Version: {}\r\n{extra}\r\n{body}", body.len(), protocol::PROTOCOL_VERSION, protocol::MIN_PROTOCOL_VERSION).as_bytes()).await.unwrap();
    }
    async fn upload_one(client: &Client, bytes: bytes::Bytes) -> Result<ReceiptPart> {
        let part = client
            .reserve_parts(&[PartReservation {
                session_id: "s1".into(),
                part_number: 1,
                size: bytes.len(),
            }])
            .await?
            .remove(0)
            .map_err(anyhow::Error::msg)?;
        client.upload_part("s1", part, bytes).await
    }
    #[tokio::test]
    async fn inline_retries_share_four_attempts_and_reject_wrong_identity_and_permanent_errors() {
        let scenarios = vec![
            vec![
                (0, Value::Null),
                (503, Value::Null),
                (200, json!({"sessionId":"s1","status":503})),
                (200, json!({"sessionId":"s1","published":true})),
            ],
            vec![(429, Value::Null); 4],
            vec![(200, json!({"sessionId":"s1","status":503})); 4],
            vec![(200, json!({"sessionId":"other","published":true}))],
            vec![(403, json!({"error":"private secret-token"}))],
            vec![(
                200,
                json!({"sessionId":"s1","status":400,"error":"private secret-token"}),
            )],
        ];
        futures_util::future::join_all(scenarios.into_iter().enumerate().map(
            |(index, responses)| async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let server = tokio::spawn(async move {
                    for (status, response) in responses {
                        let (mut socket, _) =
                            tokio::time::timeout(Duration::from_secs(10), listener.accept())
                                .await
                                .unwrap()
                                .unwrap();
                        let (headers, body) = read(&mut socket).await;
                        assert!(headers.starts_with("POST /_api/v1/uploads/inline/batch "));
                        assert!(
                            headers
                                .to_ascii_lowercase()
                                .contains("content-type: application/octet-stream")
                        );
                        let frames = inline_frames(&[&inline_upload("s1", b"abcdef")]).unwrap();
                        assert_eq!(body, frames.concat());
                        assert!(
                            headers
                                .to_ascii_lowercase()
                                .contains(&format!("content-length: {}", body.len()))
                        );
                        if status != 0 {
                            reply(
                                &mut socket,
                                status,
                                &json!({"results":[response]}).to_string(),
                                "",
                            )
                            .await;
                        }
                    }
                });
                let result = client(&url)
                    .inline_batch(&[inline_upload("s1", b"abcdef")])
                    .await;
                match index {
                    0 => assert_eq!(result.unwrap(), [RowOutcome::Published]),
                    5 => assert_eq!(result.unwrap(), [RowOutcome::Rejected { status: 400 }]),
                    _ => {
                        let error = result.unwrap_err().to_string();
                        assert!(
                            !error.contains("private")
                                && !error.contains("secret-token")
                                && !error.contains(&url)
                        );
                        if index == 1 || index == 2 {
                            assert!(error.contains("4 attempts"));
                        }
                    }
                }
                server.await.unwrap();
            },
        ))
        .await;
    }
    fn inline_upload(id: &str, bytes: &'static [u8]) -> InlineUpload {
        InlineUpload {
            session_id: id.into(),
            file_hash: "a".repeat(64),
            bytes: bytes::Bytes::from_static(bytes),
        }
    }
    #[tokio::test]
    async fn inline_frames_preserve_allocations_and_budget_until_last_frame_drops() {
        struct Owner(Vec<u8>, tokio::sync::OwnedSemaphorePermit);
        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                let _ = &self.1;
                &self.0
            }
        }
        let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(6));
        let mut upload = inline_upload("s1", b"unused");
        upload.bytes = bytes::Bytes::from_owner(Owner(
            b"abcdef".to_vec(),
            budget.clone().acquire_many_owned(6).await.unwrap(),
        ));
        let frames = inline_frames(&[&upload]).unwrap();
        let replay = inline_frames(&[&upload]).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].as_ptr(), upload.bytes.as_ptr());
        assert_eq!(replay[1].as_ptr(), upload.bytes.as_ptr());
        let manifest_len = u32::from_be_bytes(frames[0][..4].try_into().unwrap()) as usize;
        assert_eq!(manifest_len, frames[0].len() - 4);
        assert_eq!(
            serde_json::from_slice::<Value>(&frames[0][4..]).unwrap(),
            json!({"uploads":[{"sessionId":"s1","fileHash":"a".repeat(64),"fileSize":6}]})
        );
        drop(upload);
        drop(frames);
        assert_eq!(budget.available_permits(), 0);
        drop(replay);
        assert_eq!(budget.available_permits(), 6);
    }
    #[tokio::test]
    async fn inline_batch_replays_lost_ack_then_only_transient_items_in_original_order() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = client(&format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let mut bodies = Vec::new();
            for step in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (headers, body) = read(&mut socket).await;
                assert!(headers.starts_with("POST /_api/v1/uploads/inline/batch "));
                bodies.push(body);
                match step {
                    0 => (), // All published bytes may have arrived; acknowledgement lost.
                    1 => {
                        reply(
                            &mut socket,
                            200,
                            &json!({"results":[
                                {"sessionId":"ok","published":true},
                                {"sessionId":"busy","status":503},
                                {"sessionId":"bad","status":400},
                                {"sessionId":"denied","status":403},
                                {"sessionId":"full","status":507}
                            ]})
                            .to_string(),
                            "",
                        )
                        .await
                    }
                    2 => reply(&mut socket, 503, "private", "").await,
                    _ => {
                        reply(
                            &mut socket,
                            200,
                            r#"{"results":[{"sessionId":"busy","published":true}]}"#,
                            "",
                        )
                        .await
                    }
                }
            }
            bodies
        });
        let uploads: Vec<_> = ["ok", "busy", "bad", "denied", "full"]
            .into_iter()
            .map(|id| inline_upload(id, b"abcdef"))
            .collect();
        let results = client.inline_batch(&uploads).await.unwrap();
        assert_eq!(
            results,
            [
                RowOutcome::Published,
                RowOutcome::Published,
                RowOutcome::Rejected { status: 400 },
                RowOutcome::Rejected { status: 403 },
                RowOutcome::Rejected { status: 507 },
            ]
        );
        let bodies = server.await.unwrap();
        assert_eq!(
            bodies[0],
            inline_frames(&uploads.iter().collect::<Vec<_>>())
                .unwrap()
                .concat()
        );
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[2], inline_frames(&[&uploads[1]]).unwrap().concat());
        assert_eq!(bodies[2], bodies[3]);
    }
    #[tokio::test]
    async fn inline_batch_rejects_missing_extra_reordered_and_mismatched_results() {
        for ids in [
            vec!["s1"],
            vec!["s1", "s2", "s3"],
            vec!["s2", "s1"],
            vec!["s1", "wrong"],
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = client(&format!("http://{}", listener.local_addr().unwrap()));
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                read(&mut socket).await;
                reply(&mut socket, 200, &json!({"results": ids.into_iter().map(|id| json!({"sessionId":id,"published":true})).collect::<Vec<_>>()} ).to_string(), "").await;
            });
            let error = client
                .inline_batch(&[inline_upload("s1", b"a"), inline_upload("s2", b"bc")])
                .await
                .unwrap_err();
            assert!(error.to_string().contains("response count or order"));
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn inline_batch_validates_bounds_before_sending() {
        let client = client("http://127.0.0.1:1");
        for uploads in [
            vec![],
            (0..9)
                .map(|id| inline_upload(&format!("s{id}"), b"a"))
                .collect(),
            vec![inline_upload("s1", b"")],
            vec![inline_upload("s1", b"a"), inline_upload("s1", b"b")],
        ] {
            assert!(
                client
                    .inline_batch(&uploads)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("invalid")
            );
        }
        let mut upload = inline_upload("s1", b"a");
        upload.bytes = bytes::Bytes::from(vec![0; 1024 * 1024 + 1]);
        assert!(
            client
                .inline_batch(&[upload])
                .await
                .unwrap_err()
                .to_string()
                .contains("invalid")
        );
        let upload = inline_upload(&"s".repeat(16 * 1024), b"a");
        assert!(
            client
                .inline_batch(&[upload])
                .await
                .unwrap_err()
                .to_string()
                .contains("manifest exceeds")
        );
    }
    #[tokio::test]
    async fn inline_batcher_sends_full_batches_and_flushes_the_tail() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = client(&format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let mut sizes = Vec::new();
            let mut received = 0;
            while received < 19 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (headers, body) = read(&mut socket).await;
                assert!(headers.starts_with("POST /_api/v1/uploads/inline/batch "));
                assert!(!headers.to_ascii_lowercase().contains("transfer-encoding"));
                let length = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
                let manifest: Value = serde_json::from_slice(&body[4..4 + length]).unwrap();
                let uploads = manifest["uploads"].as_array().unwrap();
                sizes.push(uploads.len());
                received += uploads.len();
                let mut offset = 4 + length;
                for upload in uploads {
                    let size = upload["fileSize"].as_u64().unwrap() as usize;
                    assert_eq!(&body[offset..offset + size], b"abcdef");
                    offset += size;
                }
                assert_eq!(offset, body.len());
                reply(&mut socket, 200, &json!({"results":uploads.iter().map(|upload| json!({"sessionId":upload["sessionId"],"published":true})).collect::<Vec<_>>()} ).to_string(), "").await;
            }
            sizes
        });
        let batch = crate::batch::Batcher::new(8, 3, Duration::from_millis(10), move |uploads| {
            let client = client.clone();
            async move { client.inline_batch(&uploads).await }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            let results = futures_util::future::join_all(
                (0..19).map(|index| batch.request(inline_upload(&format!("s{index}"), b"abcdef"))),
            )
            .await;
            for row in results {
                assert_eq!(row.unwrap(), RowOutcome::Published);
            }
            assert_eq!(server.await.unwrap(), [8, 8, 3]);
        })
        .await
        .expect("full batches and an independent tail must make progress");
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
                            r#"{"sessions":[{"sessionId":"s1","partSize":8388608,"inline":false}]}"#,
                            "",
                        )
                        .await;
                    } else if step <= 2 {
                        assert!(headers.starts_with("POST /_api/v1/uploads/parts "));
                        assert_eq!(
                            serde_json::from_slice::<Value>(&body).unwrap(),
                            json!({"uploads":[{"sessionId":"s1","parts":[{"partNumber":1,"size":6}]}]})
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
                        reply(&mut socket, 200, &json!({"results":[{"sessionId":"s1","parts":[{"partNumber":1,"url":format!("{origin}/signed?private-signature"),"headers":supplied}]}]}).to_string(), "").await;
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
                        // The CLI names its protocol on part PUTs too, outside the grant.
                        let lower = headers.to_lowercase();
                        assert!(lower.contains(&format!(
                            "snowstead-protocol-version: {}\r\n",
                            protocol::PROTOCOL_VERSION
                        )));
                        assert!(lower.contains("user-agent: snowstead-cli/"));
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
                    &[PathInput {
                        store_path: "/nix/store/hash-name".into(),
                        store_path_hash: "hash".into(),
                        nar_hash: "sha256:nar".into(),
                        nar_size: 42,
                        compression: "zstd".into(),
                        references: Some(vec![]),
                        deriver: None,
                        inline: false,
                    }],
                )
                .await
                .unwrap();
            assert_eq!(sessions[0].part_size, 8388608);
            let part = upload_one(&client, bytes::Bytes::from_static(b"abcdef"))
                .await
                .unwrap();
            assert_eq!(
                client
                    .finalize(&[Receipt {
                        session_id: "s1".into(),
                        nar_hash: "sha256:nar".into(),
                        nar_size: 42,
                        file_hash: "hash".into(),
                        file_size: 6,
                        parts: vec![part]
                    }])
                    .await
                    .unwrap(),
                [RowOutcome::Published]
            );
            client.abort("s1").await.unwrap();
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn missing_etag_and_redirect_fail_without_leaking_credentials() {
        for status in [200, 307, 401, 403] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let origin = url.clone();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                read(&mut socket).await;
                reply(&mut socket, 200, &json!({"results":[{"sessionId":"s1","parts":[{"partNumber":1,"url":format!("{origin}/private-signature"),"headers":{}}]}]}).to_string(), "").await;
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
            let error = upload_one(&client(&url), bytes::Bytes::from_static(b"abc"))
                .await
                .unwrap_err();
            let text = format!("{error:#}");
            for secret in ["private", "secret-token", &url] {
                assert!(!text.contains(secret));
            }
            if matches!(status, 401 | 403) {
                assert!(text.contains("Retry the push"), "{text}");
                assert!(!text.contains("snowstead login"), "{text}");
            }
            server.await.unwrap();
        }
    }
    fn upload(id: &str) -> Receipt {
        Receipt {
            session_id: id.into(),
            nar_hash: "sha256:nar".into(),
            nar_size: 42,
            file_hash: "hash".into(),
            file_size: 6,
            parts: vec![ReceiptPart {
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
                let request: Value = serde_json::from_slice(&body).unwrap();
                if request.get("sessions").is_some() {
                    assert!(headers.starts_with("POST /_api/v1/uploads/status "));
                }
                requests.push(request);
                if status != 0 {
                    reply(&mut socket, status, &response.to_string(), "").await;
                }
            }
            requests
        });
        (client(&url), task)
    }
    #[tokio::test]
    async fn reservations_group_parts_and_retry_only_busy_sessions_without_losing_grants() {
        let grant =
            |number| json!({"partNumber":number,"url":"https://example.com/signed","headers":{}});
        let (client, server) = scripted(vec![
            (0, Value::Null),
            (
                200,
                json!({"results":[
                    {"sessionId":"a","parts":[grant(2),grant(1)]},
                    {"sessionId":"b","status":503,"error":"private busy"},
                    {"sessionId":"c","status":403,"error":"secret-token"}
                ]}),
            ),
            (503, Value::Null),
            (
                200,
                json!({"results":[{"sessionId":"b","parts":[grant(3)]}]}),
            ),
        ])
        .await;
        let requests: Vec<_> = [("a", 2, 9), ("b", 3, 7), ("a", 1, 5), ("c", 1, 3)]
            .into_iter()
            .map(|(id, number, size)| PartReservation {
                session_id: id.into(),
                part_number: number,
                size,
            })
            .collect();
        let mut results = client.reserve_parts(&requests).await.unwrap().into_iter();
        assert_eq!(results.next().unwrap().ok().unwrap().part_number, 2);
        assert_eq!(results.next().unwrap().ok().unwrap().part_number, 3);
        assert_eq!(results.next().unwrap().ok().unwrap().part_number, 1);
        let denied = results.next().unwrap().err().unwrap();
        assert!(denied.contains("403") && !denied.contains("secret-token"));
        let bodies = server.await.unwrap();
        assert_eq!(
            bodies[0],
            json!({"uploads":[
                {"sessionId":"a","parts":[{"partNumber":2,"size":9},{"partNumber":1,"size":5}]},
                {"sessionId":"b","parts":[{"partNumber":3,"size":7}]},
                {"sessionId":"c","parts":[{"partNumber":1,"size":3}]}
            ]})
        );
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(
            bodies[2],
            json!({"uploads":[{"sessionId":"b","parts":[{"partNumber":3,"size":7}]}]})
        );
        assert_eq!(bodies[2], bodies[3]);
    }
    #[tokio::test]
    async fn reservations_reject_mismatched_sessions_or_parts_without_retry() {
        for rows in [
            json!([]),
            json!([{"sessionId":"other","parts":[]}]),
            json!([{"sessionId":"s1","parts":[]}]),
            json!([{"sessionId":"s1","parts":[{"partNumber":2,"url":"https://example.com","headers":{}}]}]),
        ] {
            let (client, server) = scripted(vec![(200, json!({"results":rows}))]).await;
            assert!(
                client
                    .reserve_parts(&[PartReservation {
                        session_id: "s1".into(),
                        part_number: 1,
                        size: 9
                    }])
                    .await
                    .is_err()
            );
            assert_eq!(server.await.unwrap().len(), 1);
        }
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
            results,
            [
                RowOutcome::Published,
                RowOutcome::Published,
                RowOutcome::Rejected { status: 400 },
                RowOutcome::Rejected { status: 403 },
                RowOutcome::Rejected { status: 507 },
            ]
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
    async fn accepted_finalizations_poll_beyond_retry_budget_without_resubmitting_receipts() {
        for prepares in [false, true] {
            let pending = json!({"sessionId":"slow","status":202,"stage":"verifying"});
            let mut responses = vec![(
                202,
                json!({"results":[
                    {"sessionId":"fast","published":true}, pending.clone(),
                    {"sessionId":"bad","status":400}
                ]}),
            )];
            // Healthy progress is not a transport retry, even beyond four polls.
            responses.extend((0..5).map(|_| (200, json!({"results":[pending.clone()]}))));
            responses.push((0, Value::Null)); // A lost status read never replays finalize.
            responses.push((
                200,
                json!({"results":[if prepares {
                    json!({"sessionId":"slow","status":202,"prepared":true})
                } else {
                    json!({"sessionId":"slow","published":true})
                }]}),
            ));
            let (mut client, server) = scripted(responses).await;
            if prepares {
                client.push_job = Some("job".into());
            }
            let uploads = [upload("fast"), upload("slow"), upload("bad")];
            let outcomes = client.finalize(&uploads).await.unwrap();
            assert_eq!(
                outcomes,
                [
                    RowOutcome::Published,
                    if prepares {
                        RowOutcome::Prepared
                    } else {
                        RowOutcome::Published
                    },
                    RowOutcome::Rejected { status: 400 }
                ]
            );
            let requests = server.await.unwrap();
            assert_eq!(requests[0], json!({"uploads":uploads}));
            assert!(
                requests[1..]
                    .iter()
                    .all(|r| *r == json!({"sessions":["slow"]}))
            );
        }
    }

    #[tokio::test]
    async fn failed_admissions_do_not_exhaust_already_accepted_finalizations() {
        let pending = json!({"sessionId":"accepted","status":202,"stage":"queued"});
        let busy = json!({"sessionId":"busy","status":503});
        let (client, server) = scripted(vec![
            (202, json!({"results":[pending,busy.clone()]})),
            (200, json!({"results":[busy.clone()]})),
            (200, json!({"results":[busy.clone()]})),
            (200, json!({"results":[busy]})),
            (
                200,
                json!({"results":[{"sessionId":"accepted","published":true}]}),
            ),
        ])
        .await;
        let outcomes = client
            .finalize(&[upload("accepted"), upload("busy")])
            .await
            .unwrap();
        assert_eq!(
            outcomes,
            [RowOutcome::Published, RowOutcome::TransientExhausted]
        );
        let requests = server.await.unwrap();
        assert_eq!(requests[4], json!({"sessions":["accepted"]}));
    }

    #[tokio::test]
    async fn post_retries_are_bounded_and_ambiguous_creation_is_not_replayed() {
        let mut scenarios = vec![
            ("reserve", vec![429, 502, 503, 504]),
            ("finalize", vec![429, 502, 503, 504]),
            ("busy", vec![200; 4]),
            ("create", vec![503; 4]),
            ("create", vec![0]),
            ("create", vec![502]),
            ("create", vec![504]),
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
                "reserve" => upload_one(&client, bytes::Bytes::from_static(b"abcdef")).await.unwrap_err(),
                "finalize" => client.finalize(&[upload("s1")]).await.unwrap_err(),
                "busy" => client.finalize(&[upload("s1")]).await.unwrap_err(),
                _ => client.create_sessions("main", &[]).await.err().unwrap(),
            };
            let text = format!("{error:#}");
            assert!(!text.contains("private") && !text.contains("secret-token"));
            if count == 4 { assert!(text.contains("4 attempts")); }
            assert_eq!(server.await.unwrap().len(), count);
        })).await;
    }

    #[tokio::test]
    async fn creation_retries_busy_without_replaying_an_unknown_commit() {
        let (client, server) = scripted(vec![
            (503, json!({"error":"Concurrent write; retry"})),
            (
                201,
                json!({"sessions":[{"sessionId":"created","partSize":8388608,"inline":false}]}),
            ),
        ])
        .await;
        let sessions = client.create_sessions("main", &[]).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "created");
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
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
    #[tokio::test]
    async fn resolved_rows_survive_later_exhaustion_and_fatal_errors() {
        // (later responses, outcome of the row left pending by the first reply)
        for (later, fatal) in [(vec![503, 0, 429], false), (vec![403], true)] {
            let first = json!({"results":[
                {"sessionId":"done","published":true},
                {"sessionId":"busy","status":503},
                {"sessionId":"bad","status":400}
            ]});
            let rest = json!({"error":"private secret-token"});
            let responses: Vec<_> = std::iter::once((200, first))
                .chain(later.iter().map(|status| (*status, rest.clone())))
                .collect();

            let (client, server) = scripted(responses.clone()).await;
            let uploads: Vec<_> = ["done", "busy", "bad"].into_iter().map(upload).collect();
            let finalized = client.finalize(&uploads).await.unwrap();
            let requests = server.await.unwrap();
            assert_eq!(requests[1], json!({"uploads":[uploads[1]]}));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = self::client(&format!("http://{}", listener.local_addr().unwrap()));
            let server = tokio::spawn(async move {
                for (status, response) in responses {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    read(&mut socket).await;
                    if status != 0 {
                        reply(&mut socket, status, &response.to_string(), "").await;
                    }
                }
            });
            let uploads: Vec<_> = ["done", "busy", "bad"]
                .into_iter()
                .map(|id| inline_upload(id, b"abcdef"))
                .collect();
            let inlined = client.inline_batch(&uploads).await.unwrap();
            server.await.unwrap();

            for outcomes in [finalized, inlined] {
                assert_eq!(outcomes[0], RowOutcome::Published);
                assert_eq!(outcomes[2], RowOutcome::Rejected { status: 400 });
                match &outcomes[1] {
                    RowOutcome::TransientExhausted => assert!(!fatal),
                    RowOutcome::Failed(message) => {
                        assert!(fatal && message.contains("403"));
                        assert!(!message.contains("private") && !message.contains("secret-token"));
                    }
                    other => panic!("unexpected outcome {other:?}"),
                }
            }
        }
    }
    #[tokio::test]
    async fn missing_paths_retry_transient_failures_and_lost_responses() {
        let (client, server) = scripted(vec![
            (503, json!({"error":"Database busy; retry"})),
            (0, Value::Null),
            (200, json!({"missing":["a"]})),
        ])
        .await;
        let missing = client.missing("main", &["a".into()]).await.unwrap();
        assert_eq!(missing.missing, ["a"]);
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0], requests[2]);

        let (client, server) = scripted(vec![(503, Value::Null); 4]).await;
        let error = client.missing("main", &[]).await.unwrap_err();
        assert!(error.to_string().contains("4 attempts"));
        assert_eq!(server.await.unwrap().len(), 4);
        let (client, server) = scripted(vec![(403, json!({"error":"secret-token"}))]).await;
        let error = client.missing("main", &[]).await.unwrap_err();
        assert_eq!(error.downcast_ref::<HttpError>().unwrap().status, 403);
        assert_eq!(server.await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn retry_after_is_honored_and_capped() {
        let headers = |value: &'static str| {
            let mut headers = header::HeaderMap::new();
            headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static(value));
            headers
        };
        assert_eq!(retry_after(&headers("2")), Some(Duration::from_secs(2)));
        assert_eq!(retry_after(&headers("3600")), Some(RETRY_AFTER_CAP));
        assert_eq!(retry_after(&headers("Wed, 21 Oct 2015 07:28:00 GMT")), None);
        assert_eq!(retry_after(&header::HeaderMap::new()), None);

        // Ordinary backoff after a first attempt is at most 0.75 s.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = client(&format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let mut times = Vec::new();
            for step in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                read(&mut socket).await;
                times.push(Instant::now());
                if step == 0 {
                    reply(&mut socket, 503, "{}", "Retry-After: 1\r\n").await;
                } else {
                    reply(&mut socket, 200, r#"{"missing":[]}"#, "").await;
                }
            }
            times
        });
        client.missing("main", &[]).await.unwrap();
        let times = server.await.unwrap();
        assert!(times[1].duration_since(times[0]) >= Duration::from_secs(1));
    }
    #[tokio::test]
    async fn requests_name_the_cli_and_protocol_and_refuse_incompatible_servers() {
        // (advertised range, status, what the CLI should say)
        for (range, status, expected) in [
            ("", 200, Some("server is too old")),
            (
                "Snowstead-Protocol-Version: 1\r\nSnowstead-Min-Protocol-Version: 1\r\n",
                200,
                Some("server is too old"),
            ),
            (
                "Snowstead-Protocol-Version: 2\r\nSnowstead-Min-Protocol-Version: 2\r\n",
                200,
                None,
            ),
            (
                "Snowstead-Protocol-Version: 9\r\nSnowstead-Min-Protocol-Version: 9\r\n",
                400,
                Some("Upgrade the Snowstead CLI"),
            ),
            (
                "Snowstead-Protocol-Version: 0\r\nSnowstead-Min-Protocol-Version: 0\r\n",
                400,
                Some("server is too old"),
            ),
        ] {
            let (client, server) = {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let client = client(&format!("http://{}", listener.local_addr().unwrap()));
                let server = tokio::spawn(async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let (headers, _) = read(&mut socket).await;
                    let body = r#"{"missing":[]}"#;
                    socket.write_all(format!("HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\n{range}\r\n{body}",body.len()).as_bytes()).await.unwrap();
                    headers.to_ascii_lowercase()
                });
                (client, server)
            };
            let result = client.missing("main", &[]).await;
            let headers = server.await.unwrap();
            assert!(
                headers.contains(&format!(
                    "user-agent: snowstead-cli/{}\r\n",
                    env!("CARGO_PKG_VERSION")
                )),
                "{headers}"
            );
            assert!(
                headers.contains(&format!(
                    "snowstead-protocol-version: {}\r\n",
                    protocol::PROTOCOL_VERSION
                )),
                "{headers}"
            );
            match expected {
                None => assert!(result.is_ok()),
                // One request only: an incompatible server is not retried.
                Some(message) => {
                    let error = format!("{:#}", result.unwrap_err());
                    assert!(error.contains(message), "{error}");
                }
            }
        }
    }
}
