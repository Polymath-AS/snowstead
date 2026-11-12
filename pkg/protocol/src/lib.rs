//! The Snowstead CLI <-> cache server wire protocol.
//!
//! Both the CLI (`apps/cli`) and the server (`workers/server`) serialize and
//! deserialize the upload, missing-path, and push-job endpoints with these
//! types, so neither side can drift from the other. The JSON they produce is
//! the JSON deployed servers and CLIs already exchange: field names, nesting,
//! and which fields are present or `null` are pinned by the golden tests at
//! the end of this file. Where the CLI and server used to disagree on a type,
//! the type here accepts everything either side sent, and says so.
//!
//! The crate depends on serde alone so both sides can link it cheaply.
use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize};

/// The protocol version this build speaks. Version 1 is the protocol deployed
/// before versioning existed, so a request without a version header is
/// treated as version 1.
pub const PROTOCOL_VERSION: u32 = 1;
/// The oldest client protocol version a server built from this crate serves.
pub const MIN_PROTOCOL_VERSION: u32 = 1;
/// Request header carrying the client's protocol version; response header
/// carrying the newest version the server speaks.
pub const PROTOCOL_VERSION_HEADER: &str = "snowstead-protocol-version";
/// Response header carrying the oldest client version the server serves.
pub const MIN_PROTOCOL_VERSION_HEADER: &str = "snowstead-min-protocol-version";
/// Product token for the CLI's `User-Agent: snowstead-cli/<version>`.
pub const CLI_PRODUCT: &str = "snowstead-cli";
/// The only NAR compression the upload protocol accepts.
pub const COMPRESSION_ZSTD: &str = "zstd";

/// Limits both sides enforce. The server rejects requests outside them; the
/// CLI checks them before sending, so it never builds a request the server
/// must refuse.
pub mod limits {
    /// Largest NAR, and largest compressed file, an inline session carries.
    /// It is also the part size the server assigns inline sessions.
    pub const INLINE_MAX_BYTES: u64 = 1024 * 1024;
    /// Most uploads in one inline batch frame.
    pub const INLINE_BATCH_MAX: usize = 8;
    /// Largest JSON manifest at the head of an inline batch frame.
    pub const INLINE_MANIFEST_MAX_BYTES: usize = 16 * 1024;
    /// Most entries in one session, part-reservation, or finalize batch.
    pub const BATCH_MAX: usize = 100;
    /// Highest multipart part number, and most parts in one receipt.
    pub const MAX_PARTS: u32 = 10_000;
    /// Most store path hashes in one missing-paths request.
    pub const MISSING_PATHS_MAX: usize = 1000;
}

/// Request paths. The `*_ROUTE` constants are the server's route templates;
/// the functions build concrete paths from already-validated path segments.
pub mod routes {
    use super::PushJobAction;

    pub const PROTOCOL: &str = "/_api/v1/protocol";
    pub const MISSING_PATHS: &str = "/_api/v1/get-missing-paths";
    pub const UPLOAD_STREAMS_ROUTE: &str = "/_api/v1/caches/{cache}/upload-streams/batch";
    pub const UPLOAD_PARTS: &str = "/_api/v1/uploads/parts";
    pub const FINALIZE: &str = "/_api/v1/uploads/finalize";
    pub const INLINE_BATCH: &str = "/_api/v1/uploads/inline/batch";
    pub const SESSION_PARTS_ROUTE: &str = "/_api/v1/uploads/{id}/parts";
    pub const PART_ROUTE: &str = "/_api/v1/uploads/{id}/part/{number}";
    pub const INLINE_ROUTE: &str = "/_api/v1/uploads/{id}/inline";
    pub const ABORT_ROUTE: &str = "/_api/v1/uploads/{id}/abort";
    pub const PUSH_JOBS_ROUTE: &str = "/_api/v1/caches/{cache}/push-jobs";
    pub const PUSH_JOB_ROUTE: &str = "/_api/v1/caches/{cache}/push-jobs/{job}";
    pub const MANIFEST_CHUNK_ROUTE: &str =
        "/_api/v1/caches/{cache}/push-jobs/{job}/manifest/{chunk}";
    pub const SEAL_ROUTE: &str = "/_api/v1/caches/{cache}/push-jobs/{job}/seal";
    pub const RESUME_ROUTE: &str = "/_api/v1/caches/{cache}/push-jobs/{job}/resume";
    pub const CANCEL_ROUTE: &str = "/_api/v1/caches/{cache}/push-jobs/{job}/cancel";
    pub const COMPLETE_ROUTE: &str = "/_api/v1/caches/{cache}/push-jobs/{job}/complete";
    /// Query asking finalize and inline uploads to prepare, not publish.
    pub const PREPARE_ONLY_QUERY: &str = "prepareOnly=true";
    /// Query asking a push job's progress for readiness without members.
    pub const SUMMARY_QUERY: &str = "summary=true";

    pub fn upload_streams(cache: &str) -> String {
        format!("/_api/v1/caches/{cache}/upload-streams/batch")
    }
    /// Where a granted part is uploaded, relative to the server's origin.
    pub fn part(session: &str, number: u32) -> String {
        format!("/_api/v1/uploads/{session}/part/{number}")
    }
    pub fn abort(session: &str) -> String {
        format!("/_api/v1/uploads/{session}/abort")
    }
    pub fn push_jobs(cache: &str) -> String {
        format!("/_api/v1/caches/{cache}/push-jobs")
    }
    pub fn push_job(cache: &str, job: &str) -> String {
        format!("{}/{job}", push_jobs(cache))
    }
    pub fn manifest_chunk(cache: &str, job: &str, ordinal: usize) -> String {
        format!("{}/manifest/{ordinal}", push_job(cache, job))
    }
    pub fn push_job_action(cache: &str, job: &str, action: PushJobAction) -> String {
        format!("{}/{}", push_job(cache, job), action.as_str())
    }
    /// One page of a push job's members, after the given store path hash.
    pub fn push_job_page(cache: &str, job: &str, after: &str) -> String {
        format!("{}?after={after}", push_job(cache, job))
    }
}

/// A named feature the server supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Push-job manifests: create, chunk, seal.
    Manifest,
    /// `?prepareOnly=true` on finalize and inline uploads for push jobs.
    PrepareOnly,
    /// Push-job completion.
    Completion,
    /// Push-job readiness summaries (`?summary=true`).
    Readiness,
    /// Batched upload streams: sessions, part reservations, finalize.
    UploadStreams,
    /// Framed inline upload batches.
    InlineBatch,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::PrepareOnly => "prepareOnly",
            Self::Completion => "completion",
            Self::Readiness => "readiness",
            Self::UploadStreams => "uploadStreams",
            Self::InlineBatch => "inlineBatch",
        }
    }
}

/// The `protocolVersion` of push-job responses. It versions the push-job
/// envelope alone and stays 1 while the server serves version-1 clients.
pub const PUSH_JOB_PROTOCOL_VERSION: u32 = 1;

/// What every push-job response advertises, and what the CLI requires before
/// it starts a resumable push.
pub const PUSH_JOB_CAPABILITIES: [Capability; 4] = [
    Capability::Manifest,
    Capability::PrepareOnly,
    Capability::Completion,
    Capability::Readiness,
];

/// Everything a server built from this crate supports.
pub const SERVER_CAPABILITIES: [Capability; 6] = [
    Capability::Manifest,
    Capability::PrepareOnly,
    Capability::Completion,
    Capability::Readiness,
    Capability::UploadStreams,
    Capability::InlineBatch,
];

/// A capability list on the wire. Kept as strings so a client tolerates
/// capabilities newer than itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capabilities(pub Vec<String>);

impl Capabilities {
    pub fn of(capabilities: &[Capability]) -> Self {
        Self(capabilities.iter().map(|c| c.as_str().to_owned()).collect())
    }
    pub fn supports(&self, capability: Capability) -> bool {
        self.0.iter().any(|c| c == capability.as_str())
    }
    pub fn supports_all(&self, capabilities: &[Capability]) -> bool {
        capabilities.iter().all(|c| self.supports(*c))
    }
}

/// `GET /_api/v1/protocol`: what the server speaks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolInfo {
    pub protocol_version: u32,
    pub min_protocol_version: u32,
    pub capabilities: Capabilities,
}

impl ProtocolInfo {
    pub fn current() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            capabilities: Capabilities::of(&SERVER_CAPABILITIES),
        }
    }
}

/// Why one side cannot serve the other's protocol version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolMismatch {
    /// The version header was not a decimal version number.
    Invalid,
    /// The client is older than the server still serves.
    ClientTooOld { client: u32, min: u32 },
    /// The client is newer than the server speaks.
    ServerTooOld { client: u32, server: u32 },
}

impl fmt::Display for ProtocolMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => write!(f, "invalid Snowstead protocol version"),
            Self::ClientTooOld { client, min } => write!(
                f,
                "this Snowstead CLI speaks protocol version {client}, but the server requires \
                 version {min} or newer. Upgrade the Snowstead CLI."
            ),
            Self::ServerTooOld { client, server } => write!(
                f,
                "this Snowstead CLI speaks protocol version {client}, but the server only \
                 supports up to version {server}: the server is too old. Use an older CLI or \
                 ask the server's operator to upgrade it."
            ),
        }
    }
}

impl std::error::Error for ProtocolMismatch {}

fn parse_version(value: &str) -> Result<u32, ProtocolMismatch> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProtocolMismatch::Invalid);
    }
    value.parse().map_err(|_| ProtocolMismatch::Invalid)
}

fn compatible(client: u32, min: u32, max: u32) -> Result<(), ProtocolMismatch> {
    if client < min {
        Err(ProtocolMismatch::ClientTooOld { client, min })
    } else if client > max {
        Err(ProtocolMismatch::ServerTooOld {
            client,
            server: max,
        })
    } else {
        Ok(())
    }
}

/// Server side: the client version a request asks for. A request without the
/// header comes from a CLI predating versioning, which speaks version 1.
pub fn client_version(header: Option<&str>) -> Result<u32, ProtocolMismatch> {
    let client = header.map_or(Ok(1), parse_version)?;
    compatible(client, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION)?;
    Ok(client)
}

/// Client side: whether a server advertising this version range (its two
/// response headers) serves this build. A server predating versioning sends
/// neither header and speaks version 1.
pub fn check_server(max: Option<&str>, min: Option<&str>) -> Result<(), ProtocolMismatch> {
    let max = max.map_or(Ok(1), parse_version)?;
    let min = min.map_or(Ok(1), parse_version)?;
    compatible(PROTOCOL_VERSION, min, max)
}

/// The JSON body of a refusal for an unsupported protocol version (HTTP 400,
/// with the version range also in the response headers).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedProtocol {
    pub error: String,
    pub protocol_version: u32,
    pub min_protocol_version: u32,
}

/// An empty JSON object, the body of abort and push-job action requests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// `POST /_api/v1/get-missing-paths`. The server validates this body by hand
/// to keep its established error messages; this is the shape it accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingPathsRequest {
    pub cache: String,
    pub store_path_hashes: Vec<String>,
}

/// Which requested store path hashes the cache lacks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingPaths {
    pub missing: Vec<String>,
    /// Served by a configured upstream cache instead.
    #[serde(default)]
    pub upstream: Vec<String>,
    /// Missing here and not yet checked against the upstreams.
    #[serde(default)]
    pub unchecked: Vec<String>,
    /// The configured upstream caches.
    #[serde(default)]
    pub upstreams: Vec<String>,
}

/// One store path to upload, or one push-job manifest member. The server
/// stores and returns this serialization, with every field written; clients
/// send the compact form deployed CLIs used (see `compact_paths`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathInput {
    pub store_path: String,
    pub store_path_hash: String,
    pub nar_hash: String,
    /// Unsigned: the CLI sent `u64`, the server read `i64` and rejects
    /// nonpositive sizes and anything over its 5 TiB object limit.
    pub nar_size: u64,
    /// Always [`COMPRESSION_ZSTD`]; the server validates it.
    pub compression: String,
    /// The CLI always sent an array; the server also accepts `null` or a
    /// missing field (no references) and normalizes stored manifests to `[]`.
    pub references: Option<Vec<String>>,
    pub deriver: Option<String>,
    /// Ask for an inline session. The CLI used to omit this unless true; the
    /// server treats a missing field as false.
    #[serde(default)]
    pub inline: bool,
}

/// How clients send [`PathInput`]s: as deployed CLIs always did, without
/// `deriver` when there is none and without `inline` unless it is true. The
/// server reads both forms alike.
fn compact_paths<S: serde::Serializer>(
    paths: &[PathInput],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Compact<'a> {
        store_path: &'a str,
        store_path_hash: &'a str,
        nar_hash: &'a str,
        nar_size: u64,
        compression: &'a str,
        references: &'a Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        deriver: &'a Option<String>,
        #[serde(skip_serializing_if = "is_false")]
        inline: bool,
    }
    serializer.collect_seq(paths.iter().map(|path| Compact {
        store_path: &path.store_path,
        store_path_hash: &path.store_path_hash,
        nar_hash: &path.nar_hash,
        nar_size: path.nar_size,
        compression: &path.compression,
        references: &path.references,
        deriver: &path.deriver,
        inline: path.inline,
    }))
}

/// `POST /_api/v1/caches/{cache}/upload-streams/batch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessions {
    #[serde(serialize_with = "compact_paths")]
    pub paths: Vec<PathInput>,
    /// Allocate the sessions for this sealed push job's members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
}

/// The status of an upload session, as `upload_sessions.status` spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Streaming,
    Finalizing,
    Completed,
    Aborted,
    Expired,
    /// Written only by the retired TypeScript service.
    #[serde(rename = "pending")]
    LegacyPending,
    /// Written only by the retired TypeScript service.
    #[serde(rename = "uploading")]
    LegacyUploading,
    /// Written only by the retired TypeScript service.
    #[serde(rename = "completing")]
    LegacyCompleting,
}

/// `{"sessions": [...]}`, in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedSessions {
    pub sessions: Vec<UploadSession>,
}

/// One allocated (or, for a push job, reused) upload session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadSession {
    pub session_id: String,
    /// Unsigned: the server stores `i32` and the CLI read `u64`.
    pub part_size: u64,
    pub inline: bool,
    /// Present only for push-job sessions.
    #[serde(flatten)]
    pub job: Option<JobSession>,
}

impl UploadSession {
    pub fn status(&self) -> Option<SessionStatus> {
        self.job.as_ref().map(|job| job.status)
    }
    /// Whether a reused push-job session's bytes are already prepared.
    pub fn prepared(&self) -> bool {
        self.retained().is_some_and(|r| r.prepared)
    }
    /// A reused, sealed multipart session's receipt, to replay.
    pub fn receipt(&self) -> Option<&Receipt> {
        self.retained().and_then(|r| r.receipt.as_ref())
    }
    fn retained(&self) -> Option<&RetainedSession> {
        self.job.as_ref().and_then(|job| job.retained.as_ref())
    }
}

/// Push-job fields of an [`UploadSession`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSession {
    pub status: SessionStatus,
    /// Always written, as `null` until the session publishes.
    pub publication_result: Option<UploadResult>,
    /// Present only when the session already existed.
    #[serde(flatten)]
    pub retained: Option<RetainedSession>,
}

/// What the server retained of an existing push-job session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedSession {
    pub prepared: bool,
    /// Written (possibly `null`) only for sealed multipart sessions.
    pub receipt: Option<Receipt>,
}

/// One part to reserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartRequest {
    /// Unsigned: the CLI sent `u32`; the server read `i32` and rejects
    /// anything outside `1..=MAX_PARTS`.
    pub part_number: u32,
    pub size: u64,
}

/// One session's parts to reserve. The server reads `parts` as raw JSON (the
/// type parameter) so one malformed entry fails only its own row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionParts<P = Vec<PartRequest>> {
    pub session_id: String,
    pub parts: P,
}

/// `POST /_api/v1/uploads/parts`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservePartsBatch<P = Vec<PartRequest>> {
    pub uploads: Vec<SessionParts<P>>,
}

/// A signed instruction to upload one part. Never log it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartGrant {
    pub part_number: u32,
    pub url: String,
    /// Send exactly these headers with the part, and no API credentials.
    pub headers: BTreeMap<String, String>,
}

impl fmt::Debug for PartGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartGrant")
            .field("part_number", &self.part_number)
            .finish_non_exhaustive()
    }
}

/// `{"parts": [...]}`: the grants for one session, in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartGrants {
    pub parts: Vec<PartGrant>,
}

/// One session's outcome in a reservation batch: grants, or an HTTP status
/// and message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReservationResult {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<PartGrant>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `{"results": [...]}`, one row per session in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationResults {
    pub results: Vec<ReservationResult>,
}

/// An uploaded part's receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptPart {
    pub part_number: u32,
    /// The part's ETag. A quoted HTTP ETag (as the CLI sends it) is read
    /// without its quotes.
    #[serde(deserialize_with = "unquote_etag")]
    pub etag: String,
}

fn unquote_etag<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    Ok(value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .map_or_else(|| value.clone(), str::to_owned))
}

/// A multipart session's receipt: what to seal and publish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub session_id: String,
    pub nar_hash: String,
    /// Unsigned: the CLI sent `u64`; the server read `i64` and rejects
    /// nonpositive sizes.
    pub nar_size: u64,
    pub file_hash: String,
    pub file_size: u64,
    pub parts: Vec<ReceiptPart>,
}

/// `POST /_api/v1/uploads/finalize`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeBatch {
    pub uploads: Vec<Receipt>,
}

/// One entry of an inline batch manifest; its bytes follow the manifest in
/// the frame, in manifest order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InlineEntry {
    pub session_id: String,
    pub file_hash: String,
    pub file_size: u64,
}

/// The JSON manifest of a framed inline batch: a big-endian `u32` manifest
/// length, the manifest, then each upload's bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineManifest {
    pub uploads: Vec<InlineEntry>,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// How one finalized or inline upload ended. A completed session stores this
/// and replays it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResult {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path_hash: Option<String>,
    #[serde(default)]
    pub published: bool,
    /// Verified and stored for a push job, which publishes it later.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prepared: bool,
    /// The cache already had the path.
    #[serde(default, skip_serializing_if = "is_false")]
    pub already_existed: bool,
    /// The HTTP status of a refused upload, or 202 for a prepared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl UploadResult {
    pub fn published(session_id: &str, store_path_hash: &str) -> Self {
        Self {
            session_id: session_id.to_owned(),
            store_path_hash: Some(store_path_hash.to_owned()),
            published: true,
            prepared: false,
            already_existed: false,
            status: None,
            error: None,
        }
    }
    pub fn prepared(session_id: &str, store_path_hash: &str) -> Self {
        Self {
            published: false,
            prepared: true,
            status: Some(202),
            ..Self::published(session_id, store_path_hash)
        }
    }
    pub fn failed(session_id: &str, status: u16, error: &str) -> Self {
        Self {
            session_id: session_id.to_owned(),
            store_path_hash: None,
            published: false,
            prepared: false,
            already_existed: false,
            status: Some(status),
            error: Some(error.to_owned()),
        }
    }
}

/// `{"results": [...]}`, one row per upload in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadResults {
    pub results: Vec<UploadResult>,
}

/// `{"aborted": true}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aborted {
    pub aborted: bool,
}

/// Whether a push job covers its roots' closures or exactly its roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushJobMode {
    Closure,
    Selected,
}

impl PushJobMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closure => "closure",
            Self::Selected => "selected",
        }
    }
}

/// `push_jobs.state`: building -> sealed -> completed, or cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushJobState {
    Building,
    Sealed,
    Completed,
    Cancelled,
}

impl PushJobState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Sealed => "sealed",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl TryFrom<&str> for PushJobState {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, String> {
        [
            Self::Building,
            Self::Sealed,
            Self::Completed,
            Self::Cancelled,
        ]
        .into_iter()
        .find(|state| state.as_str() == value)
        .ok_or_else(|| format!("unknown push job state {value:?}"))
    }
}

impl TryFrom<&str> for PushJobMode {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, String> {
        [Self::Closure, Self::Selected]
            .into_iter()
            .find(|mode| mode.as_str() == value)
            .ok_or_else(|| format!("unknown push job mode {value:?}"))
    }
}

/// The push-job operations posted to `.../push-jobs/{job}/<action>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushJobAction {
    Seal,
    Resume,
    Cancel,
    Complete,
}

impl PushJobAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Seal => "seal",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
            Self::Complete => "complete",
        }
    }
}

/// `POST /_api/v1/caches/{cache}/push-jobs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatePushJob {
    pub idempotency_key: String,
    pub mode: PushJobMode,
    pub roots: Vec<String>,
}

/// `PUT .../push-jobs/{job}/manifest/{ordinal}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestChunk {
    #[serde(serialize_with = "compact_paths")]
    pub members: Vec<PathInput>,
}

/// A push job. Times are Unix seconds; signed because the server computes
/// them in SQL as `bigint` (the CLI used to read `u64`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushJob {
    pub id: String,
    pub mode: PushJobMode,
    pub roots: Vec<String>,
    pub state: PushJobState,
    pub manifest_digest: Option<String>,
    /// When the job stops being resumable.
    pub expires_at: i64,
    pub authorization_expires_at: Option<i64>,
    // Server bookkeeping. The server always sends these; clients need not.
    #[serde(default)]
    pub revision: i32,
    #[serde(default)]
    pub manifest_bytes: i32,
    #[serde(default)]
    pub input_members: i32,
    #[serde(default)]
    pub hard_expires_at: i64,
    #[serde(default)]
    pub grant_generation: i64,
    #[serde(default)]
    pub completed_at: Option<i64>,
    #[serde(default)]
    pub protection_expires_at: Option<i64>,
}

/// The server's push-job limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushJobLimits {
    pub members: usize,
    pub chunk_members: usize,
    #[serde(default)]
    pub manifest_bytes: usize,
    pub background_publication: bool,
}

/// Every push-job response: the job, the protocol, and the limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushJobEnvelope {
    pub protocol_version: u32,
    pub capabilities: Capabilities,
    pub job: PushJob,
    /// The server always sends limits; the CLI refuses a push without them.
    pub limits: Option<PushJobLimits>,
}

/// `GET .../push-jobs/{job}`: the envelope plus one page of members. The
/// server emits members as raw JSON (`M = serde_json::Value`) so it can pass
/// a stored member it cannot type through unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushJobPage<M = PushJobMember> {
    #[serde(flatten)]
    pub envelope: PushJobEnvelope,
    /// Ordinals of the manifest chunks received so far.
    #[serde(default)]
    pub chunks: Vec<i32>,
    pub members: Vec<M>,
    /// The cursor for the next page, if any.
    pub next: Option<String>,
    /// Summary requests: whether every member is published.
    pub available: Option<bool>,
    /// Summary requests: whether publication is blocked.
    pub blocked: Option<bool>,
}

/// One manifest member and its progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushJobMember {
    #[serde(flatten)]
    pub input: PathInput,
    pub session: Option<MemberSession>,
    pub available: bool,
    /// Why publication is blocked for the current grant, if it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_error: Option<String>,
}

/// The upload session a member is using.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSession {
    /// The server always sends this; clients need not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub status: SessionStatus,
    #[serde(default)]
    pub publication_result: Option<UploadResult>,
    pub prepared: bool,
}

/// Capacity-blocked publication, as [`PushJobMember::publication_error`].
pub const CAPACITY_BLOCKED: &str = "capacity_blocked";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// The server answers through `serde_json::Value`, whose maps sort keys,
    /// so this is byte-for-byte what it sends.
    fn wire<T: Serialize>(value: &T) -> String {
        serde_json::to_value(value).unwrap().to_string()
    }

    fn round_trip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug>(
        text: &str,
    ) -> T {
        let value: T = serde_json::from_str(text).unwrap();
        assert_eq!(wire(&value), text, "wire form changed");
        assert_eq!(serde_json::from_str::<T>(&wire(&value)).unwrap(), value);
        value
    }

    fn path(inline: bool) -> PathInput {
        PathInput {
            store_path: format!("/nix/store/{}-x", "a".repeat(32)),
            store_path_hash: "a".repeat(32),
            nar_hash: "sha256:nar".into(),
            nar_size: 42,
            compression: COMPRESSION_ZSTD.into(),
            references: Some(vec![]),
            deriver: None,
            inline,
        }
    }

    #[test]
    fn path_input_keeps_the_stored_manifest_form() {
        // Push-job manifests store and digest this exact serialization.
        assert_eq!(
            serde_json::to_string(&path(false)).unwrap(),
            format!(
                r#"{{"storePath":"/nix/store/{0}-x","storePathHash":"{0}","narHash":"sha256:nar","narSize":42,"compression":"zstd","references":[],"deriver":null,"inline":false}}"#,
                "a".repeat(32)
            )
        );
        // What deployed CLIs send: no deriver or inline when absent.
        let sent: PathInput = serde_json::from_value(json!({
            "storePath":"/nix/store/p","storePathHash":"h","narHash":"sha256:n","narSize":1,
            "compression":"zstd","references":["r"]}))
        .unwrap();
        assert_eq!((sent.deriver, sent.inline), (None, false));
        // What the server accepted: null or missing references.
        let body = json!({"storePath":"p","storePathHash":"h","narHash":"n","narSize":1,
            "compression":"zstd","deriver":"d.drv","inline":true});
        let mut null = body.clone();
        null["references"] = Value::Null;
        for body in [body, null] {
            let read: PathInput = serde_json::from_value(body).unwrap();
            assert_eq!(read.references, None);
            assert!(read.inline);
        }
        assert!(
            serde_json::from_value::<PathInput>(json!({"storePath":"p","storePathHash":"h",
            "narHash":"n","narSize":-1,"compression":"zstd"}))
            .is_err()
        );
    }

    #[test]
    fn session_requests_and_responses_match_the_deployed_wire() {
        let ordinary = CreateSessions {
            paths: vec![path(true)],
            job_id: None,
        };
        let text = serde_json::to_value(&ordinary).unwrap();
        assert!(text.get("jobId").is_none());
        assert_eq!(text["paths"][0]["inline"], true);
        // Clients send the compact form deployed CLIs sent.
        let compact = ManifestChunk {
            members: vec![path(false)],
        };
        assert_eq!(
            serde_json::to_string(&compact).unwrap(),
            format!(
                r#"{{"members":[{{"storePath":"/nix/store/{0}-x","storePathHash":"{0}","narHash":"sha256:nar","narSize":42,"compression":"zstd","references":[]}}]}}"#,
                "a".repeat(32)
            )
        );
        let read: ManifestChunk =
            serde_json::from_str(&serde_json::to_string(&compact).unwrap()).unwrap();
        assert_eq!(read, compact);
        let job = CreateSessions {
            job_id: Some("job-1".into()),
            ..ordinary
        };
        assert_eq!(serde_json::to_value(&job).unwrap()["jobId"], "job-1");

        let fresh: CreatedSessions =
            round_trip(r#"{"sessions":[{"inline":false,"partSize":8388608,"sessionId":"s1"}]}"#);
        assert_eq!(fresh.sessions[0].status(), None);
        assert!(!fresh.sessions[0].prepared());
        let job_fresh: CreatedSessions = round_trip(
            r#"{"sessions":[{"inline":true,"partSize":1048576,"publicationResult":null,"sessionId":"s2","status":"streaming"}]}"#,
        );
        assert_eq!(
            job_fresh.sessions[0].status(),
            Some(SessionStatus::Streaming)
        );
        let reused: CreatedSessions = round_trip(
            r#"{"sessions":[{"inline":false,"partSize":8388608,"prepared":false,"publicationResult":null,"receipt":{"fileHash":"f","fileSize":96,"narHash":"sha256:n","narSize":128,"parts":[{"etag":"e","partNumber":1}],"sessionId":"s3"},"sessionId":"s3","status":"finalizing"},{"inline":true,"partSize":1048576,"prepared":true,"publicationResult":{"published":true,"sessionId":"s4","storePathHash":"h"},"receipt":null,"sessionId":"s4","status":"completed"}]}"#,
        );
        assert_eq!(reused.sessions[0].receipt().unwrap().file_size, 96);
        assert!(reused.sessions[1].prepared());
        assert_eq!(
            reused.sessions[1]
                .job
                .as_ref()
                .unwrap()
                .publication_result
                .as_ref()
                .unwrap(),
            &UploadResult::published("s4", "h")
        );
    }

    #[test]
    fn part_reservations_and_grants_match_the_deployed_wire() {
        let request: ReservePartsBatch = round_trip(
            r#"{"uploads":[{"parts":[{"partNumber":2,"size":9},{"partNumber":1,"size":5}],"sessionId":"a"}]}"#,
        );
        assert_eq!(request.uploads[0].parts[1].part_number, 1);
        // The server defers parsing each session's parts to its own row.
        let lenient: ReservePartsBatch<Value> =
            serde_json::from_str(r#"{"uploads":[{"sessionId":"a","parts":"bad"}]}"#).unwrap();
        assert_eq!(lenient.uploads[0].parts, "bad");
        let results: ReservationResults = round_trip(
            r#"{"results":[{"parts":[{"headers":{"authorization":"Bearer t","content-length":"9"},"partNumber":2,"url":"https://h/_api/v1/uploads/a/part/2"}],"sessionId":"a"},{"error":"Upload staging is busy; retry","sessionId":"b","status":429}]}"#,
        );
        assert!(results.results[0].status.is_none());
        assert!(!format!("{:?}", results.results[0]).contains("Bearer"));
        let single: PartGrants = round_trip(
            r#"{"parts":[{"headers":{"content-length":"1"},"partNumber":1,"url":"u"}]}"#,
        );
        assert_eq!(single.parts.len(), 1);
    }

    #[test]
    fn receipts_and_results_match_the_deployed_wire() {
        let batch: FinalizeBatch = serde_json::from_str(
            r#"{"uploads":[{"sessionId":"s1","narHash":"sha256:n","narSize":42,"fileHash":"f","fileSize":6,"parts":[{"partNumber":1,"etag":"\"part\""}]}]}"#,
        )
        .unwrap();
        assert_eq!(batch.uploads[0].parts[0].etag, "part");
        let unquoted = ReceiptPart {
            part_number: 1,
            etag: "\"quoted\"".into(),
        };
        assert_eq!(
            wire(&unquoted),
            r#"{"etag":"\"quoted\"","partNumber":1}"#,
            "the CLI sends ETags as it received them"
        );
        for (row, text) in [
            (
                UploadResult::published("s", "h"),
                r#"{"published":true,"sessionId":"s","storePathHash":"h"}"#,
            ),
            (
                UploadResult {
                    already_existed: true,
                    ..UploadResult::published("s", "h")
                },
                r#"{"alreadyExisted":true,"published":true,"sessionId":"s","storePathHash":"h"}"#,
            ),
            (
                UploadResult::prepared("s", "h"),
                r#"{"prepared":true,"published":false,"sessionId":"s","status":202,"storePathHash":"h"}"#,
            ),
            (
                UploadResult::failed("s", 503, "Installation busy"),
                r#"{"error":"Installation busy","published":false,"sessionId":"s","status":503}"#,
            ),
        ] {
            assert_eq!(wire(&row), text);
            assert_eq!(round_trip::<UploadResult>(text), row);
        }
        // Rows deployed CLIs were written against: absent flags and null errors.
        let row: UploadResult =
            serde_json::from_str(r#"{"sessionId":"s","status":503,"error":null}"#).unwrap();
        assert!(!row.published && !row.prepared && row.error.is_none());
        let manifest: InlineManifest =
            round_trip(r#"{"uploads":[{"fileHash":"aaaa","fileSize":6,"sessionId":"s1"}]}"#);
        assert_eq!(manifest.uploads[0].file_size, 6);
        round_trip::<Aborted>(r#"{"aborted":true}"#);
        assert_eq!(wire(&Empty {}), "{}");
        let missing: MissingPaths = round_trip(
            r#"{"missing":["a"],"unchecked":["a"],"upstream":["b"],"upstreams":["https://cache.nixos.org"]}"#,
        );
        assert_eq!(missing.upstream, ["b"]);
        let sparse: MissingPaths = serde_json::from_str(r#"{"missing":["a"]}"#).unwrap();
        assert!(sparse.upstreams.is_empty());
        assert_eq!(
            wire(&MissingPathsRequest {
                cache: "main".into(),
                store_path_hashes: vec!["a".into()]
            }),
            r#"{"cache":"main","storePathHashes":["a"]}"#
        );
    }

    #[test]
    fn push_jobs_match_the_deployed_wire() {
        let create = CreatePushJob {
            idempotency_key: "cli-1".into(),
            mode: PushJobMode::Selected,
            roots: vec!["/nix/store/r".into()],
        };
        assert_eq!(
            wire(&create),
            r#"{"idempotencyKey":"cli-1","mode":"selected","roots":["/nix/store/r"]}"#
        );
        assert!(
            serde_json::from_str::<CreatePushJob>(
                r#"{"idempotencyKey":"k","mode":"closure","roots":[],"extra":1}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<ManifestChunk>(r#"{"members":[],"extra":1}"#).is_err());
        let envelope: PushJobEnvelope = round_trip(
            r#"{"capabilities":["manifest","prepareOnly","completion","readiness"],"job":{"authorizationExpiresAt":null,"completedAt":null,"expiresAt":1700001800,"grantGeneration":0,"hardExpiresAt":1700086400,"id":"job-1","inputMembers":0,"manifestBytes":42,"manifestDigest":null,"mode":"closure","protectionExpiresAt":null,"revision":0,"roots":["/nix/store/r"],"state":"building"},"limits":{"backgroundPublication":true,"chunkMembers":1000,"manifestBytes":16777216,"members":100000},"protocolVersion":1}"#,
        );
        assert!(envelope.capabilities.supports_all(&PUSH_JOB_CAPABILITIES));
        assert_eq!(
            envelope.capabilities,
            Capabilities::of(&PUSH_JOB_CAPABILITIES)
        );
        assert_eq!(envelope.job.state, PushJobState::Building);
        // What the CLI's own fixtures send: only the fields it reads.
        let sparse: PushJobEnvelope = serde_json::from_value(json!({"protocolVersion":1,
            "capabilities":["manifest","prepareOnly","completion","readiness","future"],
            "job":{"id":"job-1","state":"completed","mode":"selected","roots":[],
                "manifestDigest":"fixed","expiresAt":4_000_000_000u64,"authorizationExpiresAt":null},
            "limits":{"members":100,"chunkMembers":100,"backgroundPublication":false}}))
        .unwrap();
        assert_eq!(sparse.job.state, PushJobState::Completed);
        let page: PushJobPage = round_trip(&format!(
            r#"{{"available":null,"blocked":null,"capabilities":["manifest","prepareOnly","completion","readiness"],"chunks":[0],"job":{},"limits":{},"members":[{{"available":false,"compression":"zstd","deriver":null,"inline":false,"narHash":"sha256:n","narSize":128,"publicationError":"capacity_blocked","references":[],"session":{{"prepared":true,"publicationResult":null,"sessionId":"s1","status":"finalizing"}},"storePath":"/nix/store/h-x","storePathHash":"h"}},{{"available":true,"compression":"zstd","deriver":null,"inline":false,"narHash":"sha256:n","narSize":128,"references":[],"session":null,"storePath":"/nix/store/i-y","storePathHash":"i"}}],"next":"i","protocolVersion":1}}"#,
            wire(&envelope.job),
            wire(&envelope.limits)
        ));
        assert_eq!(
            page.members[0].publication_error.as_deref(),
            Some(CAPACITY_BLOCKED)
        );
        assert_eq!(
            page.members[0].session.as_ref().unwrap().status,
            SessionStatus::Finalizing
        );
        // The CLI's fixtures omit the session ID and publication result.
        let member: PushJobMember = serde_json::from_value(json!({"storePath":"/nix/store/h-x",
            "storePathHash":"h","narHash":"sha256:n","narSize":128,"compression":"zstd",
            "references":[],"deriver":null,"available":false,
            "session":{"status":"finalizing","prepared":true}}))
        .unwrap();
        assert!(member.session.unwrap().prepared);
    }

    #[test]
    fn states_use_their_stored_spelling() {
        for (state, text) in [
            (SessionStatus::Streaming, "streaming"),
            (SessionStatus::Finalizing, "finalizing"),
            (SessionStatus::Completed, "completed"),
            (SessionStatus::Aborted, "aborted"),
            (SessionStatus::Expired, "expired"),
            (SessionStatus::LegacyPending, "pending"),
            (SessionStatus::LegacyUploading, "uploading"),
            (SessionStatus::LegacyCompleting, "completing"),
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), text);
        }
        for state in [
            PushJobState::Building,
            PushJobState::Sealed,
            PushJobState::Completed,
            PushJobState::Cancelled,
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), state.as_str());
            assert_eq!(PushJobState::try_from(state.as_str()), Ok(state));
        }
        for mode in [PushJobMode::Closure, PushJobMode::Selected] {
            assert_eq!(serde_json::to_value(mode).unwrap(), mode.as_str());
            assert_eq!(PushJobMode::try_from(mode.as_str()), Ok(mode));
        }
        assert!(PushJobState::try_from("expired").is_err());
    }

    #[test]
    fn routes_build_the_paths_the_server_routes() {
        assert_eq!(
            routes::upload_streams("main"),
            routes::UPLOAD_STREAMS_ROUTE.replace("{cache}", "main")
        );
        assert_eq!(
            routes::abort("s1"),
            routes::ABORT_ROUTE.replace("{id}", "s1")
        );
        assert_eq!(
            routes::part("s1", 7),
            routes::PART_ROUTE
                .replace("{id}", "s1")
                .replace("{number}", "7")
        );
        let job = |route: &str| route.replace("{cache}", "main").replace("{job}", "j");
        assert_eq!(routes::push_jobs("main"), job(routes::PUSH_JOBS_ROUTE));
        assert_eq!(routes::push_job("main", "j"), job(routes::PUSH_JOB_ROUTE));
        assert_eq!(
            routes::manifest_chunk("main", "j", 3),
            job(routes::MANIFEST_CHUNK_ROUTE).replace("{chunk}", "3")
        );
        for (action, route) in [
            (PushJobAction::Seal, routes::SEAL_ROUTE),
            (PushJobAction::Resume, routes::RESUME_ROUTE),
            (PushJobAction::Cancel, routes::CANCEL_ROUTE),
            (PushJobAction::Complete, routes::COMPLETE_ROUTE),
        ] {
            assert_eq!(routes::push_job_action("main", "j", action), job(route));
        }
        assert_eq!(
            routes::push_job_page("main", "j", ""),
            "/_api/v1/caches/main/push-jobs/j?after="
        );
    }

    #[test]
    fn versions_negotiate_in_both_directions() {
        assert_eq!(client_version(None), Ok(1), "deployed CLIs send no header");
        assert_eq!(
            client_version(Some(&PROTOCOL_VERSION.to_string())),
            Ok(PROTOCOL_VERSION)
        );
        assert_eq!(
            client_version(Some("0")),
            Err(ProtocolMismatch::ClientTooOld { client: 0, min: 1 })
        );
        let newer = PROTOCOL_VERSION + 1;
        assert_eq!(
            client_version(Some(&newer.to_string())),
            Err(ProtocolMismatch::ServerTooOld {
                client: newer,
                server: PROTOCOL_VERSION
            })
        );
        for bad in ["", "v1", "-1", "1.0", "99999999999"] {
            assert_eq!(client_version(Some(bad)), Err(ProtocolMismatch::Invalid));
        }
        assert_eq!(
            check_server(None, None),
            Ok(()),
            "servers predating versions"
        );
        assert_eq!(check_server(Some("1"), Some("1")), Ok(()));
        assert!(matches!(
            check_server(Some("9"), Some("9")),
            Err(ProtocolMismatch::ClientTooOld { min: 9, .. })
        ));
        assert!(matches!(
            check_server(Some("0"), Some("0")),
            Err(ProtocolMismatch::ServerTooOld { server: 0, .. })
        ));
        let too_old = ProtocolMismatch::ClientTooOld { client: 1, min: 2 }.to_string();
        assert!(too_old.contains("Upgrade the Snowstead CLI"), "{too_old}");
        let too_new = ProtocolMismatch::ServerTooOld {
            client: 2,
            server: 1,
        }
        .to_string();
        assert!(too_new.contains("server is too old"), "{too_new}");
        assert_eq!(
            wire(&ProtocolInfo::current()),
            r#"{"capabilities":["manifest","prepareOnly","completion","readiness","uploadStreams","inlineBatch"],"minProtocolVersion":1,"protocolVersion":1}"#
        );
    }
}
