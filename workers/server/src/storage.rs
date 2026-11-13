use std::{io, sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    http::StatusCode,
};
use futures_util::{Stream, StreamExt, TryStreamExt};
use http_body_util::StreamBody;
use object_store::{
    Attribute, Attributes, ClientOptions, MultipartUpload, ObjectMeta, ObjectStore, ObjectStoreExt,
    PutMultipartOptions, PutOptions,
    aws::{AmazonS3, AmazonS3Builder},
    client::{
        HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest, HttpResponse,
        HttpResponseBody, HttpService, ReqwestConnector,
    },
    multipart::{MultipartStore, PartId},
    path::Path,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::AsyncRead,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
};
use tokio_util::io::StreamReader;

use crate::{
    config::{Config, ResourceLimits},
    error::ApiError,
};

// Equal-sized, sequential parts satisfy R2's non-final-part rule. Larger
// objects need larger parts to stay within its 10,000-part limit.
const PART_SIZE: usize = 8 * 1024 * 1024;
const MAX_OBJECT_SIZE: u64 = 5 * 1024_u64.pow(4);
// Bound aggregate application-owned part buffers, including large legal objects.
const MEMORY_UNIT: usize = 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

/// Reqwest's read timer stays armed between polls, including while verification
/// or destination uploads backpressure a GET. Time only demanded reads instead.
#[derive(Debug)]
struct StreamingConnector;

impl HttpConnector for StreamingConnector {
    fn connect(&self, options: &ClientOptions) -> object_store::Result<HttpClient> {
        let options = options
            .clone()
            .with_timeout_disabled()
            .with_read_timeout_disabled()
            .with_connect_timeout(CONNECT_TIMEOUT);
        Ok(HttpClient::new(StreamingTransport {
            inner: ReqwestConnector::default().connect(&options)?,
        }))
    }
}

#[derive(Debug)]
struct StreamingTransport {
    inner: HttpClient,
}

fn network_timeout(error: tokio::time::error::Elapsed) -> HttpError {
    HttpError::new(HttpErrorKind::Timeout, error)
}

#[async_trait::async_trait]
impl HttpService for StreamingTransport {
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        // PUT bodies are already bounded, buffered parts. Bound sending those
        // parts and waiting for headers, but never the lifetime of a GET body.
        let response = tokio::time::timeout(NETWORK_TIMEOUT, self.inner.execute(request))
            .await
            .map_err(network_timeout)??;
        let (parts, body) = response.into_parts();
        let frames = futures_util::stream::try_unfold(body, |mut body| async move {
            let frame =
                tokio::time::timeout(NETWORK_TIMEOUT, http_body_util::BodyExt::frame(&mut body))
                    .await
                    .map_err(network_timeout)?;
            frame
                .transpose()
                .map(|frame| frame.map(|frame| (frame, body)))
        });
        Ok(HttpResponse::from_parts(
            parts,
            HttpResponseBody::new(StreamBody::new(frames)),
        ))
    }
}

#[derive(Clone)]
pub struct Storage {
    public: Arc<dyn ObjectStore>,
    private: Arc<dyn ObjectStore>,
    multipart: Option<[Arc<AmazonS3>; 2]>,
    private_url: Option<reqwest::Url>,
    upload_memory: Arc<Semaphore>,
    max_part_size: usize,
}

pub struct StoredObject {
    pub metadata: ObjectMeta,
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl Storage {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        config.resources.validate()?;
        for (name, value) in [
            ("R2_ENDPOINT", &config.r2_endpoint),
            ("R2_ACCESS_KEY_ID", &config.r2_access_key_id),
            ("R2_SECRET_ACCESS_KEY", &config.r2_secret_access_key),
            ("R2_BUCKET_NAME", &config.r2_bucket_name),
            ("R2_PUBLIC_BUCKET_NAME", &config.r2_public_bucket_name),
        ] {
            anyhow::ensure!(!value.trim().is_empty(), "Missing required setting {name}");
        }
        let allow_http = endpoint_allows_http(&config.r2_endpoint)?;
        let build = |bucket: &str| -> anyhow::Result<Arc<AmazonS3>> {
            // Never use from_env: explicit static credentials prevent IMDS,
            // environment, and web-identity credential discovery.
            let store = AmazonS3Builder::new()
                .with_region("auto")
                .with_endpoint(&config.r2_endpoint)
                .with_bucket_name(bucket)
                .with_access_key_id(&config.r2_access_key_id)
                .with_secret_access_key(&config.r2_secret_access_key)
                .with_virtual_hosted_style_request(false)
                .with_allow_http(allow_http)
                .with_http_connector(StreamingConnector)
                .build()
                .map_err(|_| anyhow::anyhow!("Cannot initialize R2 storage; check R2 settings"))?;
            Ok(Arc::new(store))
        };
        let public = build(&config.r2_public_bucket_name)?;
        let private = build(&config.r2_bucket_name)?;
        Ok(Self {
            public: public.clone(),
            private: private.clone(),
            multipart: Some([public, private]),
            private_url: Some(reqwest::Url::parse(&format!(
                "{}/{}/",
                config.r2_endpoint.trim_end_matches('/'),
                config.r2_bucket_name
            ))?),
            upload_memory: Arc::new(Semaphore::new(config.resources.upload_buffer_mib)),
            max_part_size: config.resources.upload_part_mib * MEMORY_UNIT,
        })
    }

    pub fn from_stores(public: Arc<dyn ObjectStore>, private: Arc<dyn ObjectStore>) -> Self {
        Self {
            public,
            private,
            multipart: None,
            private_url: None,
            upload_memory: Arc::new(Semaphore::new(ResourceLimits::default().upload_buffer_mib)),
            max_part_size: ResourceLimits::default().upload_part_mib * MEMORY_UNIT,
        }
    }

    pub(crate) fn configure_limits(&mut self, limits: &ResourceLimits) {
        self.upload_memory = Arc::new(Semaphore::new(limits.upload_buffer_mib));
        self.max_part_size = limits.upload_part_mib * MEMORY_UNIT;
    }

    /// Start a private staging upload. Only the server can complete or abort it.
    pub(crate) async fn create_multipart(&self, key: &str) -> io::Result<String> {
        let stores = self.multipart.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Multipart uploads require S3 storage",
            )
        })?;
        MultipartStore::create_multipart(&*stores[1], &object_path(key)?)
            .await
            .map_err(io_error)
    }

    pub(crate) async fn sign_part(
        &self,
        key: &str,
        upload: &str,
        number: i32,
        size: i64,
    ) -> io::Result<String> {
        let stores = self.multipart.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Multipart uploads require S3 storage",
            )
        })?;
        use aws_sigv4::{
            http_request::{
                PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation,
                SigningSettings, UriPathNormalizationMode, sign,
            },
            sign::v4,
        };
        let credentials = stores[1]
            .credentials()
            .get_credential()
            .await
            .map_err(io_error)?;
        let identity = aws_credential_types::Credentials::new(
            &credentials.key_id,
            &credentials.secret_key,
            credentials.token.clone(),
            None,
            "static R2",
        )
        .into();
        let mut url = self
            .private_url
            .clone()
            .expect("S3 storage has an endpoint");
        url.path_segments_mut()
            .map_err(|_| io::Error::other("Invalid S3 endpoint"))?
            .pop_if_empty()
            .extend(
                object_path(key)?
                    .parts()
                    .map(|part| part.as_ref().to_owned()),
            );
        url.query_pairs_mut()
            .append_pair("partNumber", &number.to_string())
            .append_pair("uploadId", upload);
        // object_store deliberately excludes Content-Length from signing. AWS's
        // signer binds it, so a grant cannot exceed its SQL staging reservation.
        let mut settings = SigningSettings::default();
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(Duration::from_secs(900));
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region("auto")
            .name("s3")
            .time(std::time::SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|_| io::Error::other("Cannot initialize upload signer"))?
            .into();
        let length = size.to_string();
        let request = SignableRequest::new(
            "PUT",
            url.as_str(),
            [("content-length", length.as_str())].into_iter(),
            SignableBody::UnsignedPayload,
        )
        .map_err(|_| io::Error::other("Cannot sign upload part"))?;
        let (instructions, _) = sign(request, &params)
            .map_err(|_| io::Error::other("Cannot sign upload part"))?
            .into_parts();
        for (name, value) in instructions.params() {
            url.query_pairs_mut().append_pair(name, value);
        }
        Ok(url.to_string())
    }

    /// A lost completion response is reconciled against the immutable staging
    /// object. The caller has already frozen the part receipts in PostgreSQL.
    pub(crate) async fn complete_multipart(
        &self,
        key: &str,
        upload: &str,
        etags: Vec<String>,
        size: u64,
    ) -> io::Result<()> {
        let stores = self.multipart.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Multipart uploads require S3 storage",
            )
        })?;
        let parts = etags
            .into_iter()
            .map(|etag| PartId {
                content_id: format!("\"{etag}\""),
            })
            .collect();
        let result = MultipartStore::complete_multipart(
            &*stores[1],
            &object_path(key)?,
            &upload.to_owned(),
            parts,
        )
        .await;
        if let Err(failure) = result {
            match self.head(true, key).await {
                Ok(object) if object.size == size => return Ok(()),
                _ => return Err(io_error(failure)),
            }
        }
        Ok(())
    }

    /// Backends without this API must retain the SQL cleanup record for retry.
    #[cfg_attr(
        feature = "observability",
        tracing::instrument(
            target = "snowstead_observability",
            skip_all,
            name = "storage.abort_multipart"
        )
    )]
    pub(crate) async fn abort_multipart(
        &self,
        private: bool,
        key: &str,
        upload: &str,
    ) -> io::Result<()> {
        let stores = self.multipart.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Persisted multipart abort is unsupported by this store",
            )
        })?;
        match MultipartStore::abort_multipart(
            &*stores[usize::from(private)],
            &object_path(key)?,
            &upload.to_owned(),
        )
        .await
        {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }

    fn store(&self, private: bool) -> &Arc<dyn ObjectStore> {
        if private { &self.private } else { &self.public }
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(target = "snowstead_observability", skip_all, name = "storage.open")
    )]
    pub async fn open(&self, private: bool, key: &str) -> io::Result<StoredObject> {
        let object = self
            .store(private)
            .get(&object_path(key)?)
            .await
            .map_err(io_error)?;
        let metadata = object.meta.clone();
        let stream = object.into_stream().map_err(io_error);
        #[cfg(any(feature = "profiling", feature = "observability"))]
        let stream = Box::pin(crate::profile_stream!(
            stream,
            label = "storage.object_body"
        ));
        let reader = Box::new(StreamReader::new(stream));
        Ok(StoredObject { metadata, reader })
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(target = "snowstead_observability", skip_all, name = "storage.head")
    )]
    pub async fn head(&self, private: bool, key: &str) -> io::Result<ObjectMeta> {
        self.store(private)
            .head(&object_path(key)?)
            .await
            .map_err(io_error)
    }

    /// S3 lists keys lexicographically; use the last key as an exclusive cursor.
    #[cfg_attr(
        feature = "observability",
        tracing::instrument(target = "snowstead_observability", skip_all, name = "storage.list")
    )]
    pub async fn list(
        &self,
        private: bool,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> io::Result<Vec<String>> {
        let prefix = object_path(prefix)?;
        let offset = after.map(object_path).transpose()?;
        let stream = match offset.as_ref() {
            Some(offset) => self.store(private).list_with_offset(Some(&prefix), offset),
            None => self.store(private).list(Some(&prefix)),
        };
        stream
            .take(limit)
            .map_ok(|object| object.location.to_string())
            .map_err(io_error)
            .try_collect()
            .await
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(target = "snowstead_observability", skip_all, name = "storage.put")
    )]
    pub async fn put(&self, private: bool, key: &str, bytes: &[u8]) -> io::Result<()> {
        let path = object_path(key)?;
        let options = PutOptions {
            attributes: attributes(key),
            ..Default::default()
        };
        // These bytes are already materialized and validated by the caller.
        // A plain PUT keeps the existing R2 ETag and metadata behavior.
        self.store(private)
            .put_opts(&path, Bytes::copy_from_slice(bytes).into(), options)
            .await
            .map(|_| ())
            .map_err(io_error)
    }

    pub async fn write_body(
        &self,
        private: bool,
        key: &str,
        body: Body,
        expected_size: u64,
    ) -> Result<String, ApiError> {
        self.upload(
            private,
            key,
            body.into_data_stream().map_err(io::Error::other),
            expected_size,
        )
        .await
        .map_err(|error| match error {
            UploadError::Size => ApiError::new(StatusCode::BAD_REQUEST, "File size mismatch"),
            UploadError::TooLarge => ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Object exceeds storage size or MAX_UPLOAD_PART_MIB limit",
            ),
            UploadError::Busy => {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Upload capacity exhausted")
            }
            UploadError::Io(_) => {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        })
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(target = "snowstead_observability", skip_all, name = "storage.upload")
    )]
    async fn upload<S>(
        &self,
        private: bool,
        key: &str,
        stream: S,
        expected_size: u64,
    ) -> Result<String, UploadError>
    where
        S: Stream<Item = io::Result<Bytes>>,
    {
        let part_size = multipart_part_size(expected_size)?;
        if part_size > self.max_part_size {
            return Err(UploadError::TooLarge);
        }
        let path = object_path(key)?;
        let options = PutMultipartOptions {
            attributes: attributes(key),
            ..Default::default()
        };
        let buffer_size = expected_size.min(part_size as u64) as usize;
        // No waiting queue, body polling, buffer allocation, or provider mutation
        // before the upload buffer memory has been reserved.
        let memory = self
            .upload_memory
            .clone()
            .try_acquire_many_owned(buffer_size.div_ceil(MEMORY_UNIT) as u32)
            .map_err(|_| UploadError::Busy)?;
        let stream = crate::profile_stream!(stream, label = "storage.upload_body");
        futures_util::pin_mut!(stream);
        if expected_size < PART_SIZE as u64 {
            let mut buffer = Vec::with_capacity(buffer_size);
            let mut hash = Sha256::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if chunk.len() as u64 > expected_size - buffer.len() as u64 {
                    return Err(UploadError::Size);
                }
                crate::profile_block!("storage.upload_hash", hash.update(&chunk));
                buffer.extend_from_slice(&chunk);
            }
            if buffer.len() as u64 != expected_size {
                return Err(UploadError::Size);
            }
            let store = self.store(private).clone();
            // A dispatched PUT can outlive its caller. Its task owns both the
            // payload and memory reservation until the provider request ends.
            tokio::spawn(async move {
                let _memory = memory;
                store
                    .put_opts(
                        &path,
                        buffer.into(),
                        PutOptions {
                            attributes: options.attributes,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(io_error)
            })
            .await
            .map_err(io::Error::other)??;
            return Ok(hex::encode(hash.finalize()));
        }
        let mut pending =
            PendingUpload::new(self.store(private).clone(), path, options, memory).await?;
        let mut buffer = Vec::new();
        let mut size = 0_u64;
        let mut hash = Sha256::new();
        let result = async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                size = size
                    .checked_add(chunk.len() as u64)
                    .ok_or(UploadError::Size)?;
                if size > expected_size {
                    return Err(UploadError::Size);
                }
                crate::profile_block!("storage.upload_hash", hash.update(&chunk));
                let mut remaining = chunk.as_ref();
                while !remaining.is_empty() {
                    if buffer.capacity() == 0 {
                        let unwritten = expected_size - (size - remaining.len() as u64);
                        buffer = Vec::with_capacity(unwritten.min(part_size as u64) as usize);
                    }
                    let take = remaining.len().min(part_size - buffer.len());
                    buffer.extend_from_slice(&remaining[..take]);
                    remaining = &remaining[take..];
                    if buffer.len() == part_size {
                        // Release the uploaded part before allocating the next
                        // buffer: at 5 TiB each part can be 525 MiB.
                        pending.part(std::mem::take(&mut buffer)).await?;
                    }
                }
            }
            if size != expected_size {
                return Err(UploadError::Size);
            }
            // A single empty final part also handles a zero-length object.
            if !buffer.is_empty() || size == 0 {
                pending.part(buffer).await?;
            }
            crate::profile_future!(
                pending.upload.as_mut().expect("active upload").complete(),
                label = "storage.multipart_complete"
            )
            .await
            .map_err(io_error)?;
            pending.upload = None;
            Ok(hex::encode(hash.finalize()))
        }
        .await;
        if result.is_err() {
            pending.abort().await;
        }
        result
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(target = "snowstead_observability", skip_all, name = "storage.delete")
    )]
    pub async fn delete(&self, private: bool, key: &str) -> io::Result<()> {
        match self.store(private).delete(&object_path(key)?).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(target = "snowstead_observability", skip_all, name = "storage.copy")
    )]
    pub async fn copy(
        &self,
        source_private: bool,
        source_key: &str,
        target_private: bool,
        target_key: &str,
    ) -> io::Result<()> {
        // Validate both keys before I/O. GET pins a single object version; no
        // range-by-range reads that could mix concurrent source replacements.
        let source_path = object_path(source_key)?;
        object_path(target_key)?;
        let source = self
            .store(source_private)
            .get(&source_path)
            .await
            .map_err(io_error)?;
        let size = source.meta.size;
        // Stream through upload, not CopyObject (which is limited to 5 GiB).
        // upload derives metadata from the destination, never from staging.
        self.upload(
            target_private,
            target_key,
            source.into_stream().map_err(io_error),
            size,
        )
        .await
        .map(|_| ())
        .map_err(UploadError::into_io)
    }
}

fn multipart_part_size(expected_size: u64) -> Result<usize, UploadError> {
    if expected_size > MAX_OBJECT_SIZE {
        return Err(UploadError::TooLarge);
    }
    const MIB: u64 = 1024 * 1024;
    let rounded = expected_size.div_ceil(10_000).div_ceil(MIB) * MIB;
    // At the existing 5 TiB object limit this is 525 MiB, well below
    // S3/R2's 5 GiB per-part maximum, and fits usize on supported targets.
    Ok(PART_SIZE.max(rounded as usize))
}

fn endpoint_allows_http(endpoint: &str) -> anyhow::Result<bool> {
    let invalid = || {
        anyhow::anyhow!(
            "R2_ENDPOINT must be HTTPS, or HTTP on a loopback host, without credentials, query, or fragment"
        )
    };
    let url = reqwest::Url::parse(endpoint).map_err(|_| invalid())?;
    anyhow::ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "{invalid}",
        invalid = invalid()
    );
    let host = url.host_str().unwrap_or_default();
    let loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" if !host.is_empty() => Ok(false),
        "http" if loopback => Ok(true),
        _ => Err(invalid()),
    }
}

fn object_path(key: &str) -> io::Result<Path> {
    if key.contains(['\0', '\\']) || key.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid object key",
        ));
    }
    Path::parse(key).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid object key"))
}

fn attributes(key: &str) -> Attributes {
    let (content_type, cache_control) = if key.ends_with(".narinfo") {
        ("text/x-nix-narinfo", Some("public, max-age=300"))
    } else if key.rsplit('/').next() == Some("nix-cache-info") {
        ("text/x-nix-cache-info", Some("public, max-age=3600"))
    } else if (key.starts_with("nar/") || key.starts_with("nars/sha256/")) && key.ends_with(".nar")
    {
        (
            "application/x-nix-nar",
            Some("public, max-age=31536000, immutable"),
        )
    } else {
        ("application/octet-stream", None)
    };
    let mut attributes = Attributes::new();
    attributes.insert(Attribute::ContentType, content_type.into());
    if let Some(value) = cache_control {
        attributes.insert(Attribute::CacheControl, value.into());
    }
    attributes
}

fn io_error(error: object_store::Error) -> io::Error {
    let kind = match error {
        object_store::Error::NotFound { .. } => io::ErrorKind::NotFound,
        _ => io::ErrorKind::Other,
    };
    // Provider errors may contain signed URLs or credentials. Never expose them.
    io::Error::new(kind, "Object storage operation failed")
}

#[derive(Debug)]
enum UploadError {
    Size,
    TooLarge,
    Busy,
    Io(io::Error),
}

impl From<io::Error> for UploadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl UploadError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Size => io::Error::new(io::ErrorKind::InvalidData, "File size mismatch"),
            Self::TooLarge => io::Error::new(
                io::ErrorKind::FileTooLarge,
                "Object requires an upload buffer larger than MAX_UPLOAD_PART_MIB",
            ),
            Self::Busy => io::Error::new(io::ErrorKind::WouldBlock, "Upload capacity exhausted"),
            Self::Io(error) => error,
        }
    }
}

struct PendingUpload {
    upload: Option<Box<dyn MultipartUpload>>,
    _memory: Option<OwnedSemaphorePermit>,
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl PendingUpload {
    async fn new(
        store: Arc<dyn ObjectStore>,
        path: Path,
        options: PutMultipartOptions,
        memory: OwnedSemaphorePermit,
    ) -> io::Result<Self> {
        let (tx, rx) = oneshot::channel();
        // Initiation must survive caller cancellation: once the server returns
        // the upload ID we can abort it, even if the receiver has disappeared.
        tokio::spawn(crate::profile_future!(
            async move {
                let result = store
                    .put_multipart_opts(&path, options)
                    .await
                    .map_err(io_error)
                    .map(|upload| Self {
                        upload: Some(upload),
                        _memory: Some(memory),
                    });
                let _ = tx.send(result);
            },
            label = "storage.multipart_start"
        ));
        rx.await.map_err(io::Error::other)?
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(
            target = "snowstead_observability",
            skip_all,
            name = "storage.multipart_part"
        )
    )]
    async fn part(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.upload
            .as_mut()
            .expect("active upload")
            .put_part(bytes.into())
            .await
            .map_err(io_error)
    }

    #[cfg_attr(
        feature = "observability",
        tracing::instrument(
            target = "snowstead_observability",
            skip_all,
            name = "storage.multipart_abort"
        )
    )]
    async fn abort(&mut self) {
        if let Some(upload) = &mut self.upload
            && matches!(
                tokio::time::timeout(Duration::from_secs(30), upload.abort()).await,
                Ok(Ok(()))
            )
        {
            self.upload = None;
        }
    }
}

impl Drop for PendingUpload {
    fn drop(&mut self) {
        if let Some(mut upload) = self.upload.take() {
            let memory = self._memory.take();
            // One bounded cleanup task per admitted upload; shutdown/crash or
            // network failure still requires the bucket's incomplete-MPU policy.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _memory = memory;
                    let _ = tokio::time::timeout(Duration::from_secs(30), upload.abort()).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{stream, stream::BoxStream};
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, PutOptions, PutPayload, PutResult,
        UploadPart, memory::InMemory,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    #[ignore = "requires disposable S3: scripts/with-r2.sh cargo test -p snowstead-server storage_transport_disposable_s3 -- --ignored"]
    async fn storage_transport_disposable_s3() {
        let endpoint = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT")
            .expect("run through scripts/with-r2.sh, never against production storage");
        assert!(endpoint.starts_with("http://127.0.0.1:"));
        let config = Config::from_env();
        assert_eq!(config.r2_endpoint, endpoint);
        assert_eq!(config.r2_bucket_name, "snowstead-private");
        assert_eq!(config.r2_public_bucket_name, "snowstead-public");
        let storage = Storage::new(&config).unwrap();
        let key = format!("transport/{}", uuid::Uuid::now_v7());
        let expected = vec![42; 16 * MEMORY_UNIT];
        storage.put(true, &key, &expected).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            let mut object = storage.open(true, &key).await.unwrap();
            let mut first = [0];
            object.reader.read_exact(&mut first).await.unwrap();
            assert_eq!(first, [42]);
            tokio::time::sleep(Duration::from_secs(33)).await;
            let mut rest = Vec::new();
            object.reader.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, expected[1..]);
        })
        .await;
        storage.delete(true, &key).await.unwrap();
        result.unwrap();
    }

    // A disposable, loopback-only S3 GET fixture exercises the production
    // Storage::new client, including signing, transport, and ranged retries.
    // No external service or production credentials are used.
    async fn streaming_storage(
        stall: bool,
        recover: bool,
    ) -> (
        Storage,
        Arc<AtomicUsize>,
        tokio_util::task::AbortOnDropHandle<()>,
    ) {
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let app = axum::Router::new().route(
            "/private/object",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let observed = observed.clone();
                async move {
                    let attempt = observed.fetch_add(1, Ordering::SeqCst);
                    if stall && attempt > 0 && !recover {
                        return axum::http::Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::empty())
                            .unwrap();
                    }
                    let ranged = headers.contains_key(axum::http::header::RANGE);
                    if ranged {
                        assert_eq!(headers[axum::http::header::RANGE], "bytes=1-2");
                    }
                    let chunks =
                        stream::unfold(if ranged { 1 } else { 0 }, move |index| async move {
                            if index == 3 {
                                return None;
                            }
                            if index > 0 && attempt == 0 {
                                if stall {
                                    std::future::pending::<()>().await;
                                } else {
                                    tokio::time::sleep(Duration::from_secs(16)).await;
                                }
                            }
                            Some((
                                Ok::<_, io::Error>(Bytes::from(vec![b'a' + index])),
                                index + 1,
                            ))
                        });
                    let mut response = axum::http::Response::builder()
                        .status(if ranged {
                            StatusCode::PARTIAL_CONTENT
                        } else {
                            StatusCode::OK
                        })
                        .header("content-length", if ranged { "2" } else { "3" })
                        .header("etag", "\"stable\"")
                        .header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT");
                    if ranged {
                        response = response.header("content-range", "bytes 1-2/3");
                    }
                    response.body(Body::from_stream(chunks)).unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let config = Config {
            r2_endpoint: endpoint,
            r2_access_key_id: "test".into(),
            r2_secret_access_key: "test-secret".into(),
            r2_bucket_name: "private".into(),
            r2_public_bucket_name: "public".into(),
            ..Default::default()
        };
        (Storage::new(&config).unwrap(), requests, server)
    }

    #[tokio::test]
    async fn storage_transport_allows_healthy_transfer_past_thirty_seconds() {
        let (storage, requests, _server) = streaming_storage(false, false).await;
        let start = tokio::time::Instant::now();
        let bytes = tokio::time::timeout(Duration::from_secs(45), async {
            storage
                .private
                .get(&Path::from("object"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(bytes.as_ref(), b"abc");
        assert!(start.elapsed() > Duration::from_secs(30));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn storage_transport_does_not_count_consumer_backpressure_as_a_stall() {
        let (storage, requests, _server) = streaming_storage(false, false).await;
        let mut stream = storage
            .private
            .get(&Path::from("object"))
            .await
            .unwrap()
            .into_stream();
        assert_eq!(stream.next().await.unwrap().unwrap().as_ref(), b"a");
        // Longer than both the former whole-request deadline and read timeout.
        tokio::time::sleep(Duration::from_secs(33)).await;
        let rest = tokio::time::timeout(Duration::from_secs(5), stream.try_collect::<Vec<_>>())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rest.concat(), b"bc");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn storage_transport_times_out_stalled_reads_and_retries_remaining_range() {
        for recover in [true, false] {
            let (storage, requests, _server) = streaming_storage(true, recover).await;
            let start = tokio::time::Instant::now();
            let result = tokio::time::timeout(Duration::from_secs(45), async {
                storage
                    .private
                    .get(&Path::from("object"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
            })
            .await
            .unwrap();
            assert!(start.elapsed() >= NETWORK_TIMEOUT);
            if recover {
                assert_eq!(result.unwrap().as_ref(), b"abc");
            } else {
                assert!(result.is_err());
            }
            assert_eq!(requests.load(Ordering::SeqCst), 2);
        }
    }

    #[derive(Debug, Default)]
    struct Observations {
        parts: Mutex<Vec<usize>>,
        starts: AtomicUsize,
        abort_gate: Mutex<Option<Arc<Semaphore>>>,
        put_gate: Mutex<Option<Arc<Semaphore>>>,
        puts: AtomicUsize,
        metadata_size: Mutex<Option<u64>>,
        completions: AtomicUsize,
        aborts: AtomicUsize,
        fail_put: AtomicBool,
        fail_part: AtomicBool,
        fail_complete: AtomicBool,
    }

    #[derive(Debug, Default)]
    struct ObservedStore {
        inner: Arc<InMemory>,
        observations: Arc<Observations>,
    }

    impl std::fmt::Display for ObservedStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ObservedStore")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for ObservedStore {
        async fn put_opts(
            &self,
            path: &Path,
            bytes: PutPayload,
            options: PutOptions,
        ) -> object_store::Result<PutResult> {
            self.observations.puts.fetch_add(1, Ordering::SeqCst);
            let gate = self.observations.put_gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.acquire().await.unwrap().forget();
            }
            if self.observations.fail_put.load(Ordering::SeqCst) {
                return Err(injected_error());
            }
            self.inner.put_opts(path, bytes, options).await
        }

        async fn put_multipart_opts(
            &self,
            path: &Path,
            options: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn MultipartUpload>> {
            self.observations.starts.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(ObservedUpload {
                inner: self.inner.put_multipart_opts(path, options).await?,
                observations: self.observations.clone(),
            }))
        }

        async fn get_opts(
            &self,
            path: &Path,
            options: GetOptions,
        ) -> object_store::Result<GetResult> {
            let mut result = self.inner.get_opts(path, options).await?;
            if let Some(size) = *self.observations.metadata_size.lock().unwrap() {
                result.meta.size = size;
            }
            Ok(result)
        }

        fn delete_stream(
            &self,
            paths: BoxStream<'static, object_store::Result<Path>>,
        ) -> BoxStream<'static, object_store::Result<Path>> {
            self.inner.delete_stream(paths)
        }

        fn list(
            &self,
            prefix: Option<&Path>,
        ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&Path>,
        ) -> object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &Path,
            to: &Path,
            options: CopyOptions,
        ) -> object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }

    #[derive(Debug)]
    struct ObservedUpload {
        inner: Box<dyn MultipartUpload>,
        observations: Arc<Observations>,
    }

    fn injected_error() -> object_store::Error {
        object_store::Error::Generic {
            store: "test",
            source: Box::new(io::Error::other("secret provider detail")),
        }
    }

    #[async_trait::async_trait]
    impl MultipartUpload for ObservedUpload {
        fn put_part(&mut self, bytes: PutPayload) -> UploadPart {
            self.observations
                .parts
                .lock()
                .unwrap()
                .push(bytes.content_length());
            if self.observations.fail_part.load(Ordering::SeqCst) {
                return Box::pin(async { Err(injected_error()) });
            }
            self.inner.put_part(bytes)
        }

        async fn complete(&mut self) -> object_store::Result<PutResult> {
            self.observations.completions.fetch_add(1, Ordering::SeqCst);
            if self.observations.fail_complete.load(Ordering::SeqCst) {
                return Err(injected_error());
            }
            self.inner.complete().await
        }

        async fn abort(&mut self) -> object_store::Result<()> {
            let gate = self.observations.abort_gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.acquire().await.unwrap().forget();
            }
            self.inner.abort().await?;
            self.observations.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn fixture() -> Storage {
        Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new()))
    }

    #[tokio::test]
    async fn small_host_rejects_large_parts_before_body_or_provider_mutation() {
        let store = Arc::new(ObservedStore::default());
        let observations = store.observations.clone();
        let mut storage = Storage::from_stores(store, Arc::new(InMemory::new()));
        storage.configure_limits(&ResourceLimits {
            upload_part_mib: 8,
            upload_buffer_mib: 8,
            ..Default::default()
        });
        let boundary = PART_SIZE as u64 * 10_000;
        let unread = || {
            Body::from_stream(stream::poll_fn(
                |_| -> std::task::Poll<Option<io::Result<Bytes>>> {
                    panic!("rejected body must not be polled")
                },
            ))
        };
        let error = storage
            .write_body(false, "object", unread(), boundary + 1)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(observations.starts.load(Ordering::SeqCst), 0);
        storage.put(false, "source", b"small").await.unwrap();
        *observations.metadata_size.lock().unwrap() = Some(boundary + 1);
        assert_eq!(
            storage
                .copy(false, "source", true, "target")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::FileTooLarge
        );
        assert_eq!(observations.starts.load(Ordering::SeqCst), 0);

        // Exact boundary is admitted without allocating an entire object.
        let (sent, received) = oneshot::channel();
        let body = Body::from_stream(stream::once(async move {
            sent.send(()).unwrap();
            std::future::pending::<io::Result<Bytes>>().await
        }));
        let mut upload = Box::pin(storage.write_body(false, "boundary", body, boundary));
        tokio::select! {
            result = &mut upload => panic!("unexpected completion: {result:?}"),
            _ = received => {}
        }
        assert_eq!(observations.starts.load(Ordering::SeqCst), 1);
        drop(upload);
    }

    #[tokio::test]
    async fn memory_overload_retains_reservation_through_cancelled_cleanup() {
        // Reject a part that cannot fit, even with some memory still available.
        for memory in [8, 15] {
            let store = Arc::new(ObservedStore::default());
            let observations = store.observations.clone();
            let gate = Arc::new(Semaphore::new(0));
            *observations.abort_gate.lock().unwrap() = Some(gate.clone());
            let mut storage = Storage::from_stores(store, Arc::new(InMemory::new()));
            storage.configure_limits(&ResourceLimits {
                upload_buffer_mib: memory,
                upload_part_mib: 8,
                ..Default::default()
            });
            let (sent, received) = oneshot::channel();
            let body = Body::from_stream(stream::once(async move {
                sent.send(()).unwrap();
                std::future::pending::<io::Result<Bytes>>().await
            }));
            let mut active = Some(Box::pin(storage.write_body(
                false,
                "active",
                body,
                PART_SIZE as u64,
            )));
            tokio::select! {
                result = active.as_mut().unwrap() => panic!("unexpected completion: {result:?}"),
                _ = received => {}
            }
            let rejected = || {
                Body::from_stream(stream::poll_fn(
                    |_| -> std::task::Poll<Option<io::Result<Bytes>>> {
                        panic!("overloaded body must not be polled")
                    },
                ))
            };
            for cancelled in [false, true] {
                let error = tokio::time::timeout(
                    Duration::from_secs(1),
                    storage.write_body(false, "other", rejected(), PART_SIZE as u64),
                )
                .await
                .unwrap()
                .unwrap_err();
                assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(observations.starts.load(Ordering::SeqCst), 1);
                if !cancelled {
                    // Cancellation must not release the memory reservation while
                    // the provider's abort is still running.
                    drop(active.take());
                }
            }
            gate.add_permits(1);
            tokio::time::timeout(Duration::from_secs(2), async {
                while observations.aborts.load(Ordering::SeqCst) != 1 {
                    tokio::task::yield_now().await;
                }
                // The abort's completion and task drop release the memory.
                while storage.upload_memory.available_permits() != memory {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            storage
                .write_body(false, "after", Body::from("ok"), 2)
                .await
                .unwrap();
        }
    }

    async fn read(storage: &Storage, private: bool, key: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        storage
            .open(private, key)
            .await
            .unwrap()
            .reader
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        bytes
    }

    #[tokio::test]
    async fn materialized_put_replaces_bytes_and_sets_delivery_metadata() {
        let store = Arc::new(InMemory::new());
        let storage = Storage::from_stores(store.clone(), Arc::new(InMemory::new()));
        for (key, content_type, cache_control) in [
            (
                "org/cache/hash.narinfo",
                "text/x-nix-narinfo",
                Some("public, max-age=300"),
            ),
            (
                "org/cache/nix-cache-info",
                "text/x-nix-cache-info",
                Some("public, max-age=3600"),
            ),
            (
                "nar/hash/zstd.nar",
                "application/x-nix-nar",
                Some("public, max-age=31536000, immutable"),
            ),
            ("compiler/object", "application/octet-stream", None),
        ] {
            for bytes in [b"old".as_slice(), b"replacement", b""] {
                storage.put(false, key, bytes).await.unwrap();
                let object = store.get(&Path::from(key)).await.unwrap();
                assert_eq!(
                    object
                        .attributes
                        .get(&Attribute::ContentType)
                        .unwrap()
                        .as_ref(),
                    content_type
                );
                assert_eq!(
                    object
                        .attributes
                        .get(&Attribute::CacheControl)
                        .map(|value| value.as_ref()),
                    cache_control
                );
                assert_eq!(object.bytes().await.unwrap().as_ref(), bytes);
            }
        }
    }

    #[tokio::test]
    async fn streaming_hash_empty_and_large_frame() {
        let store = Arc::new(ObservedStore::default());
        let observations = store.observations.clone();
        let storage = Storage::from_stores(store, Arc::new(InMemory::new()));
        for size in [0, PART_SIZE - 1, PART_SIZE, PART_SIZE * 2 + 1] {
            let bytes = vec![0xa5; size];
            let receipt = storage
                .write_body(false, "object", Body::from(bytes.clone()), size as u64)
                .await
                .unwrap();
            assert_eq!(receipt, hex::encode(Sha256::digest(&bytes)));
            let object = storage.open(false, "object").await.unwrap();
            assert_eq!(object.metadata.size, size as u64);
            assert!(object.metadata.e_tag.is_some());
            assert_ne!(object.metadata.e_tag.as_deref(), Some(receipt.as_str()));
            let head = storage.head(false, "object").await.unwrap();
            assert_eq!(head, object.metadata);
            assert_eq!(read(&storage, false, "object").await, bytes);
        }
        assert_eq!(observations.puts.load(Ordering::SeqCst), 2);
        assert_eq!(observations.starts.load(Ordering::SeqCst), 2);
        let chunks = (0..4096).map(|_| Ok::<_, io::Error>(Bytes::from_static(b"abcd")));
        let receipt = storage
            .write_body(
                true,
                "tiny-frames",
                Body::from_stream(stream::iter(chunks)),
                16384,
            )
            .await
            .unwrap();
        assert_eq!(receipt, hex::encode(Sha256::digest(b"abcd".repeat(4096))));
    }

    #[tokio::test]
    async fn small_put_failure_and_cancellation_keep_memory_until_provider_finishes() {
        let store = Arc::new(ObservedStore::default());
        let observations = store.observations.clone();
        let mut storage = Storage::from_stores(store, Arc::new(InMemory::new()));
        storage.configure_limits(&ResourceLimits {
            upload_buffer_mib: 8,
            ..Default::default()
        });
        storage.put(false, "object", b"old").await.unwrap();
        observations.fail_put.store(true, Ordering::SeqCst);
        let error = storage
            .write_body(false, "object", Body::from("new"), 3)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.message, "Internal error");
        assert_eq!(read(&storage, false, "object").await, b"old");
        observations.fail_put.store(false, Ordering::SeqCst);

        let gate = Arc::new(Semaphore::new(0));
        *observations.put_gate.lock().unwrap() = Some(gate.clone());
        let bytes = vec![0xa5; PART_SIZE - 1];
        let mut upload = Box::pin(storage.write_body(
            false,
            "object",
            Body::from(bytes.clone()),
            bytes.len() as u64,
        ));
        tokio::select! {
            result = &mut upload => panic!("unexpected completion: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), async {
                while observations.puts.load(Ordering::SeqCst) < 3 {
                    tokio::task::yield_now().await;
                }
            }) => result.unwrap(),
        }
        drop(upload);
        let unread = Body::from_stream(stream::poll_fn(
            |_| -> std::task::Poll<Option<io::Result<Bytes>>> {
                panic!("overloaded body must not be polled")
            },
        ));
        let error = storage
            .write_body(false, "blocked", unread, 1)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(read(&storage, false, "object").await, b"old");
        gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while storage.upload_memory.available_permits() != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(read(&storage, false, "object").await, bytes);
        assert_eq!(observations.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failures_and_cancellation_preserve_replacement() {
        let store = Arc::new(ObservedStore::default());
        let observations = store.observations.clone();
        let storage = Storage::from_stores(store, Arc::new(InMemory::new()));
        storage.put(false, "object", b"old").await.unwrap();
        for expected in [2, 4, u64::MAX] {
            let error = storage
                .write_body(false, "object", Body::from("new"), expected)
                .await
                .unwrap_err();
            assert_eq!(
                error.status,
                if expected == u64::MAX {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                }
            );
            assert_eq!(read(&storage, false, "object").await, b"old");
        }
        let chunks = stream::iter([
            Ok(Bytes::from(vec![1; PART_SIZE + 1])),
            Err(io::Error::other("secret transport details")),
        ]);
        let error = storage
            .write_body(
                false,
                "object",
                Body::from_stream(chunks),
                (PART_SIZE * 2) as u64,
            )
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.message, "Internal error");
        assert_eq!(read(&storage, false, "object").await, b"old");
        assert_eq!(observations.aborts.load(Ordering::SeqCst), 1);
        assert_eq!(observations.completions.load(Ordering::SeqCst), 0);

        let (sent, received) = oneshot::channel();
        let chunks =
            stream::once(async { Ok::<_, io::Error>(Bytes::from(vec![1; PART_SIZE + 1])) }).chain(
                stream::once(async move {
                    let _ = sent.send(());
                    std::future::pending::<io::Result<Bytes>>().await
                }),
            );
        let mut upload = Box::pin(storage.write_body(
            false,
            "object",
            Body::from_stream(chunks),
            (PART_SIZE * 2) as u64,
        ));
        tokio::select! {
            result = &mut upload => panic!("unexpected completion: {result:?}"),
            result = received => result.unwrap(),
        }
        drop(upload);
        tokio::time::timeout(Duration::from_secs(2), async {
            while observations.aborts.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(read(&storage, false, "object").await, b"old");
    }

    #[tokio::test]
    async fn bounded_parts_and_provider_failures() {
        let store = Arc::new(ObservedStore::default());
        let observations = store.observations.clone();
        let storage = Storage::from_stores(store, Arc::new(InMemory::new()));
        let bytes = vec![42; PART_SIZE * 3 + 17];
        storage
            .write_body(
                false,
                "object",
                Body::from(bytes),
                (PART_SIZE * 3 + 17) as u64,
            )
            .await
            .unwrap();
        assert_eq!(
            *observations.parts.lock().unwrap(),
            [PART_SIZE, PART_SIZE, PART_SIZE, 17]
        );
        observations.parts.lock().unwrap().clear();
        storage.copy(false, "object", false, "copy").await.unwrap();
        assert_eq!(
            *observations.parts.lock().unwrap(),
            [PART_SIZE, PART_SIZE, PART_SIZE, 17]
        );
        storage.put(false, "object", b"old").await.unwrap();
        for fail_complete in [false, true] {
            observations
                .fail_part
                .store(!fail_complete, Ordering::SeqCst);
            observations
                .fail_complete
                .store(fail_complete, Ordering::SeqCst);
            let error = storage
                .write_body(
                    false,
                    "object",
                    Body::from(vec![1; PART_SIZE]),
                    PART_SIZE as u64,
                )
                .await
                .unwrap_err();
            assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error.message, "Internal error");
            assert_eq!(read(&storage, false, "object").await, b"old");
        }
        assert_eq!(observations.aborts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn isolation_copy_metadata_and_delete() {
        let storage = fixture();
        storage.put(false, "same", b"public").await.unwrap();
        storage.put(true, "same", b"private").await.unwrap();
        assert_eq!(read(&storage, false, "same").await, b"public");
        assert_eq!(read(&storage, true, "same").await, b"private");
        storage
            .put(true, "staging/source", &vec![7; PART_SIZE + 9])
            .await
            .unwrap();
        for (private, key, content_type, cache_control) in [
            (
                false,
                "nar/hash/zstd.nar",
                "application/x-nix-nar",
                Some("public, max-age=31536000, immutable"),
            ),
            (
                true,
                "nars/sha256/hash/zstd.nar",
                "application/x-nix-nar",
                Some("public, max-age=31536000, immutable"),
            ),
            (
                false,
                "org/cache/hash.narinfo",
                "text/x-nix-narinfo",
                Some("public, max-age=300"),
            ),
            (
                true,
                "narinfo/org/cache/hash.narinfo",
                "text/x-nix-narinfo",
                Some("public, max-age=300"),
            ),
            (
                false,
                "org/cache/nix-cache-info",
                "text/x-nix-cache-info",
                Some("public, max-age=3600"),
            ),
            (false, "go/cache/file", "application/octet-stream", None),
        ] {
            storage
                .copy(true, "staging/source", private, key)
                .await
                .unwrap();
            let object = storage
                .store(private)
                .get(&object_path(key).unwrap())
                .await
                .unwrap();
            assert_eq!(
                object
                    .attributes
                    .get(&Attribute::ContentType)
                    .unwrap()
                    .as_ref(),
                content_type
            );
            assert_eq!(
                object
                    .attributes
                    .get(&Attribute::CacheControl)
                    .map(|v| v.as_ref()),
                cache_control
            );
            assert_eq!(read(&storage, private, key).await, vec![7; PART_SIZE + 9]);
        }
        assert_eq!(
            storage
                .copy(false, "missing", true, "same")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(read(&storage, true, "same").await, b"private");
        storage.copy(true, "same", true, "same").await.unwrap();
        storage.delete(true, "same").await.unwrap();
        storage.delete(true, "same").await.unwrap();
        assert_eq!(read(&storage, false, "same").await, b"public");
    }

    #[test]
    fn multipart_sizing_preserves_five_tib_limit() {
        const MIB: u64 = 1024 * 1024;
        let boundary = PART_SIZE as u64 * 10_000;
        for (size, expected_part) in [
            (0, PART_SIZE),
            (1, PART_SIZE),
            (boundary - 1, PART_SIZE),
            (boundary, PART_SIZE),
            (boundary + 1, 9 * MIB as usize),
            (9 * MIB * 10_000, 9 * MIB as usize),
            (9 * MIB * 10_000 + 1, 10 * MIB as usize),
            (MAX_OBJECT_SIZE - 1, 525 * MIB as usize),
            (MAX_OBJECT_SIZE, 525 * MIB as usize),
        ] {
            let part = multipart_part_size(size).unwrap();
            assert_eq!(part, expected_part);
            assert!(size.div_ceil(part as u64) <= 10_000);
            assert_eq!(part as u64 % MIB, 0);
            assert!(part as u64 <= 5 * 1024_u64.pow(3));
        }
        assert!(multipart_part_size(MAX_OBJECT_SIZE + 1).is_err());
        assert!(multipart_part_size(u64::MAX).is_err());
    }

    #[test]
    fn endpoint_and_key_validation() {
        for endpoint in [
            "http://localhost:9000",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            assert!(endpoint_allows_http(endpoint).unwrap());
        }
        assert!(!endpoint_allows_http("https://account.r2.cloudflarestorage.com").unwrap());
        for endpoint in [
            "http://example.com",
            "http://127.0.0.1.example.com",
            "file:///tmp/bucket",
            "https://user:secret@example.com",
            "https://example.com?secret=value",
        ] {
            assert!(endpoint_allows_http(endpoint).is_err());
        }
        for key in [
            "",
            "/absolute",
            "a//b",
            "a/",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "a\0b",
            "a\\b",
        ] {
            assert!(object_path(key).is_err());
        }
    }
}
