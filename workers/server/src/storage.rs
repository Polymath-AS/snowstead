use std::{io, sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    http::StatusCode,
};
use futures_util::{Stream, StreamExt, TryStreamExt};
use object_store::{
    Attribute, Attributes, MultipartUpload, ObjectMeta, ObjectStore, ObjectStoreExt,
    PutMultipartOptions, PutOptions,
    aws::{AmazonS3, AmazonS3Builder},
    multipart::MultipartStore,
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

#[derive(Clone)]
pub struct Storage {
    public: Arc<dyn ObjectStore>,
    private: Arc<dyn ObjectStore>,
    multipart: Option<[Arc<AmazonS3>; 2]>,
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
            upload_memory: Arc::new(Semaphore::new(config.resources.upload_buffer_mib)),
            max_part_size: config.resources.upload_part_mib * MEMORY_UNIT,
        })
    }

    pub fn from_stores(public: Arc<dyn ObjectStore>, private: Arc<dyn ObjectStore>) -> Self {
        Self {
            public,
            private,
            multipart: None,
            upload_memory: Arc::new(Semaphore::new(ResourceLimits::default().upload_buffer_mib)),
            max_part_size: ResourceLimits::default().upload_part_mib * MEMORY_UNIT,
        }
    }

    pub(crate) fn configure_limits(&mut self, limits: &ResourceLimits) {
        self.upload_memory = Arc::new(Semaphore::new(limits.upload_buffer_mib));
        self.max_part_size = limits.upload_part_mib * MEMORY_UNIT;
    }

    /// Abort a persisted provider upload from before the runtime cutover.
    /// Backends without this API must retain its SQL cleanup record for retry.
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
        let mut pending =
            PendingUpload::new(self.store(private).clone(), path, options, memory).await?;
        let stream = crate::profile_stream!(stream, label = "storage.upload_body");
        futures_util::pin_mut!(stream);
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
        // Stream through multipart, not CopyObject (which is limited to 5 GiB).
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

    #[derive(Debug, Default)]
    struct Observations {
        parts: Mutex<Vec<usize>>,
        starts: AtomicUsize,
        abort_gate: Mutex<Option<Arc<Semaphore>>>,
        metadata_size: Mutex<Option<u64>>,
        completions: AtomicUsize,
        aborts: AtomicUsize,
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
        let storage = fixture();
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
        assert_eq!(observations.aborts.load(Ordering::SeqCst), 3);
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
            while observations.aborts.load(Ordering::SeqCst) != 4 {
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
                .write_body(false, "object", Body::from("new"), 3)
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
