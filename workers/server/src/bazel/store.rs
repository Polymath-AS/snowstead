//! Independent, verified publication per digest. Retention is a soft target:
//! background approximate LRU never makes uploads wait for quota accounting.
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::body::Body;
use chrono::Utc;
use futures_util::{StreamExt, TryStreamExt, stream};
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, UpdateVersion, path::Path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::OwnedSemaphorePermit;

use crate::storage::{Storage, StoredObject};

const SESSION_LIMIT: usize = 1024 * 1024;
const SESSION_SECONDS: i64 = 3600;
const CANDIDATES: usize = 32768;
static READ_SAMPLE: AtomicU64 = AtomicU64::new(0);
static ACCESS_WRITES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);

#[derive(Clone)]
pub struct Store {
    storage: Storage,
    metadata: Arc<dyn ObjectStore>,
    prefix: String,
    capacity: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    key: String,
    size: u64,
    accessed: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct Session {
    expires: i64,
    revision: String,
    chunks: Vec<String>,
    committed: u64,
    sealed: bool,
    complete: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn storage_error(error: object_store::Error) -> io::Error {
    io::Error::other(error)
}

impl Store {
    pub fn new(storage: Storage, generation: &str, capacity: u64) -> Self {
        Self {
            metadata: storage.private_store(),
            storage,
            prefix: format!("bazel/{generation}"),
            capacity,
        }
    }

    pub fn max_blob_size(&self) -> u64 {
        // The negotiated limit keeps resumable-session metadata bounded too.
        // It is independent of the cache's retained-storage target.
        8 * 1024_u64.pow(3)
    }

    fn entry_key(&self, kind: &str, digest: &str) -> io::Result<Path> {
        if !matches!(kind, "cas" | "ac") || !crate::cache::sha256_hex(digest) {
            return Err(invalid("Invalid Bazel digest"));
        }
        Ok(Path::from(format!("{}/index/{kind}/{digest}", self.prefix)))
    }

    fn marker(&self, key: &str) -> String {
        format!("{}/access/{}", self.prefix, key.rsplit('/').next().unwrap())
    }

    async fn entry(&self, key: &Path) -> io::Result<(Option<Entry>, PutMode)> {
        match self.metadata.get(key).await {
            Ok(object) => {
                if object.meta.size > 4096 {
                    return Err(invalid("Invalid Bazel entry"));
                }
                let version = UpdateVersion {
                    e_tag: object.meta.e_tag.clone(),
                    version: object.meta.version.clone(),
                };
                let bytes = object.bytes().await.map_err(storage_error)?;
                Ok((
                    serde_json::from_slice(&bytes).map_err(io::Error::other)?,
                    PutMode::Update(version),
                ))
            }
            Err(object_store::Error::NotFound { .. }) => Ok((None, PutMode::Create)),
            Err(error) => Err(storage_error(error)),
        }
    }

    pub async fn read(&self, kind: &str, digest: &str) -> io::Result<Option<StoredObject>> {
        let key = self.entry_key(kind, digest)?;
        if kind == "cas"
            && digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        {
            return Ok(Some(StoredObject {
                metadata: object_store::ObjectMeta {
                    location: Path::from("empty"),
                    last_modified: Utc::now(),
                    size: 0,
                    e_tag: None,
                    version: None,
                },
                reader: Box::new(tokio::io::empty()),
            }));
        }
        let (Some(entry), _) = self.entry(&key).await? else {
            return Ok(None);
        };
        let object = match self.storage.open(true, &entry.key).await {
            Ok(object) => object,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if object.metadata.size != entry.size {
            return Err(invalid("Bazel object size mismatch"));
        }
        self.touch(&entry);
        Ok(Some(object))
    }

    pub async fn stat(
        &self,
        kind: &str,
        digest: &str,
    ) -> io::Result<Option<object_store::ObjectMeta>> {
        let key = self.entry_key(kind, digest)?;
        if kind == "cas"
            && digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        {
            return Ok(self.read(kind, digest).await?.map(|object| object.metadata));
        }
        let (Some(entry), _) = self.entry(&key).await? else {
            return Ok(None);
        };
        let metadata = match self.storage.head(true, &entry.key).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if metadata.size != entry.size {
            return Err(invalid("Bazel object size mismatch"));
        }
        self.touch(&entry);
        Ok(Some(metadata))
    }

    fn touch(&self, entry: &Entry) {
        // Dropped access telemetry changes eviction quality, never correctness.
        if READ_SAMPLE
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(64)
            && let Ok(permit) = ACCESS_WRITES.try_acquire()
        {
            let marker = self.marker(&entry.key);
            let storage = self.storage.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = storage.put(true, &marker, &[]).await;
            });
        }
    }

    pub async fn write(&self, kind: &str, digest: &str, size: u64, body: Body) -> io::Result<()> {
        let index = self.entry_key(kind, digest)?;
        if size > self.max_blob_size() {
            return Err(invalid("Blob exceeds object-store limit"));
        }
        // Physical keys are unique even for competing writes of one digest.
        // CAS bytes are verified; AC replacement is last completed publication.
        let key = format!(
            "{}/objects/{kind}/{digest}/{}",
            self.prefix,
            uuid::Uuid::now_v7()
        );
        let hash = tokio::time::timeout(
            Duration::from_secs(SESSION_SECONDS as u64),
            self.storage.write_body(true, &key, body, size),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upload expired"))?
        .map_err(|error| {
            io::Error::new(
                if error.status.is_client_error() {
                    io::ErrorKind::InvalidData
                } else if error.status == axum::http::StatusCode::SERVICE_UNAVAILABLE {
                    io::ErrorKind::WouldBlock
                } else {
                    io::ErrorKind::Other
                },
                error.message,
            )
        })?;
        if kind == "cas" && hash != digest {
            // No pointer can refer to a failed verification. An ambiguous object
            // completion is still found by the independent orphan sweep.
            self.storage.delete(true, &key).await?;
            return Err(invalid("Bazel digest mismatch"));
        }
        self.publish(index, key, size).await
    }

    // The receive buffer already owns its memory reservation. Move both into
    // the provider task instead of allocating another buffer or multipart upload.
    pub(crate) async fn write_buffered(
        &self,
        digest: &str,
        bytes: Vec<u8>,
        memory: OwnedSemaphorePermit,
    ) -> io::Result<()> {
        let index = self.entry_key("cas", digest)?;
        let size = bytes.len() as u64;
        let key = self.verified_candidate(digest, &bytes)?;
        let metadata = self.metadata.clone();
        let path = Path::from(key.clone());
        tokio::spawn(async move {
            let _memory = memory;
            metadata
                .put(&path, bytes.into())
                .await
                .map_err(storage_error)
        })
        .await
        .map_err(io::Error::other)??;
        self.publish(index, key, size).await
    }

    fn verified_candidate(&self, digest: &str, bytes: &[u8]) -> io::Result<String> {
        if bytes.len() > 8 * 1024 * 1024 || hex::encode(Sha256::digest(bytes)) != digest {
            return Err(invalid("Bazel digest mismatch or receive buffer exceeded"));
        }
        Ok(format!(
            "{}/objects/cas/{digest}/{}",
            self.prefix,
            uuid::Uuid::now_v7()
        ))
    }

    async fn publish(&self, index: Path, key: String, size: u64) -> io::Result<()> {
        let entry = Entry {
            key,
            size,
            accessed: Utc::now().timestamp_millis(),
        };
        self.metadata
            .put(
                &index,
                serde_json::to_vec(&entry).map_err(io::Error::other)?.into(),
            )
            .await
            .map_err(storage_error)?;
        // Receipt follows publication. A collector can reclaim this object's
        // bytes immediately once another pointer replaces it, without guessing
        // whether an upload still intends to publish. No conditional write/lock.
        self.storage
            .put(true, &entry.key.replace("/objects/", "/published/"), &[])
            .await?;
        Ok(())
    }

    /// Return observed retained bytes and entries. Publication never waits on
    /// this scan, and concurrent writes can change the observation immediately.
    pub async fn usage(&self) -> io::Result<(u64, u64)> {
        let prefix = Path::from(format!("{}/index/", self.prefix));
        let mut entries = self
            .metadata
            .list(Some(&prefix))
            .map_err(storage_error)
            .map_ok(|object| async move { self.entry(&object.location).await })
            .try_buffer_unordered(32);
        let (mut count, mut size) = (0, 0u64);
        while let Some((entry, _)) = entries.try_next().await? {
            if let Some(entry) = entry {
                count += 1;
                size = size.saturating_add(entry.size);
            }
        }
        Ok((count, size))
    }

    /// Physical blob and resumable-chunk bytes, independent of live pointers.
    pub async fn physical_usage(&self) -> io::Result<(u64, u64)> {
        let mut totals = [0u64; 2];
        for (i, kind) in ["objects", "sessions"].into_iter().enumerate() {
            let prefix = Path::from(format!("{}/{kind}/", self.prefix));
            let mut objects = self.metadata.list(Some(&prefix));
            while let Some(object) = objects.try_next().await.map_err(storage_error)? {
                if i == 0 || object.location.as_ref().contains("/chunks/") {
                    totals[i] = totals[i].saturating_add(object.size);
                }
            }
        }
        Ok((totals[0], totals[1]))
    }

    /// Concurrent collectors use conditional retirement, not a cache-wide lock.
    /// Candidate memory is bounded; large excesses drain over successive sweeps.
    pub async fn collect(&self) -> io::Result<u64> {
        let prefix = Path::from(format!("{}/index/", self.prefix));
        let mut entries = self
            .metadata
            .list(Some(&prefix))
            .map_err(storage_error)
            .map_ok(|object| async move {
                let (entry, mode) = self.entry(&object.location).await?;
                let Some(mut entry) = entry else {
                    // Finish a retirement interrupted after its tombstone PUT.
                    // A replacement racing this DELETE may become a cache miss.
                    self.storage.delete(true, object.location.as_ref()).await?;
                    return Ok(None);
                };
                match self.storage.head(true, &self.marker(&entry.key)).await {
                    Ok(marker) => {
                        entry.accessed = entry.accessed.max(marker.last_modified.timestamp_millis())
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                Ok(Some((entry, object.location, mode)))
            })
            .try_buffer_unordered(32);
        let mut candidates = Vec::new();
        let mut used = 0u64;
        while let Some(candidate) = entries.try_next().await? {
            let Some(candidate) = candidate else { continue };
            used = used.saturating_add(candidate.0.size);
            candidates.push(candidate);
            if candidates.len() == 2 * CANDIDATES {
                candidates.sort_unstable_by_key(|(entry, _, _)| entry.accessed);
                candidates.truncate(CANDIDATES);
            }
        }
        candidates.sort_unstable_by_key(|(entry, _, _)| entry.accessed);
        let candidates = candidates.into_iter().take_while(|(entry, _, _)| {
            if used <= self.capacity {
                return false;
            }
            used = used.saturating_sub(entry.size);
            true
        });
        let mut deleted = stream::iter(candidates.map(|(entry, path, mode)| async move {
            // Coordinate collectors with a conditional tombstone, then remove
            // it. R2 has no conditional DELETE. A same-digest replacement can
            // race deletion and become a miss; cache retention is not durable.
            // Its unique physical object becomes an orphan, never wrong bytes.
            match self
                .metadata
                .put_opts(
                    &path,
                    b"null".to_vec().into(),
                    PutOptions {
                        mode,
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(_) => {
                    self.storage.delete(true, path.as_ref()).await?;
                    self.storage.delete(true, &entry.key).await?;
                    self.storage
                        .delete(true, &entry.key.replace("/objects/", "/published/"))
                        .await?;
                    self.storage.delete(true, &self.marker(&entry.key)).await?;
                    Ok(1u64)
                }
                Err(
                    object_store::Error::Precondition { .. }
                    | object_store::Error::AlreadyExists { .. }
                    | object_store::Error::NotFound { .. },
                ) => {
                    // This snapshot's entry was retired or replaced. Do not
                    // evict another entry to compensate for a competing sweep;
                    // the next scan accounts for any replacement's bytes.
                    Ok(0)
                }
                Err(error) => Err(storage_error(error)),
            }
        }))
        .buffer_unordered(32)
        .try_fold(0u64, |total, count| async move { Ok(total + count) })
        .await?;
        // Confirmed superseded objects need no upload grace. Only objects
        // without a publication receipt retain the ambiguous-upload grace.
        let prefix = Path::from(format!("{}/objects/", self.prefix));
        let mut objects = self.metadata.list(Some(&prefix));
        while let Some(object) = objects.try_next().await.map_err(storage_error)? {
            let parts: Vec<_> = object.location.as_ref().split('/').collect();
            if parts.len() != 6 {
                continue;
            }
            let index = self.entry_key(parts[3], parts[4])?;
            let (current, _) = self.entry(&index).await?;
            if current.is_none_or(|entry| entry.key != object.location.as_ref()) {
                let receipt = object.location.as_ref().replace("/objects/", "/published/");
                let published = match self.storage.head(true, &receipt).await {
                    Ok(_) => true,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(error) => return Err(error),
                };
                if !published
                    && object.last_modified.timestamp() + 2 * SESSION_SECONDS
                        >= Utc::now().timestamp()
                {
                    continue;
                }
                self.storage.delete(true, object.location.as_ref()).await?;
                self.storage.delete(true, &receipt).await?;
                self.storage
                    .delete(true, &self.marker(object.location.as_ref()))
                    .await?;
                deleted += 1;
            }
        }
        // A receipt can arrive after a racing retirement removed its object.
        let prefix = Path::from(format!("{}/published/", self.prefix));
        let mut receipts = self.metadata.list(Some(&prefix));
        while let Some(receipt) = receipts.try_next().await.map_err(storage_error)? {
            let key = receipt
                .location
                .as_ref()
                .replace("/published/", "/objects/");
            match self.storage.head(true, &key).await {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.storage.delete(true, receipt.location.as_ref()).await?;
                }
                Err(error) => return Err(error),
            }
        }
        // Access samples may arrive after an entry is deleted. Expiring old
        // samples bounds their lifetime too; lost samples only affect LRU quality.
        for kind in ["sessions", "access"] {
            let prefix = Path::from(format!("{}/{kind}/", self.prefix));
            let mut objects = self.metadata.list(Some(&prefix));
            while let Some(object) = objects.try_next().await.map_err(storage_error)? {
                if object.last_modified.timestamp() + 2 * SESSION_SECONDS < Utc::now().timestamp() {
                    self.storage.delete(true, object.location.as_ref()).await?;
                    deleted += 1;
                }
            }
        }
        Ok(deleted)
    }

    fn session_key(&self, resource: &str) -> String {
        format!(
            "{}/sessions/{}",
            self.prefix,
            hex::encode(Sha256::digest(resource))
        )
    }

    async fn session(&self, key: &str) -> io::Result<(Session, PutMode)> {
        match self.metadata.get(&Path::from(format!("{key}/state"))).await {
            Ok(object) => {
                if object.meta.size > SESSION_LIMIT as u64 {
                    return Err(invalid("Upload session exceeds metadata limit"));
                }
                let mode = PutMode::Update(UpdateVersion {
                    e_tag: object.meta.e_tag.clone(),
                    version: object.meta.version.clone(),
                });
                let bytes = object.bytes().await.map_err(storage_error)?;
                Ok((
                    serde_json::from_slice(&bytes).map_err(io::Error::other)?,
                    mode,
                ))
            }
            Err(object_store::Error::NotFound { .. }) => Ok((Session::default(), PutMode::Create)),
            Err(error) => Err(storage_error(error)),
        }
    }

    async fn save_session(
        &self,
        key: &str,
        session: &mut Session,
        mode: PutMode,
    ) -> io::Result<()> {
        session.revision = uuid::Uuid::now_v7().to_string();
        let bytes = serde_json::to_vec(session).map_err(io::Error::other)?;
        if bytes.len() > SESSION_LIMIT {
            return Err(invalid("Upload session exceeds metadata limit"));
        }
        self.metadata
            .put_opts(
                &Path::from(format!("{key}/state")),
                bytes.into(),
                PutOptions {
                    mode,
                    ..Default::default()
                },
            )
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) async fn upload_status(
        &self,
        resource: &str,
        digest: &str,
        size: u64,
    ) -> io::Result<(u64, bool)> {
        if self
            .stat("cas", digest)
            .await?
            .is_some_and(|object| object.size == size)
        {
            return Ok((size, true));
        }
        let (session, _) = self.session(&self.session_key(resource)).await?;
        if session.expires < Utc::now().timestamp() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Upload session not found",
            ));
        }
        Ok((session.committed, session.complete))
    }

    pub(crate) async fn append(
        &self,
        resource: &str,
        digest: &str,
        size: u64,
        offset: u64,
        bytes: Vec<u8>,
    ) -> io::Result<u64> {
        self.entry_key("cas", digest)?;
        let key = self.session_key(resource);
        if size > self.max_blob_size() || bytes.len() > 8 * 1024 * 1024 {
            return Err(invalid("Upload exceeds capacity"));
        }
        let (mut session, mode) = self.session(&key).await?;
        if matches!(mode, PutMode::Create) {
            session.expires = Utc::now().timestamp() + SESSION_SECONDS;
        }
        if session.expires < Utc::now().timestamp() {
            return Err(invalid("Upload session expired; use a new upload ID"));
        }
        if session.sealed || session.complete || session.committed != offset {
            return Err(invalid("Upload offset does not match committed size"));
        }
        let next = offset
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= size)
            .ok_or_else(|| invalid("Upload exceeds declared size"))?;
        if !bytes.is_empty() {
            // A complete receive buffer can be verified before its first PUT.
            // Store it at its immutable final location, but do not publish until
            // finish_write. Unpublished candidates retain the two-hour GC grace.
            let chunk = if offset == 0 && next == size {
                self.verified_candidate(digest, &bytes)?
            } else {
                format!("{key}/chunks/{}", uuid::Uuid::now_v7())
            };
            self.storage.put(true, &chunk, &bytes).await?;
            session.chunks.push(chunk);
        }
        session.committed = next;
        self.save_session(&key, &mut session, mode).await?;
        Ok(next)
    }

    /// Continuous uploads write each byte once. Closing the request stream
    /// checkpoints an immutable prefix; only a resumed RPC reads it back.
    pub(crate) async fn write_stream(
        &self,
        resource: &str,
        digest: &str,
        size: u64,
        offset: u64,
        body: Body,
        finished: Arc<AtomicBool>,
    ) -> io::Result<u64> {
        let index = self.entry_key("cas", digest)?;
        if size > self.max_blob_size() {
            return Err(invalid("Upload exceeds capacity"));
        }
        let session_key = self.session_key(resource);
        let (mut session, mode) = self.session(&session_key).await?;
        if matches!(mode, PutMode::Create) {
            session.expires = Utc::now().timestamp() + SESSION_SECONDS;
        }
        if session.expires < Utc::now().timestamp() || session.committed != offset {
            return Err(invalid("Upload session expired or offset changed"));
        }
        let key = format!(
            "{}/objects/cas/{digest}/{}",
            self.prefix,
            uuid::Uuid::now_v7()
        );
        let storage = self.storage.clone();
        let prefixes = stream::iter(session.chunks.clone().into_iter().map(move |key| {
            let storage = storage.clone();
            async move {
                let object = storage.open(true, &key).await?;
                Ok::<_, io::Error>(tokio_util::io::ReaderStream::new(object.reader))
            }
        }))
        .buffered(1)
        .try_flatten();
        let body =
            Body::from_stream(prefixes.chain(body.into_data_stream().map_err(io::Error::other)));
        let (hash, received) = self.storage.write_prefix(&key, body, size).await?;
        if received == size && hash != digest {
            self.storage.delete(true, &key).await?;
            return Err(invalid("Bazel digest mismatch"));
        }
        if received == size && finished.load(Ordering::Relaxed) {
            self.publish(index, key, size).await?;
        } else {
            // CAS only arbitrates competing updates to this upload ID, never
            // publication or another user's progress. Retain old prefixes for
            // racing readers; the orphan sweep removes them after its grace.
            session.chunks = vec![key];
            session.committed = received;
            session.sealed = false;
            session.complete = false;
            self.save_session(&session_key, &mut session, mode).await?;
        }
        Ok(received)
    }

    pub(crate) async fn finish_upload(
        &self,
        resource: &str,
        digest: &str,
        size: u64,
    ) -> io::Result<()> {
        let key = self.session_key(resource);
        let (mut session, mode) = self.session(&key).await?;
        if session.expires < Utc::now().timestamp() {
            return Err(invalid("Upload session expired; use a new upload ID"));
        }
        if session.committed != size {
            return Err(invalid("Upload is incomplete"));
        }
        let candidate_prefix = format!("{}/objects/cas/{digest}/", self.prefix);
        let candidate =
            session.chunks.len() == 1 && session.chunks[0].starts_with(&candidate_prefix);
        if candidate {
            // A single complete candidate was verified before its session was
            // saved. It needs no sealing or payload transfer. upload_status
            // observes completion through the published index.
            return self
                .publish(
                    self.entry_key("cas", digest)?,
                    session.chunks[0].clone(),
                    size,
                )
                .await;
        }
        if !session.sealed {
            session.sealed = true;
            self.save_session(&key, &mut session, mode).await?;
        }
        let storage = self.storage.clone();
        let bodies = stream::iter(session.chunks.clone().into_iter().map(move |key| {
            let storage = storage.clone();
            async move {
                let object = storage.open(true, &key).await?;
                Ok::<_, io::Error>(tokio_util::io::ReaderStream::new(object.reader))
            }
        }))
        .buffered(1);
        self.write("cas", digest, size, Body::from_stream(bodies.try_flatten()))
            .await?;
        let (mut session, mode) = self.session(&key).await?;
        session.complete = true;
        self.save_session(&key, &mut session, mode).await?;
        for chunk in session.chunks {
            self.storage.delete(true, &chunk).await?;
        }
        Ok(())
    }
}
