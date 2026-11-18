use std::{
    collections::{BTreeSet, VecDeque},
    pin::Pin,
};

use axum::body::Body;
use futures_util::{Stream, StreamExt, stream};
use prost::Message;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use tonic::{Request, Response, Status};

use super::{MAX_METADATA, blob, complete, failure, open, proto, store::Store, valid_digest};
use crate::{AppState, cache_host::OrganizationHost, error::ApiError};
use proto::build::bazel::{remote::execution::v2::*, semver::SemVer};
use proto::google::bytestream::{self as bs, byte_stream_server::ByteStream};

type Responses<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[derive(Clone)]
pub(super) struct Cache(pub AppState);

fn status(error: ApiError) -> Status {
    match error.status.as_u16() {
        400 | 411 => Status::invalid_argument(error.message),
        413 => Status::resource_exhausted(error.message),
        401 => Status::unauthenticated("Credentials required"),
        403 => Status::permission_denied("Forbidden"),
        404 => Status::not_found("Not found"),
        429 => Status::resource_exhausted("Request limit exceeded"),
        503 => Status::unavailable("Retry the request"),
        _ => Status::internal("Storage request failed"),
    }
}

fn io(error: std::io::Error) -> Status {
    status(failure(error))
}

fn digest(value: Option<Digest>) -> Result<Digest, Status> {
    value
        .filter(valid_digest)
        .ok_or_else(|| Status::invalid_argument("Invalid SHA-256 digest"))
}

fn algorithm(value: i32) -> Result<(), Status> {
    if matches!(value, 0 | 1) {
        Ok(())
    } else {
        Err(Status::invalid_argument("Only SHA-256 is supported"))
    }
}

fn wire_status(value: Result<(), Status>) -> Option<proto::google::rpc::Status> {
    let (code, message) = match value {
        Ok(()) => (0, String::new()),
        Err(status) => (status.code() as i32, status.message().to_owned()),
    };
    Some(proto::google::rpc::Status {
        code,
        message,
        details: vec![],
    })
}

/// The organization named by the host, when the request came from an
/// organization host.
fn organization<T>(request: &Request<T>) -> Option<&str> {
    request
        .extensions()
        .get::<OrganizationHost>()
        .map(|host| host.0.as_str())
}

impl Cache {
    async fn store<T>(
        &self,
        request: &Request<T>,
        instance: &str,
        write: bool,
    ) -> Result<Store, Status> {
        open(
            &self.0,
            organization(request),
            instance,
            &request.metadata().clone().into_headers(),
            write,
        )
        .await
        .map(|(store, _)| store)
        .map_err(status)
    }
}

#[tonic::async_trait]
impl capabilities_server::Capabilities for Cache {
    async fn get_capabilities(
        &self,
        request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<ServerCapabilities>, Status> {
        let store = self
            .store(&request, &request.get_ref().instance_name, false)
            .await?;
        let version = SemVer {
            major: 2,
            minor: 0,
            patch: 0,
            prerelease: String::new(),
        };
        Ok(Response::new(ServerCapabilities {
            low_api_version: Some(version.clone()),
            // Bazel uses output_paths at 2.1+, matching its HTTP cache keys.
            high_api_version: Some(SemVer {
                minor: 1,
                ..version
            }),
            cache_capabilities: Some(CacheCapabilities {
                digest_functions: vec![digest_function::Value::Sha256 as i32],
                symlink_absolute_path_strategy: symlink_absolute_path_strategy::Value::Allowed
                    as i32,
                action_cache_update_capabilities: Some(ActionCacheUpdateCapabilities {
                    update_enabled: true,
                }),
                max_batch_total_size_bytes: MAX_METADATA as i64,
                max_cas_blob_size_bytes: store.max_blob_size() as i64,
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl action_cache_server::ActionCache for Cache {
    async fn get_action_result(
        &self,
        request: Request<GetActionResultRequest>,
    ) -> Result<Response<ActionResult>, Status> {
        let store = self
            .store(&request, &request.get_ref().instance_name, false)
            .await?;
        let request = request.into_inner();
        algorithm(request.digest_function)?;
        let digest = digest(request.action_digest)?;
        let mut object = store
            .read("ac", &digest.hash)
            .await
            .map_err(io)?
            .ok_or_else(|| Status::not_found("Action result not found"))?;
        if object.metadata.size > MAX_METADATA as u64 {
            return Err(Status::not_found("Action result exceeds metadata limit"));
        }
        let mut bytes = Vec::new();
        object.reader.read_to_end(&mut bytes).await.map_err(io)?;
        let result = ActionResult::decode(bytes.as_slice())
            .map_err(|_| Status::data_loss("Invalid action result"))?;
        if !complete(&store, &result).await.map_err(status)? {
            return Err(Status::not_found("Action outputs were evicted"));
        }
        // Inlining is a client preference, not a requirement. Blob digests remain
        // available through CAS and ByteStream without expanding this response.
        Ok(Response::new(result))
    }

    async fn update_action_result(
        &self,
        request: Request<UpdateActionResultRequest>,
    ) -> Result<Response<ActionResult>, Status> {
        let store = self
            .store(&request, &request.get_ref().instance_name, true)
            .await?;
        let request = request.into_inner();
        algorithm(request.digest_function)?;
        let digest = digest(request.action_digest)?;
        let result = request
            .action_result
            .ok_or_else(|| Status::invalid_argument("Action result required"))?;
        if !complete(&store, &result).await.map_err(status)? {
            return Err(Status::failed_precondition("Action outputs are missing"));
        }
        let bytes = result.encode_to_vec();
        if bytes.len() > MAX_METADATA {
            return Err(Status::resource_exhausted(
                "Action result exceeds metadata limit",
            ));
        }
        store
            .write("ac", &digest.hash, bytes.len() as u64, Body::from(bytes))
            .await
            .map_err(io)?;
        Ok(Response::new(result))
    }
}

#[tonic::async_trait]
impl content_addressable_storage_server::ContentAddressableStorage for Cache {
    async fn find_missing_blobs(
        &self,
        request: Request<FindMissingBlobsRequest>,
    ) -> Result<Response<FindMissingBlobsResponse>, Status> {
        let store = self
            .store(&request, &request.get_ref().instance_name, false)
            .await?;
        let request = request.into_inner();
        algorithm(request.digest_function)?;
        if request.blob_digests.len() > 4096 {
            return Err(Status::resource_exhausted("Too many digests"));
        }
        use futures_util::TryStreamExt;
        let values = request
            .blob_digests
            .into_iter()
            .map(|value| digest(Some(value)))
            .collect::<Result<Vec<_>, _>>()?;
        let missing: Vec<_> = stream::iter(values.into_iter().map(|value| {
            let store = store.clone();
            async move {
                let absent = store
                    .stat("cas", &value.hash)
                    .await
                    .map_err(io)?
                    .is_none_or(|object| object.size != value.size_bytes as u64);
                Ok::<_, Status>(absent.then_some(value))
            }
        }))
        .buffer_unordered(32)
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .flatten()
        .collect();
        Ok(Response::new(FindMissingBlobsResponse {
            missing_blob_digests: missing,
        }))
    }

    async fn batch_update_blobs(
        &self,
        request: Request<BatchUpdateBlobsRequest>,
    ) -> Result<Response<BatchUpdateBlobsResponse>, Status> {
        let store = self
            .store(&request, &request.get_ref().instance_name, true)
            .await?;
        let request = request.into_inner();
        algorithm(request.digest_function)?;
        if request.requests.len() > 1024
            || request.requests.iter().map(|r| r.data.len()).sum::<usize>() > MAX_METADATA
        {
            return Err(Status::resource_exhausted("Batch exceeds advertised limit"));
        }
        let responses = stream::iter(request.requests.into_iter().map(|item| {
            let store = store.clone();
            async move {
                let value = async {
                    let digest = digest(item.digest.clone())?;
                    if item.compressor != 0 || digest.size_bytes as usize != item.data.len() {
                        return Err(Status::invalid_argument("Invalid uncompressed blob"));
                    }
                    store
                        .write(
                            "cas",
                            &digest.hash,
                            digest.size_bytes as u64,
                            Body::from(item.data),
                        )
                        .await
                        .map_err(io)
                }
                .await;
                batch_update_blobs_response::Response {
                    digest: item.digest,
                    status: wire_status(value),
                }
            }
        }))
        .buffer_unordered(8)
        .collect()
        .await;
        Ok(Response::new(BatchUpdateBlobsResponse { responses }))
    }

    async fn batch_read_blobs(
        &self,
        request: Request<BatchReadBlobsRequest>,
    ) -> Result<Response<BatchReadBlobsResponse>, Status> {
        let store = self
            .store(&request, &request.get_ref().instance_name, false)
            .await?;
        let request = request.into_inner();
        algorithm(request.digest_function)?;
        let total = request
            .digests
            .iter()
            .try_fold(0u64, |sum, d| {
                if !valid_digest(d) {
                    return None;
                }
                sum.checked_add(d.size_bytes as u64)
            })
            .ok_or_else(|| Status::invalid_argument("Invalid digest sizes"))?;
        if request.digests.len() > 1024 || total > MAX_METADATA as u64 {
            return Err(Status::resource_exhausted("Batch exceeds advertised limit"));
        }
        let responses = stream::iter(request.digests.into_iter().map(|digest| {
            let store = store.clone();
            async move {
                let result = blob(&store, &digest)
                    .await
                    .map_err(status)
                    .and_then(|bytes| bytes.ok_or_else(|| Status::not_found("Blob not found")));
                let (data, outcome) = match result {
                    Ok(data) => (data, Ok(())),
                    Err(error) => (Vec::new(), Err(error)),
                };
                batch_read_blobs_response::Response {
                    digest: Some(digest),
                    data,
                    compressor: 0,
                    status: wire_status(outcome),
                }
            }
        }))
        .buffer_unordered(8)
        .collect()
        .await;
        Ok(Response::new(BatchReadBlobsResponse { responses }))
    }

    type GetTreeStream = Responses<GetTreeResponse>;
    async fn get_tree(
        &self,
        request: Request<GetTreeRequest>,
    ) -> Result<Response<Self::GetTreeStream>, Status> {
        let store = self
            .store(&request, &request.get_ref().instance_name, false)
            .await?;
        let request = request.into_inner();
        algorithm(request.digest_function)?;
        if !request.page_token.is_empty() {
            return Err(Status::invalid_argument("Invalid page token"));
        }
        let root = digest(request.root_digest)?;
        let pending = VecDeque::from([root]);
        let stream = stream::try_unfold(
            (store, pending, BTreeSet::new()),
            |(store, mut pending, mut seen)| async move {
                while let Some(digest) = pending.pop_front() {
                    if !seen.insert(digest.hash.clone()) {
                        continue;
                    }
                    if seen.len() > 100_000 {
                        return Err(Status::resource_exhausted(
                            "Directory tree exceeds traversal limit",
                        ));
                    }
                    let Some(bytes) = blob(&store, &digest).await.map_err(status)? else {
                        if seen.len() == 1 {
                            return Err(Status::not_found("Directory root missing"));
                        }
                        // Evicted descendants do not hide available siblings.
                        continue;
                    };
                    let directory = Directory::decode(bytes.as_slice())
                        .map_err(|_| Status::data_loss("Invalid directory"))?;
                    for child in &directory.directories {
                        let child = child
                            .digest
                            .clone()
                            .filter(valid_digest)
                            .ok_or_else(|| Status::data_loss("Invalid child digest"))?;
                        pending.push_back(child);
                    }
                    if pending.len() > 100_000 {
                        return Err(Status::resource_exhausted(
                            "Directory tree exceeds traversal limit",
                        ));
                    }
                    return Ok(Some((
                        GetTreeResponse {
                            directories: vec![directory],
                            next_page_token: String::new(),
                        },
                        (store, pending, seen),
                    )));
                }
                Ok(None)
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }

    // Optional REAPI 2.12+ chunk mapping is not advertised by this 2.1 service.
    async fn split_blob(
        &self,
        _: Request<SplitBlobRequest>,
    ) -> Result<Response<SplitBlobResponse>, Status> {
        Err(Status::unimplemented("Chunk mapping is not advertised"))
    }
    type GetChunkMappingStream = Responses<GetChunkMappingResponse>;
    async fn get_chunk_mapping(
        &self,
        _: Request<GetChunkMappingRequest>,
    ) -> Result<Response<Self::GetChunkMappingStream>, Status> {
        Err(Status::unimplemented("Chunk mapping is not advertised"))
    }
    async fn splice_blob(
        &self,
        _: Request<SpliceBlobRequest>,
    ) -> Result<Response<SpliceBlobResponse>, Status> {
        Err(Status::unimplemented("Chunk mapping is not advertised"))
    }
    async fn register_chunk_mapping(
        &self,
        _: Request<tonic::Streaming<RegisterChunkMappingRequest>>,
    ) -> Result<Response<RegisterChunkMappingResponse>, Status> {
        Err(Status::unimplemented("Chunk mapping is not advertised"))
    }
}

pub(super) fn router(state: AppState) -> axum::Router<AppState> {
    let service = Cache(state);
    axum::Router::new()
        .route_service(
            "/build.bazel.remote.execution.v2.Capabilities/{method}",
            capabilities_server::CapabilitiesServer::new(service.clone()),
        )
        .route_service(
            "/build.bazel.remote.execution.v2.ActionCache/{method}",
            action_cache_server::ActionCacheServer::new(service.clone())
                .max_decoding_message_size(MAX_METADATA + 65536),
        )
        .route_service(
            "/build.bazel.remote.execution.v2.ContentAddressableStorage/{method}",
            content_addressable_storage_server::ContentAddressableStorageServer::new(
                service.clone(),
            )
            .max_decoding_message_size(MAX_METADATA + 65536),
        )
        .route_service(
            "/google.bytestream.ByteStream/{method}",
            bs::byte_stream_server::ByteStreamServer::new(service)
                .max_decoding_message_size(MAX_METADATA + 65536),
        )
}

/// Parses a ByteStream resource name. On an organization host the name has
/// no owner segment, so `depth` is the number of instance segments before the
/// protocol path: two (`<slug>/<cache>`) on the shared host, one (`<cache>`)
/// on an organization host.
fn resource(name: &str, write: bool, org_host: bool) -> Result<(String, Digest), Status> {
    let parts: Vec<_> = name.split('/').collect();
    let depth = if org_host { 1 } else { 2 };
    let (hash, size) = if write
        && parts.len() >= depth + 5
        && parts[depth] == "uploads"
        && parts[depth + 2] == "blobs"
        && !parts[depth + 1].is_empty()
        && parts[depth + 1].len() <= 128
        && parts[depth + 1]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
    {
        (parts[depth + 3], parts[depth + 4])
    } else if !write && parts.len() == depth + 3 && parts[depth] == "blobs" {
        (parts[depth + 1], parts[depth + 2])
    } else {
        return Err(Status::invalid_argument("Invalid ByteStream resource name"));
    };
    if size.is_empty() || !size.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Status::invalid_argument("Invalid blob size"));
    }
    let digest = digest(Some(Digest {
        hash: hash.to_owned(),
        size_bytes: size
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid blob size"))?,
    }))?;
    Ok((parts[..depth].join("/"), digest))
}

#[tonic::async_trait]
impl ByteStream for Cache {
    type ReadStream = Responses<bs::ReadResponse>;
    async fn read(
        &self,
        request: Request<bs::ReadRequest>,
    ) -> Result<Response<Self::ReadStream>, Status> {
        let (instance, digest) = resource(
            &request.get_ref().resource_name,
            false,
            organization(&request).is_some(),
        )?;
        let store = self.store(&request, &instance, false).await?;
        let request = request.into_inner();
        if request.read_offset < 0 || request.read_limit < 0 {
            return Err(Status::invalid_argument("Negative read offset or limit"));
        }
        if request.read_offset > digest.size_bytes {
            return Err(Status::out_of_range("Read offset exceeds blob size"));
        }
        let object = store
            .read("cas", &digest.hash)
            .await
            .map_err(io)?
            .ok_or_else(|| Status::not_found("Blob not found"))?;
        if object.metadata.size != digest.size_bytes as u64 {
            return Err(Status::not_found("Blob size mismatch"));
        }
        let start = request.read_offset as u64;
        let end = if request.read_limit == 0 {
            object.metadata.size
        } else {
            start
                .saturating_add(request.read_limit as u64)
                .min(object.metadata.size)
        };
        if start == end {
            return Ok(Response::new(Box::pin(stream::empty())));
        }
        let reader = if start == 0 && end == object.metadata.size {
            object.reader
        } else {
            let object = self
                .0
                .storage
                .private_store()
                .get_opts(
                    &object.metadata.location,
                    object_store::GetOptions {
                        range: Some((start..end).into()),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| Status::unavailable("Blob range read failed"))?;
            let stream = object
                .into_stream()
                .map(|value| value.map_err(std::io::Error::other));
            Box::new(tokio_util::io::StreamReader::new(stream))
                as Box<dyn tokio::io::AsyncRead + Unpin + Send>
        };
        Ok(Response::new(Box::pin(
            ReaderStream::with_capacity(reader, 256 * 1024).map(|value| {
                value
                    .map(|data| bs::ReadResponse {
                        data: data.to_vec(),
                    })
                    .map_err(io)
            }),
        )))
    }

    async fn write(
        &self,
        request: Request<tonic::Streaming<bs::WriteRequest>>,
    ) -> Result<Response<bs::WriteResponse>, Status> {
        let absolute_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
        // This deadline covers authorization, receiving, persistence, and final
        // verification. The byte-progress deadline below only covers receiving.
        let result = tokio::time::timeout_at(absolute_deadline, async {
            let mut progress_deadline =
                tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            let headers = request.metadata().clone().into_headers();
            // Extensions do not survive `into_inner`, so capture the owner first.
            let owner = organization(&request).map(str::to_owned);
            let mut stream = request.into_inner();
            let first = tokio::time::timeout_at(progress_deadline, stream.message())
                .await
                .map_err(|_| Status::deadline_exceeded("Upload made no byte progress"))??
                .ok_or_else(|| Status::invalid_argument("Write request required"))?;
            let name = first.resource_name.clone();
            let (instance, digest) = resource(&name, true, owner.is_some())?;
            let (store, _) = open(&self.0, owner.as_deref(), &instance, &headers, true)
                .await
                .map_err(status)?;
            let size = digest.size_bytes as u64;
            if size > store.max_blob_size() {
                return Err(Status::invalid_argument(
                    "Blob exceeds advertised size limit",
                ));
            }
            let (mut offset, completed) = match store.upload_status(&name, &digest.hash, size).await
            {
                Ok(status) => status,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (0, false),
                Err(error) => return Err(io(error)),
            };
            if completed {
                return Ok(Response::new(bs::WriteResponse {
                    committed_size: size as i64,
                }));
            }
            if size > 8 * 1024 * 1024 && offset < size {
                use std::sync::{
                    Arc,
                    atomic::{AtomicBool, Ordering},
                };
                let finished = Arc::new(AtomicBool::new(false));
                let completed_stream = finished.clone();
                let stream_name = name.clone();
                let (error_sender, mut error_receiver) = tokio::sync::oneshot::channel();
                let incoming = stream::try_unfold(
                    (
                        stream,
                        Some(first),
                        offset,
                        None::<tokio::time::Instant>,
                        Some(error_sender),
                    ),
                    move |(mut stream, first, mut position, deadline, mut error_sender)| {
                        let name = stream_name.clone();
                        let finished = completed_stream.clone();
                        async move {
                            if finished.load(Ordering::Relaxed) {
                                return Ok(None);
                            }
                            // Do not charge storage backpressure or prefix replay
                            // against the client's receive-progress deadline.
                            let deadline = deadline.unwrap_or_else(|| {
                                tokio::time::Instant::now() + std::time::Duration::from_secs(30)
                            });
                            let read = async {
                                if tokio::time::Instant::now() >= deadline {
                                    return Err(Status::deadline_exceeded(
                                        "Upload made no byte progress",
                                    ));
                                }
                                let message = match first {
                                    Some(message) => Some(message),
                                    None => tokio::time::timeout_at(deadline, stream.message())
                                        .await
                                        .map_err(|_| {
                                            Status::deadline_exceeded(
                                                "Upload made no byte progress",
                                            )
                                        })??,
                                };
                                let Some(message) = message else {
                                    return Ok(None);
                                };
                                if (!message.resource_name.is_empty()
                                    && message.resource_name != name)
                                    || message.write_offset < 0
                                    || message.write_offset as u64 != position
                                {
                                    return Err(Status::out_of_range(
                                        "Write offset does not match committed bytes",
                                    ));
                                }
                                if message.data.len() as u64 > size - position {
                                    return Err(Status::invalid_argument(
                                        "Write exceeds declared size",
                                    ));
                                }
                                position += message.data.len() as u64;
                                if message.finish_write {
                                    if position != size {
                                        return Err(Status::invalid_argument(
                                            "Write ended before declared size",
                                        ));
                                    }
                                    finished.store(true, Ordering::Relaxed);
                                }
                                Ok(Some(axum::body::Bytes::from(message.data)))
                            }
                            .await;
                            match read {
                                Ok(Some(bytes)) => {
                                    let deadline = bytes.is_empty().then_some(deadline);
                                    Ok(Some((
                                        bytes,
                                        (stream, None, position, deadline, error_sender),
                                    )))
                                }
                                Ok(None) => Ok(None),
                                Err(error) => {
                                    if let Some(sender) = error_sender.take() {
                                        let _ = sender.send(error);
                                    }
                                    Err(std::io::Error::other("ByteStream input failed"))
                                }
                            }
                        }
                    },
                );
                let result = store
                    .write_stream(
                        &name,
                        &digest.hash,
                        size,
                        offset,
                        Body::from_stream(incoming),
                        finished.clone(),
                    )
                    .await;
                if let Ok(error) = error_receiver.try_recv() {
                    return Err(error);
                }
                let committed = result.map_err(io)?;
                if !finished.load(Ordering::Relaxed) {
                    return Err(Status::invalid_argument(
                        "finish_write is required; resume at committed_size",
                    ));
                }
                return Ok(Response::new(bs::WriteResponse {
                    committed_size: committed as i64,
                }));
            }
            let remaining = (size - offset) as usize;
            let _memory = self.0.storage.upload_buffer(remaining).map_err(status)?;
            let mut buffer = Vec::with_capacity(remaining);
            let mut next = Some(first);
            let mut finished = false;
            while let Some(message) = next {
                // timeout_at polls its inner future first. Explicitly check clocks
                // so an always-ready stream of empty messages cannot evade either
                // deadline (or renew progress after it has already expired).
                let now = tokio::time::Instant::now();
                if now >= absolute_deadline {
                    return Err(Status::deadline_exceeded("Upload exceeded one hour"));
                }
                if now >= progress_deadline {
                    return Err(Status::deadline_exceeded("Upload made no byte progress"));
                }
                if (!message.resource_name.is_empty() && message.resource_name != name)
                    || message.write_offset < 0
                    || message.write_offset as u64 != offset + buffer.len() as u64
                {
                    return Err(Status::out_of_range(
                        "Write offset does not match committed bytes",
                    ));
                }
                if offset + buffer.len() as u64 + message.data.len() as u64 > size {
                    return Err(Status::invalid_argument("Write exceeds declared size"));
                }
                if !message.data.is_empty() {
                    progress_deadline = now + std::time::Duration::from_secs(30);
                }
                // A complete small blob stays buffered until finish_write,
                // including when that flag arrives in an empty message.
                buffer.extend_from_slice(&message.data);
                if message.finish_write {
                    finished = true;
                    break;
                }
                next = tokio::time::timeout_at(progress_deadline, stream.message())
                    .await
                    .map_err(|_| Status::deadline_exceeded("Upload made no byte progress"))??;
            }
            if finished && offset == 0 && buffer.len() as u64 == size {
                store
                    .write_buffered(&digest.hash, buffer, _memory)
                    .await
                    .map_err(io)?;
                return Ok(Response::new(bs::WriteResponse {
                    committed_size: size as i64,
                }));
            }
            if !buffer.is_empty() || size == 0 {
                offset = store
                    .append(&name, &digest.hash, size, offset, buffer)
                    .await
                    .map_err(io)?;
            }
            if !finished {
                return Err(Status::invalid_argument(
                    "finish_write is required; resume at committed_size",
                ));
            }
            if offset != size {
                return Err(Status::invalid_argument("Write ended before declared size"));
            }
            // The receive buffer has been persisted. Final verification acquires
            // its own multipart budget; holding both would starve concurrent writes.
            drop(_memory);
            store
                .finish_upload(&name, &digest.hash, size)
                .await
                .map_err(io)?;
            Ok(Response::new(bs::WriteResponse {
                committed_size: size as i64,
            }))
        })
        .await
        .map_err(|_| Status::deadline_exceeded("Upload exceeded one hour"))?;
        if tokio::time::Instant::now() >= absolute_deadline {
            return Err(Status::deadline_exceeded("Upload exceeded one hour"));
        }
        result
    }

    async fn query_write_status(
        &self,
        request: Request<bs::QueryWriteStatusRequest>,
    ) -> Result<Response<bs::QueryWriteStatusResponse>, Status> {
        let (instance, digest) = resource(
            &request.get_ref().resource_name,
            true,
            organization(&request).is_some(),
        )?;
        let store = self.store(&request, &instance, true).await?;
        let (committed, complete) = store
            .upload_status(
                &request.get_ref().resource_name,
                &digest.hash,
                digest.size_bytes as u64,
            )
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Status::not_found("Upload session not found")
                } else {
                    io(error)
                }
            })?;
        Ok(Response::new(bs::QueryWriteStatusResponse {
            committed_size: committed as i64,
            complete,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::resource;

    fn hash() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn resource_names_follow_the_host() {
        let h = hash();
        // Shared host: the instance is `<slug>/<cache>`.
        let (instance, digest) =
            resource(&format!("alpha/private/blobs/{h}/3"), false, false).expect("shared read");
        assert_eq!(instance, "alpha/private");
        assert_eq!((digest.hash.as_str(), digest.size_bytes), (h.as_str(), 3));
        let (instance, _) = resource(
            &format!("alpha/private/uploads/u-1/blobs/{h}/3"),
            true,
            false,
        )
        .expect("shared write");
        assert_eq!(instance, "alpha/private");
        // The organization host's name has no owner, so the shared shape is refused.
        assert!(resource(&format!("alpha/private/blobs/{h}/3"), false, true).is_err());
        assert!(
            resource(
                &format!("alpha/private/uploads/u-1/blobs/{h}/3"),
                true,
                true
            )
            .is_err()
        );

        // Organization host: the instance is `<cache>`.
        let (instance, _) =
            resource(&format!("private/blobs/{h}/3"), false, true).expect("organization read");
        assert_eq!(instance, "private");
        let (instance, digest) = resource(&format!("private/uploads/u-1/blobs/{h}/3"), true, true)
            .expect("organization write");
        assert_eq!(instance, "private");
        assert_eq!(digest.size_bytes, 3);
    }
}
