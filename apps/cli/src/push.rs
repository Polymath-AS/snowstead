use crate::{
    api::{self, Client, SessionParams},
    batch::Batcher,
    nar, nix,
};
use anyhow::{Context, bail};
use futures_util::{StreamExt, TryStreamExt};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet},
    io::{self, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tracing::Instrument;

pub struct Summary {
    pub pushed: usize,
    pub skipped: usize,
    pub upstream: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

#[cfg_attr(snowstead_hotpath, hotpath::measure)]
pub async fn push(
    client: &Client,
    cache: &str,
    paths: Vec<String>,
    jobs: usize,
    level: i32,
) -> anyhow::Result<Summary> {
    if jobs == 0 {
        bail!("--jobs must be positive")
    }
    let mut unique = BTreeMap::new();
    for path in paths {
        let path = if path.starts_with("/nix/store/") {
            path
        } else {
            std::fs::canonicalize(path)?
                .to_str()
                .context("store path is not UTF-8")?
                .to_owned()
        };
        let base = path
            .strip_prefix("/nix/store/")
            .context("path is not in /nix/store")?;
        let (hash, name) = base.split_once('-').context("invalid store path")?;
        if hash.len() != 32
            || !hash
                .bytes()
                .all(|c| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&c))
            || name.is_empty()
            || name.contains('/')
        {
            bail!("invalid store path: {path}")
        }
        unique.insert(hash.to_owned(), path);
    }
    let hashes: Vec<_> = unique.keys().cloned().collect();
    let answers: Vec<_> =
        futures_util::stream::iter(hashes.chunks(500).map(|chunk| client.missing(cache, chunk)))
            .buffer_unordered(8)
            .try_collect()
            .await?;
    let mut missing: HashSet<_> = answers
        .iter()
        .flat_map(|a| a.missing.iter().cloned())
        .collect();
    let mut upstream: HashSet<_> = answers
        .iter()
        .flat_map(|a| a.upstream.iter().cloned())
        .collect();
    let unchecked: HashSet<_> = answers
        .iter()
        .flat_map(|a| a.unchecked.iter().cloned())
        .collect();
    let upstreams: HashSet<_> = answers
        .iter()
        .flat_map(|a| a.upstreams.iter().cloned())
        .collect();
    let mut checks = futures_util::stream::iter(unchecked.into_iter().map(|hash| {
        let upstreams = &upstreams;
        async move {
            for url in upstreams {
                if client.upstream_has(url, &hash).await {
                    return Some(hash);
                }
            }
            None
        }
    }))
    .buffer_unordered(64);
    while let Some(found) = checks.next().await {
        if let Some(hash) = found {
            missing.remove(&hash);
            upstream.insert(hash);
        }
    }
    let todo: Vec<_> = unique
        .iter()
        .filter(|(h, _)| missing.contains(*h))
        .map(|(_, p)| p.clone())
        .collect();
    let mut summary = Summary {
        pushed: 0,
        skipped: unique.len() - todo.len(),
        upstream: upstream.len(),
        failed: 0,
        errors: Vec::new(),
    };
    tracing::debug!(
        paths = unique.len(),
        missing = todo.len(),
        upstream = summary.upstream,
        "checked remote availability"
    );
    if todo.is_empty() {
        return Ok(summary);
    }
    let mut infos = nix::path_infos(&todo).await?;
    let mut ordered = Vec::with_capacity(todo.len());
    for path in todo {
        ordered.push(
            infos
                .remove(&path)
                .with_context(|| format!("missing path info for {path}"))?,
        );
    }
    let ordered = publish_order(ordered);
    // Each path publishes only after the references pushed alongside it have.
    // Paths start in publish order, so every wait is on an earlier path that
    // already holds a job slot or has finished: waits cannot deadlock.
    let mut published = HashMap::new();
    let mut outcomes = Vec::with_capacity(ordered.len());
    for info in &ordered {
        let (sender, receiver) = watch::channel(None::<bool>);
        published.insert(basename(info).to_owned(), receiver);
        outcomes.push(sender);
    }
    let published = &published;
    let cpu = std::thread::available_parallelism().map_or(1, usize::from);
    // Independent paths already use blocking workers. Large NARs get codec
    // workers too, charging the producer and workers to one CPU budget.
    const LARGE_NAR: u64 = 64 * 1024 * 1024;
    let large_threads = cpu.saturating_sub(1).min(4) as i32;
    let compression = Arc::new(Semaphore::new(cpu));
    let parts = Arc::new(Semaphore::new(16));
    // Negotiate first so one global byte semaphore can enforce the exact
    // max(64 MiB, largest part) budget even with mixed-size sessions.
    let mut sessions = Vec::with_capacity(ordered.len());
    let mut largest = 64 * 1024 * 1024;
    for chunk in ordered.chunks(100) {
        let specs: Vec<_> = chunk
            .iter()
            .map(|info| SessionParams {
                store_path: info.store_path.clone(),
                store_path_hash: info.store_path_hash.clone(),
                nar_hash: info.nar_hash.clone(),
                nar_size: info.nar_size,
                compression: "zstd".into(),
                references: info.references.clone(),
                deriver: info.deriver.clone(),
            })
            .collect();
        let rows = client.create_sessions(cache, &specs).await?;
        let count = rows.len();
        for session in rows {
            let guard = AbortGuard::new(client.clone(), session.session_id.clone());
            sessions.push((session, guard));
        }
        if count != chunk.len() {
            bail!("API batch response length differs from request");
        }
    }
    for (session, _) in &sessions {
        if session.part_size == 0 || session.part_size > 1024 * 1024 * 1024 {
            bail!("invalid multipart part size");
        }
        largest = largest.max(session.part_size as usize);
    }
    let buffers = Arc::new(Semaphore::new(largest));
    let session_ids: Vec<_> = sessions
        .iter()
        .map(|(session, _)| session.session_id.clone())
        .collect();
    let multipart_client = client.clone();
    let multipart_commits = Batcher::new(
        jobs.min(8),
        Duration::from_millis(10),
        move |uploads: Vec<api::Finalize>| {
            let client = multipart_client.clone();
            async move { client.finalize(&uploads).await }
        },
    );
    let mut work = futures_util::stream::iter(ordered.into_iter().zip(sessions).zip(outcomes).map(
        |((info, (session, mut guard)), outcome)| {
            let compression = compression.clone();
            let parts = parts.clone();
            let buffers = buffers.clone();
            let multipart_commits = multipart_commits.clone();
            let span = tracing::debug_span!("push_path",path=%info.store_path);
            async move {
                let path = info.store_path.clone();
                let start = Instant::now();
                let result = async {
                    let threads = if info.nar_size >= LARGE_NAR {
                        large_threads
                    } else {
                        0
                    };
                    let permit = compression.acquire_many_owned(threads as u32 + 1).await?;
                    let file_path = path.clone();
                    let expected = info.nar_hash.clone();
                    let size = info.nar_size;
                    let (sender, receiver) = mpsc::channel(1);
                    let mut writer = Bridge::new(session.part_size as usize, buffers, sender);
                    let producer = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let digest =
                            nar::dump(Path::new(&file_path), size, level, threads, &mut writer)?;
                        if digest.nar_size != size
                            || Some(digest.nar_hash) != nar::parse_hash(&expected)
                        {
                            bail!("NAR hash or size differs from the Nix database for {file_path}");
                        }
                        writer.finish()?;
                        Ok::<_, anyhow::Error>(digest)
                    });
                    let uploaded = upload_parts(client, &session.session_id, receiver, parts).await;
                    // upload_parts drops its receiver on error, waking a blocked
                    // producer before we join it. Cancellation does the same.
                    let digest = producer.await?;
                    let uploaded = uploaded?;
                    let digest = digest?;
                    let own = basename(&info);
                    for reference in info.references.iter().filter(|r| *r != own) {
                        let Some(mut done) = published.get(reference).cloned() else {
                            continue;
                        };
                        let ok = done.wait_for(Option::is_some).await;
                        if !matches!(ok.as_deref(), Ok(Some(true))) {
                            bail!("dependency {reference} was not published");
                        }
                    }
                    let published = multipart_commits
                        .request(api::Finalize {
                            session_id: session.session_id.clone(),
                            nar_hash: info.nar_hash,
                            nar_size: digest.nar_size,
                            file_hash: hex::encode(digest.file_hash),
                            file_size: digest.file_size,
                            parts: uploaded,
                        })
                        .await?;
                    if published.session_id != session.session_id || !published.published {
                        tracing::debug!(
                            has_error = published.error.is_some(),
                            "publication rejected"
                        );
                        bail!(
                            "publication failed (status {})",
                            published.status.unwrap_or(500)
                        )
                    }
                    guard.disarm();
                    tracing::debug!(
                        elapsed_ms = start.elapsed().as_millis(),
                        compressed_bytes = digest.file_size,
                        "published store path"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                outcome.send_replace(Some(result.is_ok()));
                if result.is_err() {
                    guard.abort().await;
                }
                (path, result)
            }
            .instrument(span)
        },
    ))
    .buffer_unordered(jobs);
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    loop {
        let next = tokio::select! {
            next = work.next() => next,
            _ = &mut interrupt => {
                // Closing receivers wakes both channel-blocked and byte-budget-
                // blocked native workers. Give abort requests a bounded grace
                // period before the CLI tears down its runtime. Guard drops may
                // also abort: the endpoint is deliberately idempotent.
                drop(work);
                let cleanup = futures_util::stream::iter(session_ids.iter().map(|id| client.abort(id)))
                    .buffer_unordered(16).collect::<Vec<_>>();
                let _ = tokio::time::timeout(Duration::from_secs(5), cleanup).await;
                bail!("upload cancelled");
            }
        };
        let Some((path, result)) = next else {
            break;
        };
        match result {
            Ok(()) => summary.pushed += 1,
            Err(error) => {
                summary.failed += 1;
                summary.errors.push(format!("{path}: {error:#}"));
            }
        }
    }
    Ok(summary)
}

fn basename(info: &nix::PathInfo) -> &str {
    &info.store_path["/nix/store/".len()..]
}

/// Dependencies before dependents, so a published narinfo never names a
/// reference that is still uploading. Among ready paths, smaller NARs go
/// first to fill the pipeline while larger ones use codec workers.
fn publish_order(infos: Vec<nix::PathInfo>) -> Vec<nix::PathInfo> {
    let index: HashMap<&str, usize> = infos
        .iter()
        .enumerate()
        .map(|(i, info)| (basename(info), i))
        .collect();
    let mut waiting = vec![0usize; infos.len()];
    let mut dependents = vec![Vec::new(); infos.len()];
    for (i, info) in infos.iter().enumerate() {
        for reference in &info.references {
            if let Some(&dep) = index.get(reference.as_str())
                && dep != i
            {
                waiting[i] += 1;
                dependents[dep].push(i);
            }
        }
    }
    let mut ready: BinaryHeap<_> = (0..infos.len())
        .filter(|&i| waiting[i] == 0)
        .map(|i| Reverse((infos[i].nar_size, i)))
        .collect();
    let mut order = Vec::with_capacity(infos.len());
    while let Some(Reverse((_, i))) = ready.pop() {
        order.push(i);
        for &next in &dependents[i] {
            waiting[next] -= 1;
            if waiting[next] == 0 {
                ready.push(Reverse((infos[next].nar_size, next)));
            }
        }
    }
    // Store references are acyclic apart from self-references, skipped above.
    let mut infos: Vec<_> = infos.into_iter().map(Some).collect();
    order.into_iter().filter_map(|i| infos[i].take()).collect()
}

// The permit belongs to the bytes, including any clones retained by HTTP
// transports after a future is cancelled. No replay allocation escapes accounting.
struct Buffer {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
struct Bridge {
    size: usize,
    budget: Arc<Semaphore>,
    sender: mpsc::Sender<(u32, bytes::Bytes)>,
    current: Option<Buffer>,
    number: u32,
    runtime: tokio::runtime::Handle,
}
impl Bridge {
    fn new(size: usize, budget: Arc<Semaphore>, sender: mpsc::Sender<(u32, bytes::Bytes)>) -> Self {
        Self {
            size,
            budget,
            sender,
            current: None,
            number: 1,
            runtime: tokio::runtime::Handle::current(),
        }
    }
    fn finish(&mut self) -> io::Result<()> {
        if let Some(buffer) = self.current.take() {
            self.sender
                .blocking_send((self.number, bytes::Bytes::from_owner(buffer)))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "upload stopped"))?;
            self.number += 1;
        }
        Ok(())
    }
}
impl Write for Bridge {
    #[cfg_attr(snowstead_hotpath, hotpath::measure)]
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let len = bytes.len();
        while !bytes.is_empty() {
            if self.sender.is_closed() {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "upload stopped"));
            }
            if self.current.is_none() {
                if self.number > 10_000 {
                    return Err(io::Error::other("too many upload parts"));
                }
                let permit = self.runtime.block_on(async {
                    tokio::select! {
                        permit = self.budget.clone().acquire_many_owned(self.size as u32) => permit.map_err(|_| io::Error::other("upload budget closed")),
                        _ = self.sender.closed() => Err(io::Error::new(io::ErrorKind::BrokenPipe, "upload stopped")),
                    }
                })?;
                self.current = Some(Buffer {
                    bytes: Vec::with_capacity(self.size),
                    _permit: permit,
                });
            }
            let current = self.current.as_mut().unwrap();
            let count = bytes.len().min(self.size - current.bytes.len());
            current.bytes.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if current.bytes.len() == self.size {
                self.finish()?;
            }
        }
        Ok(len)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg_attr(snowstead_hotpath, hotpath::measure)]
async fn upload_parts(
    client: &Client,
    id: &str,
    receiver: mpsc::Receiver<(u32, bytes::Bytes)>,
    limit: Arc<Semaphore>,
) -> anyhow::Result<Vec<api::UploadedPart>> {
    let mut parts: Vec<_> = futures_util::stream::unfold(receiver, |mut receiver| async {
        receiver.recv().await.map(|part| (part, receiver))
    })
    .map(|(number, bytes)| {
        let limit = limit.clone();
        async move {
            let _permit = limit.acquire().await?;
            client.upload_part(id, number, bytes).await
        }
    })
    .buffer_unordered(4)
    .try_collect()
    .await?;
    parts.sort_by_key(|part| part.part_number);
    Ok(parts)
}
struct AbortGuard {
    client: Client,
    id: Option<String>,
}
impl AbortGuard {
    fn new(client: Client, id: String) -> Self {
        Self {
            client,
            id: Some(id),
        }
    }
    fn disarm(&mut self) {
        self.id = None;
    }
    async fn abort(&mut self) {
        if let Some(id) = &self.id {
            let _ = tokio::time::timeout(Duration::from_secs(5), self.client.abort(id)).await;
        }
        self.disarm();
    }
}
impl Drop for AbortGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let client = self.client.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(5), client.abort(&id)).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::{client, read, reply};
    use serde_json::{Value, json};
    use tokio::{net::TcpListener, sync::Notify};

    #[test]
    fn publish_order_puts_references_first_even_when_larger() {
        let info = |name: &str, size: u64, references: &[&str]| nix::PathInfo {
            store_path: format!("/nix/store/{name}"),
            store_path_hash: name[..32].into(),
            nar_hash: String::new(),
            nar_size: size,
            references: references.iter().map(|r| r.to_string()).collect(),
            deriver: None,
        };
        let lib = "00000000000000000000000000000000-lib";
        let app = "11111111111111111111111111111111-app";
        let doc = "22222222222222222222222222222222-doc";
        let tool = "33333333333333333333333333333333-tool";
        let order: Vec<_> = publish_order(vec![
            info(
                app,
                1,
                &[app, lib, "44444444444444444444444444444444-elsewhere"],
            ),
            info(lib, 1000, &[lib]),
            info(doc, 5, &[]),
            info(tool, 500, &[app]),
        ])
        .into_iter()
        .map(|i| i.store_path[11..].to_owned())
        .collect();
        // Size alone would give app, doc, tool, lib.
        assert_eq!(order, [doc, lib, app, tool]);
    }

    #[tokio::test]
    async fn native_stream_starts_before_completion_bounds_all_producers_and_cleans_up() {
        for cancel in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("data");
            // Incompressible input ensures many parts, without a second NAR pass.
            let data: Vec<u8> = (0..128 * 1024).map(|_| rand::random::<u8>()).collect();
            std::fs::write(&path, data).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let received = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let aborted = Arc::new(Notify::new());
            let server = tokio::spawn({
                let received = received.clone();
                let release = release.clone();
                let aborted = aborted.clone();
                let origin = url.clone();
                async move {
                    loop {
                        let (mut socket, _) = listener.accept().await.unwrap();
                        let origin = origin.clone();
                        let received = received.clone();
                        let release = release.clone();
                        let aborted = aborted.clone();
                        tokio::spawn(async move {
                            let (headers, body) = read(&mut socket).await;
                            if headers.starts_with("POST /_api/v1/uploads/s1/parts ") {
                                let body: Value = serde_json::from_slice(&body).unwrap();
                                assert_eq!(body["parts"][0]["size"], 1024);
                                let number = &body["parts"][0]["partNumber"];
                                reply(&mut socket, 200, &json!({"parts":[{"partNumber":number,"url":format!("{origin}/part"),"headers":{}}]}).to_string(), "").await;
                            } else if headers.starts_with("PUT /part ") {
                                assert_eq!(body.len(), 1024);
                                received.notify_one();
                                release.notified().await;
                                if !cancel {
                                    reply(&mut socket, 403, "denied", "").await;
                                }
                            } else {
                                assert!(headers.starts_with("POST /_api/v1/uploads/s1/abort "));
                                reply(&mut socket, 200, "{}", "").await;
                                aborted.notify_one();
                            }
                        });
                    }
                }
            });
            // Scale the byte budget down to two parts. The same semaphore is
            // shared by two native producers, not recreated for each path.
            let budget = Arc::new(Semaphore::new(2048));
            let mut producers = Vec::new();
            let mut receivers = Vec::new();
            for _ in 0..2 {
                let (sender, receiver) = mpsc::channel(1);
                let mut writer = Bridge::new(1024, budget.clone(), sender);
                let path = path.clone();
                producers.push(tokio::task::spawn_blocking(move || {
                    nar::dump(&path, 0, 3, 0, &mut writer)?;
                    writer.finish()?;
                    Ok::<_, anyhow::Error>(())
                }));
                receivers.push(receiver);
            }
            let client = client(&url);
            let consumer = tokio::spawn(async move {
                let mut guard = AbortGuard::new(client.clone(), "s1".into());
                let limit = Arc::new(Semaphore::new(1));
                let tasks = receivers
                    .into_iter()
                    .map(|receiver| upload_parts(&client, "s1", receiver, limit.clone()));
                let result = futures_util::future::try_join_all(tasks).await;
                assert!(result.is_err());
                guard.abort().await;
            });
            tokio::time::timeout(Duration::from_secs(5), received.notified())
                .await
                .unwrap();
            assert!(
                producers.iter().all(|producer| !producer.is_finished()),
                "HTTP must start before either encoder finishes"
            );
            assert_eq!(budget.available_permits(), 0);
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(
                producers.iter().all(|producer| !producer.is_finished()),
                "slow HTTP must backpressure both encoders"
            );
            if cancel {
                consumer.abort();
            }
            release.notify_waiters();
            if cancel {
                assert!(consumer.await.unwrap_err().is_cancelled());
            } else {
                tokio::time::timeout(Duration::from_secs(5), consumer)
                    .await
                    .unwrap()
                    .unwrap();
            }
            for producer in producers {
                assert!(
                    tokio::time::timeout(Duration::from_secs(5), producer)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
            }
            tokio::time::timeout(Duration::from_secs(5), aborted.notified())
                .await
                .unwrap();
            // The HTTP transport can briefly retain an owned body after cancellation.
            tokio::time::timeout(Duration::from_secs(5), async {
                while budget.available_permits() != 2048 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            server.abort();
        }
    }
}
