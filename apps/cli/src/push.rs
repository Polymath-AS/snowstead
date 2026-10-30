use crate::{
    api::{self, Client, CommitResult, Session, SessionParams},
    batch::Batcher,
    nar, nix,
};
use anyhow::{Context, bail};
use futures_util::{StreamExt, TryStreamExt};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Instant,
};
use tokio::sync::{Mutex, Semaphore};
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
    // Fill the upload pipeline with short preparations before a large NAR
    // reserves the compression budget for its producer and codec workers.
    ordered.sort_unstable_by_key(|i| i.nar_size);
    let cpu = std::thread::available_parallelism().map_or(1, usize::from);
    // Independent paths already use blocking workers. Large NARs get codec
    // workers too, charging the producer and workers to one CPU budget.
    const LARGE_NAR: u64 = 64 * 1024 * 1024;
    let large_threads = cpu.saturating_sub(1).min(4) as i32;
    let compression = Arc::new(Semaphore::new(cpu));
    let parts = Arc::new(Semaphore::new(16));
    let object_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let session_client = client.clone();
    let cache_owned = cache.to_owned();
    let sessions: Batcher<SessionParams, Session> = Batcher::new(move |specs| {
        let client = session_client.clone();
        let cache = cache_owned.clone();
        async move { client.create_sessions(&cache, &specs).await }
    });
    let commit_client = client.clone();
    let commits: Batcher<String, CommitResult> = Batcher::new(move |ids| {
        let client = commit_client.clone();
        async move { client.commit(&ids, None).await }
    });
    let mut work = futures_util::stream::iter(ordered.into_iter().map(|info| {
        let compression = compression.clone();
        let parts = parts.clone();
        let sessions = sessions.clone();
        let commits = commits.clone();
        let locks = object_locks.clone();
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
                let encoded = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    nar::prepare(Path::new(&file_path), size, &expected, level, threads)
                })
                .await??;
                tracing::debug!(
                    elapsed_ms = start.elapsed().as_millis(),
                    nar_bytes = size,
                    compressed_bytes = encoded.digest.file_size,
                    compression_threads = threads,
                    "compressed NAR"
                );
                let session = sessions
                    .request(SessionParams {
                        store_path: info.store_path,
                        store_path_hash: info.store_path_hash,
                        nar_hash: info.nar_hash,
                        nar_size: info.nar_size,
                        file_hash: hex::encode(encoded.digest.file_hash),
                        file_size: encoded.digest.file_size,
                        compression: "zstd".into(),
                        references: info.references,
                        deriver: info.deriver,
                    })
                    .await?;
                let lock = {
                    let mut locks = locks.lock().await;
                    locks
                        .entry(session.r2_key.clone())
                        .or_insert_with(|| Arc::new(Mutex::new(())))
                        .clone()
                };
                let _guard = lock.lock().await;
                let published = match session.upload_method.as_str() {
                    "presigned-parts" => {
                        let uploaded = client
                            .upload_presigned_parts(&session, &encoded.path, parts)
                            .await?;
                        let map = HashMap::from([(session.session_id.clone(), uploaded)]);
                        client
                            .commit(std::slice::from_ref(&session.session_id), Some(&map))
                            .await?
                            .into_iter()
                            .next()
                            .context("empty commit response")?
                    }
                    "direct" if encoded.digest.file_size > api::MULTIPART_THRESHOLD => {
                        client
                            .upload_multipart(&session.session_id, &encoded.path, parts)
                            .await?;
                        client.complete(&session.session_id).await?;
                        commits.request(session.session_id.clone()).await?
                    }
                    "direct" | "presigned" => {
                        match client.upload_single(&session, &encoded.path, parts).await? {
                            Some(result) => result,
                            None => commits.request(session.session_id.clone()).await?,
                        }
                    }
                    _ => bail!("unsupported upload method"),
                };
                if !published.published {
                    bail!(
                        "publication failed (status {})",
                        published.status.unwrap_or(500)
                    )
                }
                tracing::debug!(
                    elapsed_ms = start.elapsed().as_millis(),
                    compressed_bytes = encoded.digest.file_size,
                    "published store path"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
            (path, result)
        }
        .instrument(span)
    }))
    .buffer_unordered(jobs);
    while let Some((path, result)) = work.next().await {
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
