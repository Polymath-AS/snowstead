//! Resumable manifests coordinate bounded transfers, not whole-closure transactions.
use crate::{
    api::{Client, SessionParams, segment},
    nix, push,
};
use anyhow::{Context, Result, bail};
use reqwest::Method;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Job {
    id: String,
    state: String,
    mode: String,
    roots: Vec<String>,
    manifest_digest: Option<String>,
    expires_at: u64,
    authorization_expires_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Limits {
    members: usize,
    chunk_members: usize,
    background_publication: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    protocol_version: u32,
    capabilities: Vec<String>,
    job: Job,
    limits: Option<Limits>,
}

impl Envelope {
    fn validate(&self) -> Result<()> {
        if self.protocol_version != 1
            || ["manifest", "prepareOnly", "completion", "readiness"]
                .iter()
                .any(|capability| !self.capabilities.iter().any(|c| c == capability))
        {
            bail!("server does not support resumable preparation and completion");
        }
        segment(&self.job.id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::{client, read, reply};
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    #[tokio::test]
    async fn resume_rejects_an_empty_page_that_repeats_the_cursor() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = client(&format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let hash = "0".repeat(32);
            let mut response = json!({"protocolVersion":1,"capabilities":["manifest","prepareOnly","completion","readiness"],
                "job":{"id":"job-1","state":"completed","mode":"selected","roots":[],
                    "manifestDigest":"fixed","expiresAt":4_000_000_000u64,"authorizationExpiresAt":null},
                "limits":{"members":100,"chunkMembers":100,"backgroundPublication":false}});
            for page in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (headers, _) = read(&mut socket).await;
                assert!(headers.starts_with("GET /_api/v1/caches/main/push-jobs/job-1"));
                if page == 1 {
                    response["members"] = json!([{"storePath":format!("/nix/store/{hash}-fixture"),
                        "storePathHash":hash,"narHash":format!("sha256:{}","a".repeat(64)),"narSize":128,
                        "compression":"zstd","references":[],"deriver":null,"available":true,"session":null}]);
                    response["next"] = json!(hash);
                } else if page == 2 {
                    assert!(headers.contains(&format!("?after={hash} ")));
                    response["members"] = json!([]);
                }
                reply(&mut socket, 200, &response.to_string(), "").await;
            }
        });
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            push(&client, "main", vec![], false, Some("job-1"), 2, 3),
        )
        .await
        .unwrap()
        .err()
        .unwrap();
        assert!(error.to_string().contains("empty page"), "{error}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn resume_reuses_prepared_bytes_and_isolates_a_failed_prerequisite() {
        for (failed_dependency, recover_multipart) in [(false, false), (true, false), (false, true)]
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = client(&format!("http://{}", listener.local_addr().unwrap()));
            let paths: Vec<_> = (0..3)
                .map(|i| format!("/nix/store/{}-resumable-fixture", i.to_string().repeat(32)))
                .collect();
            assert!(
                paths
                    .iter()
                    .all(|path| !std::path::Path::new(path).exists())
            );
            let receipt = json!({"sessionId":format!("session-{}","1".repeat(32)),
                "narHash":format!("sha256:{}","a".repeat(64)),"narSize":128,
                "fileHash":"b".repeat(64),"fileSize":96,
                "parts":[{"partNumber":1,"etag":"retained-part-etag"}]});
            let rows: Vec<_> = paths.iter().enumerate().map(|(i, path)| json!({
                "storePath":path,"storePathHash":i.to_string().repeat(32),"narHash":format!("sha256:{}","a".repeat(64)),
                "narSize":128,"compression":"zstd","references":if i==0 {vec![paths[1][11..].to_owned(),paths[0][11..].to_owned()]} else {vec![]},
                "deriver":null,"available":false,"session":{"status":"finalizing","prepared":!(failed_dependency || recover_multipart) || i!=1}
            })).collect();
            let job = json!({"id":"job-1","state":"sealed","mode":"selected","roots":[paths[0]],
                "manifestDigest":"fixed","expiresAt":4_000_000_000u64,"authorizationExpiresAt":4_000_000_000u64});
            let envelope = json!({"protocolVersion":1,"capabilities":["manifest","prepareOnly","completion","readiness"],"job":job,
                "limits":{"members":100,"chunkMembers":100,"backgroundPublication":true}});
            let mut initial = envelope.clone();
            initial["members"] = json!(rows);
            initial["next"] = Value::Null;
            let mut settled = initial.clone();
            for (i, row) in settled["members"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .enumerate()
            {
                row["available"] = json!(!failed_dependency || i == 2);
            }
            let server = tokio::spawn(async move {
                let mut progress = 0;
                let mut summaries = 0;
                let mut allocations = 0;
                let mut finalizations = 0;
                let mut allocated = None;
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let (headers, body) = read(&mut socket).await;
                    let line = headers.lines().next().unwrap();
                    let response = if line == "GET /_api/v1/caches/main/push-jobs/job-1 HTTP/1.1"
                        || line == "POST /_api/v1/caches/main/push-jobs/job-1/resume HTTP/1.1"
                    {
                        envelope.clone()
                    } else if line == "GET /_api/v1/caches/main/push-jobs/job-1?after= HTTP/1.1" {
                        progress += 1;
                        if progress == 1 {
                            initial.clone()
                        } else {
                            settled.clone()
                        }
                    } else if line
                        == "GET /_api/v1/caches/main/push-jobs/job-1?summary=true HTTP/1.1"
                    {
                        assert_eq!(finalizations, usize::from(recover_multipart));
                        summaries += 1;
                        let mut summary = envelope.clone();
                        summary["members"] = json!([]);
                        summary["available"] = json!(!failed_dependency && summaries > 1);
                        summary["blocked"] = json!(false);
                        summary
                    } else if line == "POST /_api/v1/caches/main/upload-streams/batch HTTP/1.1" {
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(body["jobId"], "job-1");
                        allocations += 1;
                        if !failed_dependency && allocations == 1 {
                            allocated = Some(body);
                            socket.shutdown().await.unwrap();
                            continue;
                        }
                        if let Some(previous) = &allocated {
                            assert_eq!(previous, &body);
                        }
                        json!({"sessions":body["paths"].as_array().unwrap().iter().map(|p| {
                            let hash=p["storePathHash"].as_str().unwrap();
                            let recovering = recover_multipart && hash=="1".repeat(32);
                            json!({"sessionId":format!("session-{hash}"),"partSize":1048576,"inline":!recovering,
                                "status":"finalizing","prepared":!(failed_dependency || recover_multipart) || hash!="1".repeat(32),
                                "receipt":if recovering {receipt.clone()} else {Value::Null}})
                        }).collect::<Vec<_>>()})
                    } else if line == "POST /_api/v1/uploads/finalize?prepareOnly=true HTTP/1.1" {
                        assert!(recover_multipart);
                        finalizations += 1;
                        assert_eq!(finalizations, 1);
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(body, json!({"uploads":[receipt]}));
                        json!({"results":[{"sessionId":receipt["sessionId"],
                            "published":false,"prepared":true,"status":202,"error":null}]})
                    } else if line == "POST /_api/v1/caches/main/push-jobs/job-1/complete HTTP/1.1"
                    {
                        assert!(!failed_dependency);
                        assert_eq!(finalizations, usize::from(recover_multipart));
                        assert!(
                            summaries > 1,
                            "pending readiness must not complete an empty member list"
                        );
                        let mut completed = envelope.clone();
                        completed["job"]["state"] = json!("completed");
                        reply(&mut socket, 200, &completed.to_string(), "").await;
                        break;
                    } else {
                        panic!("unexpected request: {line}");
                    };
                    reply(&mut socket, 200, &response.to_string(), "").await;
                    if failed_dependency && progress == 2 {
                        break;
                    }
                }
                assert_eq!(allocations, if failed_dependency { 1 } else { 2 });
                assert_eq!(finalizations, usize::from(recover_multipart));
            });
            // None of these paths exists locally. A prepared member must not
            // invoke the encoder, reserve parts, finalize again, or be aborted.
            // A sealed multipart member must replay only its retained receipt.
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                push(&client, "main", vec![], false, Some("job-1"), 2, 3),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.pushed, if failed_dependency { 1 } else { 3 });
            assert_eq!(result.failed, if failed_dependency { 2 } else { 0 });
            assert_eq!(result.skipped, 0);
            if failed_dependency {
                assert!(result.errors.iter().any(|e| e.contains(&paths[0])));
                assert!(result.errors.iter().any(|e| e.contains(&paths[1])));
                assert!(!result.errors.iter().any(|e| e.contains(&paths[2])));
            }
            server.await.unwrap();
        }
    }
}

#[derive(Deserialize)]
struct Session {
    status: String,
    prepared: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Member {
    #[serde(flatten)]
    input: SessionParams,
    session: Option<Session>,
    available: bool,
    publication_error: Option<String>,
}

#[derive(Deserialize)]
struct Page {
    #[serde(flatten)]
    envelope: Envelope,
    members: Vec<Member>,
    next: Option<String>,
    available: Option<bool>,
    blocked: Option<bool>,
}

// Every operation here has a stable identity and is safe to replay after a
// lost response. Ordinary session creation deliberately does not use this loop.
async fn request<T: DeserializeOwned>(
    client: &Client,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<T> {
    for attempt in 1..=4 {
        if let Ok(response) = client
            .request("push-job", method.clone(), path, body.clone())
            .await
        {
            let status = response.status();
            if !matches!(status.as_u16(), 429 | 502 | 503 | 504) {
                if !status.is_success() {
                    bail!("push job request failed (HTTP {})", status.as_u16());
                }
                match response.json().await {
                    Ok(value) => return Ok(value),
                    Err(error) if error.is_body() || error.is_timeout() => (),
                    Err(_) => bail!("push job: invalid response"),
                }
            }
        }
        if attempt < 4 {
            tokio::time::sleep(Duration::from_secs_f64(
                0.25 * 2_f64.powi(attempt) * (0.5 + rand::random::<f64>()),
            ))
            .await;
        }
    }
    bail!("push job request failed after 4 attempts");
}

async fn action(client: &Client, path: &str, name: &str) -> Result<Envelope> {
    let response: Envelope = request(
        client,
        Method::POST,
        &format!("{path}/{name}"),
        Some(json!({})),
    )
    .await?;
    response.validate()?;
    Ok(response)
}

async fn progress(client: &Client, path: &str, expected: &Job, query: &str) -> Result<Page> {
    let page: Page = request(client, Method::GET, &format!("{path}?{query}"), None).await?;
    page.envelope.validate()?;
    if page.envelope.job.id != expected.id
        || page.envelope.job.manifest_digest != expected.manifest_digest
        || page.envelope.job.state != expected.state
    {
        bail!("push job changed while reading progress; resume it again");
    }
    Ok(page)
}

async fn members(client: &Client, path: &str, expected: &Job, limit: usize) -> Result<Vec<Member>> {
    let mut members = Vec::new();
    let mut after = String::new();
    loop {
        let page = progress(client, path, expected, &format!("after={after}")).await?;
        if page.members.is_empty() && page.next.is_some() {
            bail!("push job: empty page with a continuation cursor");
        }
        for member in &page.members {
            if member.input.compression != "zstd"
                || member.input.store_path_hash.len() != 32
                || !member
                    .input
                    .store_path
                    .starts_with(&format!("/nix/store/{}-", member.input.store_path_hash))
                || member.input.store_path_hash <= after
            {
                bail!("push job: invalid member order or metadata");
            }
            after.clone_from(&member.input.store_path_hash);
        }
        members.extend(page.members);
        if members.len() > limit {
            bail!("push job exceeds advertised member limit");
        }
        match page.next {
            Some(next) if next == after && !after.is_empty() => (),
            Some(_) => bail!("push job: invalid page cursor"),
            None => break,
        }
    }
    if members.is_empty() {
        bail!("push job manifest is unavailable; start a new push");
    }
    Ok(members)
}

fn info(input: &SessionParams) -> nix::PathInfo {
    nix::PathInfo {
        store_path: input.store_path.clone(),
        store_path_hash: input.store_path_hash.clone(),
        nar_hash: input.nar_hash.clone(),
        nar_size: input.nar_size,
        references: input.references.clone(),
        deriver: input.deriver.clone(),
    }
}

/// A failed prerequisite blocks its dependents, not independent prepared paths.
fn blocked(members: &[Member]) -> Vec<bool> {
    let names: HashMap<_, _> = members
        .iter()
        .enumerate()
        .map(|(i, m)| (m.input.store_path.trim_start_matches("/nix/store/"), i))
        .collect();
    let mut dependents = vec![Vec::new(); members.len()];
    let mut failed = vec![false; members.len()];
    let mut queue = VecDeque::new();
    for (i, member) in members.iter().enumerate() {
        if !member.available
            && (member.publication_error.is_some()
                || !member
                    .session
                    .as_ref()
                    .is_some_and(|s| s.prepared && s.status == "finalizing"))
        {
            failed[i] = true;
            queue.push_back(i);
        }
        for reference in &member.input.references {
            if let Some(&dependency) = names.get(reference.as_str())
                && dependency != i
            {
                dependents[dependency].push(i);
            }
        }
    }
    while let Some(i) = queue.pop_front() {
        for &dependent in &dependents[i] {
            if !members[dependent].available && !failed[dependent] {
                failed[dependent] = true;
                queue.push_back(dependent);
            }
        }
    }
    failed
}

pub async fn push(
    client: &Client,
    cache: &str,
    roots: Vec<String>,
    selected: bool,
    resume: Option<&str>,
    jobs: usize,
    level: i32,
) -> Result<push::Summary> {
    let base = format!("/_api/v1/caches/{}/push-jobs", segment(cache)?);
    let mut envelope: Envelope = if let Some(id) = resume {
        request(
            client,
            Method::GET,
            &format!("{base}/{}", segment(id)?),
            None,
        )
        .await?
    } else {
        let key = format!("cli-{:032x}", rand::random::<u128>());
        request(
            client,
            Method::POST,
            &base,
            Some(json!({"idempotencyKey":key,
            "mode":if selected { "selected" } else { "closure" },"roots":roots})),
        )
        .await?
    };
    envelope.validate()?;
    let id = envelope.job.id.clone();
    let path = format!("{base}/{id}");
    println!("Push job: {id}");
    println!("Resume with: snowstead push {cache} --resume {id}");
    let limits = envelope
        .limits
        .take()
        .context("push job response has no limits")?;
    if limits.members == 0
        || limits.members > 100_000
        || limits.chunk_members == 0
        || limits.chunk_members > limits.members
    {
        bail!("push job: invalid server limits");
    }
    if !limits.background_publication && envelope.job.state != "completed" {
        bail!("resumable pushes require server publication workers; no uploads started");
    }
    if envelope.job.state == "building" {
        let paths = if envelope.job.mode == "selected" {
            envelope.job.roots.clone()
        } else {
            nix::closure(&envelope.job.roots).await?
        };
        if paths.len() > limits.members {
            bail!("closure exceeds server member limit");
        }
        let mut infos: Vec<_> = nix::path_infos(&paths).await?.into_values().collect();
        infos.sort_by(|a, b| a.store_path_hash.cmp(&b.store_path_hash));
        let specs: Vec<_> = infos
            .iter()
            .map(|p| SessionParams {
                store_path: p.store_path.clone(),
                store_path_hash: p.store_path_hash.clone(),
                nar_hash: p.nar_hash.clone(),
                nar_size: p.nar_size,
                compression: "zstd".into(),
                references: p.references.clone(),
                deriver: p.deriver.clone(),
                inline: None,
            })
            .collect();
        for (ordinal, chunk) in specs.chunks(limits.chunk_members).enumerate() {
            let response: Envelope = request(
                client,
                Method::PUT,
                &format!("{path}/manifest/{ordinal}"),
                Some(json!({"members":chunk})),
            )
            .await?;
            response.validate()?;
        }
        envelope = action(client, &path, "seal").await?;
    }
    if !matches!(envelope.job.state.as_str(), "sealed" | "completed") {
        bail!("push job is not active");
    }
    if envelope.job.state == "sealed" {
        envelope = action(client, &path, "resume").await?;
    }
    let initial = members(client, &path, &envelope.job, limits.members).await?;
    let skipped: HashSet<_> = initial
        .iter()
        .filter(|m| m.available)
        .map(|m| m.input.store_path_hash.clone())
        .collect();
    if envelope.job.state == "completed" {
        if initial.iter().any(|m| !m.available) {
            bail!("completed push is no longer fully available; start a new push");
        }
        return Ok(push::Summary {
            pushed: 0,
            skipped: initial.len(),
            upstream: 0,
            failed: 0,
            errors: vec![],
        });
    }
    let pending: Vec<_> = initial
        .iter()
        .filter(|m| !m.available)
        .map(|m| info(&m.input))
        .collect();
    let job_client = client.for_job(&id)?;
    let transfer = push::transfer(&job_client, cache, pending, jobs, level);
    tokio::pin!(transfer);
    let mut renew = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(300),
        Duration::from_secs(300),
    );
    let transfers = loop {
        tokio::select! {
            result = &mut transfer => { break result?; }
            _ = renew.tick() => { envelope = action(client, &path, "resume").await?; }
        }
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    // A prepared receipt can arrive just before its publication commits.
    // Probe readiness promptly without repeatedly downloading the manifest,
    // then return to the steady-state polling budget for blocked work.
    let mut poll_delay = Duration::from_millis(25);
    loop {
        let readiness = progress(client, &path, &envelope.job, "summary=true").await?;
        if readiness
            .available
            .context("push job response has no readiness")?
        {
            let completed = action(client, &path, "complete").await?;
            if completed.job.state != "completed" {
                bail!("push job completion was not recorded");
            }
            return Ok(push::Summary {
                pushed: initial.len() - skipped.len(),
                skipped: skipped.len(),
                upstream: 0,
                failed: 0,
                errors: vec![],
            });
        }
        if readiness
            .blocked
            .context("push job response has no blocked status")?
            || transfers.failed > 0
        {
            let current = members(client, &path, &envelope.job, limits.members).await?;
            if current.iter().all(|m| m.available) {
                continue;
            }
            let failed = blocked(&current);
            if current
                .iter()
                .enumerate()
                .all(|(i, m)| m.available || failed[i])
            {
                let remaining = current.iter().filter(|m| !m.available).count();
                let mut errors: Vec<_> = transfers.errors.iter().take(20).cloned().collect();
                errors.extend(
                    current
                        .iter()
                        .filter(|m| !m.available)
                        .take(20usize.saturating_sub(errors.len()))
                        .map(|m| {
                            format!(
                                "{}: {}",
                                m.input.store_path,
                                if m.publication_error.as_deref() == Some("capacity_blocked") {
                                    "retained capacity blocked; resume after freeing capacity"
                                } else {
                                    "preparation or prerequisite incomplete; resume the push job"
                                }
                            )
                        }),
                );
                if remaining > errors.len() {
                    errors.push(format!(
                        "{remaining} members remain unavailable; resume push job {id}"
                    ));
                }
                return Ok(push::Summary {
                    pushed: current
                        .iter()
                        .filter(|m| m.available && !skipped.contains(&m.input.store_path_hash))
                        .count(),
                    skipped: skipped.len(),
                    upstream: 0,
                    failed: remaining,
                    errors,
                });
            }
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if now >= envelope.job.expires_at
            || envelope
                .job
                .authorization_expires_at
                .is_none_or(|expires| now >= expires)
            || tokio::time::Instant::now() >= deadline
        {
            bail!("publication wait expired; resume push job {id}");
        }
        tokio::select! {
            _ = tokio::time::sleep(poll_delay) => (),
            _ = renew.tick() => { envelope = action(client, &path, "resume").await?; }
            _ = tokio::signal::ctrl_c() => bail!("upload cancelled; resume push job {id}"),
        }
        poll_delay = (poll_delay * 2).min(Duration::from_millis(250));
    }
}
