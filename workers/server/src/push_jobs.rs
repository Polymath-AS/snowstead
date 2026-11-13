//! Durable manifest construction. Sealing does not grant uploads or publish bytes.
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    time::Duration,
};

use axum::{
    Extension, Router,
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_protocol::{
    Capabilities, CreatePushJob, JobSession, ManifestChunk, PUSH_JOB_CAPABILITIES,
    PUSH_JOB_PROTOCOL_VERSION, PushJob, PushJobEnvelope, PushJobLimits, PushJobMode, PushJobPage,
    PushJobState, RetainedSession, SessionStatus, UploadSession, routes,
};
use sqlx::{FromRow, types::Json};

use crate::{
    AppState,
    authz::{Action, Principal as Identity, Resource, authorize},
    db::{self, Transaction},
    error::ApiError,
    lifecycle::UploadStatus,
    uploads::{PathInput, PathInputExt, basename},
    wire::{member, respond, stored},
};

pub(crate) fn router(state: AppState) -> Router<AppState> {
    let access = middleware::from_fn_with_state(state.clone(), crate::nix::write_access);
    Router::new()
        .route(routes::PUSH_JOBS_ROUTE, post(create))
        .route(routes::PUSH_JOB_ROUTE, get(progress))
        .route(routes::MANIFEST_CHUNK_ROUTE, put(chunk))
        .route(routes::SEAL_ROUTE, post(seal))
        .route(routes::RESUME_ROUTE, post(resume))
        .route(routes::CANCEL_ROUTE, post(cancel))
        .route(routes::COMPLETE_ROUTE, post(complete))
        .route_layer(middleware::from_fn_with_state(state, admit))
        .route_layer(access)
}

async fn admit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Reject overload before consuming a body or borrowing SQL. Keep the
    // permit through parsing and graph validation, but not audit logging.
    let _permit = state
        .manifest_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            error(503, "Manifest processing busy; retry")
                .header(header::RETRY_AFTER, HeaderValue::from_static("1"))
        })?;
    Ok(next.run(request).await)
}

fn error(code: u16, message: &str) -> ApiError {
    ApiError::new(StatusCode::from_u16(code).unwrap(), message)
}

async fn body<T: serde::de::DeserializeOwned>(
    request: Request,
    limit: usize,
) -> Result<T, ApiError> {
    let bytes = tokio::time::timeout(
        Duration::from_secs(30),
        to_bytes(request.into_body(), limit),
    )
    .await
    .map_err(|_| error(408, "Manifest body read timed out"))?
    .map_err(|_| error(413, "Manifest body exceeds limit"))?;
    serde_json::from_slice(&bytes).map_err(|_| error(400, "Invalid manifest JSON"))
}

async fn cache(
    executor: impl sqlx::PgExecutor<'_>,
    identity: &Identity,
    name: &str,
    push: bool,
) -> Result<i32, ApiError> {
    let (id, public, allowed, nix): (i32, bool, bool, bool) = sqlx::query_as(
        "SELECT c.id,c.is_public,o.private_caches,EXISTS (SELECT 1 FROM cache_protocols p \
         WHERE p.cache_id=c.id AND p.protocol='nix') FROM caches c JOIN orgs o ON o.id=c.org_id \
         WHERE c.org_id=$1 AND c.name=$2",
    )
    .bind(identity.org())
    .bind(name)
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| error(404, "Cache not found"))?;
    authorize(
        identity,
        Action::NixPush,
        &Resource::cache(identity.org(), id, name),
    )
    .map_err(|_| error(403, "Forbidden"))?;
    if push && !nix {
        return Err(error(404, "Cache not found"));
    }
    if push && !public && !allowed {
        return Err(error(403, "Private cache pushes are disabled"));
    }
    Ok(id)
}

async fn writer(
    state: &AppState,
    identity: &Identity,
    name: &str,
    push: bool,
) -> Result<(Transaction, i32), ApiError> {
    let mut tx = db::begin(state, identity.org()).await?;
    db::advisory_lock(&mut tx, &format!("org:{}", identity.org())).await?;
    let id = cache(&mut *tx, identity, name, push).await?;
    Ok((tx, id))
}

#[derive(FromRow)]
struct Job {
    id: String,
    mode: String,
    roots: Json<Vec<String>>,
    state: String,
    revision: i32,
    manifest_digest: Option<String>,
    manifest_bytes: i32,
    input_members: i32,
    // Unix seconds, so clients can stop resuming an expired builder.
    expires_at: i64,
    hard_expires_at: i64,
    grant_generation: i64,
    authorization_expires_at: Option<i64>,
    completed_at: Option<i64>,
    protection_expires_at: Option<i64>,
    valid: bool,
}
async fn load(
    executor: impl sqlx::PgExecutor<'_>,
    cache: i32,
    actor: &str,
    id: &str,
) -> Result<Job, ApiError> {
    let job: Job = sqlx::query_as("SELECT id,mode,roots,state,revision,manifest_digest,manifest_bytes,input_members, \
        grant_generation,FLOOR(EXTRACT(EPOCH FROM authorization_expires_at))::bigint AS authorization_expires_at, \
        FLOOR(EXTRACT(EPOCH FROM completed_at))::bigint AS completed_at, \
        FLOOR(EXTRACT(EPOCH FROM protection_expires_at))::bigint AS protection_expires_at, \
        FLOOR(EXTRACT(EPOCH FROM LEAST(idle_expires_at,hard_expires_at)))::bigint AS expires_at, \
        FLOOR(EXTRACT(EPOCH FROM hard_expires_at))::bigint AS hard_expires_at, \
        state='completed' OR (idle_expires_at>NOW() AND hard_expires_at>NOW()) AS valid FROM push_jobs WHERE cache_id=$1 AND creator=$2 AND id=$3")
        .bind(cache)
        .bind(actor)
        .bind(id)
        .fetch_optional(executor)
        .await?
        .ok_or_else(|| error(404, "Job not found"))?;
    if !job.valid {
        return Err(error(410, "Push job expired; create a new job"));
    }
    Ok(job)
}

impl Job {
    /// The wire form. The columns' CHECK constraints admit only the
    /// protocol's modes and states.
    fn wire(self) -> Result<PushJob, ApiError> {
        let invalid = |_| error(500, "Invalid push job state");
        Ok(PushJob {
            mode: PushJobMode::try_from(self.mode.as_str()).map_err(invalid)?,
            state: PushJobState::try_from(self.state.as_str()).map_err(invalid)?,
            id: self.id,
            roots: self.roots.0,
            revision: self.revision,
            manifest_digest: self.manifest_digest,
            manifest_bytes: self.manifest_bytes,
            input_members: self.input_members,
            expires_at: self.expires_at,
            hard_expires_at: self.hard_expires_at,
            grant_generation: self.grant_generation,
            authorization_expires_at: self.authorization_expires_at,
            completed_at: self.completed_at,
            protection_expires_at: self.protection_expires_at,
        })
    }
}

fn envelope(job: Job, state: &AppState) -> Result<PushJobEnvelope, ApiError> {
    let limits = &state.config.push_jobs;
    Ok(PushJobEnvelope {
        protocol_version: PUSH_JOB_PROTOCOL_VERSION,
        capabilities: Capabilities::of(&PUSH_JOB_CAPABILITIES),
        job: job.wire()?,
        limits: Some(PushJobLimits {
            members: limits.members,
            chunk_members: limits.chunk_members,
            manifest_bytes: limits.manifest_bytes,
            background_publication: limits.publication_workers > 0,
        }),
    })
}

fn response(status: StatusCode, job: Job, state: &AppState) -> Response {
    match envelope(job, state) {
        Ok(envelope) => respond(status, &envelope),
        Err(error) => axum::response::IntoResponse::into_response(error),
    }
}

// Call under writer()'s org fence. Reserve metadata before accepting it, not
// at completion: successful publication must never lose its promised grace.
async fn reserve_manifest(
    tx: &mut Transaction,
    org: &str,
    limits: &crate::config::PushJobLimits,
    new_job: bool,
    added_members: usize,
    added_bytes: usize,
) -> Result<(), ApiError> {
    // Every job reserves at least one member. Sealing requires a nonempty
    // manifest, so this also bounds protected job rows without a separate cap.
    let (active, members, bytes): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE j.state IN ('building','sealed')), \
            COALESCE(sum(GREATEST(j.input_members,1)),0)::bigint,COALESCE(sum(j.manifest_bytes),0)::bigint \
        FROM push_jobs j JOIN caches c ON c.id=j.cache_id \
        WHERE c.org_id=$1 AND (j.state IN ('building','sealed') \
            OR (j.state='completed' AND j.protection_expires_at>NOW())) \
        AND j.idle_expires_at>NOW() AND j.hard_expires_at>NOW()",
    )
    .bind(org)
    .fetch_one(&mut **tx)
    .await?;
    if new_job && active >= limits.active_per_org as i64 {
        return Err(error(429, "Too many active push jobs"));
    }
    if members + added_members as i64 > limits.protected_members_per_org as i64
        || bytes + added_bytes as i64 > limits.protected_manifest_bytes_per_org as i64
    {
        return Err(error(
            429,
            "Organization push job protection budget is full",
        ));
    }
    Ok(())
}

async fn create(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(name): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let mut input: CreatePushJob = body(request, state.config.push_jobs.manifest_bytes).await?;
    if input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 128
        || !input
            .idempotency_key
            .bytes()
            .all(|b| (33..=126).contains(&b))
        || input.roots.is_empty()
        || input.roots.len() > state.config.push_jobs.members
        || input
            .roots
            .iter()
            .any(|p| !basename(p.strip_prefix("/nix/store/").unwrap_or("")))
    {
        return Err(error(400, "Invalid push job identity, mode, or roots"));
    }
    input.roots.sort();
    input.roots.dedup();
    let roots = Json(input.roots);
    let size = serde_json::to_vec(&(&input.mode, &roots.0)).unwrap().len();
    if size > state.config.push_jobs.manifest_bytes {
        return Err(error(413, "Manifest exceeds byte limit"));
    }
    let (mut tx, cache_id) = writer(&state, &identity, &name, true).await?;
    let actor = identity.actor();
    let existing: Option<Job> = sqlx::query_as("SELECT id,mode,roots,state,revision,manifest_digest,manifest_bytes,input_members, \
        grant_generation,FLOOR(EXTRACT(EPOCH FROM authorization_expires_at))::bigint AS authorization_expires_at, \
        FLOOR(EXTRACT(EPOCH FROM completed_at))::bigint AS completed_at, \
        FLOOR(EXTRACT(EPOCH FROM protection_expires_at))::bigint AS protection_expires_at, \
        FLOOR(EXTRACT(EPOCH FROM LEAST(idle_expires_at,hard_expires_at)))::bigint AS expires_at, \
        FLOOR(EXTRACT(EPOCH FROM hard_expires_at))::bigint AS hard_expires_at, \
        state='completed' OR (idle_expires_at>NOW() AND hard_expires_at>NOW()) AS valid FROM push_jobs WHERE cache_id=$1 AND creator=$2 AND idempotency_key=$3")
    .bind(cache_id)
    .bind(&actor)
    .bind(&input.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(job) = existing {
        if job.mode != input.mode.as_str() || job.roots.0 != roots.0 {
            return Err(error(
                409,
                "Idempotency key has different manifest identity",
            ));
        }
        if !job.valid {
            return Err(error(410, "Push job expired; create a new job"));
        }
        tx.commit().await?;
        return Ok(response(StatusCode::OK, job, &state));
    }
    reserve_manifest(
        &mut tx,
        identity.org(),
        &state.config.push_jobs,
        true,
        1,
        size,
    )
    .await?;
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO push_jobs(id,cache_id,creator,idempotency_key,mode,roots,manifest_bytes) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(&id).bind(cache_id).bind(&actor).bind(input.idempotency_key).bind(input.mode.as_str()).bind(roots).bind(size as i32)
        .execute(&mut *tx).await?;
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    tx.commit().await?;
    Ok(response(StatusCode::CREATED, job, &state))
}

async fn chunk(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((name, id, ordinal)): Path<(String, String, i32)>,
    request: Request,
) -> Result<Response, ApiError> {
    let mut input: ManifestChunk = body(request, state.config.push_jobs.manifest_bytes).await?;
    if ordinal < 0
        || ordinal as usize >= state.config.push_jobs.members
        || input.members.is_empty()
        || input.members.len() > state.config.push_jobs.chunk_members
    {
        return Err(error(400, "Invalid manifest chunk size or index"));
    }
    for member in &mut input.members {
        // Transfer hints are not part of manifest identity.
        member.normalize()?;
    }
    input.members.sort_by(|a, b| {
        a.store_path_hash
            .cmp(&b.store_path_hash)
            .then(a.store_path.cmp(&b.store_path))
    });
    let bytes = serde_json::to_vec(&input.members).unwrap().len();
    let members = Json(input.members);
    let (mut tx, cache_id) = writer(&state, &identity, &name, true).await?;
    let actor = identity.actor();
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    if job.state == "cancelled" {
        return Err(error(409, "Push job is cancelled"));
    }
    let existing: Option<Json<Vec<PathInput>>> = sqlx::query_scalar(
        "SELECT members FROM push_manifest_chunks WHERE job_id=$1 AND ordinal=$2",
    )
    .bind(&id)
    .bind(ordinal)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(previous) = existing {
        if previous.0 != members.0 {
            return Err(error(409, "Chunk index has different content"));
        }
    } else {
        if job.state != "building" {
            return Err(error(409, "Manifest is sealed"));
        }
        if job.manifest_bytes as usize + bytes > state.config.push_jobs.manifest_bytes
            || job.input_members as usize + members.0.len() > state.config.push_jobs.members
        {
            return Err(error(413, "Manifest exceeds job limits"));
        }
        reserve_manifest(
            &mut tx,
            identity.org(),
            &state.config.push_jobs,
            false,
            members.0.len() - usize::from(job.input_members == 0),
            bytes,
        )
        .await?;
        sqlx::query("INSERT INTO push_manifest_chunks(job_id,ordinal,members) VALUES($1,$2,$3)")
            .bind(&id)
            .bind(ordinal)
            .bind(&members)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE push_jobs SET revision=revision+1,manifest_bytes=manifest_bytes+$2,input_members=input_members+$3, \
            idle_expires_at=LEAST(hard_expires_at,NOW()+INTERVAL '30 minutes') WHERE id=$1")
            .bind(&id).bind(bytes as i32).bind(members.0.len() as i32).execute(&mut *tx).await?;
    }
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    tx.commit().await?;
    Ok(response(StatusCode::OK, job, &state))
}

async fn seal(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let cache_id = cache(&state.pool, &identity, &name, true).await?;
    let actor = identity.actor();
    let before = load(&state.pool, cache_id, &actor, &id).await?;
    if before.state == "cancelled" {
        return Err(error(409, "Push job is cancelled"));
    }
    if matches!(before.state.as_str(), "sealed" | "completed") {
        return Ok(response(StatusCode::OK, before, &state));
    }
    let chunks: Vec<(i32, Json<Vec<PathInput>>)> = sqlx::query_as(
        "SELECT ordinal,members FROM push_manifest_chunks WHERE job_id=$1 ORDER BY ordinal",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await?;
    if chunks.is_empty()
        || chunks
            .iter()
            .enumerate()
            .any(|(i, (n, _))| i != *n as usize)
    {
        return Err(error(400, "Manifest chunks are missing"));
    }
    // All graph work happens after releasing the read connection. The revision
    // check below rejects a concurrent append rather than sealing a partial read.
    let mut members = BTreeMap::new();
    for (_, chunk) in chunks {
        for member in chunk.0 {
            if let Some(previous) = members.get(&member.store_path_hash)
                && previous != &member
            {
                return Err(error(409, "Conflicting manifest member"));
            }
            members.insert(member.store_path_hash.clone(), member);
        }
    }
    let names: HashMap<_, _> = members
        .values()
        .map(|p| {
            (
                p.store_path.strip_prefix("/nix/store/").unwrap(),
                p.store_path_hash.as_str(),
            )
        })
        .collect();
    if before
        .roots
        .0
        .iter()
        .any(|root| !names.contains_key(root.strip_prefix("/nix/store/").unwrap()))
    {
        return Err(error(400, "Manifest root is missing"));
    }
    let mut dependencies = HashMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
    for member in members.values() {
        let mut count = 0;
        for reference in member.references.as_ref().unwrap() {
            match names.get(reference.as_str()) {
                Some(target) if *target != member.store_path_hash => {
                    count += 1;
                    dependents
                        .entry(target)
                        .or_default()
                        .push(&member.store_path_hash);
                }
                None if before.mode == "closure" => {
                    return Err(error(400, "Manifest reference is missing"));
                }
                _ => {}
            }
        }
        dependencies.insert(member.store_path_hash.as_str(), count);
    }
    let mut ready: VecDeque<_> = dependencies
        .iter()
        .filter_map(|(id, n)| (*n == 0).then_some(*id))
        .collect();
    let mut visited = 0;
    let mut publication_order = HashMap::new();
    while let Some(id) = ready.pop_front() {
        visited += 1;
        publication_order.insert(id, visited);
        for dependent in dependents.get(id).into_iter().flatten() {
            let count = dependencies.get_mut(dependent).unwrap();
            *count -= 1;
            if *count == 0 {
                ready.push_back(*dependent);
            }
        }
    }
    if visited != members.len() {
        return Err(error(400, "Non-self reference cycles are unsupported"));
    }
    let members: Vec<_> = members.values().collect();
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&(&before.mode, &before.roots.0, &members)).unwrap(),
    ));
    let (mut tx, cache_id) = writer(&state, &identity, &name, true).await?;
    let current = load(&mut *tx, cache_id, &actor, &id).await?;
    if current.state == "cancelled" {
        return Err(error(409, "Push job is cancelled"));
    }
    if matches!(current.state.as_str(), "sealed" | "completed") {
        tx.commit().await?;
        return Ok(response(StatusCode::OK, current, &state));
    }
    if current.revision != before.revision {
        return Err(error(409, "Manifest changed; retry sealing"));
    }
    sqlx::query("INSERT INTO push_job_members(job_id,store_path_hash,metadata,publication_order) SELECT $1,m.metadata->>'storePathHash',m.metadata,m.publication_order FROM jsonb_to_recordset($2) AS m(metadata jsonb,publication_order integer)")
        .bind(&id).bind(Json(members.iter().map(|member| json!({"metadata":member,"publication_order":publication_order[member.store_path_hash.as_str()]})).collect::<Vec<_>>())).execute(&mut *tx).await?;
    sqlx::query("UPDATE push_jobs SET state='sealed',manifest_digest=$2,idle_expires_at=LEAST(hard_expires_at,NOW()+INTERVAL '30 minutes') WHERE id=$1")
        .bind(&id).bind(digest).execute(&mut *tx).await?;
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    tx.commit().await?;
    Ok(response(StatusCode::OK, job, &state))
}

async fn resume(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let Identity::ApiToken(token) = &identity else {
        return Err(error(409, "Background authorization requires an API token"));
    };
    let (mut tx, cache_id) = writer(&state, &identity, &name, true).await?;
    let job = load(&mut *tx, cache_id, &token.id, &id).await?;
    if job.state == "completed" {
        tx.commit().await?;
        return progress(
            State(state),
            Extension(identity),
            Path((name, id)),
            Query(Page {
                after: None,
                summary: false,
            }),
        )
        .await;
    }
    if job.state != "sealed" {
        return Err(error(409, "Only a sealed job can renew authorization"));
    }
    // Authentication outside this transaction is not a revocation fence.
    // Registered tokens provide a durable, revocable identity; no bearer token
    // or reusable client credential is persisted with the job.
    let registered: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NULL FROM api_tokens WHERE jti=$1 AND COALESCE(org_id,'default')=$2 FOR SHARE NOWAIT",
    ).bind(&token.id).bind(identity.org()).fetch_optional(&mut *tx).await?;
    match registered {
        None => {
            return Err(error(409, "Background authorization requires an API token"));
        }
        Some(false) => return Err(error(401, "Token revoked")),
        _ => {}
    }
    // Record only the delegated action and cache. The worker acts as this
    // token, limited to pushing to this cache, while the token stays live.
    let delegated = json!({"jti": token.id, "cacheId": cache_id, "perms": ["push"]});
    let renewed = sqlx::query("UPDATE push_jobs SET authorization_jti=$2,grant_generation=grant_generation+1, \
        authorization_claims=$4,work_id=NULL,work_expires_at=NULL,work_at=NOW(),work_failures=0,work_blocked=false,work_members=16, \
        idle_expires_at=LEAST(hard_expires_at,NOW()+INTERVAL '30 minutes'), \
        authorization_expires_at=LEAST(hard_expires_at,NOW()+INTERVAL '30 minutes',to_timestamp($3::bigint::double precision)) \
        WHERE id=$1 AND ($3::bigint IS NULL OR to_timestamp($3::bigint::double precision)>NOW())")
        .bind(&id).bind(&token.id).bind(token.expires_at.map(|at| at.timestamp())).bind(Json(delegated)).execute(&mut *tx).await?;
    if renewed.rows_affected() == 0 {
        return Err(error(401, "Token expired"));
    }
    // Resume renews queued multipart work too. Failed verification remains
    // terminal; only authorization failures can run under the renewed grant.
    sqlx::query(
        "WITH renewed AS (UPDATE upload_finalization_batches b SET \
         expires_at=LEAST(j.authorization_expires_at,j.idle_expires_at,j.hard_expires_at), \
         actor=$2,token_jti=$2,grant_generation=j.grant_generation, \
         work_id=NULL,lease_expires_at=NULL,work_at=NOW(),failures=0 \
         FROM push_jobs j WHERE j.id=$1 AND b.job_id=j.id RETURNING b.id) \
         UPDATE upload_finalizations f SET result=NULL FROM renewed r \
         WHERE f.batch_id=r.id AND (f.result->>'status')::integer=401",
    )
    .bind(&id)
    .bind(&token.id)
    .execute(&mut *tx)
    .await?;
    let job = load(&mut *tx, cache_id, &token.id, &id).await?;
    tx.commit().await?;
    Ok(response(StatusCode::OK, job, &state))
}

/// The caller normalizes metadata before taking the org fence and policy rows.
/// Reuse durable sessions instead of issuing transfers on allocation retries.
pub(crate) async fn upload_members(
    tx: &mut Transaction,
    identity: &Identity,
    cache: i32,
    id: &str,
    paths: &[PathInput],
) -> Result<HashMap<String, UploadSession>, ApiError> {
    if !matches!(identity, Identity::ApiToken(_)) {
        return Err(error(409, "Job uploads require the owning API token"));
    }
    let actor = identity.actor();
    let job = load(&mut **tx, cache, &actor, id).await?;
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM push_jobs j JOIN api_tokens t ON t.jti=j.authorization_jti \
         WHERE j.id=$1 AND j.state='sealed' AND j.authorization_expires_at>NOW() AND t.revoked_at IS NULL)",
    ).bind(&job.id).fetch_one(&mut **tx).await?;
    if !authorized {
        return Err(error(
            409,
            "Push job authorization is inactive; resume the job",
        ));
    }
    #[derive(FromRow)]
    struct Member {
        store_path_hash: String,
        metadata: Json<PathInput>,
        id: Option<String>,
        part_size: Option<i32>,
        inline: Option<bool>,
        status: Option<UploadStatus>,
        publication_result: Option<Value>,
        receipt: Option<Value>,
        prepared: bool,
    }
    let hashes: Vec<_> = paths.iter().map(|p| &p.store_path_hash).collect();
    let members: Vec<Member> = sqlx::query_as(
        "SELECT m.store_path_hash,m.metadata,u.id,u.part_size,u.r2_upload_id IS NULL AS inline, \
         u.status,u.publication_result, \
         CASE WHEN u.status='finalizing' AND u.r2_upload_id IS NOT NULL THEN jsonb_build_object( \
             'sessionId',u.id,'narHash',u.nar_hash,'narSize',u.nar_size, \
             'fileHash',u.file_hash,'fileSize',u.file_size, \
             'parts',COALESCE((SELECT jsonb_agg(jsonb_build_object( \
                 'partNumber',p.part_number,'etag',p.etag) ORDER BY p.part_number) \
                 FROM upload_parts p WHERE p.session_id=u.id),'[]'::jsonb)) END AS receipt, \
         u.status='finalizing' AND EXISTS ( \
             SELECT 1 FROM nar_installations n JOIN caches c ON c.id=n.cache_id \
             WHERE n.session_id=u.id AND n.phase='ready' AND n.expires_at>NOW() \
                 AND n.is_private=NOT c.is_public) AS prepared \
         FROM push_job_members m LEFT JOIN upload_sessions u \
         ON u.id=m.session_id AND u.expires_at>NOW() AND u.status<>'aborted' \
         WHERE m.job_id=$1 AND m.store_path_hash=ANY($2)",
    )
    .bind(id)
    .bind(hashes)
    .fetch_all(&mut **tx)
    .await?;
    let mut members: HashMap<_, _> = members
        .into_iter()
        .map(|m| (m.store_path_hash.clone(), m))
        .collect();
    let mut reused = HashMap::new();
    for path in paths {
        let member = members
            .remove(&path.store_path_hash)
            .ok_or_else(|| error(409, "Path is not a sealed manifest member"))?;
        if path != &member.metadata.0 {
            return Err(error(409, "Upload metadata conflicts with sealed manifest"));
        }
        if let Some(session) = member.id {
            // The joined row exists, so its NOT NULL columns are present.
            let (Some(part_size), Some(inline), Some(status)) =
                (member.part_size, member.inline, member.status)
            else {
                return Err(error(500, "Invalid upload session"));
            };
            reused.insert(
                path.store_path_hash.clone(),
                UploadSession {
                    session_id: session,
                    part_size: part_size.unsigned_abs().into(),
                    inline,
                    job: Some(JobSession {
                        status: SessionStatus::from(status),
                        publication_result: stored(member.publication_result),
                        retained: Some(RetainedSession {
                            prepared: member.prepared,
                            receipt: stored(member.receipt),
                        }),
                    }),
                },
            );
        }
    }
    Ok(reused)
}

/// Recheck logical identity and in-manifest prerequisites under the publication
/// org fence. Transfer/preparation order is independent of dependency order.
pub(crate) async fn publication(tx: &mut Transaction, ids: &[String]) -> Result<(), ApiError> {
    let blocked: Option<(String, String)> = sqlx::query_as(
        r#"
        WITH incoming AS (
            SELECT id,cache_id,push_job_id,store_path_hash FROM upload_sessions
            WHERE id=ANY($1) AND push_job_id IS NOT NULL
        ), edges AS (
            SELECT i.id,i.push_job_id,d.store_path_hash FROM incoming i
            JOIN push_job_members m ON m.job_id=i.push_job_id AND m.store_path_hash=i.store_path_hash
            CROSS JOIN LATERAL jsonb_array_elements_text(m.metadata->'references') r
            JOIN push_job_members d ON d.job_id=i.push_job_id
                AND d.store_path_hash=left(r.value,32)
                AND d.metadata->>'storePath'='/nix/store/'||r.value
            WHERE d.store_path_hash<>i.store_path_hash
        ), needed AS (
            SELECT push_job_id,store_path_hash FROM incoming
            UNION SELECT push_job_id,store_path_hash FROM edges
        ), matching AS (
            SELECT m.job_id,m.store_path_hash FROM needed n
            JOIN push_jobs j ON j.id=n.push_job_id
            JOIN push_job_members m ON m.job_id=j.id AND m.store_path_hash=n.store_path_hash
            JOIN published_paths p ON p.cache_id=j.cache_id AND p.store_path_hash=m.store_path_hash
            WHERE m.metadata->>'storePath'=p.store_path AND m.metadata->>'narHash'=p.nar_hash
                AND (m.metadata->>'narSize')::bigint=p.nar_size
                AND (m.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver
                AND p.references_json::jsonb @> (m.metadata->'references')
                AND (m.metadata->'references') @> p.references_json::jsonb
        )
        SELECT i.store_path_hash,'metadata conflict'::text FROM incoming i
        JOIN published_paths p ON p.cache_id=i.cache_id AND p.store_path_hash=i.store_path_hash
        LEFT JOIN matching m ON m.job_id=i.push_job_id AND m.store_path_hash=i.store_path_hash
        WHERE m.job_id IS NULL
        UNION ALL
        SELECT i.store_path_hash,'prerequisites missing'::text FROM edges e
        JOIN incoming i ON i.id=e.id
        LEFT JOIN matching m ON m.job_id=e.push_job_id AND m.store_path_hash=e.store_path_hash
        LEFT JOIN incoming ready ON ready.push_job_id=e.push_job_id AND ready.store_path_hash=e.store_path_hash
        WHERE m.job_id IS NULL AND ready.id IS NULL
        LIMIT 1
        "#,
    ).bind(ids).fetch_optional(&mut **tx).await?;
    if let Some((hash, reason)) = blocked {
        return Err(error(409, &format!("Push job member {hash}: {reason}")));
    }
    Ok(())
}

/// Check the bounded manifest once, not after every publication group. The org
/// fence orders this receipt with publication, withdrawal, and revocation.
async fn complete(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (mut tx, cache_id) = writer(&state, &identity, &name, true).await?;
    let actor = identity.actor();
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    if job.state == "completed" {
        tx.commit().await?;
        return Ok(response(StatusCode::OK, job, &state));
    }
    if job.state != "sealed" {
        return Err(error(409, "Only a sealed job can complete"));
    }
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM push_jobs j JOIN api_tokens t ON t.jti=j.authorization_jti \
         WHERE j.id=$1 AND j.authorization_expires_at>NOW() AND t.revoked_at IS NULL)",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;
    if !authorized {
        return Err(error(
            409,
            "Push job authorization is inactive; resume the job",
        ));
    }
    let missing: Option<String> = sqlx::query_scalar(
        "SELECT m.store_path_hash FROM push_job_members m WHERE m.job_id=$1 AND NOT EXISTS ( \
         SELECT 1 FROM published_paths p WHERE p.cache_id=$2 AND p.store_path_hash=m.store_path_hash \
         AND m.metadata->>'storePath'=p.store_path AND m.metadata->>'narHash'=p.nar_hash \
         AND (m.metadata->>'narSize')::bigint=p.nar_size \
         AND (m.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver \
         AND p.references_json::jsonb @> (m.metadata->'references') \
         AND (m.metadata->'references') @> p.references_json::jsonb) LIMIT 1",
    ).bind(&id).bind(cache_id).fetch_optional(&mut *tx).await?;
    if let Some(hash) = missing {
        return Err(error(
            409,
            &format!("Push job member {hash}: absent or conflicting metadata"),
        ));
    }
    sqlx::query(
        "WITH completed AS (UPDATE push_jobs SET state='completed',completed_at=NOW(), \
         protection_expires_at=LEAST(NOW()+INTERVAL '5 minutes',idle_expires_at,hard_expires_at,authorization_expires_at), \
         grant_generation=grant_generation+1,work_id=NULL,work_expires_at=NULL WHERE id=$1 RETURNING id) \
         UPDATE upload_sessions SET status='aborted',expires_at=LEAST(expires_at,NOW()) \
         WHERE push_job_id IN (SELECT id FROM completed) AND status IN ('streaming','finalizing')",
    ).bind(&id).execute(&mut *tx).await?;
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    tx.commit().await?;
    Ok(response(StatusCode::OK, job, &state))
}

async fn cancel(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // A tier downgrade or disabled protocol must not prevent cancellation.
    let (mut tx, cache_id) = writer(&state, &identity, &name, false).await?;
    let actor = identity.actor();
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    if !matches!(job.state.as_str(), "cancelled" | "completed") {
        sqlx::query(
            "WITH cancelled AS (UPDATE push_jobs SET state='cancelled',grant_generation=grant_generation+1, \
            authorization_jti=NULL,authorization_expires_at=NULL WHERE id=$1 RETURNING id) \
            UPDATE upload_sessions SET status='aborted' WHERE push_job_id IN (SELECT id FROM cancelled) \
            AND status IN ('streaming','finalizing')",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    }
    let job = load(&mut *tx, cache_id, &actor, &id).await?;
    tx.commit().await?;
    Ok(response(StatusCode::OK, job, &state))
}

#[derive(Deserialize)]
struct Page {
    after: Option<String>,
    #[serde(default)]
    summary: bool,
}

// Callers hold the org fence. Include absent named members: a deletion must
// invalidate their existing authorization, not merely remove visible rows.
pub(crate) async fn withdraw(
    tx: &mut Transaction,
    cache: i32,
    hashes: Option<&[String]>,
) -> Result<(), ApiError> {
    sqlx::query("WITH cancelled AS (UPDATE push_jobs j SET state='cancelled',grant_generation=grant_generation+1, \
        authorization_jti=NULL,authorization_expires_at=NULL WHERE cache_id=$1 AND state IN ('building','sealed') \
        AND ($2::text[] IS NULL OR EXISTS (SELECT 1 FROM push_job_members m \
        WHERE m.job_id=j.id AND m.store_path_hash=ANY($2))) RETURNING id) \
        UPDATE upload_sessions SET status='aborted' WHERE push_job_id IN (SELECT id FROM cancelled) \
        AND status IN ('streaming','finalizing')")
        .bind(cache).bind(hashes).execute(&mut **tx).await?;
    Ok(())
}

async fn progress(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((name, id)): Path<(String, String)>,
    Query(page): Query<Page>,
) -> Result<Response, ApiError> {
    let cache_id = cache(&state.pool, &identity, &name, true).await?;
    let after = page.after.unwrap_or_default();
    if after.len() > 32 {
        return Err(error(400, "Invalid page cursor"));
    }
    let limit = state.config.push_jobs.chunk_members;
    #[derive(FromRow)]
    struct Progress {
        #[sqlx(flatten)]
        job: Job,
        chunks: Json<Vec<i32>>,
        members: Json<Vec<Value>>,
        available: Option<bool>,
        blocked: Option<bool>,
    }
    // One statement snapshot prevents mixing a building revision with members
    // from a concurrent seal. No read transaction or org fence is necessary.
    // Summary requests check exact current membership but skip the member
    // page, session hydration, and candidate lookups with a zero row limit.
    let Progress { job, chunks, mut members, available, blocked }: Progress = sqlx::query_as(
        "SELECT j.id,j.mode,j.roots,j.state,j.revision,j.manifest_digest,j.manifest_bytes,j.input_members, \
         j.grant_generation,FLOOR(EXTRACT(EPOCH FROM j.authorization_expires_at))::bigint AS authorization_expires_at, \
         FLOOR(EXTRACT(EPOCH FROM j.completed_at))::bigint AS completed_at, \
         FLOOR(EXTRACT(EPOCH FROM j.protection_expires_at))::bigint AS protection_expires_at, \
         FLOOR(EXTRACT(EPOCH FROM LEAST(j.idle_expires_at,j.hard_expires_at)))::bigint AS expires_at, \
         FLOOR(EXTRACT(EPOCH FROM j.hard_expires_at))::bigint AS hard_expires_at, \
         j.state='completed' OR (j.idle_expires_at>NOW() AND j.hard_expires_at>NOW()) AS valid, \
         CASE WHEN (j.state='completed' OR ($6 AND j.state='sealed')) AND j.manifest_bytes>0 THEN NOT EXISTS ( \
             SELECT 1 FROM push_job_members m WHERE m.job_id=j.id AND NOT EXISTS ( \
                 SELECT 1 FROM published_paths p WHERE p.cache_id=j.cache_id AND p.store_path_hash=m.store_path_hash \
                 AND m.metadata->>'storePath'=p.store_path AND m.metadata->>'narHash'=p.nar_hash \
                 AND (m.metadata->>'narSize')::bigint=p.nar_size \
                 AND (m.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver \
                 AND p.references_json::jsonb @> (m.metadata->'references') \
                 AND (m.metadata->'references') @> p.references_json::jsonb)) END AS available, \
         CASE WHEN $6 THEN EXISTS (SELECT 1 FROM push_job_members m WHERE m.job_id=j.id \
             AND m.blocked_generation=j.grant_generation AND m.publication_error IS NOT NULL) END AS blocked, \
         COALESCE((SELECT jsonb_agg(ordinal ORDER BY ordinal) FROM push_manifest_chunks WHERE job_id=j.id),'[]') AS chunks, \
         COALESCE((SELECT jsonb_agg(metadata ORDER BY store_path_hash) FROM (SELECT m.store_path_hash, \
             m.metadata || CASE WHEN m.blocked_generation=j.grant_generation \
                 THEN jsonb_build_object('publicationError',m.publication_error) ELSE '{}'::jsonb END \
             || jsonb_build_object('session',CASE WHEN u.id IS NOT NULL THEN jsonb_build_object( \
                 'sessionId',u.id,'status',u.status,'publicationResult',u.publication_result, \
                 'prepared',u.status='finalizing' AND EXISTS ( \
                     SELECT 1 FROM nar_installations n JOIN caches c ON c.id=n.cache_id \
                     WHERE n.session_id=u.id AND n.phase='ready' AND n.expires_at>NOW() \
                         AND n.is_private=NOT c.is_public)) END, \
                 'available',EXISTS (SELECT 1 FROM published_paths p WHERE p.cache_id=j.cache_id \
                     AND p.store_path_hash=m.store_path_hash AND m.metadata->>'storePath'=p.store_path \
                     AND m.metadata->>'narHash'=p.nar_hash AND (m.metadata->>'narSize')::bigint=p.nar_size \
                     AND (m.metadata->>'deriver') IS NOT DISTINCT FROM p.deriver \
                     AND p.references_json::jsonb @> (m.metadata->'references') \
                     AND (m.metadata->'references') @> p.references_json::jsonb)) AS metadata \
             FROM push_job_members m LEFT JOIN upload_sessions u ON u.id=m.session_id \
                 AND u.expires_at>NOW() AND u.status<>'aborted' \
             WHERE m.job_id=j.id AND m.store_path_hash>$4 ORDER BY m.store_path_hash LIMIT $5) page),'[]') AS members \
         FROM push_jobs j WHERE j.cache_id=$1 AND j.creator=$2 AND j.id=$3",
    ).bind(cache_id).bind(identity.actor()).bind(&id).bind(after)
        .bind(if page.summary { 0 } else { (limit+1) as i64 }).bind(page.summary)
        .fetch_optional(&state.pool).await?.ok_or_else(|| error(404, "Job not found"))?;
    if !job.valid {
        return Err(error(410, "Push job expired; create a new job"));
    }
    let more = members.0.len() > limit;
    members.0.truncate(limit);
    let next = more.then(|| {
        members.0.last().unwrap()["storePathHash"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    });
    Ok(respond(
        StatusCode::OK,
        &PushJobPage::<Value> {
            envelope: envelope(job, &state)?,
            chunks: chunks.0,
            members: members.0.into_iter().map(member).collect(),
            next,
            available,
            blocked,
        },
    ))
}
