//! Durable multipart admission and consumers. Candidate leases own bytes;
//! batch leases bound scheduling. Neither lease holds a SQL connection.
use super::*;
use crate::authz::{ApiToken, CacheGrant, Permission};
use tokio_util::sync::CancellationToken;

pub(super) async fn enqueue_finalizations(
    state: &AppState,
    identity: &Identity,
    inputs: Vec<Receipt>,
    options: Finalization,
) -> Result<UploadResults, ApiError> {
    let mut batches = HashMap::<(String, Option<String>), String>::new();
    let mut results = Vec::with_capacity(inputs.len());
    for (ordinal, input) in inputs.into_iter().enumerate() {
        let id = input.session_id.clone();
        let accepted = async {
            let session = load(&state.pool, &id, identity).await?;
            options.validate(&session)?;
            let group = (session.org_id.clone(), session.push_job_id.clone());
            let batch = match batches.get(&group) {
                Some(batch) => batch.clone(),
                None => {
                    let batch = uuid::Uuid::now_v7().to_string();
                    let token = match identity { Identity::ApiToken(token) => Some(token), _ => None };
                    sqlx::query(
                        "INSERT INTO upload_finalization_batches(id,org_id,actor,token_jti,shared_generation,prepare_only,expires_at,job_id,grant_generation) \
                         VALUES($1,$2,$3,$4,$5,$6,LEAST((SELECT expires_at FROM upload_sessions WHERE id=$8),to_timestamp($7::double precision)), \
                         $9,(SELECT grant_generation FROM push_jobs WHERE id=$9))",
                    ).bind(&batch).bind(&session.org_id).bind(identity.actor())
                        .bind(token.map(|t| t.id.as_str()))
                        .bind(if token.is_none() { shared_generation(state) } else { None })
                        .bind(options.prepare_only).bind(token.and_then(|t| t.expires_at.map(|at| at.timestamp() as f64)))
                        .bind(&session.id)
                        .bind(&session.push_job_id)
                        .execute(&state.pool).await?;
                    batches.insert(group, batch.clone());
                    batch
                }
            };
            seal(state, identity, &session, &input, None, Some((&batch, ordinal, options.prepare_only))).await?;
            Ok::<_, ApiError>(())
        }.await;
        results.push(match accepted {
            Ok(()) => UploadResult::pending(&id, UploadStage::Queued),
            Err(error) => UploadResult::failed(&id, error.status.as_u16(), &error.message),
        });
    }
    // A crashed admission becomes runnable after 60 seconds. Its already
    // sealed members are complete durable work, not an incomplete receipt.
    let batches: Vec<_> = batches.into_values().collect();
    sqlx::query("UPDATE upload_finalization_batches SET admitted=true WHERE id=ANY($1)")
        .bind(&batches)
        .execute(&state.pool)
        .await?;
    sqlx::query(
        "DELETE FROM upload_finalization_batches b WHERE id=ANY($1) \
        AND NOT EXISTS(SELECT 1 FROM upload_finalizations f WHERE f.batch_id=b.id)",
    )
    .bind(&batches)
    .execute(&state.pool)
    .await?;
    let accepted: Vec<_> = results
        .iter()
        .filter(|r| r.error.is_none())
        .map(|r| r.session_id.clone())
        .collect();
    let current = status_rows(state, identity, &accepted).await?;
    for row in &mut results {
        if let Some(value) = current
            .iter()
            .find(|value| value.session_id == row.session_id)
        {
            *row = value.clone();
        }
    }
    Ok(UploadResults { results })
}

pub(super) async fn status(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    request: Request,
) -> Result<Response, ApiError> {
    request_origin(&state, &request)?;
    let input: UploadStatusRequest = json_body(request).await?;
    batch(&input.sessions)?;
    distinct(input.sessions.iter().map(String::as_str))?;
    Ok(respond(
        StatusCode::OK,
        &UploadResults {
            results: status_rows(&state, &identity, &input.sessions).await?,
        },
    ))
}

#[derive(sqlx::FromRow)]
struct StatusRow {
    id: String,
    cache_id: i32,
    org: String,
    name: String,
    status: String,
    store_path_hash: String,
    publication_result: Option<Value>,
    result: Option<Value>,
    expires: bool,
    authorized: bool,
    prepare_only: Option<bool>,
    prepared: bool,
    verifying: bool,
    actor: Option<String>,
    job_authorized: bool,
}

async fn status_rows(
    state: &AppState,
    identity: &Identity,
    ids: &[String],
) -> Result<Vec<UploadResult>, ApiError> {
    // A single statement snapshot. This never renews, cleans, or schedules work.
    let rows: Vec<StatusRow> = sqlx::query_as(
        "SELECT u.id,u.cache_id,c.org_id AS org,c.name,u.status,u.store_path_hash,u.publication_result, \
         f.result,u.expires_at<=NOW() AS expires, \
         COALESCE(b.expires_at>NOW() AND ((b.token_jti IS NOT NULL AND t.revoked_at IS NULL \
             AND (t.expires_at IS NULL OR t.expires_at>NOW())) OR b.shared_generation=$2),false) AS authorized, \
         b.prepare_only,b.actor, \
         COALESCE(u.push_job_id IS NULL OR (j.creator=$3 AND j.cache_id=u.cache_id AND $4 \
             AND (j.state='sealed' OR (j.state='completed' AND u.status='completed')) \
             AND j.idle_expires_at>NOW() AND j.hard_expires_at>NOW() AND j.authorization_expires_at>NOW() \
             AND EXISTS(SELECT 1 FROM api_tokens jt WHERE jt.jti=j.authorization_jti AND jt.revoked_at IS NULL)),false) AS job_authorized, \
         COALESCE(n.phase='ready' AND n.expires_at>NOW() AND n.is_private=NOT c.is_public,false) AS prepared, \
         COALESCE(n.phase='preparing' AND n.lease_expires_at>NOW(),false) AS verifying \
         FROM upload_sessions u JOIN caches c ON c.id=u.cache_id \
         LEFT JOIN upload_finalizations f ON f.session_id=u.id \
         LEFT JOIN upload_finalization_batches b ON b.id=f.batch_id \
         LEFT JOIN api_tokens t ON t.jti=b.token_jti \
         LEFT JOIN push_jobs j ON j.id=u.push_job_id \
         LEFT JOIN nar_installations n ON n.session_id=u.id WHERE u.id=ANY($1) \
         AND EXISTS(SELECT 1 FROM cache_protocols p WHERE p.cache_id=c.id AND p.protocol='nix')",
    ).bind(ids).bind(shared_generation(state)).bind(identity.actor())
        .bind(matches!(identity, Identity::ApiToken(_))).fetch_all(&state.pool).await?;
    Ok(ids
        .iter()
        .map(|id| {
            let Some(row) = rows.iter().find(|row| &row.id == id) else {
                return UploadResult::failed(id, 404, "Not found");
            };
            if decide(
                identity,
                Action::NixPush,
                &Resource::cache(&row.org, row.cache_id, &row.name),
            )
            .is_err()
            {
                return UploadResult::failed(id, 403, "Forbidden");
            }
            if !row.job_authorized {
                return UploadResult::failed(
                    id,
                    409,
                    "Push job authorization is inactive; resume the job",
                );
            }
            if row.expires {
                return UploadResult::failed(id, 410, "Upload session expired");
            }
            if row.status == "aborted" {
                return UploadResult::failed(id, 409, "Upload session aborted");
            }
            if row.status == "completed" {
                return crate::wire::stored(row.publication_result.clone())
                    .unwrap_or_else(|| UploadResult::published(id, &row.store_path_hash));
            }
            if let Some(result) = crate::wire::stored(row.result.clone()) {
                return result;
            }
            if row.actor.is_none() {
                return UploadResult::failed(id, 409, "Upload is not finalized");
            }
            if !row.authorized {
                return UploadResult::failed(
                    id,
                    401,
                    "Finalization authorization expired or revoked",
                );
            }
            if row.prepared && row.prepare_only == Some(true) {
                return UploadResult::prepared(id, &row.store_path_hash);
            }
            UploadResult::pending(
                id,
                if row.prepared {
                    UploadStage::Publishing
                } else if row.verifying {
                    UploadStage::Verifying
                } else {
                    UploadStage::Queued
                },
            )
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct Work {
    id: String,
    org_id: String,
    actor: String,
    token_jti: Option<String>,
    shared_generation: Option<String>,
    prepare_only: bool,
    failures: i32,
    remaining: f64,
}

/// Separate preparation consumers keep slow storage from starving the
/// existing SQL-only job publisher. Local resource gates bound actual I/O.
pub(crate) async fn run(state: AppState, stopped: CancellationToken) {
    let mut after = String::new();
    loop {
        if stopped.is_cancelled() {
            break;
        }
        match turn(&state, &mut after).await {
            Ok(true) => tokio::task::yield_now().await,
            result => {
                if result.is_err() {
                    tracing::warn!("Multipart finalization deferred; SQL retains work");
                }
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn turn(state: &AppState, after: &mut String) -> Result<bool, ApiError> {
    let org: Option<String> = sqlx::query_scalar(
        "SELECT b.org_id FROM upload_finalization_batches b WHERE b.org_id>$1 AND b.work_at<=NOW() \
         AND (b.admitted OR b.created_at<NOW()-INTERVAL '60 seconds') \
         AND (b.lease_expires_at IS NULL OR b.lease_expires_at<=NOW()) \
         AND EXISTS(SELECT 1 FROM upload_finalizations f WHERE f.batch_id=b.id AND f.result IS NULL) \
         ORDER BY b.org_id LIMIT 1",
    ).bind(&*after).fetch_optional(&state.pool).await?;
    let Some(org) = org else {
        after.clear();
        return Ok(false);
    };
    *after = org.clone();
    let mut tx = db::begin(state, &org).await?;
    lock(&mut tx, &format!("org:{org}")).await?;
    let work: Option<Work> = sqlx::query_as(
        "SELECT b.id,b.org_id,b.actor,b.token_jti,b.shared_generation,b.prepare_only,b.failures, \
         EXTRACT(EPOCH FROM b.expires_at-NOW())::double precision AS remaining \
         FROM upload_finalization_batches b WHERE b.org_id=$1 AND b.work_at<=NOW() \
         AND (b.admitted OR b.created_at<NOW()-INTERVAL '60 seconds') \
         AND (b.lease_expires_at IS NULL OR b.lease_expires_at<=NOW()) \
         AND EXISTS(SELECT 1 FROM upload_finalizations f WHERE f.batch_id=b.id AND f.result IS NULL) \
         ORDER BY b.work_at,b.id LIMIT 1 FOR UPDATE OF b NOWAIT",
    ).bind(&org).fetch_optional(&mut *tx).await?;
    let Some(work) = work else {
        return Ok(false);
    };
    let started = std::time::Instant::now();
    let claim = uuid::Uuid::now_v7().to_string();
    sqlx::query("UPDATE upload_finalization_batches SET admitted=true,work_id=$2,lease_expires_at=NOW()+INTERVAL '60 seconds' WHERE id=$1")
        .bind(&work.id).bind(&claim).execute(&mut *tx).await?;
    let receipts: Vec<sqlx::types::Json<Receipt>> = sqlx::query_scalar(
        "SELECT receipt FROM upload_finalizations WHERE batch_id=$1 AND result IS NULL ORDER BY ordinal",
    ).bind(&work.id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let result = async {
    let inputs: Vec<_> = receipts.into_iter().map(|r| r.0).collect();
    let ids: Vec<_> = inputs.iter().map(|r| r.session_id.clone()).collect();
    let identity = if let Some(token) = &work.token_jti {
        let caches: Vec<i32> =
            sqlx::query_scalar("SELECT DISTINCT cache_id FROM upload_sessions WHERE id=ANY($1)")
                .bind(&ids)
                .fetch_all(&state.pool)
                .await?;
        Identity::ApiToken(ApiToken {
            id: token.clone(),
            org: work.org_id.clone(),
            permissions: vec![Permission::Push],
            caches: caches.into_iter().map(CacheGrant::Id).collect(),
            expires_at: None,
        })
    } else {
        Identity::SharedToken
    };
    let live = work.remaining > 0.0
        && (work.token_jti.is_some()
            || (work.actor == "legacy"
                && work.shared_generation.is_some()
                && work.shared_generation == shared_generation(state)));
    let results = if !live {
        ids.iter()
            .map(|id| {
                Some(UploadResult::failed(
                    id,
                    401,
                    "Finalization authorization expired or revoked",
                ))
            })
            .collect()
    } else {
        let task = finalize_batch(
            state,
            &identity,
            inputs,
            Finalization {
                prepare_only: work.prepare_only,
            },
        );
        tokio::pin!(task);
        let deadline = tokio::time::sleep(Duration::from_secs_f64(work.remaining));
        tokio::pin!(deadline);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(20),
            Duration::from_secs(20),
        );
        // Continue polling work while renewal waits for SQL. The work may
        // itself own the only pool connection during a short transaction.
        let renew = async {
            loop {
                heartbeat.tick().await;
                let changed = sqlx::query("UPDATE upload_finalization_batches SET lease_expires_at=LEAST(expires_at,NOW()+INTERVAL '60 seconds') \
                    WHERE id=$1 AND work_id=$2 AND lease_expires_at>NOW() AND expires_at>NOW()")
                    .bind(&work.id).bind(&claim).execute(&state.pool).await?.rows_affected();
                if changed != 1 { return Ok::<_, ApiError>(()); }
            }
        };
        tokio::pin!(renew);
        tokio::select! {
            result = &mut task => result,
            _ = &mut deadline => ids.iter().map(|id| Some(UploadResult::failed(id,401,"Finalization deadline expired"))).collect(),
            result = &mut renew => { result?; return Ok(true); }
        }
    };
    let mut tx = db::begin_queued(state, &org).await?;
    lock(&mut tx, &format!("org:{org}")).await?;
    // Hold the batch row while settling. A job resume resets results and the
    // claim under the same row lock, so it runs wholly before or after this.
    let owned: Option<bool> = sqlx::query_scalar("SELECT TRUE FROM upload_finalization_batches WHERE id=$1 AND work_id=$2 AND lease_expires_at>NOW() FOR UPDATE")
        .bind(&work.id).bind(&claim).fetch_optional(&mut *tx).await?;
    if owned.is_none() {
        tracing::info!(batch_id=%work.id,work_id=%claim,count=ids.len(),elapsed_ms=started.elapsed().as_millis() as u64,
            status="replaced",error_category="lease","Multipart finalization turn finished");
        return Ok(true);
    }
    let mut retry = false;
    let mut category = "none";
    for (id, result) in ids.iter().zip(results) {
        let Some(result) = result else {
            retry = true;
            continue;
        };
        if let Some(code) = result.status.filter(|code| *code != 202) {
            category = match code {
                400 => "verification",
                401 | 403 => "authorization",
                404 | 409 | 410 => "state",
                413 | 507 => "capacity",
                _ => "transient",
            };
        }
        if result
            .status
            .is_some_and(|code| matches!(code, 408 | 409 | 429 | 500 | 502 | 503 | 504))
            && !result.prepared
            && !result.published
        {
            retry = true;
            continue;
        }
        // Each write still requires the claim, so a result computed under a
        // replaced grant is never written back over a reset.
        sqlx::query("UPDATE upload_finalizations f SET result=$2 FROM upload_finalization_batches b \
            WHERE f.session_id=$1 AND f.batch_id=$3 AND f.result IS NULL AND b.id=f.batch_id AND b.work_id=$4")
            .bind(id).bind(sqlx::types::Json(&result)).bind(&work.id).bind(&claim).execute(&mut *tx).await?;
    }
    let failures = if retry { (work.failures + 1).min(6) } else { 0 };
    let delay = if retry {
        (25 * (1i32 << failures)).min(1000) + (uuid::Uuid::now_v7().as_u128() % 26) as i32
    } else {
        0
    };
    sqlx::query(
        "UPDATE upload_finalization_batches SET work_id=NULL,lease_expires_at=NULL,failures=$3, \
        work_at=CASE WHEN $5 THEN clock_timestamp()+$4*INTERVAL '1 millisecond' \
        ELSE 'infinity'::timestamptz END WHERE id=$1 AND work_id=$2",
    )
    .bind(&work.id)
    .bind(&claim)
    .bind(failures)
    .bind(f64::from(delay))
    .bind(retry)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(batch_id=%work.id,work_id=%claim,count=ids.len(),elapsed_ms=started.elapsed().as_millis() as u64,
        status=if retry {"retry"} else {"settled"},error_category=category,failures,
        "Multipart finalization turn finished");
    Ok::<_, ApiError>(true)
    }.await;
    if let Err(error) = &result {
        // A live process must not strand its batch until the crash lease
        // expires merely because SQL admission or an org fence was busy.
        // Matching the claim prevents this cleanup from disturbing a successor.
        let released = sqlx::query(
            "UPDATE upload_finalization_batches SET work_id=NULL,lease_expires_at=NULL, \
            failures=LEAST(failures+1,6),work_at=clock_timestamp()+INTERVAL '100 milliseconds' \
            WHERE id=$1 AND work_id=$2",
        )
        .bind(&work.id)
        .bind(&claim)
        .execute(&state.pool)
        .await;
        tracing::warn!(batch_id=%work.id,work_id=%claim,status=error.status.as_u16(),
            requeued=released.as_ref().is_ok_and(|row| row.rows_affected()>0),"Multipart finalization settlement deferred");
    }
    result
}

/// Release non-job staging admission at the delegation deadline. Revoked
/// credentials release job staging too; a revoked token cannot resume a job.
pub(crate) async fn expire(state: &AppState) -> anyhow::Result<u64> {
    // This runs every second. Start from the sessions still finalizing and
    // from the deadline index, never from every retained batch and member.
    let batches: Vec<(String, String)> = sqlx::query_as(
        "SELECT id,org_id FROM ( \
             SELECT b.id,b.org_id,b.expires_at FROM upload_sessions u \
             JOIN upload_finalizations f ON f.session_id=u.id \
             JOIN upload_finalization_batches b ON b.id=f.batch_id \
             LEFT JOIN api_tokens t ON t.jti=b.token_jti \
             WHERE u.status='finalizing' AND ( \
                 (b.expires_at<=NOW() AND u.push_job_id IS NULL) \
                 OR (b.shared_generation IS NULL AND (t.jti IS NULL OR t.revoked_at IS NOT NULL)) \
                 OR (b.shared_generation IS NOT NULL AND b.shared_generation IS DISTINCT FROM $1)) \
             UNION \
             SELECT b.id,b.org_id,b.expires_at FROM upload_finalization_batches b \
             WHERE b.expires_at<NOW()-INTERVAL '24 hours') due \
         ORDER BY expires_at,id LIMIT 20",
    )
    .bind(shared_generation(state))
    .fetch_all(&state.pool)
    .await?;
    let mut count = 0;
    for (id, org) in batches {
        let mut tx = db::begin(state, &org).await?;
        lock(&mut tx, &format!("org:{org}")).await?;
        count+=sqlx::query(
            "WITH expired AS (UPDATE upload_sessions u SET status='aborted',expires_at=LEAST(u.expires_at,NOW()) \
             FROM upload_finalizations f,upload_finalization_batches b LEFT JOIN api_tokens t ON t.jti=b.token_jti \
             WHERE b.id=$1 AND f.batch_id=b.id AND u.id=f.session_id AND u.status='finalizing' AND ( \
                 (b.expires_at<=NOW() AND u.push_job_id IS NULL) \
                 OR (b.shared_generation IS NULL AND (t.jti IS NULL OR t.revoked_at IS NOT NULL)) \
                 OR (b.shared_generation IS NOT NULL AND b.shared_generation IS DISTINCT FROM $2)) \
             RETURNING u.id,u.r2_upload_key,u.r2_upload_id) \
             INSERT INTO object_cleanup(is_private,key,upload_id) \
             SELECT TRUE,r2_upload_key,NULLIF(r2_upload_id,id) FROM expired WHERE r2_upload_key IS NOT NULL \
             ON CONFLICT(is_private,key) DO UPDATE SET upload_id=COALESCE(EXCLUDED.upload_id,object_cleanup.upload_id)",
        ).bind(&id).bind(shared_generation(state)).execute(&mut *tx).await?.rows_affected();
        sqlx::query("DELETE FROM upload_finalization_batches b WHERE b.id=$1 AND b.expires_at<NOW()-INTERVAL '24 hours' \
            AND NOT EXISTS(SELECT 1 FROM upload_finalizations f JOIN upload_sessions u ON u.id=f.session_id \
                WHERE f.batch_id=b.id AND u.status='finalizing' AND u.expires_at>NOW())")
            .bind(&id).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn fixture(pool: sqlx::PgPool) -> (AppState, Receipt) {
        let state = AppState::new(
            pool.clone(),
            crate::config::Config {
                shared_auth_token: Some("fixture-shared".into()),
                ..Default::default()
            },
            crate::storage::Storage::from_stores(
                Arc::new(InMemory::new()),
                Arc::new(InMemory::new()),
            ),
            reqwest::Client::new(),
        )
        .unwrap();
        let cache: i32 = sqlx::query_scalar(
            "INSERT INTO caches(name,is_public) VALUES('queued',true) RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) VALUES($1,'nix')")
            .bind(cache)
            .execute(&pool)
            .await
            .unwrap();
        let receipt = Receipt {
            session_id: "queued-session".into(),
            nar_hash: format!("sha256:{}", signing::nix32(&[0; 32])),
            nar_size: 1,
            file_hash: "a".repeat(64),
            file_size: 1,
            parts: vec![ReceiptPart {
                part_number: 1,
                etag: "receipt-etag".into(),
            }],
        };
        sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at,part_size) \
            VALUES($1,$2,$3,$4,$5,1,1,'zstd','streaming','staging/queued-session/source','provider-upload',NOW()+INTERVAL '2 hours',8388608)")
            .bind(&receipt.session_id).bind(cache).bind("0".repeat(32)).bind(format!("/nix/store/{}-queued","0".repeat(32)))
            .bind(&receipt.nar_hash).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO upload_parts(session_id,part_number,size) VALUES($1,1,1)")
            .bind(&receipt.session_id)
            .execute(&pool)
            .await
            .unwrap();
        (state, receipt)
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn admission_is_immediate_and_status_does_not_schedule(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        // The plain router deliberately has no consumer. There are no source
        // bytes, so an inline storage/verification implementation would fail.
        let app = crate::router(state.clone());
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(routes::FINALIZE)
            .header("host", "backend.local")
            .header("authorization", "Bearer fixture-shared")
            .header(
                protocol::PROTOCOL_VERSION_HEADER,
                protocol::PROTOCOL_VERSION,
            )
            .body(Body::from(
                serde_json::to_vec(&FinalizeBatch {
                    uploads: vec![receipt.clone()],
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 65536).await.unwrap();
        let rows: UploadResults = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.results[0].stage, Some(UploadStage::Queued));
        let before: Value =
            sqlx::query_scalar("SELECT to_jsonb(b) FROM upload_finalization_batches b")
                .fetch_one(&pool)
                .await
                .unwrap();
        let ids = vec!["missing".to_owned(), receipt.session_id.clone()];
        for _ in 0..3 {
            let rows = status_rows(&state, &Identity::SharedToken, &ids)
                .await
                .unwrap();
            assert_eq!(rows[0].status, Some(404));
            assert_eq!(rows[1].stage, Some(UploadStage::Queued));
        }
        let after: Value =
            sqlx::query_scalar("SELECT to_jsonb(b) FROM upload_finalization_batches b")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(before, after);
        let duplicate = enqueue_finalizations(
            &state,
            &Identity::SharedToken,
            vec![receipt.clone()],
            Finalization::default(),
        )
        .await
        .unwrap();
        assert_eq!(duplicate.results[0].stage, Some(UploadStage::Queued));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_finalization_batches")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let mut changed = receipt.clone();
        changed.parts[0].etag = "changed".into();
        let rejected = enqueue_finalizations(
            &state,
            &Identity::SharedToken,
            vec![changed],
            Finalization::default(),
        )
        .await
        .unwrap();
        assert_eq!(rejected.results[0].status, Some(409));

        // A recovery consumer closes admission under the same org fence as
        // appends. A late request must retry into a new batch, not disappear.
        sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at,part_size) \
            SELECT 'late-session',cache_id,repeat('1',32),'/nix/store/'||repeat('1',32)||'-late',nar_hash,nar_size,file_size,compression,'streaming','staging/late/source','late-provider',expires_at,part_size FROM upload_sessions WHERE id='queued-session'")
            .execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO upload_parts(session_id,part_number,size) VALUES('late-session',1,1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let late = Receipt {
            session_id: "late-session".into(),
            ..receipt
        };
        let session = load(&pool, &late.session_id, &Identity::SharedToken)
            .await
            .unwrap();
        let closed = seal(
            &state,
            &Identity::SharedToken,
            &session,
            &late,
            None,
            Some((before["id"].as_str().unwrap(), 1, false)),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(closed.status, StatusCode::SERVICE_UNAVAILABLE);
        let unsealed: bool = sqlx::query_scalar("SELECT status='streaming' AND NOT EXISTS(SELECT 1 FROM upload_finalizations WHERE session_id=u.id) FROM upload_sessions u WHERE id='late-session'")
            .fetch_one(&pool).await.unwrap();
        assert!(unsealed);

        sqlx::query(
            "UPDATE upload_sessions SET push_job_id='missing-job' WHERE id='queued-session'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            status_rows(&state, &Identity::SharedToken, &ids)
                .await
                .unwrap()[1]
                .status,
            Some(409)
        );
        sqlx::raw_sql("UPDATE upload_sessions SET push_job_id=NULL WHERE id='queued-session'; DELETE FROM cache_protocols")
            .execute(&pool).await.unwrap();
        assert_eq!(
            status_rows(&state, &Identity::SharedToken, &ids)
                .await
                .unwrap()[1]
                .status,
            Some(404)
        );
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn restarted_consumer_reuses_ready_candidate_and_replays_result(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        enqueue_finalizations(
            &state,
            &Identity::SharedToken,
            vec![receipt.clone()],
            Finalization::default(),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE upload_finalization_batches SET admitted=false,created_at=NOW()-INTERVAL '61 seconds',work_id='dead-process',lease_expires_at=NOW()-INTERVAL '1 second'")
            .execute(&pool).await.unwrap();
        // Model a verifier which committed readiness before the process died.
        // No source or destination I/O may be needed to finish publication.
        sqlx::query("INSERT INTO nar_installations(key,operation_id,file_hash,compression,is_private,file_size,cache_id,session_id,expires_at,phase) \
            SELECT 'nar/objects/fixture','fixture-operation',file_hash,'zstd',false,file_size,cache_id,id,expires_at,'ready' FROM upload_sessions WHERE id=$1")
            .bind(&receipt.session_id).execute(&pool).await.unwrap();
        // Losing a result write after publication must release the live claim
        // immediately, not hide accepted work behind its 60-second crash lease.
        sqlx::raw_sql("CREATE FUNCTION fail_finalization_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected settlement failure'; END $$;
            CREATE TRIGGER fail_finalization_result BEFORE UPDATE ON upload_finalizations FOR EACH ROW EXECUTE FUNCTION fail_finalization_result();")
            .execute(&pool).await.unwrap();
        assert!(turn(&state, &mut String::new()).await.is_err());
        let requeued: bool = sqlx::query_scalar("SELECT work_id IS NULL AND lease_expires_at IS NULL AND work_at<clock_timestamp()+INTERVAL '1 second' FROM upload_finalization_batches")
            .fetch_one(&pool).await.unwrap();
        assert!(requeued);
        sqlx::raw_sql("DROP TRIGGER fail_finalization_result ON upload_finalizations; DROP FUNCTION fail_finalization_result(); UPDATE upload_finalization_batches SET work_at=NOW();")
            .execute(&pool).await.unwrap();
        assert!(turn(&state, &mut String::new()).await.unwrap());
        let ids = vec![receipt.session_id.clone()];
        let parked: bool = sqlx::query_scalar(
            "SELECT admitted AND work_at='infinity'::timestamptz FROM upload_finalization_batches",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            parked,
            "settled batches must leave the runnable index range"
        );
        let first = status_rows(&state, &Identity::SharedToken, &ids)
            .await
            .unwrap();
        assert!(first[0].published);
        let replay = enqueue_finalizations(
            &state,
            &Identity::SharedToken,
            vec![receipt],
            Finalization::default(),
        )
        .await
        .unwrap();
        assert_eq!(first, replay.results);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn deadline_releases_staging_and_abort_blocks_adoption(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        enqueue_finalizations(
            &state,
            &Identity::SharedToken,
            vec![receipt.clone()],
            Finalization::default(),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE upload_finalization_batches SET expires_at=NOW()-INTERVAL '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(expire(&state).await.unwrap(), 1);
        let status: String = sqlx::query_scalar("SELECT status FROM upload_sessions WHERE id=$1")
            .bind(&receipt.session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "aborted");
        let rows = status_rows(
            &state,
            &Identity::SharedToken,
            std::slice::from_ref(&receipt.session_id),
        )
        .await
        .unwrap();
        assert_eq!(rows[0].status, Some(410));
        assert!(turn(&state, &mut String::new()).await.unwrap());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn explicit_job_resume_renews_only_its_grant_and_fences_old_publication(
        pool: sqlx::PgPool,
    ) {
        let (state, receipt) = fixture(pool.clone()).await;
        let (id, bearer, hash) = crate::auth::issue_token().unwrap();
        sqlx::query("INSERT INTO api_tokens(jti,subject,created_by,org_id,secret_hash) VALUES($1,'fixture','fixture','default',$2)")
            .bind(&id).bind(hash).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO token_permissions(token_jti,permission,position) VALUES($1,'push',0)",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO token_caches(token_jti,pattern) VALUES($1,'*')")
            .bind(&id)
            .execute(&pool)
            .await
            .unwrap();
        let identity = Identity::ApiToken(ApiToken {
            id: id.clone(),
            org: "default".into(),
            permissions: vec![Permission::Push],
            caches: vec![CacheGrant::Pattern("*".into())],
            expires_at: None,
        });
        sqlx::query("INSERT INTO push_jobs(id,cache_id,creator,idempotency_key,mode,roots,state,manifest_bytes,authorization_jti,authorization_claims,authorization_expires_at,grant_generation) \
            SELECT 'resume-job',cache_id,$2,'fixture','selected','[]','sealed',0,$2,'{}',NOW()+INTERVAL '20 minutes',1 FROM upload_sessions WHERE id=$1")
            .bind(&receipt.session_id).bind(&id).execute(&pool).await.unwrap();
        sqlx::query("UPDATE upload_sessions SET push_job_id='resume-job' WHERE id=$1")
            .bind(&receipt.session_id)
            .execute(&pool)
            .await
            .unwrap();
        enqueue_finalizations(
            &state,
            &identity,
            vec![receipt.clone()],
            Finalization { prepare_only: true },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE upload_finalization_batches SET work_id='old-claim',lease_expires_at=NOW()+INTERVAL '60 seconds'").execute(&pool).await.unwrap();
        let session = load(&pool, &receipt.session_id, &identity).await.unwrap();
        let old = seal(&state, &identity, &session, &receipt, None, None)
            .await
            .unwrap();
        sqlx::query("UPDATE push_jobs SET authorization_expires_at=NOW()-INTERVAL '1 second' WHERE id='resume-job'").execute(&pool).await.unwrap();
        sqlx::query("UPDATE upload_finalization_batches SET expires_at=NOW()-INTERVAL '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE upload_finalizations SET result=$1")
            .bind(sqlx::types::Json(UploadResult::failed(
                &receipt.session_id,
                401,
                "expired grant",
            )))
            .execute(&pool)
            .await
            .unwrap();
        let response = crate::router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/_api/v1/caches/queued/push-jobs/resume-job/resume")
                    .header(
                        protocol::PROTOCOL_VERSION_HEADER,
                        protocol::PROTOCOL_VERSION,
                    )
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let renewed:bool=sqlx::query_scalar("SELECT b.work_id IS NULL AND b.grant_generation=j.grant_generation AND b.expires_at>NOW() AND f.result IS NULL \
            FROM upload_finalization_batches b JOIN upload_finalizations f ON f.batch_id=b.id JOIN push_jobs j ON j.id=b.job_id")
            .fetch_one(&pool).await.unwrap();
        assert!(renewed);
        let failed = publish(&state, &identity, &old, &[]).await.unwrap_err();
        assert_eq!(failed.status, StatusCode::CONFLICT);
        let replay = enqueue_finalizations(
            &state,
            &identity,
            vec![receipt.clone()],
            Finalization { prepare_only: true },
        )
        .await
        .unwrap();
        assert_eq!(replay.results[0].stage, Some(UploadStage::Queued));
        let conflict =
            enqueue_finalizations(&state, &identity, vec![receipt], Finalization::default())
                .await
                .unwrap();
        assert_eq!(conflict.results[0].status, Some(409));
        // Resuming a job whose batch already settled must not requeue it.
        sqlx::query("UPDATE upload_finalizations SET result=$1")
            .bind(sqlx::types::Json(UploadResult::failed(
                &old.session.id,
                400,
                "failed verification",
            )))
            .execute(&pool)
            .await
            .unwrap();
        let response = crate::router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/_api/v1/caches/queued/push-jobs/resume-job/resume")
                    .header(
                        protocol::PROTOCOL_VERSION_HEADER,
                        protocol::PROTOCOL_VERSION,
                    )
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parked: bool = sqlx::query_scalar(
            "SELECT work_at='infinity'::timestamptz FROM upload_finalization_batches",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(parked, "settled batches stay out of the runnable range");
        state.finish_background().await;
    }

    /// A registered token allowed to push to every cache of the default org.
    async fn api_token(pool: &sqlx::PgPool) -> Identity {
        let (id, _, hash) = crate::auth::issue_token().unwrap();
        sqlx::query("INSERT INTO api_tokens(jti,subject,created_by,org_id,secret_hash) VALUES($1,'fixture','fixture','default',$2)")
            .bind(&id).bind(hash).execute(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO token_permissions(token_jti,permission,position) VALUES($1,'push',0)",
        )
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO token_caches(token_jti,pattern) VALUES($1,'*')")
            .bind(&id)
            .execute(pool)
            .await
            .unwrap();
        Identity::ApiToken(ApiToken {
            id,
            org: "default".into(),
            permissions: vec![Permission::Push],
            caches: vec![CacheGrant::Pattern("*".into())],
            expires_at: None,
        })
    }

    /// Seal the fixture session and give it a verified candidate, as a
    /// finished preparation leaves it. Publication then needs no storage I/O.
    async fn prepared(state: &AppState, receipt: &Receipt) -> Prepared {
        let identity = Identity::SharedToken;
        let session = load(&state.pool, &receipt.session_id, &identity)
            .await
            .unwrap();
        assert!(
            seal(state, &identity, &session, receipt, None, None)
                .await
                .is_ok()
        );
        sqlx::query("INSERT INTO nar_installations(key,operation_id,file_hash,compression,is_private,file_size,cache_id,session_id,expires_at,phase) \
            SELECT 'nar/objects/'||id,'operation-'||id,file_hash,'zstd',false,file_size,cache_id,id,expires_at,'ready' FROM upload_sessions WHERE id=$1")
            .bind(&receipt.session_id).execute(&state.pool).await.unwrap();
        let session = load(&state.pool, &receipt.session_id, &identity)
            .await
            .unwrap();
        let Ok(ready) = seal(state, &identity, &session, receipt, None, None).await else {
            panic!("a sealed session replays its receipt");
        };
        assert!(matches!(ready.source, PreparedSource::Ready));
        ready
    }

    async fn session_status(pool: &sqlx::PgPool, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM upload_sessions WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn sealing_loses_to_an_abort_since_its_reload(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        // Sealing records part receipts just before it changes the status.
        db::interleave(
            &pool,
            "UPDATE",
            "upload_parts",
            "UPDATE upload_sessions SET status='aborted'",
        )
        .await;
        let session = load(&pool, &receipt.session_id, &Identity::SharedToken)
            .await
            .unwrap();
        let refused = seal(
            &state,
            &Identity::SharedToken,
            &session,
            &receipt,
            None,
            None,
        )
        .await
        .err()
        .expect("an aborted session must not be sealed");
        assert_eq!(refused.status, StatusCode::CONFLICT);
        state.finish_background().await;
        // The refusal rolled back with the stand-in abort; nothing was sealed.
        let unsealed: bool = sqlx::query_scalar(
            "SELECT status='streaming' AND file_hash IS NULL FROM upload_sessions WHERE id=$1",
        )
        .bind(&receipt.session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(unsealed);
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn publication_loses_to_an_abort_since_its_reload(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        let ready = prepared(&state, &receipt).await;
        // Publication inserts the path just before it completes the session.
        db::interleave(
            &pool,
            "INSERT",
            "published_paths",
            "UPDATE upload_sessions SET status='aborted'",
        )
        .await;
        let refused = publish(&state, &Identity::SharedToken, &ready, &[])
            .await
            .unwrap_err();
        assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
        // The whole publication rolled back, leaving the candidate reusable.
        let (paths, candidates): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM published_paths),(SELECT count(*) FROM nar_installations)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((paths, candidates), (0, 1));
        assert_eq!(
            session_status(&pool, &receipt.session_id).await,
            "finalizing"
        );
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn publication_adopts_only_a_candidate_in_the_session_bucket(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        let identity = Identity::SharedToken;
        let session = load(&pool, &receipt.session_id, &identity).await.unwrap();
        let Ok(sealed) = seal(&state, &identity, &session, &receipt, None, None).await else {
            panic!("the fixture session seals");
        };
        // The cache is public. This candidate was verified into the private
        // bucket, as one discovered before a visibility change would be.
        sqlx::query("INSERT INTO nar_installations(key,operation_id,file_hash,compression,is_private,file_size,cache_id,session_id,expires_at,phase) \
            SELECT 'nars/objects/private','private-operation',file_hash,'zstd',true,file_size,cache_id,id,expires_at,'ready' FROM upload_sessions WHERE id=$1")
            .bind(&receipt.session_id).execute(&pool).await.unwrap();
        let stale = Prepared {
            session: sealed.session,
            source: PreparedSource::Ready,
            key: "nars/objects/private".into(),
            operation: "private-operation".into(),
            finalization_claim: None,
        };
        let refused = publish(&state, &identity, &stale, &[]).await.unwrap_err();
        assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
        let (paths, blobs, candidates): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM published_paths),(SELECT count(*) FROM blob_objects), \
             (SELECT count(*) FROM nar_installations)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((paths, blobs, candidates), (0, 0, 1));
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn finalization_authority_orders_against_token_revocation(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        let identity = api_token(&pool).await;
        let session = load(&pool, &receipt.session_id, &identity).await.unwrap();
        let revoke = "UPDATE api_tokens SET revoked_at=NOW(),revoked_by='fixture'";
        // A revocation in flight: the decision must wait for it, not read past it.
        let mut revocation = pool.begin().await.unwrap();
        sqlx::query(revoke).execute(&mut *revocation).await.unwrap();
        let (mut tx, current) = locked(&state, &session, &identity).await.unwrap();
        let waited = finalization_authority(&state, &mut tx, &identity, &current, false)
            .await
            .unwrap_err();
        assert_eq!(waited.status, StatusCode::SERVICE_UNAVAILABLE);
        tx.rollback().await.unwrap();
        revocation.rollback().await.unwrap();
        // An authorized transaction in flight: revocation must wait for it.
        let (mut tx, current) = locked(&state, &session, &identity).await.unwrap();
        finalization_authority(&state, &mut tx, &identity, &current, false)
            .await
            .unwrap();
        let mut revocation = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='100ms'")
            .execute(&mut *revocation)
            .await
            .unwrap();
        let blocked = sqlx::query(revoke)
            .execute(&mut *revocation)
            .await
            .unwrap_err();
        assert_eq!(
            blocked.as_database_error().unwrap().code().as_deref(),
            Some("55P03")
        );
        revocation.rollback().await.unwrap();
        // Only the token row is locked, not its permission and cache rows.
        let mut grants = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "SET LOCAL lock_timeout='100ms'; UPDATE token_permissions SET position=position; \
             UPDATE token_caches SET pattern=pattern",
        )
        .execute(&mut *grants)
        .await
        .unwrap();
        grants.rollback().await.unwrap();
        tx.rollback().await.unwrap();
        sqlx::query(revoke).execute(&pool).await.unwrap();
        let (mut tx, current) = locked(&state, &session, &identity).await.unwrap();
        let revoked = finalization_authority(&state, &mut tx, &identity, &current, false)
            .await
            .unwrap_err();
        assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
        tx.rollback().await.unwrap();
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn an_append_orders_against_admission_closing(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        let identity = Identity::SharedToken;
        sqlx::query("INSERT INTO upload_finalization_batches(id,org_id,actor,shared_generation,prepare_only,expires_at) \
            VALUES('closing','default',$1,$2,false,NOW()+INTERVAL '1 hour')")
            .bind(identity.actor()).bind(shared_generation(&state)).execute(&pool).await.unwrap();
        let session = load(&pool, &receipt.session_id, &identity).await.unwrap();
        // A consumer is closing admission but has not committed. Appending
        // now would add a member its claim has already stopped looking for.
        let mut closing = pool.begin().await.unwrap();
        sqlx::query("UPDATE upload_finalization_batches SET admitted=true")
            .execute(&mut *closing)
            .await
            .unwrap();
        let admission = Some(("closing", 0, false));
        let waited = seal(&state, &identity, &session, &receipt, None, admission)
            .await
            .err()
            .expect("an append must wait for a close in flight");
        assert_eq!(waited.status, StatusCode::SERVICE_UNAVAILABLE);
        closing.commit().await.unwrap();
        let closed = seal(&state, &identity, &session, &receipt, None, admission)
            .await
            .err()
            .expect("admission is closed");
        assert_eq!(closed.message, "Finalization admission closed; retry");
        state.finish_background().await;
        let members: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_finalizations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(members, 0);
        assert_eq!(
            session_status(&pool, &receipt.session_id).await,
            "streaming"
        );
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn a_consumer_retries_its_claim_while_an_append_holds_admission_open(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        enqueue_finalizations(
            &state,
            &Identity::SharedToken,
            vec![receipt.clone()],
            Finalization::default(),
        )
        .await
        .unwrap();
        // An abandoned admission that recovery may claim, with an append to
        // it still in flight on another connection.
        sqlx::query("UPDATE upload_finalization_batches SET admitted=false,created_at=NOW()-INTERVAL '61 seconds'")
            .execute(&pool).await.unwrap();
        let mut append = pool.begin().await.unwrap();
        sqlx::query("SELECT TRUE FROM upload_finalization_batches WHERE NOT admitted FOR SHARE")
            .execute(&mut *append)
            .await
            .unwrap();
        let busy = turn(&state, &mut String::new()).await.unwrap_err();
        assert_eq!(busy.status, StatusCode::SERVICE_UNAVAILABLE);
        let unclaimed: bool = sqlx::query_scalar(
            "SELECT NOT admitted AND work_id IS NULL FROM upload_finalization_batches",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(unclaimed);
        append.rollback().await.unwrap();
        // The next tick claims it.
        assert!(turn(&state, &mut String::new()).await.unwrap());
        let admitted: bool = sqlx::query_scalar("SELECT admitted FROM upload_finalization_batches")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(admitted);
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn settlement_writes_no_result_after_losing_its_claim(pool: sqlx::PgPool) {
        let (state, receipt) = fixture(pool.clone()).await;
        sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at,part_size) \
            SELECT 'second-session',cache_id,repeat('1',32),'/nix/store/'||repeat('1',32)||'-second',nar_hash,nar_size,file_size,compression,'streaming','staging/second-session/source','second-provider',expires_at,part_size FROM upload_sessions WHERE id='queued-session'")
            .execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO upload_parts(session_id,part_number,size) VALUES('second-session',1,1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let second = Receipt {
            session_id: "second-session".into(),
            ..receipt.clone()
        };
        enqueue_finalizations(
            &state,
            &Identity::SharedToken,
            vec![receipt, second],
            Finalization::default(),
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO nar_installations(key,operation_id,file_hash,compression,is_private,file_size,cache_id,session_id,expires_at,phase) \
            SELECT 'nar/objects/'||id,'operation-'||id,file_hash,'zstd',false,file_size,cache_id,id,expires_at,'ready' FROM upload_sessions")
            .execute(&pool).await.unwrap();
        // A job resume takes the claim away after the first result is written.
        db::interleave(
            &pool,
            "UPDATE",
            "upload_finalizations",
            "UPDATE upload_finalization_batches SET work_id=NULL,lease_expires_at=NULL",
        )
        .await;
        assert!(turn(&state, &mut String::new()).await.unwrap());
        // Both members have a terminal result to write; only the one settled
        // while the claim was still held may be recorded.
        let (completed, unsettled, unclaimed): (i64, i64, bool) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM upload_sessions WHERE status='completed'), \
             (SELECT count(*) FROM upload_finalizations WHERE result IS NULL), \
             (SELECT work_id IS NULL FROM upload_finalization_batches)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((completed, unsettled, unclaimed), (2, 1, true));
        state.finish_background().await;
    }
}
