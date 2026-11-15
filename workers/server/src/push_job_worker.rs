//! Opt-in SQL-only publication of verified job candidates. Discovery owns no
//! locks. A durable job lease fences competing processes; publication rechecks
//! it under the existing org fence. No worker here transfers or verifies bytes.
use std::time::Duration;

use axum::http::StatusCode;
use sqlx::FromRow;
use tokio_util::sync::CancellationToken;

use crate::{
    AppState,
    authz::{ApiToken, CacheGrant, Permission, Principal as Identity},
    db::{self, Transaction},
    error::ApiError,
};

pub(crate) struct Claim {
    pub job: String,
    pub id: String,
    pub generation: i64,
    pub org: String,
    pub identity: Identity,
    pub members: i32,
    failures: i32,
}

// Round-robin organizations, then least-recently-claimed jobs within the org.
// These cursors control fairness only; database leases provide correctness.
pub(crate) async fn run(state: AppState, stopped: CancellationToken) {
    let mut after = String::new();
    loop {
        if stopped.is_cancelled() {
            break;
        }
        let result = turn(&state, &mut after).await;
        match result {
            Ok(true) => tokio::task::yield_now().await,
            _ => {
                if result.is_err() {
                    tracing::warn!("Push job publication deferred; durable candidates retained");
                }
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
}

async fn turn(state: &AppState, after: &mut String) -> Result<bool, ApiError> {
    // At most one discovery read at a time, closed before org admission.
    // Wrap only after exhausting larger org IDs, rather than sorting every org.
    let mut org = discover(state, after).await?;
    if org.is_none() && !after.is_empty() {
        after.clear();
        org = discover(state, after).await?;
    }
    let Some(org) = org else {
        return Ok(false);
    };
    *after = org.clone();
    let Some(mut claim) = claim(state, &org).await? else {
        return Ok(false);
    };
    let published = crate::uploads::publish_job(state, &mut claim).await;
    // Successful publication releases the claim in its own atomic commit.
    // Only empty/failed turns need a separate backoff transaction.
    if !matches!(&published, Ok(count) if *count > 0) {
        // A busy release must not abandon an otherwise healthy job for the
        // entire execution lease. Each retry drops its SQL/gate ownership
        // before waiting, and still checks the same work ID and generation.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match release(state, &claim, &published).await {
                Ok(()) => break,
                Err(error)
                    if error.status == StatusCode::SERVICE_UNAVAILABLE
                        && tokio::time::Instant::now() < deadline =>
                {
                    let jitter = (uuid::Uuid::now_v7().as_u128() % 26) as u64;
                    tokio::time::sleep(Duration::from_millis(10 + jitter)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
    published.map(|count| count > 0)
}

async fn discover(state: &AppState, after: &str) -> Result<Option<String>, ApiError> {
    let mut tx = db::begin_read(state).await?;
    let org = sqlx::query_scalar(
        "SELECT c.org_id FROM push_jobs j JOIN caches c ON c.id=j.cache_id \
         JOIN api_tokens t ON t.jti=j.authorization_jti \
         WHERE c.org_id>$1 AND j.state='sealed' AND NOT j.work_blocked \
         AND j.work_at<=NOW() AND (j.work_expires_at IS NULL OR j.work_expires_at<=NOW()) \
         AND j.authorization_claims IS NOT NULL AND j.authorization_expires_at>NOW() \
         AND j.idle_expires_at>NOW() AND j.hard_expires_at>NOW() AND t.revoked_at IS NULL \
         AND EXISTS (SELECT 1 FROM push_job_members m JOIN upload_sessions u ON u.id=m.session_id \
             JOIN nar_installations n ON n.session_id=u.id \
             WHERE m.job_id=j.id AND m.session_id IS NOT NULL \
             AND m.blocked_generation IS DISTINCT FROM j.grant_generation \
             AND u.push_job_id=j.id AND u.status='finalizing' AND u.expires_at>NOW() \
             AND n.phase='ready' AND n.expires_at>NOW()) \
         ORDER BY c.org_id LIMIT 1",
    )
    .bind(after)
    .fetch_optional(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(org)
}

async fn claim(state: &AppState, org: &str) -> Result<Option<Claim>, ApiError> {
    let mut tx = db::begin(state, org).await?;
    db::advisory_lock(&mut tx, &format!("org:{org}")).await?;
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut *tx)
        .await?;
    #[derive(FromRow)]
    struct Grant {
        id: String,
        grant_generation: i64,
        authorization_jti: String,
        cache_id: i32,
        work_failures: i32,
        work_members: i32,
    }
    let grant: Option<Grant> = sqlx::query_as(
        "SELECT j.id,j.grant_generation,j.authorization_jti,j.cache_id,j.work_failures,j.work_members \
         FROM push_jobs j JOIN caches c ON c.id=j.cache_id JOIN api_tokens t ON t.jti=j.authorization_jti \
         WHERE c.org_id=$1 AND j.state='sealed' AND NOT j.work_blocked AND j.work_at<=NOW() \
         AND (j.work_expires_at IS NULL OR j.work_expires_at<=NOW()) \
         AND j.authorization_claims IS NOT NULL AND j.authorization_expires_at>NOW() \
         AND j.idle_expires_at>NOW() AND j.hard_expires_at>NOW() AND t.revoked_at IS NULL \
         AND EXISTS (SELECT 1 FROM push_job_members m JOIN upload_sessions u ON u.id=m.session_id \
             JOIN nar_installations n ON n.session_id=u.id \
             WHERE m.job_id=j.id AND m.session_id IS NOT NULL \
             AND m.blocked_generation IS DISTINCT FROM j.grant_generation \
             AND u.push_job_id=j.id AND u.status='finalizing' AND u.expires_at>NOW() \
             AND n.phase='ready' AND n.expires_at>NOW()) \
         ORDER BY j.work_at,j.id LIMIT 1 FOR UPDATE OF j NOWAIT",
    ).bind(org).fetch_optional(&mut *tx).await?;
    let Some(grant) = grant else {
        return Ok(None);
    };
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "UPDATE push_jobs SET work_id=$2,work_expires_at=LEAST(authorization_expires_at, \
        idle_expires_at,hard_expires_at,NOW()+INTERVAL '60 seconds'),work_at=NOW() WHERE id=$1",
    )
    .bind(&grant.id)
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(Claim {
        job: grant.id,
        id,
        generation: grant.grant_generation,
        org: org.into(),
        // The delegation resume recorded: the job's token, pushing to the
        // job's cache only. The query above requires the token unrevoked.
        identity: Identity::ApiToken(ApiToken {
            id: grant.authorization_jti,
            org: org.into(),
            permissions: vec![Permission::Push],
            caches: vec![CacheGrant::Id(grant.cache_id)],
            expires_at: None,
        }),
        members: grant.work_members,
        failures: grant.work_failures,
    }))
}

pub(crate) async fn validate(tx: &mut Transaction, claim: &Claim) -> Result<(), ApiError> {
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut **tx)
        .await?;
    // Hold the job row from here to `complete`, before any session row:
    // cancellation, completion, and resume lock it first too.
    let live: Option<bool> = sqlx::query_scalar(
        "SELECT TRUE FROM push_jobs WHERE id=$1 AND work_id=$2 \
         AND grant_generation=$3 AND work_expires_at>NOW() AND state='sealed' FOR NO KEY UPDATE",
    )
    .bind(&claim.job)
    .bind(&claim.id)
    .bind(claim.generation)
    .fetch_optional(&mut **tx)
    .await?;
    if live.is_none() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Push job claim expired or replaced",
        ));
    }
    Ok(())
}

pub(crate) async fn complete(tx: &mut Transaction, claim: &Claim) -> Result<(), ApiError> {
    // A claim replaced since `validate` must not publish: the error rolls the
    // caller's publication back.
    let released = sqlx::query("UPDATE push_jobs SET work_id=NULL,work_expires_at=NULL,work_failures=0,work_at=clock_timestamp() \
        WHERE id=$1 AND work_id=$2 AND grant_generation=$3")
        .bind(&claim.job).bind(&claim.id).bind(claim.generation).execute(&mut **tx).await?
        .rows_affected();
    if released != 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Push job claim expired or replaced",
        ));
    }
    Ok(())
}

async fn release(
    state: &AppState,
    claim: &Claim,
    result: &Result<usize, ApiError>,
) -> Result<(), ApiError> {
    let mut tx = db::begin(state, &claim.org).await?;
    db::advisory_lock(&mut tx, &format!("org:{}", claim.org)).await?;
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut *tx)
        .await?;
    let blocked = result
        .as_ref()
        .is_err_and(|e| matches!(e.status.as_u16(), 400 | 401 | 403 | 404));
    let waiting = !matches!(result, Ok(n) if *n > 0);
    let failures = if waiting {
        (claim.failures + 1).min(6)
    } else {
        0
    };
    // 50–1000 ms exponential backoff with jitter, outside all SQL/slot ownership.
    let jitter = (uuid::Uuid::now_v7().as_u128() % 26) as i32;
    let delay = if waiting {
        (25 * (1 << failures) + jitter).min(1000)
    } else {
        0
    };
    sqlx::query(
        "UPDATE push_jobs SET work_id=NULL,work_expires_at=NULL,work_blocked=$4, \
        work_failures=$5,work_at=clock_timestamp()+$6*INTERVAL '1 millisecond',work_members=$7 \
        WHERE id=$1 AND work_id=$2 AND grant_generation=$3",
    )
    .bind(&claim.job)
    .bind(&claim.id)
    .bind(claim.generation)
    .bind(blocked)
    .bind(failures)
    .bind(delay as f64)
    .bind(claim.members)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, storage::Storage};
    use object_store::memory::InMemory;
    use std::sync::Arc;

    /// A claimed job whose only member is sealed and has a verified candidate,
    /// so publishing it is SQL-only.
    async fn fixture(pool: sqlx::PgPool) -> (AppState, Claim) {
        let state = AppState::new(
            pool.clone(),
            Config::default(),
            Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new())),
            reqwest::Client::new(),
        )
        .unwrap();
        let (token, _, secret) = crate::auth::issue_token().unwrap();
        let cache: i32 = sqlx::query_scalar(
            "INSERT INTO caches(name,is_public) VALUES('claimed',true) RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let hash = "0".repeat(32);
        let path = format!("/nix/store/{hash}-claimed");
        let nar_hash = format!("sha256:{}", crate::signing::nix32(&[0; 32]));
        sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) VALUES($1,'nix')")
            .bind(cache)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_tokens(jti,subject,created_by,org_id,secret_hash) VALUES($1,'fixture','fixture','default',$2)")
            .bind(&token).bind(secret).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO token_permissions(token_jti,permission,position) VALUES($1,'push',0)",
        )
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO token_caches(token_jti,pattern) VALUES($1,'*')")
            .bind(&token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO push_jobs(id,cache_id,creator,idempotency_key,mode,roots,state,manifest_bytes,authorization_jti,authorization_claims,authorization_expires_at,grant_generation,work_id,work_expires_at) \
            VALUES('claimed-job',$1,$2,'fixture','selected','[]','sealed',0,$2,'{}',NOW()+INTERVAL '20 minutes',1,'claim',NOW()+INTERVAL '1 minute')")
            .bind(cache).bind(&token).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at,part_size,push_job_id) \
            VALUES('claimed-session',$1,$2,$3,$4,1,$5,1,'zstd','finalizing','staging/claimed-session/source','provider-upload',NOW()+INTERVAL '2 hours',8388608,'claimed-job')")
            .bind(cache).bind(&hash).bind(&path).bind(&nar_hash).bind("a".repeat(64))
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO push_job_members(job_id,store_path_hash,metadata,session_id) VALUES('claimed-job',$1,$2,'claimed-session')")
            .bind(&hash)
            .bind(sqlx::types::Json(serde_json::json!({
                "storePath": path, "storePathHash": hash, "narHash": nar_hash,
                "narSize": 1, "references": []
            })))
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO nar_installations(key,operation_id,file_hash,compression,is_private,file_size,cache_id,session_id,expires_at,phase) \
            SELECT 'nar/objects/claimed','claimed-operation',file_hash,'zstd',false,file_size,cache_id,id,expires_at,'ready' FROM upload_sessions")
            .execute(&pool).await.unwrap();
        let claim = Claim {
            job: "claimed-job".into(),
            id: "claim".into(),
            generation: 1,
            org: "default".into(),
            identity: Identity::ApiToken(ApiToken {
                id: token,
                org: "default".into(),
                permissions: vec![Permission::Push],
                caches: vec![CacheGrant::Id(cache)],
                expires_at: None,
            }),
            members: 16,
            failures: 0,
        };
        (state, claim)
    }

    async fn published(pool: &sqlx::PgPool) -> (i64, String) {
        sqlx::query_as("SELECT (SELECT count(*) FROM published_paths),status FROM upload_sessions")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn publication_holds_the_job_row_from_validation(pool: sqlx::PgPool) {
        let (state, mut claim) = fixture(pool.clone()).await;
        // Nothing publication later writes conflicts with a key-share lock.
        // Only an exclusive lock on the job row, taken first, waits for it.
        let mut holder = pool.begin().await.unwrap();
        sqlx::query("SELECT FROM push_jobs FOR SHARE")
            .execute(&mut *holder)
            .await
            .unwrap();
        let waited = crate::uploads::publish_job(&state, &mut claim)
            .await
            .unwrap_err();
        assert_eq!(waited.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(published(&pool).await, (0, "finalizing".into()));
        holder.rollback().await.unwrap();
        assert_eq!(
            crate::uploads::publish_job(&state, &mut claim)
                .await
                .unwrap(),
            1
        );
        assert_eq!(published(&pool).await, (1, "completed".into()));
        state.finish_background().await;
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable PostgreSQL and S3 via the server test script"]
    async fn a_claim_replaced_during_publication_publishes_nothing(pool: sqlx::PgPool) {
        let (state, mut claim) = fixture(pool.clone()).await;
        // Publication inserts the path before it releases the claim.
        db::interleave(
            &pool,
            "INSERT",
            "published_paths",
            "UPDATE push_jobs SET work_id='replacement'",
        )
        .await;
        let replaced = crate::uploads::publish_job(&state, &mut claim)
            .await
            .unwrap_err();
        assert_eq!(replaced.status, StatusCode::CONFLICT);
        assert_eq!(published(&pool).await, (0, "finalizing".into()));
        state.finish_background().await;
    }
}
