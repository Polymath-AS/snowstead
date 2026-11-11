//! Opt-in SQL-only publication of verified job candidates. Discovery owns no
//! locks. A durable job lease fences competing processes; publication rechecks
//! it under the existing org fence. No worker here transfers or verifies bytes.
use std::time::Duration;

use axum::http::StatusCode;
use sqlx::{FromRow, types::Json};
use tokio_util::sync::CancellationToken;

use crate::{
    AppState,
    auth::{Claims, Identity},
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
    pub member: Option<String>,
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
    match published {
        // Splitting a group or skipping one blocked member also advances work.
        Err(error) if error.status == StatusCode::PAYLOAD_TOO_LARGE => Ok(true),
        result => result.map(|count| count > 0),
    }
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
        authorization_claims: Json<Claims>,
        work_failures: i32,
        work_members: i32,
    }
    let grant: Option<Grant> = sqlx::query_as(
        "SELECT j.id,j.grant_generation,j.authorization_claims,j.work_failures,j.work_members \
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
        identity: Identity::Jwt(grant.authorization_claims.0),
        members: grant.work_members,
        member: None,
        failures: grant.work_failures,
    }))
}

pub(crate) async fn validate(tx: &mut Transaction, claim: &Claim) -> Result<(), ApiError> {
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut **tx)
        .await?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM push_jobs WHERE id=$1 AND work_id=$2 \
         AND grant_generation=$3 AND work_expires_at>NOW() AND state='sealed')",
    )
    .bind(&claim.job)
    .bind(&claim.id)
    .bind(claim.generation)
    .fetch_one(&mut **tx)
    .await?;
    if !live {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Push job claim expired or replaced",
        ));
    }
    Ok(())
}

pub(crate) async fn complete(tx: &mut Transaction, claim: &Claim) -> Result<(), ApiError> {
    sqlx::query("UPDATE push_jobs SET work_id=NULL,work_expires_at=NULL,work_failures=0,work_at=clock_timestamp() \
        WHERE id=$1 AND work_id=$2 AND grant_generation=$3")
        .bind(&claim.job).bind(&claim.id).bind(claim.generation).execute(&mut **tx).await?;
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
    let capacity = result
        .as_ref()
        .is_err_and(|e| e.status == StatusCode::PAYLOAD_TOO_LARGE);
    let members = if capacity && claim.members > 1 {
        claim.members / 2
    } else if capacity {
        16
    } else {
        claim.members
    };
    let blocked = result
        .as_ref()
        .is_err_and(|e| matches!(e.status.as_u16(), 400 | 401 | 403 | 404 | 507));
    let waiting = !capacity && !matches!(result, Ok(n) if *n > 0);
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
        "WITH released AS (UPDATE push_jobs SET work_id=NULL,work_expires_at=NULL,work_blocked=$4, \
        work_failures=$5,work_at=clock_timestamp()+$6*INTERVAL '1 millisecond',work_members=$7 \
        WHERE id=$1 AND work_id=$2 AND grant_generation=$3 RETURNING id,grant_generation) \
        UPDATE push_job_members m SET blocked_generation=r.grant_generation,publication_error='capacity_blocked' \
        FROM released r WHERE m.job_id=r.id AND m.session_id=$8 AND $9",
    )
    .bind(&claim.job)
    .bind(&claim.id)
    .bind(claim.generation)
    .bind(blocked)
    .bind(failures)
    .bind(delay as f64)
    .bind(members)
    .bind(&claim.member)
    .bind(capacity && claim.members == 1)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
