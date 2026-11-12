//! Process-local caller limits and bounded compiler admission. No task or SQL
//! connection is retained while waiting; cancellation releases every slot.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::http::{HeaderValue, StatusCode, header};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;

const MAX_KEYS: usize = 16_384;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum CallerLimit {
    Push,
    Read,
}

impl CallerLimit {
    fn requests(self) -> u32 {
        match self {
            Self::Push => 6000,
            Self::Read => 12000,
        }
    }
}

struct Lane {
    active: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
}

impl Default for Lane {
    fn default() -> Self {
        Self {
            active: Arc::new(Semaphore::new(8)),
            waiting: Arc::new(Semaphore::new(64)),
        }
    }
}

#[derive(Default)]
struct Lanes {
    read: Lane,
    write: Lane,
}

type Key = [u8; 32];
type Calls = HashMap<(CallerLimit, Key), (Instant, u32)>;

#[derive(Default)]
pub(crate) struct ProtocolLimits {
    calls: Mutex<Calls>,
    orgs: Mutex<HashMap<Key, Arc<Lanes>>>,
}

/// Own the lane as well as the permit, so idle-map reclamation cannot create
/// a second admission lane for a request that is still active or waiting.
pub(crate) struct Admission {
    _permit: OwnedSemaphorePermit,
    _lanes: Arc<Lanes>,
}

fn key(caller: &str) -> Key {
    Sha256::digest(caller.as_bytes()).into()
}

fn limited() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many requests: slow down, and retry in 60 seconds",
    )
    .header(header::RETRY_AFTER, HeaderValue::from_static("60"))
}

fn busy() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "Compiler cache queue is busy; retry",
    )
    .header(header::RETRY_AFTER, HeaderValue::from_static("1"))
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl ProtocolLimits {
    pub(crate) fn check(&self, kind: CallerLimit, caller: &str) -> Result<(), ApiError> {
        self.check_at(kind, key(caller), Instant::now())
    }

    fn check_at(&self, kind: CallerLimit, caller: Key, now: Instant) -> Result<(), ApiError> {
        let mut calls = crate::profile_block!("protocol.caller_mutex_wait", self.calls.lock())
            .expect("protocol limiter poisoned");
        let key = (kind, caller);
        if calls.len() >= MAX_KEYS {
            calls.retain(|_, (until, _)| *until > now);
            if calls.len() >= MAX_KEYS && !calls.contains_key(&key) {
                return Err(limited());
            }
        }
        let entry = calls
            .entry(key)
            .or_insert((now + Duration::from_secs(60), 0));
        if entry.0 <= now {
            *entry = (now + Duration::from_secs(60), 0);
        }
        if entry.1 >= kind.requests() {
            return Err(limited());
        }
        entry.1 += 1;
        Ok(())
    }

    pub(crate) async fn admit_sccache(
        &self,
        org: &str,
        write: bool,
    ) -> Result<Admission, ApiError> {
        let lanes = {
            let mut orgs = crate::profile_block!("protocol.org_mutex_wait", self.orgs.lock())
                .expect("compiler admission poisoned");
            let key = key(org);
            if orgs.len() >= MAX_KEYS {
                orgs.retain(|_, lanes| Arc::strong_count(lanes) > 1);
                if orgs.len() >= MAX_KEYS && !orgs.contains_key(&key) {
                    return Err(busy());
                }
            }
            orgs.entry(key).or_default().clone()
        };
        let lane = if write { &lanes.write } else { &lanes.read };
        let permit = match lane.active.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let _waiting = lane
                    .waiting
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| busy())?;
                crate::profile_future!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        lane.active.clone().acquire_owned()
                    ),
                    label = "protocol.sccache_admission_wait"
                )
                .await
                .map_err(|_| busy())?
                .map_err(|_| busy())?
            }
        };
        Ok(Admission {
            _permit: permit,
            _lanes: lanes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_windows_boundaries_and_memory() {
        let limits = ProtocolLimits::default();
        let now = Instant::now();
        for kind in [CallerLimit::Push, CallerLimit::Read] {
            for _ in 0..kind.requests() {
                limits.check_at(kind, key("actor"), now).unwrap();
            }
            let error = limits.check_at(kind, key("actor"), now).unwrap_err();
            assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(error.headers[header::RETRY_AFTER], "60");
            assert_eq!(
                error.message,
                "Too many requests: slow down, and retry in 60 seconds"
            );
            limits.check_at(kind, key("other"), now).unwrap();
            assert!(
                limits
                    .check_at(kind, key("actor"), now + Duration::from_secs(59))
                    .is_err()
            );
            limits
                .check_at(kind, key("actor"), now + Duration::from_secs(60))
                .unwrap();
        }
        for i in 0..MAX_KEYS {
            let _ = limits.check_at(CallerLimit::Push, key(&i.to_string()), now);
        }
        assert_eq!(limits.calls.lock().unwrap().len(), MAX_KEYS);
        assert!(limits.check_at(CallerLimit::Push, key("new"), now).is_err());
        limits
            .check_at(
                CallerLimit::Push,
                key("new"),
                now + Duration::from_secs(120),
            )
            .unwrap();
        assert_eq!(limits.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn admission_lanes_queue_cancel_and_timeout() {
        let limits = ProtocolLimits::default();
        let mut active = Vec::new();
        for _ in 0..8 {
            active.push(limits.admit_sccache("alpha", true).await.unwrap());
        }
        let read = limits.admit_sccache("alpha", false).await.unwrap();
        let other = limits.admit_sccache("beta", true).await.unwrap();
        let mut waiting = Vec::new();
        for _ in 0..64 {
            let mut future = Box::pin(limits.admit_sccache("alpha", true));
            assert!(futures_util::poll!(&mut future).is_pending());
            waiting.push(future);
        }
        let error = limits.admit_sccache("alpha", true).await.err().unwrap();
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.headers[header::RETRY_AFTER], "1");
        assert_eq!(error.message, "Compiler cache queue is busy; retry");
        // Canceling a queued request frees its waiting slot immediately.
        waiting.pop();
        let error = limits.admit_sccache("alpha", true).await.err().unwrap();
        assert_eq!(error.headers[header::RETRY_AFTER], "1");
        drop(waiting);
        let mut next = Box::pin(limits.admit_sccache("alpha", true));
        assert!(futures_util::poll!(&mut next).is_pending());
        active.pop();
        let granted = next.await.unwrap();
        drop((active, granted, read, other));
        let orgs = limits.orgs.lock().unwrap();
        assert!(orgs.values().all(|lanes| Arc::strong_count(lanes) == 1));
    }

    #[tokio::test]
    async fn router_rejects_before_database_or_body_work() {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        pool.close().await;
        let store = Arc::new(object_store::memory::InMemory::new());
        let state = crate::AppState::new(
            pool,
            crate::config::Config {
                shared_auth_token: Some("legacy-secret".into()),
                ..Default::default()
            },
            crate::storage::Storage::from_stores(store.clone(), store),
            reqwest::Client::new(),
        )
        .unwrap();
        for _ in 0..6000 {
            state
                .protocol_limits
                .check(CallerLimit::Push, "legacy")
                .unwrap();
        }
        let app = crate::router(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_api/v1/get-missing-paths")
                    .header("authorization", "Bearer legacy-secret")
                    .body(Body::from("not JSON"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error":"Too many requests: slow down, and retry in 60 seconds"})
        );

        let mut active = Vec::new();
        for _ in 0..8 {
            active.push(
                state
                    .protocol_limits
                    .admit_sccache("alpha", false)
                    .await
                    .unwrap(),
            );
        }
        let mut waiting = Vec::new();
        for _ in 0..64 {
            let mut future = Box::pin(state.protocol_limits.admit_sccache("alpha", false));
            assert!(futures_util::poll!(&mut future).is_pending());
            waiting.push(future);
        }
        // No credentials, and a closed pool: only pre-SQL admission can return this 429.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_api/v1/sccache/alpha/cache/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error":"Compiler cache queue is busy; retry"})
        );
    }
}
