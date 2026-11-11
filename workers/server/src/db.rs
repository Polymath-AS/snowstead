use sqlx::{PgConnection, Postgres};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedSemaphorePermit};

use crate::error::ApiError;
use axum::http::{HeaderValue, StatusCode, header};

fn busy(message: &str) -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, message)
        .header(header::RETRY_AFTER, HeaderValue::from_static("1"))
}

#[derive(Default)]
pub(crate) struct Writers(Mutex<HashMap<String, Weak<AsyncMutex<()>>>>);

impl Writers {
    fn org(&self, org: &str) -> Arc<AsyncMutex<()>> {
        let mut writers = self.0.lock().unwrap();
        writers.retain(|_, writer| writer.strong_count() > 0);
        if let Some(writer) = writers.get(org).and_then(Weak::upgrade) {
            return writer;
        }
        let writer = Arc::new(AsyncMutex::new(()));
        writers.insert(org.to_owned(), Arc::downgrade(&writer));
        writer
    }
}

/// The local org gate ends with the SQL transaction, including on cancellation.
/// It never spans storage I/O. PostgreSQL still fences other server instances.
pub(crate) struct Transaction {
    inner: sqlx::Transaction<'static, Postgres>,
    _writer: OwnedMutexGuard<()>,
}

impl Deref for Transaction {
    type Target = PgConnection;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Transaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Transaction {
    pub(crate) async fn commit(self) -> Result<(), sqlx::Error> {
        self.inner.commit().await
    }
    pub(crate) async fn rollback(self) -> Result<(), sqlx::Error> {
        self.inner.rollback().await
    }
}

/// Bound queued writers before borrowing a connection. Active SQL work remains
/// bounded by the pool; storage work must not retain the returned transaction.
pub(crate) async fn begin(state: &crate::AppState, org: &str) -> Result<Transaction, ApiError> {
    let admission = state
        .sql_waiters
        .clone()
        .try_acquire_owned()
        .map_err(|_| busy("SQL admission busy; retry"))?;
    begin_admitted(state, org, admission).await
}

/// Callers must bound their queued work before waiting here. Part transfers
/// hold a preparation slot so completed writes can wait without retransmission.
pub(crate) async fn begin_queued(
    state: &crate::AppState,
    org: &str,
) -> Result<Transaction, ApiError> {
    let admission = tokio::time::timeout(
        state.pool.options().get_acquire_timeout(),
        state.sql_waiters.clone().acquire_owned(),
    )
    .await
    .map_err(|_| busy("SQL admission busy; retry"))?
    .map_err(|_| busy("SQL admission busy; retry"))?;
    begin_admitted(state, org, admission).await
}

async fn begin_admitted(
    state: &crate::AppState,
    org: &str,
    admission: OwnedSemaphorePermit,
) -> Result<Transaction, ApiError> {
    let writer = tokio::time::timeout(
        state.pool.options().get_acquire_timeout(),
        state.sql_writers.org(org).lock_owned(),
    )
    .await
    .map_err(|_| busy("SQL capacity busy; retry"))?;
    let pool = state.pool.clone();
    // SQLx 0.9 can return an open, untracked transaction to the pool if BEGIN
    // is cancelled before its response arrives. Finish startup even if the
    // caller leaves; dropping the completed result then rolls it back safely.
    // Pool acquisition has its own deadline. Never wrap BEGIN in a timeout.
    state
        .tasks
        .spawn(async move {
            let _admission = admission;
            let inner = pool.begin().await?;
            Ok(Transaction {
                inner,
                _writer: writer,
            })
        })
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Transaction startup failed",
            )
        })?
}

/// Serialize SQL decisions only. Never queue connections behind another writer.
pub(crate) async fn advisory_lock(
    tx: &mut impl DerefMut<Target = PgConnection>,
    key: &str,
) -> Result<(), ApiError> {
    let acquired: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(key)
            .fetch_one(&mut **tx)
            .await?;
    if !acquired {
        return Err(busy("Concurrent write; retry"));
    }
    if key.starts_with("org:") {
        // NOWAIT protects explicit row locks. Give implicit FK/index/trigger
        // locks a small wait budget, only inside serialized org transactions.
        sqlx::query("SET LOCAL lock_timeout = '100ms'")
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppState, config::Config, storage::Storage};
    use object_store::memory::InMemory;
    use sqlx::{PgPool, postgres::PgSslMode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn cancelled_begin_cannot_capture_later_autocommit_writes(observer: PgPool) {
        sqlx::query("CREATE TABLE cancellation_probe (id integer PRIMARY KEY)")
            .execute(&observer)
            .await
            .unwrap();
        let options = observer.connect_options();
        let upstream = format!("{}:{}", options.get_host(), options.get_port());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (pause, mut paused) = tokio::sync::watch::channel(false);
        let proxy = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = tokio::net::TcpStream::connect(upstream).await.unwrap();
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            let responses = async {
                let mut buffer = [0; 8192];
                loop {
                    let n = server_read.read(&mut buffer).await?;
                    if n == 0 {
                        return Ok::<_, std::io::Error>(());
                    }
                    while *paused.borrow_and_update() {
                        paused.changed().await.unwrap();
                    }
                    client_write.write_all(&buffer[..n]).await?;
                }
            };
            let _ = tokio::join!(
                tokio::io::copy(&mut client_read, &mut server_write),
                responses
            );
        });
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .test_before_acquire(false)
            .connect_with(
                (*options)
                    .clone()
                    .host("127.0.0.1")
                    .port(port)
                    .ssl_mode(PgSslMode::Disable),
            )
            .await
            .unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&pool)
            .await
            .unwrap();
        let state = AppState::new(
            pool.clone(),
            Config::default(),
            Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new())),
            reqwest::Client::new(),
        )
        .unwrap();

        // Pool release performs an asynchronous health check. Do not pause
        // that response instead of the BEGIN response this test targets.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while pool.num_idle() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Let PostgreSQL execute BEGIN, but withhold its response from SQLx.
        pause.send(true).unwrap();
        let caller = tokio::spawn({
            let state = state.clone();
            async move { begin(&state, "default").await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let open: bool = sqlx::query_scalar(
                    "SELECT state='idle in transaction' FROM pg_stat_activity WHERE pid=$1",
                )
                .bind(pid)
                .fetch_one(&observer)
                .await
                .unwrap();
                if open {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        assert!(caller.await.err().unwrap().is_cancelled());
        pause.send(false).unwrap();
        state.finish_background().await;

        // An unrelated write must commit independently, not disappear inside
        // the cancelled caller's transaction. Observe through another connection.
        sqlx::query("INSERT INTO cancellation_probe VALUES (1)")
            .execute(&pool)
            .await
            .unwrap();
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM cancellation_probe")
            .fetch_one(&observer)
            .await
            .unwrap();
        assert_eq!(visible, 1, "cancelled BEGIN captured an autocommit write");
        pool.close().await;
        proxy.abort();
    }
}
