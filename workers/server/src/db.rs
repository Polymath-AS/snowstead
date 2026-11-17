//! Write transactions and the locks they take.
//!
//! No lock spans an organization. Each writer locks the rows its decision
//! depends on, every lock wait is bounded by `lock_timeout`, and the pool is
//! the only backpressure: a caller that cannot get a connection within the
//! pool's acquire timeout is answered 503 with Retry-After.
//!
//! Org-level limits are soft. Active sessions, staged bytes, compiler staging,
//! push job budgets, and retained capacity are read without a lock, so a few
//! concurrent requests can overshoot them; the evictor restores capacity.
//!
//! # Lock order
//!
//! A lock that can wait is taken in this order. Any lock may be taken out of
//! order if it cannot wait (a try-lock, NOWAIT, or SKIP LOCKED): it fails or
//! skips instead, so it cannot close a cycle. Those are the advisory locks
//! (`org-slugs`, `evict:<org>`, and `upload:<session>` in sorted order), the
//! policy locks of uploads, publications, job writers, and compiler transfers
//! (`caches` FOR KEY SHARE NOWAIT, then `orgs` FOR SHARE NOWAIT), and the
//! evictor's victims (SKIP LOCKED).
//!
//! 1. `push_jobs` rows, by ID. Job writers, worker publication, withdrawal,
//!    and token revocation take FOR NO KEY UPDATE; session creation and a
//!    client's own publication of a job's sessions take FOR SHARE.
//! 2. Policy rows, exclusively: the `orgs` row by a writer of its limits or
//!    slug, a `caches` row FOR UPDATE by whoever changes its policy columns,
//!    deletes it, or mutates it through management. Everything that depends
//!    on a cache's policy holds its row FOR KEY SHARE, and on an
//!    organization's policy its row FOR SHARE, until it commits. The evictor
//!    is such a dependent of the storage limit, and is the one that waits
//!    for the `orgs` row: it holds nothing but its lease when it does.
//! 3. `api_tokens` rows: FOR SHARE by whoever acts on a token's authority,
//!    exclusively by revocation.
//! 4. `upload_finalization_batches` rows, by ID.
//! 5. Cache totals: `caches` rows FOR NO KEY UPDATE, by ID, before the first
//!    `published_paths` row of those caches is read for a decision, inserted,
//!    or deleted, and before a job is authorized, which starts its protection
//!    of published members. The totals trigger takes this lock anyway; taking
//!    it first, in order, serializes publication, eviction, retention, job
//!    authorization, and withdrawal per cache and keeps them from waiting on
//!    each other's path rows. The evictor takes every cache of its
//!    organization, so the usage it then reads cannot shrink under it. This
//!    lock does not conflict with FOR KEY SHARE, so policy holders never
//!    wait on it, and a policy writer's FOR UPDATE excludes it.
//! 6. `upload_sessions` rows, by ID, then their parts, receipts, candidates,
//!    and job members.
//! 7. `blob_objects` by file hash, then `published_paths`, then compiler
//!    entries.
//!
//! Departures, each safe for the reason given:
//!
//! - A management mutation holds its cache FOR UPDATE (step 2) before the
//!   jobs it cancels (step 1). Nothing that holds a job row waits for a
//!   cache's policy: publication, session creation, and job writers take it
//!   with NOWAIT, and whoever already holds it keeps the mutation waiting at
//!   its first lock, where it holds nothing.
//! - A request for one session (reserve, seal, abort, candidate allocation)
//!   locks the session row (step 6) before it shares a token and a batch
//!   (steps 3 and 4), and a seal that retries a refused finalization then
//!   updates its batch. Nothing that holds a token or a batch, shared or
//!   exclusive, then waits for a session row another request can hold: the
//!   publisher of that session holds its `upload:<session>` lock, which the
//!   request would have failed on first.
//! - Deleting a path fires `invalidate_deleted_publications`, which updates
//!   the path's unfinished sessions (step 6 after step 7). Path deletion,
//!   cache withdrawal, and the evictor lock exactly those sessions first, in
//!   ID order, so for them the trigger finds its rows already held.
//!   Retention does not, and neither does the cascade of a cache deletion
//!   over jobs and sessions, which finds every row already locked by the
//!   withdrawal that precedes it.
//! - Expiry of a finalization batch locks its sessions and then deletes the
//!   batch. The batch it deletes expired a day ago and has no unfinished
//!   session, so nothing holds it shared.
//!
//! What remains waits at most `lock_timeout` and then answers 503:
//!
//! - Retention deletes paths without locking their sessions first, so its
//!   trigger and a bulk abort of two of the same sessions can meet in
//!   opposite orders.
//! - Revocation locks the jobs a token authorizes, then the token, then
//!   updates those jobs again. A job resumed between the first two steps is
//!   locked after the token, against the order of a publisher of that job.
use sqlx::{PgConnection, PgPool, Postgres};
use std::ops::{Deref, DerefMut};

use crate::error::ApiError;
use axum::http::{HeaderValue, StatusCode, header};

/// Starts a write transaction. `lock_timeout` is how long it waits for any
/// one lock before PostgreSQL cancels the statement, which callers see as a
/// retryable 503.
const WRITE: &str = "SET LOCAL lock_timeout = '100ms'; BEGIN";

/// Starts a worker discovery read, which must not hold its snapshot for long.
const READ: &str = "SET LOCAL statement_timeout = '1s'; BEGIN READ ONLY";

/// Start a transaction and apply its settings in one round trip. `statement`
/// is a constant: any `SET LOCAL` settings, then the BEGIN that opens the
/// transaction, sent as a single simple-query message.
///
/// The settings come first on purpose. PostgreSQL runs a multi-statement
/// message in an implicit transaction block, and a BEGIN in that block adopts
/// the statements before it into the transaction it opens, so the settings
/// last exactly as long as the transaction. If one of them fails, the
/// implicit block is rolled back and the connection is idle again. With BEGIN
/// first, that failure would leave an aborted transaction that SQLx has not
/// counted, does not roll back, and returns to the pool.
pub(crate) async fn start(
    pool: &PgPool,
    statement: &'static str,
) -> Result<sqlx::Transaction<'static, Postgres>, sqlx::Error> {
    pool.begin_with(statement).await
}

fn busy(message: &str) -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, message)
        .header(header::RETRY_AFTER, HeaderValue::from_static("1"))
}

/// A transaction whose COMMIT or ROLLBACK is always awaited by a tracked
/// task, including when its caller is cancelled or returns an error. Its
/// locks are therefore released before shutdown finishes, and before a
/// caller that awaits `rollback` starts its next attempt. It never spans
/// storage I/O.
pub(crate) struct Transaction {
    inner: Option<sqlx::Transaction<'static, Postgres>>,
    tasks: tokio_util::task::TaskTracker,
}

impl Deref for Transaction {
    type Target = PgConnection;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl DerefMut for Transaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

impl Transaction {
    pub(crate) async fn commit(self) -> Result<(), sqlx::Error> {
        self.finish(true).await
    }
    pub(crate) async fn rollback(self) -> Result<(), sqlx::Error> {
        self.finish(false).await
    }

    async fn finish(mut self, commit: bool) -> Result<(), sqlx::Error> {
        // A cancelled caller must not leave COMMIT or ROLLBACK half sent on a
        // connection that then returns to the pool.
        self.tasks
            .clone()
            .spawn(async move {
                let inner = self.inner.take().unwrap();
                if commit {
                    inner.commit().await
                } else {
                    inner.rollback().await
                }
            })
            .await
            .map_err(|_| sqlx::Error::Protocol("Transaction completion failed".into()))?
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            // SQLx's Drop only queues ROLLBACK. Wait for the server to
            // acknowledge it, including on handler errors and cancellation,
            // so the row locks are gone before the connection is reused.
            self.tasks.spawn(async move {
                let _ = inner.rollback().await;
            });
        }
    }
}

/// Worker discovery takes no locks, but must release its snapshot and pool
/// connection promptly even when a manifest has no ready members.
pub(crate) async fn begin_read(
    state: &crate::AppState,
) -> Result<sqlx::Transaction<'static, Postgres>, ApiError> {
    let pool = state.pool.clone();
    // Keep BEGIN cancellation-safe, just like writer transaction startup.
    Ok(state
        .tasks
        .spawn(async move { start(&pool, READ).await })
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Transaction startup failed",
            )
        })??)
}

/// A coherent reporting snapshot on the read pool. It takes no row locks.
pub(crate) async fn view(state: &crate::AppState) -> Result<Transaction, ApiError> {
    let pool = state.read_pool.clone();
    let tasks = state.tasks.clone();
    state
        .tasks
        .spawn(async move {
            let inner = start(&pool, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY").await?;
            Ok(Transaction {
                inner: Some(inner),
                tasks,
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

/// Start a write transaction with a bounded lock wait. Callers wait for a
/// pool connection up to the pool's acquire timeout; a timeout is a 503 with
/// Retry-After. Storage work must not retain the returned transaction.
///
/// There is no statement timeout: deleting or evicting a large cache is one
/// legitimately long statement. Workers that need one set it themselves.
pub(crate) async fn begin(state: &crate::AppState) -> Result<Transaction, ApiError> {
    let pool = state.pool.clone();
    let tasks = state.tasks.clone();
    // SQLx 0.9 can return an open, untracked transaction to the pool if BEGIN
    // is cancelled before its response arrives. Finish startup even if the
    // caller leaves; dropping the completed result then rolls it back safely.
    // Pool acquisition has its own deadline. Never wrap BEGIN in a timeout.
    state
        .tasks
        .spawn(async move {
            // Every lock this transaction waits for, explicit or taken by a
            // foreign key, unique index, or trigger, gives up after its
            // lock timeout.
            Ok(Transaction {
                inner: Some(start(&pool, WRITE).await?),
                tasks,
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

/// Try a transaction-scoped advisory lock: one upload session, the slug
/// namespace, or a worker lease. Never queue a connection behind its holder.
pub(crate) async fn advisory_lock(
    tx: &mut impl DerefMut<Target = PgConnection>,
    key: &str,
) -> Result<(), ApiError> {
    if !try_advisory_lock(tx, key).await? {
        return Err(busy("Concurrent write; retry"));
    }
    Ok(())
}

/// As `advisory_lock`, for a caller that does something else when it is held.
pub(crate) async fn try_advisory_lock(
    tx: &mut impl DerefMut<Target = PgConnection>,
    key: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .fetch_one(&mut **tx)
        .await
}

/// Stands in for a writer that commits between a handler's read and its
/// write, at an exact point no real race reaches on demand: `body` runs
/// inside the handler's own transaction, right after it writes `table`.
#[cfg(test)]
pub(crate) async fn interleave(pool: &sqlx::PgPool, event: &str, table: &str, body: &str) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION interleaved() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         IF pg_trigger_depth()=1 THEN {body}; END IF; RETURN NULL; END $$; \
         CREATE TRIGGER interleaved AFTER {event} ON {table} \
         FOR EACH STATEMENT EXECUTE FUNCTION interleaved();"
    )))
    .execute(pool)
    .await
    .unwrap();
}

/// A pool of one connection to `observer`'s database, through a relay that
/// counts the server's ReadyForQuery messages. PostgreSQL ends every round
/// trip with exactly one, whatever the client sent in it.
#[cfg(test)]
pub(crate) async fn counted(
    observer: &PgPool,
) -> (PgPool, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let options = observer.connect_options();
    let upstream = format!("{}:{}", options.get_host(), options.get_port());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ready = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = ready.clone();
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = tokio::net::TcpStream::connect(upstream).await.unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let responses = async {
            // Without TLS, every server message is a type byte and a length
            // that counts itself but not the type.
            let (mut header, mut body) = (Vec::with_capacity(5), 0);
            let mut buffer = [0; 8192];
            loop {
                let n = server_read.read(&mut buffer).await?;
                if n == 0 {
                    return Ok::<_, std::io::Error>(());
                }
                let mut bytes = &buffer[..n];
                while !bytes.is_empty() {
                    let taken = if body > 0 {
                        let taken = bytes.len().min(body);
                        body -= taken;
                        taken
                    } else {
                        let taken = bytes.len().min(5 - header.len());
                        header.extend_from_slice(&bytes[..taken]);
                        if header.len() == 5 {
                            if header[0] == b'Z' {
                                counter.fetch_add(1, Ordering::SeqCst);
                            }
                            let length = u32::from_be_bytes(header[1..].try_into().unwrap());
                            body = length as usize - 4;
                            header.clear();
                        }
                        taken
                    };
                    bytes = &bytes[taken..];
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
                .ssl_mode(sqlx::postgres::PgSslMode::Disable),
        )
        .await
        .unwrap();
    settle(&pool).await;
    (pool, ready)
}

/// Wait until a one-connection pool has its connection back. Release sends a
/// health check of its own, which must not be counted against what follows.
#[cfg(test)]
pub(crate) async fn settle(pool: &PgPool) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while pool.num_idle() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppState, config::Config, storage::Storage};
    use object_store::memory::InMemory;
    use sqlx::{PgPool, postgres::PgSslMode};
    use std::sync::Arc;
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
            async move { begin(&state).await }
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

    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn writers_wait_briefly_for_locks_and_an_exhausted_pool_is_a_retryable_503(
        observer: PgPool,
    ) {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_with((*observer.connect_options()).clone())
            .await
            .unwrap();
        let state = AppState::new(
            pool.clone(),
            Config::default(),
            Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new())),
            reqwest::Client::new(),
        )
        .unwrap();
        let mut held = begin(&state).await.unwrap();
        let timeout: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(&mut *held)
            .await
            .unwrap();
        assert_eq!(timeout, "100ms");
        // The only connection is taken: the next writer waits out the pool's
        // acquire timeout and is asked to retry.
        let busy = begin(&state).await.err().unwrap();
        assert_eq!(busy.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers.get(header::RETRY_AFTER).unwrap(), "1");
        held.rollback().await.unwrap();
        begin(&state).await.unwrap().commit().await.unwrap();
        // The timeout was transaction-local: the connection went back without it.
        let timeout: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(timeout, "0");
        state.finish_background().await;
        pool.close().await;
    }

    fn state(pool: &PgPool) -> AppState {
        AppState::new(
            pool.clone(),
            Config::default(),
            Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new())),
            reqwest::Client::new(),
        )
        .unwrap()
    }

    async fn one_connection(observer: &PgPool) -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with((*observer.connect_options()).clone())
            .await
            .unwrap()
    }

    async fn show(conn: impl sqlx::PgExecutor<'_>, setting: &'static str) -> String {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SHOW {setting}")))
            .fetch_one(conn)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn every_transaction_starts_in_one_round_trip_with_its_settings(observer: PgPool) {
        let (pool, ready) = counted(&observer).await;
        let state = state(&pool);
        let count = || ready.load(std::sync::atomic::Ordering::SeqCst);

        let before = count();
        let mut tx = begin(&state).await.unwrap();
        assert_eq!(count() - before, 1);
        assert_eq!(show(&mut *tx, "lock_timeout").await, "100ms");
        assert_eq!(show(&mut *tx, "statement_timeout").await, "0");
        assert_eq!(show(&mut *tx, "transaction_read_only").await, "off");
        tx.commit().await.unwrap();
        settle(&pool).await;

        let before = count();
        let mut tx = begin_read(&state).await.unwrap();
        assert_eq!(count() - before, 1);
        assert_eq!(show(&mut *tx, "statement_timeout").await, "1s");
        assert_eq!(show(&mut *tx, "lock_timeout").await, "0");
        assert_eq!(show(&mut *tx, "transaction_read_only").await, "on");
        tx.commit().await.unwrap();
        settle(&pool).await;

        let before = count();
        let mut tx = view(&state).await.unwrap();
        assert_eq!(count() - before, 1);
        assert_eq!(
            show(&mut *tx, "transaction_isolation").await,
            "repeatable read"
        );
        assert_eq!(show(&mut *tx, "transaction_read_only").await, "on");
        tx.commit().await.unwrap();
        settle(&pool).await;

        // Every setting was transaction-local: the one connection has none.
        for setting in ["lock_timeout", "statement_timeout"] {
            assert_eq!(show(&pool, setting).await, "0");
        }
        assert_eq!(show(&pool, "transaction_read_only").await, "off");
        assert_eq!(show(&pool, "transaction_isolation").await, "read committed");
        state.finish_background().await;
        pool.close().await;
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn a_dropped_transaction_rolls_back_and_returns_a_clean_connection(observer: PgPool) {
        sqlx::query("CREATE TABLE drop_probe (id integer PRIMARY KEY)")
            .execute(&observer)
            .await
            .unwrap();
        let pool = one_connection(&observer).await;
        let state = state(&pool);
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&pool)
            .await
            .unwrap();

        // The tracked wrapper, then a bare SQLx transaction as sweeps hold it.
        let mut tx = begin(&state).await.unwrap();
        sqlx::query("INSERT INTO drop_probe VALUES (1)")
            .execute(&mut *tx)
            .await
            .unwrap();
        drop(tx);
        let mut tx = start(&pool, WRITE).await.unwrap();
        sqlx::query("INSERT INTO drop_probe VALUES (2)")
            .execute(&mut *tx)
            .await
            .unwrap();
        // A savepoint nests inside it as inside any other transaction.
        let mut nested = sqlx::Acquire::begin(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO drop_probe VALUES (3)")
            .execute(&mut *nested)
            .await
            .unwrap();
        nested.commit().await.unwrap();
        drop(tx);

        // The same connection comes back outside any transaction and without
        // the settings: what it writes next commits on its own.
        sqlx::query("INSERT INTO drop_probe VALUES (4)")
            .execute(&pool)
            .await
            .unwrap();
        let reused: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(reused, pid);
        assert_eq!(show(&pool, "lock_timeout").await, "0");
        let kept: Vec<i32> = sqlx::query_scalar("SELECT id FROM drop_probe ORDER BY id")
            .fetch_all(&observer)
            .await
            .unwrap();
        assert_eq!(kept, [4]);
        state.finish_background().await;
        pool.close().await;
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn a_setting_that_fails_leaves_no_transaction_on_the_connection(observer: PgPool) {
        sqlx::query("CREATE TABLE failure_probe (id integer PRIMARY KEY)")
            .execute(&observer)
            .await
            .unwrap();
        let pool = one_connection(&observer).await;
        let state = state(&pool);
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&pool)
            .await
            .unwrap();

        for (id, statement) in [
            "SET LOCAL lock_timeout = 'never'; BEGIN",
            "SET LOCAL lock_timeout = '100ms'; SET LOCAL statement_timeout = 'never'; BEGIN",
        ]
        .into_iter()
        .enumerate()
        {
            let error = start(&pool, statement).await.err().unwrap();
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("22023"),
                "{error}"
            );
            // The same connection is idle, not inside an open or aborted
            // transaction, and kept nothing of the settings that did apply.
            let status: String =
                sqlx::query_scalar("SELECT state FROM pg_stat_activity WHERE pid=$1")
                    .bind(pid)
                    .fetch_one(&observer)
                    .await
                    .unwrap();
            assert_eq!(status, "idle");
            assert_eq!(show(&pool, "lock_timeout").await, "0");
            sqlx::query("INSERT INTO failure_probe VALUES ($1)")
                .bind(id as i32)
                .execute(&pool)
                .await
                .unwrap();
        }
        let reused: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(reused, pid);
        let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM failure_probe")
            .fetch_one(&observer)
            .await
            .unwrap();
        assert_eq!(kept, 2);
        begin(&state).await.unwrap().commit().await.unwrap();
        state.finish_background().await;
        pool.close().await;
    }
}
