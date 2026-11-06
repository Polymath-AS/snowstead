use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    http::StatusCode,
};
use futures_util::stream;
use object_store::memory::InMemory;
use sha2::Digest;
use snowstead_server::storage::Storage;
use tokio::sync::oneshot;

fn stalled_body() -> (Body, oneshot::Receiver<()>) {
    let (started, received) = oneshot::channel();
    let body = Body::from_stream(stream::once(async move {
        let _ = started.send(());
        std::future::pending::<Result<Bytes, std::io::Error>>().await
    }));
    (body, received)
}

#[tokio::test]
async fn simultaneous_small_uploads_are_limited_by_memory_not_count() {
    let storage = Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new()));
    let mut uploads = Vec::new();
    let mut releases = Vec::new();
    // Exceed the former 32-upload cap while reserving only 64 MiB of the
    // default 1 GiB memory budget (each small upload rounds up to 1 MiB).
    for index in 0..64 {
        let (started, received) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let body = Body::from_stream(stream::once(async move {
            let _ = started.send(());
            released.await.unwrap();
            Ok::<_, std::io::Error>(Bytes::from_static(b"ok"))
        }));
        let store = storage.clone();
        uploads.push(tokio::spawn(async move {
            store
                .write_body(true, &format!("small/{index}"), body, 2)
                .await
        }));
        tokio::time::timeout(Duration::from_secs(2), received)
            .await
            .unwrap()
            .unwrap();
        releases.push(release);
    }
    assert!(uploads.iter().all(|upload| !upload.is_finished()));
    for release in releases {
        release.send(()).unwrap();
    }
    for (index, upload) in uploads.into_iter().enumerate() {
        let receipt = tokio::time::timeout(Duration::from_secs(2), upload)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(receipt, hex::encode(sha2::Sha256::digest(b"ok")));
        assert_eq!(
            storage
                .head(true, &format!("small/{index}"))
                .await
                .unwrap()
                .size,
            2
        );
    }
}

#[tokio::test]
async fn large_uploads_share_a_memory_budget_and_cancellation_releases_it() {
    let storage = Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new()));
    let (body, started) = stalled_body();
    let first_store = storage.clone();
    let first = tokio::spawn(async move {
        first_store
            .write_body(true, "first", body, 5 * 1024_u64.pow(4))
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started)
        .await
        .unwrap()
        .unwrap();

    let (body, mut started) = stalled_body();
    let second_store = storage.clone();
    let second = tokio::spawn(async move {
        second_store
            .write_body(true, "second", body, 5 * 1024_u64.pow(4))
            .await
    });
    // Neither upload supplies payload bytes: admission is tested without
    // materializing a giant object or depending on the allocator/host's RAM.
    let error = tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        started.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    );
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    // Cleanup is asynchronous; retry overload rather than joining a wait queue.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (body, started) = stalled_body();
            let mut upload = Box::pin(storage.write_body(true, "after", body, 5 * 1024_u64.pow(4)));
            tokio::select! {
                result = &mut upload => assert_eq!(result.unwrap_err().status, StatusCode::SERVICE_UNAVAILABLE),
                result = started => { result.unwrap(); break; }
            }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();

    tokio::time::timeout(
        Duration::from_secs(2),
        storage.write_body(true, "small", Body::from("ok"), 2),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(storage.head(true, "small").await.unwrap().size, 2);
}
