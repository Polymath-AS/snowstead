mod common;

use axum::body::Body;
use futures_util::future::join_all;
use sha2::{Digest, Sha256};
use snowstead_server::bazel::store::Store;
use tokio::io::AsyncReadExt;

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn bytes(store: &Store, kind: &str, digest: &str) -> Option<Vec<u8>> {
    let mut object = store.read(kind, digest).await.unwrap()?;
    let mut bytes = Vec::new();
    object.reader.read_to_end(&mut bytes).await.unwrap();
    Some(bytes)
}

#[tokio::test]
async fn verified_publication_and_generation_isolation() {
    let storage = common::storage();
    let store = Store::new(storage.clone(), "first", 32);
    let digest = hash(b"good");
    assert!(
        store
            .write("cas", &digest, 4, Body::from("evil"))
            .await
            .is_err()
    );
    assert_eq!(bytes(&store, "cas", &digest).await, None);
    store
        .write("cas", &digest, 4, Body::from("good"))
        .await
        .unwrap();
    assert_eq!(bytes(&store, "cas", &digest).await, Some(b"good".to_vec()));
    let reset = Store::new(storage, "second", 32);
    assert_eq!(bytes(&reset, "cas", &digest).await, None);
    assert!(
        store
            .write("cas", &digest, 3, Body::from("good"))
            .await
            .is_err()
    );
    assert_eq!(bytes(&store, "cas", &digest).await, Some(b"good".to_vec()));
}

#[tokio::test]
async fn independent_writers_publish_without_a_database() {
    let storage = common::storage();
    let writes = (0..256u16).map(|value| {
        let store = Store::new(storage.clone(), "shared", 1024);
        async move {
            let value = value.to_le_bytes().to_vec();
            store
                .write("cas", &hash(&value), 2, Body::from(value))
                .await
                .unwrap();
        }
    });
    join_all(writes).await;
    let reader = Store::new(storage, "shared", 1024);
    for value in 0..256u16 {
        let expected = value.to_le_bytes().to_vec();
        assert_eq!(
            bytes(&reader, "cas", &hash(&expected)).await,
            Some(expected)
        );
    }
}

#[tokio::test]
async fn a_full_cache_evicts_instead_of_refusing_new_results() {
    let store = Store::new(common::storage(), "eviction", 7);
    let values = [b"one".as_slice(), b"two".as_slice(), b"new!".as_slice()];
    for value in values {
        store
            .write(
                "cas",
                &hash(value),
                value.len() as u64,
                Body::from(value.to_vec()),
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    // Publication may overshoot the target. Only the collector evicts.
    assert_eq!(store.usage().await.unwrap(), (3, 10));
    for _ in 0..256 {
        assert_eq!(
            bytes(&store, "cas", &hash(b"one")).await,
            Some(b"one".to_vec())
        );
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    store.collect().await.unwrap();
    assert_eq!(bytes(&store, "cas", &hash(b"two")).await, None);
    assert_eq!(
        bytes(&store, "cas", &hash(b"one")).await,
        Some(b"one".to_vec())
    );
    assert_eq!(
        bytes(&store, "cas", &hash(b"new!")).await,
        Some(b"new!".to_vec())
    );
    let mut retained = 0;
    for value in values {
        if let Some(value) = bytes(&store, "cas", &hash(value)).await {
            retained += value.len();
        }
    }
    assert!(retained <= 7);
}

#[tokio::test]
async fn action_results_replace_without_overwriting_blob_bytes() {
    let store = Store::new(common::storage(), "actions", 64);
    let digest = hash(b"blob");
    store
        .write("cas", &digest, 4, Body::from("blob"))
        .await
        .unwrap();
    store
        .write("ac", &digest, 3, Body::from("old"))
        .await
        .unwrap();
    store
        .write("ac", &digest, 6, Body::from("newest"))
        .await
        .unwrap();
    assert_eq!(bytes(&store, "cas", &digest).await, Some(b"blob".to_vec()));
    assert_eq!(bytes(&store, "ac", &digest).await, Some(b"newest".to_vec()));
    assert_eq!(store.physical_usage().await.unwrap(), (13, 0));
    store.collect().await.unwrap();
    assert_eq!(store.physical_usage().await.unwrap(), (10, 0));
    assert_eq!(bytes(&store, "cas", &digest).await, Some(b"blob".to_vec()));
    assert_eq!(bytes(&store, "ac", &digest).await, Some(b"newest".to_vec()));
}

#[tokio::test]
async fn repeated_digest_uploads_release_superseded_bytes_on_collection() {
    let store = Store::new(common::storage(), "replacements", 1024 * 1024);
    let body = vec![7; 1024 * 1024];
    let digest = hash(&body);
    for _ in 0..16 {
        store
            .write("cas", &digest, body.len() as u64, Body::from(body.clone()))
            .await
            .unwrap();
    }
    assert_eq!(store.usage().await.unwrap(), (1, 1024 * 1024));
    assert_eq!(store.physical_usage().await.unwrap(), (16 * 1024 * 1024, 0));
    store.collect().await.unwrap();
    assert_eq!(store.physical_usage().await.unwrap(), (1024 * 1024, 0));
    assert_eq!(bytes(&store, "cas", &digest).await, Some(body));
}

#[tokio::test]
#[ignore = "requires disposable S3 from scripts/with-r2.sh"]
async fn concurrent_collectors_preserve_the_retained_working_set() {
    let storage = common::s3_storage();
    let store = Store::new(storage.clone(), "collectors", 96);
    for value in 0..24u64 {
        let value = value.to_le_bytes().to_vec();
        store
            .write("cas", &hash(&value), 8, Body::from(value))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    for result in join_all((0..6).map(|_| store.collect())).await {
        result.unwrap();
    }
    assert_eq!(store.usage().await.unwrap(), (12, 96));
    // Evicted objects and their metadata must not accumulate forever. These
    // writes have no read samples: each entry owns bytes, pointer, and receipt.
    assert_eq!(
        storage
            .list(true, "bazel/collectors", None, 100)
            .await
            .unwrap()
            .len(),
        36
    );
    for value in 12..24u64 {
        let expected = value.to_le_bytes().to_vec();
        assert_eq!(bytes(&store, "cas", &hash(&expected)).await, Some(expected));
    }
}
