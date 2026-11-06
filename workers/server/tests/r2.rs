//! Run against disposable S3 buckets via scripts/with-r2.sh, never live R2.
use std::io;

use axum::body::{Body, Bytes};
use futures_util::stream;
use object_store::{Attribute, ObjectStoreExt, aws::AmazonS3Builder, path::Path};
use sha2::{Digest, Sha256};
use snowstead_server::{config::Config, storage::Storage};
use tokio::io::AsyncReadExt;

#[tokio::test]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn existing_objects_streaming_replacement_and_cdn_metadata() {
    let config = Config::from_env();
    let endpoint = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
    assert_eq!(config.r2_endpoint, endpoint);
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    let bucket = |name: &str| {
        AmazonS3Builder::new()
            .with_endpoint(&endpoint)
            .with_region("auto")
            .with_bucket_name(name)
            .with_access_key_id(&config.r2_access_key_id)
            .with_secret_access_key(&config.r2_secret_access_key)
            .with_allow_http(true)
            .with_virtual_hosted_style_request(false)
            .build()
            .unwrap()
    };
    let private = bucket(&config.r2_bucket_name);
    let public = bucket(&config.r2_public_bucket_name);
    let storage = Storage::new(&config).unwrap();
    let id = uuid::Uuid::now_v7();
    let key = format!("go/17/generation/action/{id}");
    let path = Path::from(key.clone());
    // Pre-existing keys need no copy, renaming, or conversion by the server.
    private
        .put(
            &path,
            Bytes::from_static(b"existing private artifact").into(),
        )
        .await
        .unwrap();
    public
        .put(&path, Bytes::from_static(b"different public bytes").into())
        .await
        .unwrap();
    let mut bytes = Vec::new();
    storage
        .open(true, &key)
        .await
        .unwrap()
        .reader
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes, b"existing private artifact");

    // Validate framing failures after an actual remote multipart part, not just
    // before any network I/O. Neither failure may replace the committed object.
    let part = Bytes::from(vec![0xa7; 8 * 1024 * 1024]);
    for expected in [part.len() as u64 - 1, part.len() as u64 + 1] {
        let result = storage
            .write_body(true, &key, Body::from(part.clone()), expected)
            .await;
        assert_eq!(
            result.unwrap_err().status,
            axum::http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            private.get(&path).await.unwrap().bytes().await.unwrap(),
            b"existing private artifact".as_slice()
        );
    }
    let failing = stream::iter([
        Ok(part.clone()),
        Err(io::Error::other("client disconnected")),
    ]);
    assert!(
        storage
            .write_body(
                true,
                &key,
                Body::from_stream(failing),
                part.len() as u64 + 1
            )
            .await
            .is_err()
    );
    assert_eq!(
        private.get(&path).await.unwrap().bytes().await.unwrap(),
        b"existing private artifact".as_slice()
    );

    let staged = format!("staging/{id}");
    let size = part.len() + 13;
    let chunks = stream::iter([
        Ok::<_, io::Error>(part.clone()),
        Ok(Bytes::from_static(b"last thirteen")),
    ]);
    let receipt = storage
        .write_body(true, &staged, Body::from_stream(chunks), size as u64)
        .await
        .unwrap();
    let mut expected = Sha256::new();
    expected.update(&part);
    expected.update(b"last thirteen");
    assert_eq!(receipt, hex::encode(expected.finalize()));
    let canonical = format!("nar/{id}/zstd.nar");
    storage
        .copy(true, &staged, false, &canonical)
        .await
        .unwrap();
    let object = public.get(&Path::from(canonical.clone())).await.unwrap();
    assert_eq!(object.meta.size, size as u64);
    assert_eq!(
        object
            .attributes
            .get(&Attribute::ContentType)
            .unwrap()
            .as_ref(),
        "application/x-nix-nar"
    );
    assert_eq!(
        object
            .attributes
            .get(&Attribute::CacheControl)
            .unwrap()
            .as_ref(),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        hex::encode(Sha256::digest(object.bytes().await.unwrap())),
        receipt
    );
    assert!(storage.head(true, &canonical).await.is_err());
    // A newly constructed client sees the same objects without local state.
    let restarted = Storage::new(&config).unwrap();
    assert_eq!(
        restarted.head(false, &canonical).await.unwrap().size,
        size as u64
    );
    for (suffix, content_type, cache_control) in [
        ("path.narinfo", "text/x-nix-narinfo", "public, max-age=300"),
        (
            "nix-cache-info",
            "text/x-nix-cache-info",
            "public, max-age=3600",
        ),
    ] {
        let key = format!("cache-{id}/{suffix}");
        storage.put(false, &key, b"metadata").await.unwrap();
        let object = public.get(&Path::from(key)).await.unwrap();
        assert_eq!(
            object
                .attributes
                .get(&Attribute::ContentType)
                .unwrap()
                .as_ref(),
            content_type
        );
        assert_eq!(
            object
                .attributes
                .get(&Attribute::CacheControl)
                .unwrap()
                .as_ref(),
            cache_control
        );
    }
    // Slug-move cursors must remain usable after deleting the previous page.
    let prefix = format!("cache-{id}");
    let page = storage.list(false, &prefix, None, 1).await.unwrap();
    assert_eq!(page, [format!("{prefix}/nix-cache-info")]);
    storage.delete(false, &page[0]).await.unwrap();
    assert_eq!(
        storage
            .list(false, &prefix, Some(&page[0]), 1)
            .await
            .unwrap(),
        [format!("{prefix}/path.narinfo")]
    );
    let empty = format!("sccache/17/generation/empty/{id}");
    storage
        .write_body(true, &empty, Body::empty(), 0)
        .await
        .unwrap();
    assert_eq!(restarted.head(true, &empty).await.unwrap().size, 0);
    storage.delete(true, &staged).await.unwrap();
    storage.delete(true, &staged).await.unwrap();
    assert_eq!(
        storage.head(true, &staged).await.unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}
