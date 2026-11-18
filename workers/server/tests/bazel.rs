mod common;

use futures_util::stream;
use prost::Message;
use sha2::{Digest as _, Sha256};
use snowstead_server::bazel::proto::{
    build::bazel::remote::execution::v2::*, google::bytestream::*,
};
use snowstead_server::{AppState, config::Config, router};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tonic::{Request, transport::Channel};

fn digest(bytes: &[u8]) -> Digest {
    Digest {
        hash: hex::encode(Sha256::digest(bytes)),
        size_bytes: bytes.len() as i64,
    }
}

struct Host {
    url: String,
    token: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Host {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn host(pool: &PgPool, storage: snowstead_server::storage::Storage) -> Host {
    let token = seed(pool).await;
    serve(pool, storage, token, Hosting::Shared).await
}

#[derive(Clone, Copy, PartialEq)]
enum Hosting {
    /// Path-based addresses on the shared host.
    Shared,
    /// Every request arrives with the organization Host, as nginx forwards it.
    Forwarded,
    /// The organization host is configured; each request's own host or
    /// `:authority` names the organization.
    Direct,
}

/// Seeds the `alpha` organization's public and private Bazel caches and a token
/// that reads and writes both. Run once per database. Returns the token.
async fn seed(pool: &PgPool) -> String {
    sqlx::raw_sql("INSERT INTO orgs(id,slug,private_caches) VALUES ('bazel-org','alpha',true);
        INSERT INTO caches(name,org_id,is_public) VALUES ('public','bazel-org',true),('private','bazel-org',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'bazel' FROM caches;
        INSERT INTO bazel_caches(cache_id,generation,capacity) SELECT id,'generation-' || id,33554432 FROM caches;")
        .execute(pool).await.unwrap();
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO api_tokens(jti,subject,org_id,created_by,secret_hash) VALUES ($1,'bazel','bazel-org','test',$2)")
        .bind(&id).bind(hex::encode(Sha256::digest(b"fixture"))).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO token_permissions(token_jti,permission,position) VALUES ($1,'bazel:read',1),($1,'bazel:write',2)")
        .bind(&id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO token_caches(token_jti,pattern) VALUES ($1,'*')")
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
    format!("snowstead_tok_{id}_fixture")
}

/// Serves the seeded caches. Unless `Hosting::Shared`, the organization host
/// is configured, and `Hosting::Forwarded` rewrites every Host to
/// `alpha.snowstead.com`; the `/_api/v1/…` addresses are unreachable there.
async fn serve(
    pool: &PgPool,
    storage: snowstead_server::storage::Storage,
    token: String,
    hosting: Hosting,
) -> Host {
    let org = hosting != Hosting::Shared;
    let config = if org {
        Config {
            cache_host_suffix: "snowstead.com".into(),
            cache_canonical_hosts: "api.snowstead.com".into(),
            ..Default::default()
        }
    } else {
        Config::default()
    };
    let state = AppState::new(pool.clone(), config, storage, reqwest::Client::new()).unwrap();
    let app = router(state);
    let app = if hosting == Hosting::Forwarded {
        app.layer(axum::middleware::map_request(
            |mut request: axum::extract::Request| async move {
                request
                    .headers_mut()
                    .insert("host", "alpha.snowstead.com".parse().unwrap());
                request
            },
        ))
    } else {
        app
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Host { url, token, task }
}

fn authorized<T>(body: T, host: &Host) -> Request<T> {
    let mut request = Request::new(body);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", host.token).parse().unwrap(),
    );
    request
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn http_integrity_action_results_and_private_access(pool: PgPool) {
    let host = host(&pool, common::storage()).await;
    let client = reqwest::Client::new();
    let bytes = b"build output";
    let file = digest(bytes);
    let base = format!("{}/_api/v1/bazel/alpha", host.url);
    let path = format!("{base}/public/cas/{}", file.hash);
    assert_eq!(
        client
            .put(&path)
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .put(&path)
            .bearer_auth(&host.token)
            .body("wrong output")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(client.get(&path).send().await.unwrap().status(), 404);
    assert_eq!(
        client
            .put(&path)
            .bearer_auth(&host.token)
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        &client
            .get(&path)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()[..],
        bytes
    );
    let cached = client.get(&path).send().await.unwrap();
    assert_eq!(
        cached.headers()["cache-control"],
        "public, no-cache, must-revalidate, no-transform"
    );
    let etag = cached.headers()["etag"].clone();
    assert_eq!(
        client
            .get(&path)
            .header("if-none-match", &etag)
            .send()
            .await
            .unwrap()
            .status(),
        304
    );
    // A CDN revalidation must not authorize with an ETag or stale public policy.
    sqlx::query("UPDATE caches SET is_public=false WHERE name='public'")
        .execute(&pool)
        .await
        .unwrap();
    let denied = client
        .get(&path)
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    assert_eq!(denied.headers()["cache-control"], "no-store");
    sqlx::query("UPDATE caches SET is_public=true WHERE name='public'")
        .execute(&pool)
        .await
        .unwrap();
    let action = ActionResult {
        output_files: vec![OutputFile {
            path: "out".into(),
            digest: Some(file),
            ..Default::default()
        }],
        ..Default::default()
    };
    let ac = format!("{base}/public/ac/{}", digest(b"action").hash);
    assert_eq!(
        client
            .put(&ac)
            .bearer_auth(&host.token)
            .body(action.encode_to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(client.get(&ac).send().await.unwrap().status(), 200);
    let private = path.replace("/public/", "/private/");
    assert_eq!(
        client
            .put(&private)
            .bearer_auth(&host.token)
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(client.get(&private).send().await.unwrap().status(), 401);
    assert_eq!(
        client
            .get(&private)
            .bearer_auth(&host.token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    sqlx::query("UPDATE bazel_caches SET generation='reset' WHERE cache_id=(SELECT id FROM caches WHERE name='public')")
        .execute(&pool).await.unwrap();
    assert_eq!(client.get(&ac).send().await.unwrap().status(), 404);
    assert_eq!(client.get(&path).send().await.unwrap().status(), 404);
    assert_eq!(
        client
            .get(&path)
            .header("if-none-match", &etag)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // Resetting one cache does not change another cache's namespace.
    assert_eq!(
        client
            .get(&private)
            .bearer_auth(&host.token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn grpc_batch_and_resumable_bytestream(pool: PgPool) {
    let host = host(&pool, common::storage()).await;
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut cas =
        content_addressable_storage_client::ContentAddressableStorageClient::new(channel.clone());
    let mut bytestream = byte_stream_client::ByteStreamClient::new(channel);
    let expected = b"first second";
    let digest = digest(expected);
    let resource = format!(
        "alpha/private/uploads/test-upload/blobs/{}/{}",
        digest.hash, digest.size_bytes
    );
    assert_eq!(
        bytestream
            .query_write_status(authorized(
                QueryWriteStatusRequest {
                    resource_name: resource.clone()
                },
                &host,
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    let partial = WriteRequest {
        resource_name: resource.clone(),
        write_offset: 0,
        finish_write: false,
        data: b"first ".to_vec(),
    };
    assert!(
        bytestream
            .write(authorized(stream::iter([partial]), &host))
            .await
            .is_err()
    );
    let committed = bytestream
        .query_write_status(authorized(
            QueryWriteStatusRequest {
                resource_name: resource.clone(),
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(committed.committed_size, 6);
    assert!(!committed.complete);
    let suffix = WriteRequest {
        resource_name: resource.clone(),
        write_offset: 6,
        finish_write: true,
        data: b"second".to_vec(),
    };
    let written = bytestream
        .write(authorized(stream::iter([suffix]), &host))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(written.committed_size, expected.len() as i64);
    let mut response = bytestream
        .read(authorized(
            ReadRequest {
                resource_name: format!("alpha/private/blobs/{}/{}", digest.hash, digest.size_bytes),
                read_offset: 3,
                read_limit: 5,
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    let mut bytes = Vec::new();
    while let Some(part) = response.message().await.unwrap() {
        bytes.extend(part.data);
    }
    assert_eq!(bytes, b"st se");
    let result = cas
        .batch_read_blobs(authorized(
            BatchReadBlobsRequest {
                instance_name: "alpha/private".into(),
                digests: vec![digest],
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.responses.len(), 1);
    assert_eq!(result.responses[0].status.as_ref().unwrap().code, 0);
    assert_eq!(result.responses[0].data, expected);
    // Native read methods cannot bypass private-cache authentication.
    assert_eq!(
        cas.find_missing_blobs(FindMissingBlobsRequest {
            instance_name: "alpha/private".into(),
            ..Default::default()
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::Unauthenticated
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires disposable S3 from scripts/with-r2.sh"]
async fn bytestream_buffer_boundary_and_delayed_finish(pool: PgPool) {
    let storage = common::s3_storage();
    let mut host = host(&pool, storage.clone()).await;
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = byte_stream_client::ByteStreamClient::new(channel);
    let http = reqwest::Client::new();
    for delayed in [false, true] {
        for size in [
            0,
            1,
            8 * 1024 * 1024 - 1,
            8 * 1024 * 1024,
            8 * 1024 * 1024 + 1,
            32 * 1024 * 1024 + 17,
        ] {
            let expected: Vec<u8> = (0..size)
                .map(|i| ((i + usize::from(delayed)) % 251) as u8)
                .collect();
            let digest = digest(&expected);
            let resource = format!(
                "alpha/private/uploads/{}/blobs/{}/{}",
                uuid::Uuid::now_v7(),
                digest.hash,
                size
            );
            let url = format!(
                "{}/_api/v1/bazel/alpha/private/cas/{}",
                host.url, digest.hash
            );
            let messages = |bytes: &[u8], finish: bool| {
                let mut messages: Vec<_> = bytes
                    .chunks(1024 * 1024)
                    .enumerate()
                    .map(|(i, part)| WriteRequest {
                        resource_name: resource.clone(),
                        write_offset: (i * 1024 * 1024) as i64,
                        finish_write: false,
                        data: part.to_vec(),
                    })
                    .collect();
                messages.push(WriteRequest {
                    resource_name: resource.clone(),
                    write_offset: size as i64,
                    finish_write: finish,
                    data: Vec::new(),
                });
                messages
            };
            if size > 0 {
                let mut corrupt = expected.clone();
                corrupt[size - 1] ^= 1;
                assert_eq!(
                    client
                        .write(authorized(stream::iter(messages(&corrupt, true)), &host))
                        .await
                        .unwrap_err()
                        .code(),
                    tonic::Code::InvalidArgument
                );
                assert_eq!(
                    http.get(&url)
                        .bearer_auth(&host.token)
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    404
                );
            }
            // A failed multi-chunk session is sealed. Use a fresh upload ID for
            // the valid retry, as a real ByteStream client must do.
            let resource = resource.replace("/uploads/", "/uploads/retry-");
            let mut requests = messages(&expected, !delayed);
            for request in &mut requests {
                request.resource_name = resource.clone();
            }
            let response = client
                .write(authorized(stream::iter(requests), &host))
                .await;
            if delayed && size > 0 {
                assert_eq!(response.unwrap_err().code(), tonic::Code::InvalidArgument);
                assert_eq!(
                    http.get(&url)
                        .bearer_auth(&host.token)
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    404
                );
                // Collection must not reclaim a verified but unpublished object.
                let generation: String = sqlx::query_scalar(
                    "SELECT b.generation FROM bazel_caches b JOIN caches c ON c.id=b.cache_id WHERE c.name='private'"
                ).fetch_one(&pool).await.unwrap();
                let store = snowstead_server::bazel::store::Store::new(
                    storage.clone(),
                    &generation,
                    u64::MAX,
                );
                store.collect().await.unwrap();
                let physical = store.physical_usage().await.unwrap();
                if size == 8 * 1024 * 1024 {
                    host.task.abort();
                    let mut config = Config::default();
                    config.resources.upload_buffer_mib = 8;
                    config.resources.upload_part_mib = 8;
                    let state = AppState::new(
                        pool.clone(),
                        config,
                        storage.clone(),
                        reqwest::Client::new(),
                    )
                    .unwrap();
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    host.url = format!("http://{}", listener.local_addr().unwrap());
                    host.task = tokio::spawn(async move {
                        axum::serve(listener, router(state)).await.unwrap();
                    });
                    client = byte_stream_client::ByteStreamClient::new(
                        Channel::from_shared(host.url.clone())
                            .unwrap()
                            .connect()
                            .await
                            .unwrap(),
                    );
                }
                let status = client
                    .query_write_status(authorized(
                        QueryWriteStatusRequest {
                            resource_name: resource.clone(),
                        },
                        &host,
                    ))
                    .await
                    .unwrap()
                    .into_inner();
                assert_eq!(status.committed_size, size as i64);
                assert!(!status.complete);
                let finish = WriteRequest {
                    resource_name: resource.clone(),
                    write_offset: size as i64,
                    finish_write: true,
                    data: Vec::new(),
                };
                assert_eq!(
                    client
                        .write(authorized(stream::iter([finish]), &host))
                        .await
                        .unwrap()
                        .into_inner()
                        .committed_size,
                    size as i64
                );
                let retained = store.physical_usage().await.unwrap();
                // Finalization must not retain a second copy of the payload.
                assert_eq!(retained.0 + retained.1, physical.0 + physical.1);
                store.collect().await.unwrap();
            } else {
                assert_eq!(response.unwrap().into_inner().committed_size, size as i64);
            }
            let status = client
                .query_write_status(authorized(
                    QueryWriteStatusRequest {
                        resource_name: resource,
                    },
                    &host,
                ))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(status.committed_size, size as i64);
            assert!(status.complete);
            let downloaded = http
                .get(format!(
                    "{}/_api/v1/bazel/alpha/private/cas/{}",
                    host.url, digest.hash
                ))
                .bearer_auth(&host.token)
                .send()
                .await
                .unwrap();
            assert_eq!(downloaded.status(), 200);
            assert_eq!(downloaded.bytes().await.unwrap().as_ref(), expected);
        }
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn upload_memory_pressure_is_retryable(pool: PgPool) {
    let mut host = host(&pool, common::storage()).await;
    host.task.abort();
    let mut config = Config::default();
    config.resources.upload_buffer_mib = 8;
    config.resources.upload_part_mib = 8;
    let state = AppState::new(pool, config, common::storage(), reqwest::Client::new()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    host.url = format!("http://{}", listener.local_addr().unwrap());
    host.task = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = byte_stream_client::ByteStreamClient::new(channel.clone());
    let bytes = b"retry after memory pressure";
    let digest = digest(bytes);
    let first = WriteRequest {
        resource_name: format!(
            "alpha/private/uploads/stalled/blobs/{}/8388608",
            "0".repeat(64)
        ),
        write_offset: 0,
        finish_write: false,
        data: bytes[..1].to_vec(),
    };
    use futures_util::StreamExt;
    let stalled = authorized(stream::iter([first]).chain(stream::pending()), &host);
    let writing = tokio::spawn(async move { client.write(stalled).await });
    let http = reqwest::Client::new();
    let url = format!(
        "{}/_api/v1/bazel/alpha/private/cas/{}",
        host.url, digest.hash
    );
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let response = http
                .put(&url)
                .bearer_auth(&host.token)
                .body(bytes.to_vec())
                .send()
                .await
                .unwrap();
            if response.status() != 204 {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut cas = content_addressable_storage_client::ContentAddressableStorageClient::new(channel);
    let batch = cas
        .batch_update_blobs(authorized(
            BatchUpdateBlobsRequest {
                instance_name: "alpha/private".into(),
                requests: vec![batch_update_blobs_request::Request {
                    digest: Some(digest),
                    data: bytes.to_vec(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    writing.abort();
    assert_eq!(response.status(), 503);
    assert_eq!(
        batch.responses[0].status.as_ref().unwrap().code,
        tonic::Code::Unavailable as i32
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let response = http
                .put(&url)
                .bearer_auth(&host.token)
                .body(bytes.to_vec())
                .send()
                .await
                .unwrap();
            if response.status() == 204 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let downloaded = http
        .get(&url)
        .bearer_auth(&host.token)
        .send()
        .await
        .unwrap();
    assert_eq!(downloaded.bytes().await.unwrap().as_ref(), bytes);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires disposable S3 from scripts/with-r2.sh"]
async fn resumable_upload_survives_server_replacement(pool: PgPool) {
    let storage = common::s3_storage();
    let mut host = host(&pool, storage.clone()).await;
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = byte_stream_client::ByteStreamClient::new(channel);
    let expected: Vec<u8> = (0..9 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let digest = digest(&expected);
    let resource = format!(
        "alpha/private/uploads/restart/blobs/{}/{}",
        digest.hash, digest.size_bytes
    );
    let checkpoint = 8 * 1024 * 1024 + 123;
    let messages = expected[..checkpoint]
        .chunks(4 * 1024 * 1024)
        .enumerate()
        .map(|(i, bytes)| WriteRequest {
            resource_name: resource.clone(),
            write_offset: (i * 4 * 1024 * 1024) as i64,
            finish_write: false,
            data: bytes.to_vec(),
        })
        .collect::<Vec<_>>();
    assert!(
        client
            .write(authorized(stream::iter(messages), &host))
            .await
            .is_err()
    );
    host.task.abort();
    drop(client);

    // Replace all application state, retaining only the external stores.
    let state = AppState::new(
        pool.clone(),
        Config::default(),
        storage,
        reqwest::Client::new(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    host.url = format!("http://{}", listener.local_addr().unwrap());
    host.task = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = byte_stream_client::ByteStreamClient::new(channel);
    let status = client
        .query_write_status(authorized(
            QueryWriteStatusRequest {
                resource_name: resource.clone(),
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.committed_size, checkpoint as i64);
    assert!(!status.complete);
    let wrong_offset = WriteRequest {
        resource_name: resource.clone(),
        write_offset: status.committed_size - 1,
        finish_write: true,
        data: expected[checkpoint..].to_vec(),
    };
    assert_eq!(
        client
            .write(authorized(stream::iter([wrong_offset]), &host))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::OutOfRange
    );
    let suffix = WriteRequest {
        resource_name: resource,
        write_offset: status.committed_size,
        finish_write: true,
        data: expected[checkpoint..].to_vec(),
    };
    assert_eq!(
        client
            .write(authorized(stream::iter([suffix]), &host))
            .await
            .unwrap()
            .into_inner()
            .committed_size,
        digest.size_bytes
    );
    let response = reqwest::Client::new()
        .get(format!(
            "{}/_api/v1/bazel/alpha/private/cas/{}",
            host.url, digest.hash
        ))
        .bearer_auth(&host.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), expected);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires Bazel 8 from the development shell"]
async fn native_bazel_upload_and_clean_remote_hit(pool: PgPool) {
    let host = host(&pool, common::s3_storage()).await;
    let bazel = std::env::var("BAZEL").unwrap_or_else(|_| "bazel".to_owned());
    tokio::task::spawn_blocking(move || {
        let root = std::env::temp_dir().join(format!("bazel-e2e-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("MODULE.bazel"), "module(name = 'cache_fixture')\n").unwrap();
        std::fs::write(root.join("BUILD.bazel"), format!(
            "genrule(name='artifact', outs=['artifact.bin'], cmd='dd if=/dev/zero of=$@ bs=1048576 count=9; echo executed >> {}/executions')\n",
            root.display()
        )).unwrap();
        for protocol in ["http", "grpc"] {
            let endpoint = if protocol == "http" {
                format!("{}/_api/v1/bazel/alpha/private", host.url)
            } else { host.url.replace("http://", "grpc://") };
            for run in 0..2 {
                let output = std::process::Command::new(&bazel)
                    .current_dir(&root)
                    .arg("--batch")
                    .arg(format!("--output_user_root={}/{protocol}-{run}", root.display()))
                    .args(["build", "//:artifact", "--spawn_strategy=local", "--remote_download_outputs=all"])
                    .arg(format!("--remote_cache={endpoint}"))
                    .arg("--remote_instance_name=alpha/private")
                    .arg(format!("--remote_header=Authorization=Bearer {}", host.token))
                    .output().unwrap();
                assert!(output.status.success(), "{protocol} run {run}: {}", String::from_utf8_lossy(&output.stderr));
                assert_eq!(std::fs::metadata(root.join("bazel-bin/artifact.bin")).unwrap().len(), 9 * 1024 * 1024);
                if run == 1 {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("remote cache hit"), "{}", String::from_utf8_lossy(&output.stderr));
                }
            }
        }
        // HTTP and gRPC share the same action keys and outputs across clean builds.
        assert_eq!(std::fs::read_to_string(root.join("executions")).unwrap().lines().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }).await.unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires Bazel 8 from the development shell"]
async fn native_bazel_through_the_organization_host(pool: PgPool) {
    let token = seed(&pool).await;
    let host = serve(&pool, common::s3_storage(), token, Hosting::Forwarded).await;
    let bazel = std::env::var("BAZEL").unwrap_or_else(|_| "bazel".to_owned());
    tokio::task::spawn_blocking(move || {
        let root = std::env::temp_dir().join(format!("bazel-org-e2e-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("MODULE.bazel"), "module(name = 'cache_fixture')\n").unwrap();
        std::fs::write(root.join("BUILD.bazel"), format!(
            "genrule(name='artifact', outs=['artifact.bin'], cmd='dd if=/dev/zero of=$@ bs=1048576 count=9; echo executed >> {}/executions')\n",
            root.display()
        )).unwrap();
        for protocol in ["grpc", "http"] {
            // The organization host names the organization; gRPC's instance names the cache.
            let endpoint = if protocol == "http" {
                format!("{}/private/bazel", host.url)
            } else {
                host.url.replace("http://", "grpc://")
            };
            let instance: &[&str] = if protocol == "grpc" {
                &["--remote_instance_name=private"]
            } else {
                &[]
            };
            for run in 0..2 {
                let output = std::process::Command::new(&bazel)
                    .current_dir(&root)
                    .arg("--batch")
                    .arg(format!("--output_user_root={}/{protocol}-{run}", root.display()))
                    .args(["build", "//:artifact", "--spawn_strategy=local", "--remote_download_outputs=all"])
                    .arg(format!("--remote_cache={endpoint}"))
                    .args(instance)
                    .arg(format!("--remote_header=Authorization=Bearer {}", host.token))
                    .output().unwrap();
                assert!(output.status.success(), "{protocol} run {run}: {}", String::from_utf8_lossy(&output.stderr));
                assert_eq!(std::fs::metadata(root.join("bazel-bin/artifact.bin")).unwrap().len(), 9 * 1024 * 1024);
                if run == 1 {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("remote cache hit"), "{}", String::from_utf8_lossy(&output.stderr));
                }
            }
        }
        assert_eq!(std::fs::read_to_string(root.join("executions")).unwrap().lines().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }).await.unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn publication_does_not_wait_on_control_plane_locks(pool: PgPool) {
    let host = host(&pool, common::storage()).await;
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM caches FOR UPDATE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM orgs FOR UPDATE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("SELECT cache_id FROM bazel_caches FOR UPDATE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let output = b"publication while policy rows are locked";
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client
            .put(format!(
                "{}/_api/v1/bazel/alpha/private/cas/{}",
                host.url,
                digest(output).hash
            ))
            .bearer_auth(&host.token)
            .body(output.to_vec())
            .send(),
    )
    .await
    .expect("publication must not acquire row locks")
    .unwrap();
    assert_eq!(response.status(), 204);
    transaction.rollback().await.unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn grpc_tree_batch_failures_and_evicted_action_dependencies(pool: PgPool) {
    let storage = common::storage();
    let host = host(&pool, storage.clone()).await;
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut cas =
        content_addressable_storage_client::ContentAddressableStorageClient::new(channel.clone());
    let mut actions = action_cache_client::ActionCacheClient::new(channel);
    let child = Directory {
        files: vec![FileNode {
            name: "out".into(),
            digest: Some(digest(b"payload")),
            ..Default::default()
        }],
        ..Default::default()
    };
    let root = Directory {
        directories: vec![DirectoryNode {
            name: "nested".into(),
            digest: Some(digest(&child.encode_to_vec())),
        }],
        ..Default::default()
    };
    let tree = Tree {
        root: Some(root.clone()),
        children: vec![child.clone()],
    };
    let values = [
        b"payload".to_vec(),
        child.encode_to_vec(),
        root.encode_to_vec(),
        tree.encode_to_vec(),
    ];
    let requests = values
        .iter()
        .map(|bytes| batch_update_blobs_request::Request {
            digest: Some(digest(bytes)),
            data: bytes.clone(),
            compressor: 0,
        })
        .chain([batch_update_blobs_request::Request {
            digest: Some(digest(b"not this")),
            data: b"corrupt!".to_vec(),
            compressor: 0,
        }])
        .collect();
    let response = cas
        .batch_update_blobs(authorized(
            BatchUpdateBlobsRequest {
                instance_name: "alpha/private".into(),
                requests,
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response
            .responses
            .iter()
            .filter(|r| r.status.as_ref().unwrap().code == 0)
            .count(),
        4
    );
    assert_eq!(
        response
            .responses
            .iter()
            .filter(|r| r.status.as_ref().unwrap().code == tonic::Code::InvalidArgument as i32)
            .count(),
        1
    );
    let mut directories = cas
        .get_tree(authorized(
            GetTreeRequest {
                instance_name: "alpha/private".into(),
                root_digest: Some(digest(&root.encode_to_vec())),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    let mut found = vec![];
    while let Some(page) = directories.message().await.unwrap() {
        found.extend(page.directories);
    }
    assert_eq!(found, vec![root, child]);
    let action_digest = digest(b"action with directory outputs");
    let result = ActionResult {
        output_symlinks: vec![OutputSymlink {
            path: "linked-tool".into(),
            target: "/opt/tool".into(),
            ..Default::default()
        }],
        output_directories: vec![OutputDirectory {
            path: "dir".into(),
            tree_digest: Some(digest(&tree.encode_to_vec())),
            ..Default::default()
        }],
        ..Default::default()
    };
    actions
        .update_action_result(authorized(
            UpdateActionResultRequest {
                instance_name: "alpha/private".into(),
                action_digest: Some(action_digest.clone()),
                action_result: Some(result.clone()),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap();
    let get = GetActionResultRequest {
        instance_name: "alpha/private".into(),
        action_digest: Some(action_digest),
        ..Default::default()
    };
    assert_eq!(
        actions
            .get_action_result(authorized(get.clone(), &host))
            .await
            .unwrap()
            .into_inner(),
        result
    );
    let generation: String = sqlx::query_scalar("SELECT generation FROM bazel_caches b JOIN caches c ON c.id=b.cache_id WHERE c.name='private'").fetch_one(&pool).await.unwrap();
    // Lose only an output blob, leaving the action and Tree present.
    let key = format!("bazel/{generation}/index/cas/{}", digest(b"payload").hash);
    storage.put(true, &key, b"null").await.unwrap();
    assert_eq!(
        actions
            .get_action_result(authorized(get, &host))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn cache_scope_permissions_tier_and_revocation_apply_to_both_transports(pool: PgPool) {
    let host = host(&pool, common::storage()).await;
    let client = reqwest::Client::new();
    let value = b"tenant-specific output";
    let blob = digest(value);
    let path = format!("{}/_api/v1/bazel/alpha/private/cas/{}", host.url, blob.hash);
    assert_eq!(
        client
            .put(&path)
            .bearer_auth(&host.token)
            .body(value.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut cas = content_addressable_storage_client::ContentAddressableStorageClient::new(channel);
    let read = BatchReadBlobsRequest {
        instance_name: "alpha/private".into(),
        digests: vec![blob.clone()],
        ..Default::default()
    };
    sqlx::query("UPDATE token_caches SET pattern='public'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client
            .get(&path)
            .bearer_auth(&host.token)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        cas.batch_read_blobs(authorized(read.clone(), &host))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    sqlx::query("UPDATE token_caches SET pattern='*'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM token_permissions WHERE permission='bazel:write'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client
            .put(&path)
            .bearer_auth(&host.token)
            .body(value.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        cas.batch_update_blobs(authorized(
            BatchUpdateBlobsRequest {
                instance_name: "alpha/private".into(),
                requests: vec![batch_update_blobs_request::Request {
                    digest: Some(blob),
                    data: value.to_vec(),
                    compressor: 0
                }],
                ..Default::default()
            },
            &host
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        cas.batch_read_blobs(authorized(read.clone(), &host))
            .await
            .unwrap()
            .into_inner()
            .responses[0]
            .data,
        value
    );
    sqlx::query("UPDATE orgs SET private_caches=false WHERE id='bazel-org'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client
            .get(&path)
            .bearer_auth(&host.token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    sqlx::query("UPDATE api_tokens SET revoked_at=NOW()")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client
            .get(&path)
            .bearer_auth(&host.token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        cas.batch_read_blobs(authorized(read, &host))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn trailing_upload_metadata_and_empty_final_message(pool: PgPool) {
    let host = host(&pool, common::s3_storage()).await;
    let mut client = byte_stream_client::ByteStreamClient::connect(host.url.clone())
        .await
        .unwrap();
    let bytes = b"metadata upload";
    let value = digest(bytes);
    let name = format!(
        "alpha/private/uploads/{}/blobs/{}/{}/client/build-42",
        "cd6dbd92-30d4-4afd-af31-f04440e42f83", value.hash, value.size_bytes
    );
    let first = WriteRequest {
        resource_name: name.clone(),
        data: bytes.to_vec(),
        ..Default::default()
    };
    assert!(
        client
            .write(authorized(stream::iter([first]), &host))
            .await
            .is_err()
    );
    let status = client
        .query_write_status(authorized(
            QueryWriteStatusRequest {
                resource_name: name.clone(),
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.committed_size, value.size_bytes);
    assert!(!status.complete);
    let finished = client
        .write(authorized(
            stream::iter([
                WriteRequest {
                    resource_name: name.clone(),
                    write_offset: value.size_bytes,
                    ..Default::default()
                },
                WriteRequest {
                    write_offset: value.size_bytes,
                    finish_write: true,
                    ..Default::default()
                },
            ]),
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(finished.committed_size, value.size_bytes);
    assert!(
        client
            .query_write_status(authorized(
                QueryWriteStatusRequest {
                    resource_name: name
                },
                &host
            ))
            .await
            .unwrap()
            .into_inner()
            .complete
    );
    let mut read = client
        .read(authorized(
            ReadRequest {
                resource_name: format!("alpha/private/blobs/{}/{}", value.hash, value.size_bytes),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    let mut actual = Vec::new();
    while let Some(message) = read.message().await.unwrap() {
        actual.extend(message.data);
    }
    assert_eq!(actual, bytes);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn get_tree_omits_missing_descendants_but_not_missing_root(pool: PgPool) {
    let host = host(&pool, common::s3_storage()).await;
    let present = Directory::default();
    let root = Directory {
        directories: vec![
            DirectoryNode {
                name: "absent".into(),
                digest: Some(digest(b"missing directory")),
            },
            DirectoryNode {
                name: "present".into(),
                digest: Some(digest(&present.encode_to_vec())),
            },
        ],
        ..Default::default()
    };
    let mut client = content_addressable_storage_client::ContentAddressableStorageClient::connect(
        host.url.clone(),
    )
    .await
    .unwrap();
    let bytes = root.encode_to_vec();
    let uploaded = client
        .batch_update_blobs(authorized(
            BatchUpdateBlobsRequest {
                instance_name: "alpha/private".into(),
                requests: vec![batch_update_blobs_request::Request {
                    digest: Some(digest(&bytes)),
                    data: bytes.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(uploaded.responses[0].status.as_ref().unwrap().code, 0);
    let mut response = client
        .get_tree(authorized(
            GetTreeRequest {
                instance_name: "alpha/private".into(),
                root_digest: Some(digest(&bytes)),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    let mut directories = Vec::new();
    while let Some(page) = response.message().await.unwrap() {
        directories.extend(page.directories);
    }
    assert_eq!(directories, vec![root, present]);
    let mut response = client
        .get_tree(authorized(
            GetTreeRequest {
                instance_name: "alpha/private".into(),
                root_digest: Some(digest(b"missing root")),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.message().await.unwrap_err().code(),
        tonic::Code::NotFound
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn empty_write_messages_do_not_extend_progress_deadline(pool: PgPool) {
    use futures_util::StreamExt;
    let storage = common::s3_storage();
    let mut host = host(&pool, storage.clone()).await;
    host.task.abort();
    let mut config = Config::default();
    config.resources.upload_buffer_mib = 8;
    config.resources.upload_part_mib = 8;
    let state = AppState::new(pool, config, storage, reqwest::Client::new()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    host.url = format!("http://{}", listener.local_addr().unwrap());
    host.task = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let mut client = byte_stream_client::ByteStreamClient::connect(host.url.clone())
        .await
        .unwrap();
    for size in [1, 9 * 1024 * 1024] {
        let first = WriteRequest {
            resource_name: format!(
                "alpha/private/uploads/no-progress/blobs/{}/{size}",
                digest(b"x").hash
            ),
            ..Default::default()
        };
        // Always-ready empty messages exercise the explicit clock check, not only
        // the timer branch of a timeout around the next message.
        let messages = stream::iter([first]).chain(stream::repeat(WriteRequest::default()));
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(35),
            client.write(authorized(messages, &host)),
        )
        .await
        .expect("empty messages must not keep a write alive")
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        let done = client
            .write(authorized(
                stream::iter([WriteRequest {
                    resource_name: format!(
                        "alpha/private/uploads/after-timeout/blobs/{}/1",
                        digest(&[size as u8]).hash
                    ),
                    data: vec![size as u8],
                    finish_write: true,
                    ..Default::default()
                }]),
                &host,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(done.committed_size, 1);
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn byte_progress_renews_write_deadline(pool: PgPool) {
    let host = host(&pool, common::s3_storage()).await;
    let mut client = byte_stream_client::ByteStreamClient::connect(host.url.clone())
        .await
        .unwrap();
    let name = format!(
        "alpha/private/uploads/progress/blobs/{}/2",
        digest(b"xy").hash
    );
    let messages = stream::unfold((0, name), |(step, name)| async move {
        if step == 3 {
            return None;
        }
        if step > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        }
        let message = WriteRequest {
            resource_name: if step == 0 {
                name.clone()
            } else {
                String::new()
            },
            write_offset: step.min(2),
            data: match step {
                0 => b"x".to_vec(),
                1 => b"y".to_vec(),
                _ => Vec::new(),
            },
            finish_write: step == 2,
        };
        Some((message, (step + 1, name)))
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(50),
        client.write(authorized(messages, &host)),
    )
    .await
    .unwrap()
    .unwrap()
    .into_inner();
    assert_eq!(result.committed_size, 2);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn action_tree_validation_deduplicates_and_bounds_total_bytes(pool: PgPool) {
    let host = host(&pool, common::s3_storage()).await;
    let channel = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut cas =
        content_addressable_storage_client::ContentAddressableStorageClient::new(channel.clone());
    let mut actions = action_cache_client::ActionCacheClient::new(channel);
    let mut trees = Vec::new();
    for index in 0..6 {
        // Each Tree is below the per-object 4 MiB limit, but six exceed 16 MiB.
        let tree = Tree {
            root: Some(Directory {
                symlinks: vec![SymlinkNode {
                    name: format!("link-{index}"),
                    target: "x".repeat(3 * 1024 * 1024),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let bytes = tree.encode_to_vec();
        trees.push(digest(&bytes));
        let response = cas
            .batch_update_blobs(authorized(
                BatchUpdateBlobsRequest {
                    instance_name: "alpha/private".into(),
                    requests: vec![batch_update_blobs_request::Request {
                        digest: Some(digest(&bytes)),
                        data: bytes,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                &host,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.responses[0].status.as_ref().unwrap().code, 0);
    }
    let result = |digests: Vec<Digest>| ActionResult {
        output_directories: digests
            .into_iter()
            .enumerate()
            .map(|(index, digest)| OutputDirectory {
                path: format!("out-{index}"),
                tree_digest: Some(digest),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let repeated = result(vec![trees[0].clone(); 10]);
    actions
        .update_action_result(authorized(
            UpdateActionResultRequest {
                instance_name: "alpha/private".into(),
                action_digest: Some(digest(b"repeated tree")),
                action_result: Some(repeated.clone()),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap();
    let cached = actions
        .get_action_result(authorized(
            GetActionResultRequest {
                instance_name: "alpha/private".into(),
                action_digest: Some(digest(b"repeated tree")),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(cached, repeated);
    // The reported expansion: 1,000 output paths share 40,000 empty files.
    // This must validate the Tree once, not retain 40 million digests.
    let empty = digest(b"");
    let large_tree = Tree {
        root: Some(Directory {
            files: (0..40_000)
                .map(|index| FileNode {
                    name: format!("file-{index:05}"),
                    digest: Some(empty.clone()),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec();
    let tree_digest = digest(&large_tree);
    let http = reqwest::Client::new();
    let base = format!("{}/_api/v1/bazel/alpha/private", host.url);
    assert!(
        http.put(format!("{base}/cas/{}", tree_digest.hash))
            .bearer_auth(&host.token)
            .body(large_tree.clone())
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let expanded = result(vec![tree_digest; 1000]).encode_to_vec();
    let action = digest(b"large repeated tree");
    assert!(
        http.put(format!("{base}/ac/{}", action.hash))
            .bearer_auth(&host.token)
            .body(expanded.clone())
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let read = http
        .get(format!("{base}/ac/{}", action.hash))
        .bearer_auth(&host.token)
        .send()
        .await
        .unwrap();
    assert!(read.status().is_success());
    assert_eq!(read.bytes().await.unwrap().as_ref(), expanded);
    // Distinct Trees below the byte budget must still obey the node budget.
    let mut tree = Tree::decode(large_tree.as_slice()).unwrap();
    let mut node_trees = Vec::new();
    for index in 0..3 {
        tree.root.as_mut().unwrap().files[0].name = format!("a-{index}");
        let bytes = tree.encode_to_vec();
        let digest = digest(&bytes);
        assert!(
            http.put(format!("{base}/cas/{}", digest.hash))
                .bearer_auth(&host.token)
                .body(bytes)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        node_trees.push(digest);
    }
    assert!(node_trees.iter().map(|d| d.size_bytes).sum::<i64>() < 16 * 1024 * 1024);
    let response = http
        .put(format!("{base}/ac/{}", digest(b"too many nodes").hash))
        .bearer_auth(&host.token)
        .body(result(node_trees).encode_to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    let error = actions
        .update_action_result(authorized(
            UpdateActionResultRequest {
                instance_name: "alpha/private".into(),
                action_digest: Some(digest(b"distinct trees")),
                action_result: Some(result(trees)),
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn grpc_through_the_organization_host(pool: PgPool) {
    let token = seed(&pool).await;
    let host = serve(&pool, common::storage(), token, Hosting::Direct).await;
    // HTTP/2 sends no Host header here: the organization is named by `:authority`.
    let org = Channel::from_shared(host.url.clone())
        .unwrap()
        .origin("http://alpha.snowstead.com".parse().unwrap())
        .connect()
        .await
        .unwrap();
    let mut capabilities = capabilities_client::CapabilitiesClient::new(org.clone());
    let mut cas =
        content_addressable_storage_client::ContentAddressableStorageClient::new(org.clone());
    let mut bytestream = byte_stream_client::ByteStreamClient::new(org);
    assert!(
        capabilities
            .get_capabilities(authorized(
                GetCapabilitiesRequest {
                    instance_name: "private".into(),
                },
                &host,
            ))
            .await
            .is_ok()
    );
    // The shared-host shape is not accepted on the organization host.
    let shared_shape = capabilities
        .get_capabilities(authorized(
            GetCapabilitiesRequest {
                instance_name: "alpha/private".into(),
            },
            &host,
        ))
        .await
        .unwrap_err();
    assert_eq!(shared_shape.code(), tonic::Code::NotFound);

    let batched = b"organization batch";
    let batched_digest = digest(batched);
    let batch = BatchUpdateBlobsRequest {
        instance_name: "private".into(),
        requests: vec![batch_update_blobs_request::Request {
            digest: Some(batched_digest.clone()),
            data: batched.to_vec(),
            compressor: 0,
        }],
        ..Default::default()
    };
    let written = cas
        .batch_update_blobs(authorized(batch, &host))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(written.responses[0].status.as_ref().unwrap().code, 0);
    let missing = cas
        .find_missing_blobs(authorized(
            FindMissingBlobsRequest {
                instance_name: "private".into(),
                blob_digests: vec![batched_digest.clone()],
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(missing.missing_blob_digests.is_empty());

    let streamed = b"organization stream";
    let streamed_digest = digest(streamed);
    let upload = WriteRequest {
        resource_name: format!(
            "private/uploads/org-upload/blobs/{}/{}",
            streamed_digest.hash, streamed_digest.size_bytes
        ),
        write_offset: 0,
        finish_write: true,
        data: streamed.to_vec(),
    };
    bytestream
        .write(authorized(stream::iter([upload]), &host))
        .await
        .unwrap();
    let mut response = bytestream
        .read(authorized(
            ReadRequest {
                resource_name: format!(
                    "private/blobs/{}/{}",
                    streamed_digest.hash, streamed_digest.size_bytes
                ),
                read_offset: 0,
                read_limit: 0,
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    let mut bytes = Vec::new();
    while let Some(part) = response.message().await.unwrap() {
        bytes.extend(part.data);
    }
    assert_eq!(bytes, streamed);

    // A client without the organization Host reaches the shared-host shape only.
    let plain = Channel::from_shared(host.url.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut shared =
        content_addressable_storage_client::ContentAddressableStorageClient::new(plain);
    let missing = shared
        .find_missing_blobs(authorized(
            FindMissingBlobsRequest {
                instance_name: "alpha/private".into(),
                blob_digests: vec![batched_digest.clone()],
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(missing.missing_blob_digests.is_empty());
    assert_eq!(
        shared
            .find_missing_blobs(authorized(
                FindMissingBlobsRequest {
                    instance_name: "private".into(),
                    blob_digests: vec![batched_digest.clone()],
                    ..Default::default()
                },
                &host,
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );

    // A second organization with its own private cache named `private`. Alpha's
    // token must not reach it through the organization host `beta`.
    sqlx::raw_sql(
        "INSERT INTO orgs(id,slug,private_caches) VALUES ('beta-org','beta',true);
        INSERT INTO caches(name,org_id,is_public) VALUES ('private','beta-org',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'bazel' FROM caches WHERE org_id='beta-org';
        INSERT INTO bazel_caches(cache_id,generation,capacity) SELECT id,'generation-beta-' || id,33554432 FROM caches WHERE org_id='beta-org';",
    )
    .execute(&pool)
    .await
    .unwrap();
    let beta = Channel::from_shared(host.url.clone())
        .unwrap()
        .origin("http://beta.snowstead.com".parse().unwrap())
        .connect()
        .await
        .unwrap();
    let mut beta = content_addressable_storage_client::ContentAddressableStorageClient::new(beta);
    assert_eq!(
        beta.find_missing_blobs(authorized(
            FindMissingBlobsRequest {
                instance_name: "private".into(),
                blob_digests: vec![batched_digest.clone()],
                ..Default::default()
            },
            &host,
        ))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::PermissionDenied
    );
    let beta_write = BatchUpdateBlobsRequest {
        instance_name: "private".into(),
        requests: vec![batch_update_blobs_request::Request {
            digest: Some(batched_digest.clone()),
            data: batched.to_vec(),
            compressor: 0,
        }],
        ..Default::default()
    };
    assert_eq!(
        beta.batch_update_blobs(authorized(beta_write, &host))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}
