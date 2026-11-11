mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowstead_server::{AppState, config::Config, router};
use sqlx::PgPool;
use tower::ServiceExt;

fn token(org: &str, cache: &str) -> String {
    let claims = json!({"jti":format!("{org}-{cache}"),"sub":"cli","iss":"snowstead","aud":"snowstead","iat":1,"org":org,"caches":[cache],"perms":["push","pull"]});
    let input = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"test-jwt").unwrap();
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    headers: &[(&str, &str)],
    bytes: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "backend.local");
    if let Some(token) = credential {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    (
        status,
        headers,
        to_bytes(response.into_body(), 32 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}

async fn post(app: &Router, path: &str, credential: &str, body: Value) -> (StatusCode, Value) {
    let (status, _, bytes) = send(
        app,
        "POST",
        path,
        Some(credential),
        &[("content-type", "application/json")],
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))),
    )
}

// Independent encoder for a regular-file NAR, including the eight-byte framing.
fn nar(contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for word in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
        contents,
        b")",
    ] {
        out.extend_from_slice(&(word.len() as u64).to_le_bytes());
        out.extend_from_slice(word);
        out.resize(out.len() + ((8 - word.len() % 8) % 8), 0);
    }
    out
}

fn path_input(hash: &str, raw: &[u8], inline: bool) -> Value {
    json!({"storePath":format!("/nix/store/{hash}-fixture"),"storePathHash":hash,
        "narHash":format!("sha256-{}",STANDARD.encode(Sha256::digest(raw))),"narSize":raw.len(),
        "compression":"zstd","references":[],"inline":inline})
}

async fn create(app: &Router, cache: &str, credential: &str, input: Value) -> Value {
    let (status, result) = post(
        app,
        &format!("/_api/v1/caches/{cache}/upload-streams/batch"),
        credential,
        json!({"paths":[input]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    result["sessions"][0].clone()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn inline_private_publication_and_read_isolation(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO orgs(id,slug) VALUES ('org_a','alpha'),('org_b','beta');
        INSERT INTO caches(name,org_id,is_public) VALUES ('vault','org_a',false),('empty','org_a',false),('vault','org_b',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let config = Config {
        jwt_secret: "test-jwt".into(),
        signing_key_name: "fixture".into(),
        signing_private_key: STANDARD.encode([7u8; 32]),
        ..Default::default()
    };
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        config.clone(),
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let a = token("org_a", "*");
    let b = token("org_b", "*");
    let hash = "0".repeat(32);
    let raw = nar(b"private bytes, not a digest possession proof");
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let file_hash = hex::encode(Sha256::digest(&compressed));
    let session = create(&app, "vault", &a, path_input(&hash, &raw, true)).await;
    let id = session["sessionId"].as_str().unwrap();
    let inline = format!("/_api/v1/uploads/{id}/inline?fileHash={file_hash}");
    assert_eq!(
        send(
            &app,
            "POST",
            &inline,
            Some(&b),
            &[("content-length", &compressed.len().to_string())],
            compressed.clone()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, _, result) = send(
        &app,
        "POST",
        &inline,
        Some(&a),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&result).unwrap()["published"],
        true
    );
    // A new state uses only durable SQL rows and objects, not per-process grants.
    let app = router(
        AppState::new(
            pool.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let (_, _, replay) = send(
        &app,
        "POST",
        &inline,
        Some(&a),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&replay).unwrap()["published"],
        true
    );
    let path = format!("/alpha/vault/{hash}.narinfo");
    let (status, headers, _) = send(&app, "GET", &path, None, &[], vec![]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers[header::WWW_AUTHENTICATE],
        "Basic realm=\"snowstead\""
    );
    assert_eq!(
        send(&app, "GET", &path, Some(&b), &[], vec![]).await.0,
        StatusCode::FORBIDDEN
    );
    let basic = format!("Basic {}", STANDARD.encode(format!("user:{a}")));
    let (status, headers, body) = send(
        &app,
        "GET",
        &path,
        None,
        &[("authorization", &basic)],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-cache");
    let text = String::from_utf8(body.clone()).unwrap();
    assert!(text.contains(&format!("URL: nar/{file_hash}/zstd.nar\n")));
    assert!(text.contains("Sig: fixture:"));
    assert!(!headers.contains_key(header::LAST_MODIFIED));
    let (status, head, bytes) = send(&app, "HEAD", &path, Some(&a), &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());
    assert_eq!(head[header::CONTENT_LENGTH], body.len().to_string());
    let download = format!("/private/alpha/vault/nar/{file_hash}/zstd.nar");
    assert_eq!(
        send(&app, "HEAD", &download, Some(&a), &[], vec![]).await.0,
        StatusCode::OK
    );
    let (status, _, bytes) = send(&app, "GET", &download, Some(&a), &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, compressed);
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/alpha/empty/nar/{file_hash}/zstd.nar"),
            Some(&a),
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/nar/{file_hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let metered: i64 = sqlx::query_scalar("SELECT bytes FROM bandwidth_daily WHERE org_id='org_a'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(metered, compressed.len() as i64);
    pool_execute(
        &pool,
        "UPDATE caches SET is_public=true WHERE org_id='org_a' AND name='vault'",
    )
    .await;
    // SQL membership renders metadata under the current visibility policy.
    // Changing visibility alone must not expose bytes from the private bucket.
    assert_eq!(
        send(&app, "GET", &path, None, &[], vec![]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/alpha/vault/nar/{file_hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    state.finish_background().await;
}

async fn pool_execute(pool: &PgPool, sql: &'static str) {
    sqlx::raw_sql(sql).execute(pool).await.unwrap();
}

// Matches the incoming CLI's inline_frames: one header frame, then payload frames.
fn inline_frame(uploads: &Value, payloads: &[Vec<u8>]) -> Vec<u8> {
    let manifest = serde_json::to_vec(&json!({"uploads":uploads})).unwrap();
    let mut frame = (manifest.len() as u32).to_be_bytes().to_vec();
    frame.extend(manifest);
    for bytes in payloads {
        frame.extend(bytes);
    }
    frame
}

async fn send_inline_batch(app: &Router, frame: Vec<u8>) -> (StatusCode, Value) {
    let (status, _, bytes) = send(
        app,
        "POST",
        "/_api/v1/uploads/inline/batch",
        Some("legacy"),
        &[
            ("content-type", "application/octet-stream"),
            ("content-length", &frame.len().to_string()),
        ],
        frame,
    )
    .await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn inline_batch_cli_contract_validates_before_work_and_protects_capacity(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let config = Config {
        auth_token: "legacy".into(),
        ..Default::default()
    };
    let storage = if std::env::var_os("SNOWSTEAD_TEST_R2_ENDPOINT").is_some() {
        snowstead_server::storage::Storage::new(&Config::from_env()).unwrap()
    } else {
        common::storage()
    };
    let state = AppState::new(
        pool.clone(),
        config,
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let mut uploads = Vec::new();
    let mut payloads = Vec::new();
    for (hash, contents) in [
        ("2".repeat(32), b"batch first".as_slice()),
        ("3".repeat(32), b"longer batch second member".as_slice()),
    ] {
        let raw = nar(contents);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let session = create(&app, "main", "legacy", path_input(&hash, &raw, true)).await;
        uploads.push(json!({"sessionId":session["sessionId"],"fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len()}));
        payloads.push(compressed);
    }
    let uploads = json!(uploads);
    let frame = inline_frame(&uploads, &payloads);
    for (headers, expected) in [
        (vec![], StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            vec![("content-type", "application/octet-stream")],
            StatusCode::LENGTH_REQUIRED,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "0"),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "8404997"),
            ],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "5"),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![
                ("content-type", "application/octet-stream"),
                ("content-length", "9999"),
            ],
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            send(
                &app,
                "POST",
                "/_api/v1/uploads/inline/batch",
                Some("legacy"),
                &headers,
                frame.clone()
            )
            .await
            .0,
            expected
        );
    }
    // A bad later checksum must not seal or stage the valid first member.
    let mut bad_checksum = frame.clone();
    *bad_checksum.last_mut().unwrap() ^= 1;
    let mut duplicate = uploads.clone();
    duplicate[1]["sessionId"] = duplicate[0]["sessionId"].clone();
    let mut invalid_hash = uploads.clone();
    invalid_hash[1]["fileHash"] = json!("A".repeat(64));
    let mut oversized = uploads.clone();
    oversized[1]["fileSize"] = json!(1024 * 1024 + 1);
    let mut trailing = frame.clone();
    trailing.push(0);
    for invalid in [
        bad_checksum,
        inline_frame(&duplicate, &payloads),
        inline_frame(&invalid_hash, &payloads),
        inline_frame(&oversized, &payloads),
        inline_frame(&json!([]), &[]),
        inline_frame(&json!(vec![uploads[0].clone(); 9]), &[]),
        frame[..frame.len() - 1].to_vec(),
        trailing,
        vec![0, 0, 0, 0, 0],
        vec![0, 0, 64, 1, 0],
    ] {
        let (status, result) = send_inline_batch(&app, invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM upload_sessions WHERE status<>'streaming' OR file_size<>0",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0);
        for input in uploads.as_array().unwrap() {
            let prefix = format!("staging/{}", input["sessionId"].as_str().unwrap());
            assert!(
                storage
                    .list(true, &prefix, None, 1)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
    // Both inclusive wire bounds: eight 1 MiB payloads pass envelope validation
    // and produce ordered item-level missing-session results, not HTTP errors.
    let maximum_payloads = vec![vec![0; 1024 * 1024]; 8];
    let maximum = json!((0..8).map(|index| json!({"sessionId":format!("missing-{index}"),"fileHash":hex::encode(Sha256::digest(&maximum_payloads[index])),"fileSize":1024*1024})).collect::<Vec<_>>());
    let (status, result) = send_inline_batch(&app, inline_frame(&maximum, &maximum_payloads)).await;
    assert_eq!(status, StatusCode::OK);
    for (index, row) in result["results"].as_array().unwrap().iter().enumerate() {
        assert_eq!(row["sessionId"], maximum[index]["sessionId"]);
        assert_eq!(row["status"], 404);
    }
    let total: usize = payloads.iter().map(Vec::len).sum();
    for (limit, admitted) in [(total - 1, false), (total, true), (total, true)] {
        sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
            .bind(limit as i64)
            .execute(&pool)
            .await
            .unwrap();
        let (status, result) = send_inline_batch(&app, frame.clone()).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        for (index, row) in result["results"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["sessionId"], uploads[index]["sessionId"]);
            assert_eq!(row["published"], admitted, "{result}");
            if !admitted {
                assert_eq!(row["status"], 413, "{result}");
            }
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, if admitted { 2 } else { 0 });
    }
    let mixed = json!([{"sessionId":"missing","fileHash":uploads[0]["fileHash"],"fileSize":payloads[0].len()}, uploads[1]]);
    let (_, result) = send_inline_batch(&app, inline_frame(&mixed, &payloads)).await;
    assert_eq!(result["results"][0]["sessionId"], "missing");
    assert_eq!(result["results"][0]["status"], 404);
    assert_eq!(result["results"][1]["published"], true);
    // A real compressed NAR that expands beyond the declared size is an item
    // failure, never a publication, even though its compressed checksum matches.
    let expanded = nar(&vec![b'x'; 256 * 1024]);
    let compressed = zstd::stream::encode_all(expanded.as_slice(), 3).unwrap();
    let mut input = path_input(&"4".repeat(32), &expanded, true);
    input["narSize"] = json!(expanded.len() - 1);
    let session = create(&app, "main", "legacy", input).await;
    let rejected = json!([{"sessionId":session["sessionId"],"fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len()}]);
    let (status, result) = send_inline_batch(&app, inline_frame(&rejected, &[compressed])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["results"][0]["published"], false);
    assert_eq!(result["results"][0]["status"], 400, "{result}");
    assert_eq!(result["results"][0]["error"], "Invalid NAR");
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{}.narinfo", "4".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let audit: (String, i32, String) = sqlx::query_as(
        "SELECT action, status, detail::jsonb->>'endpoint' FROM audit_logs ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit, ("push".into(), 200, "inline-upload-batch".into()));
    state.finish_background().await;
}

async fn upload_inline(app: &Router, cache: &str, input: Value, compressed: &[u8]) -> Value {
    let session = create(app, cache, "legacy", input).await;
    let id = session["sessionId"].as_str().unwrap();
    let path = format!(
        "/_api/v1/uploads/{id}/inline?fileHash={}",
        hex::encode(Sha256::digest(compressed))
    );
    let (status, _, bytes) = send(
        app,
        "POST",
        &path,
        Some("legacy"),
        &[("content-length", &compressed.len().to_string())],
        compressed.to_vec(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn capacity_pins_and_corrupt_uploads_fail_without_exposure(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        Config {
            auth_token: "legacy".into(),
            ..Default::default()
        },
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let raw_pinned = nar(b"pinned oldest artifact");
    let raw_evict = nar(b"evictable artifact");
    let raw_new = nar(b"newly retained replacement with different compressed size");
    let pin = zstd::stream::encode_all(raw_pinned.as_slice(), 3).unwrap();
    let evict = zstd::stream::encode_all(raw_evict.as_slice(), 3).unwrap();
    let new = zstd::stream::encode_all(raw_new.as_slice(), 3).unwrap();
    let pinned_hash = "2".repeat(32);
    let evict_hash = "3".repeat(32);
    let new_hash = "4".repeat(32);
    assert_eq!(
        upload_inline(
            &app,
            "main",
            path_input(&pinned_hash, &raw_pinned, true),
            &pin
        )
        .await["published"],
        true
    );
    assert_eq!(
        upload_inline(
            &app,
            "main",
            path_input(&evict_hash, &raw_evict, true),
            &evict
        )
        .await["published"],
        true
    );
    pool_execute(&pool,"UPDATE published_paths SET last_pushed_at='2000-01-01',last_accessed_at=NULL;
        INSERT INTO pins(id,cache_id,name,keep_kind,current_revision) SELECT 'pin',id,'keep','forever',1 FROM caches;
        INSERT INTO pin_revisions(id,pin_id,revision,store_path) VALUES ('rev','pin',1,'/nix/store/pinned');").await;
    sqlx::query("INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) SELECT 'rev',id,$1 FROM caches").bind(&pinned_hash).execute(&pool).await.unwrap();
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind((pin.len() + new.len()) as i64)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        upload_inline(&app, "main", path_input(&new_hash, &raw_new, true), &new).await["published"],
        true
    );
    let kept: Vec<String> =
        sqlx::query_scalar("SELECT store_path_hash FROM published_paths ORDER BY store_path_hash")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(kept, [pinned_hash.clone(), new_hash.clone()]);
    assert_eq!(
        storage
            .head(false, &format!("main/{evict_hash}.narinfo"))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    for hash in [&pinned_hash, &new_hash] {
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/main/{hash}.narinfo"),
                None,
                &[],
                vec![]
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    // Capacity withdraws SQL membership, not the committed immutable NAR.
    let evicted_key: String =
        sqlx::query_scalar("SELECT public_key FROM blob_objects WHERE file_hash=$1")
            .bind(hex::encode(Sha256::digest(&evict)))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(storage.head(false, &evicted_key).await.is_ok());
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{evict_hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let reason: String =
        sqlx::query_scalar("SELECT reason FROM eviction_logs WHERE key LIKE '%fixture'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason, "capacity");
    sqlx::query("INSERT INTO pin_paths(revision_id,cache_id,store_path_hash) SELECT 'rev',id,$1 FROM caches").bind(&new_hash).execute(&pool).await.unwrap();
    let denied = upload_inline(
        &app,
        "main",
        path_input(&"5".repeat(32), &raw_new, true),
        &new,
    )
    .await;
    assert_eq!(denied["published"], false);
    assert_eq!(denied["status"], 413);
    let mut corrupt = path_input(&"6".repeat(32), &raw_new, true);
    corrupt["narHash"] = json!(format!("sha256:{}", "0".repeat(64)));
    let denied = upload_inline(&app, "main", corrupt, &new).await;
    assert_eq!(denied["published"], false);
    assert_eq!(denied["status"], 400);
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{}.narinfo", "6".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // Neither a digest nor already-stored bytes substitutes for proof of possession.
    let fake = create(
        &app,
        "main",
        "legacy",
        path_input(&"7".repeat(32), &raw_new, false),
    )
    .await;
    let (status,result)=post(&app,"/_api/v1/uploads/finalize","legacy",json!({"uploads":[{"sessionId":fake["sessionId"],"narHash":path_input("",&raw_new,false)["narHash"],"narSize":raw_new.len(),"fileHash":hex::encode(Sha256::digest(&new)),"fileSize":new.len(),"parts":[{"partNumber":1,"etag":hex::encode(Sha256::digest(&new))}]}]})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["results"][0]["published"], false);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    // Abort is idempotent, but expiry is checked at request time even without GC.
    let id = fake["sessionId"].as_str().unwrap();
    for _ in 0..2 {
        assert_eq!(
            post(
                &app,
                &format!("/_api/v1/uploads/{id}/abort"),
                "legacy",
                json!({})
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    sqlx::query("UPDATE upload_sessions SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{id}/abort"),
            "legacy",
            json!({})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn multipart_survives_restart_and_preserves_immutable_receipts(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let config = Config {
        auth_token: "legacy".into(),
        admin_secret: "admin".into(),
        public_url: "https://cache.example.test".into(),
        ..Default::default()
    };
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        config.clone(),
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let mut seed = 0x12345678u32;
    let contents: Vec<u8> = (0..9 * 1024 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let raw = nar(&contents);
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let hash = "1".repeat(32);
    let input = path_input(&hash, &raw, false);
    let session = create(&app, "main", "legacy", input.clone()).await;
    let id = session["sessionId"].as_str().unwrap();
    let size = session["partSize"].as_u64().unwrap() as usize;
    assert!(compressed.len() > size);
    let reservations: Vec<_> = compressed
        .chunks(size)
        .enumerate()
        .map(|(i, bytes)| json!({"partNumber":i+1,"size":bytes.len()}))
        .collect();
    let (status, grants) = post(
        &app,
        "/_api/v1/uploads/parts",
        "legacy",
        json!({"uploads":[{"sessionId":id,"parts":reservations}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let grants = grants["results"][0]["parts"].as_array().unwrap();
    assert_eq!(grants.len(), 2);
    let mut receipts = Vec::new();
    for (i, (grant, bytes)) in grants.iter().zip(compressed.chunks(size)).enumerate() {
        let url = reqwest::Url::parse(grant["url"].as_str().unwrap()).unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://cache.example.test"
        );
        assert_eq!(grant["headers"]["authorization"], "Bearer legacy");
        let (status, headers, result) = send(
            &app,
            "PUT",
            url.path(),
            Some("legacy"),
            &[("content-length", &bytes.len().to_string())],
            bytes.to_vec(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&result)
        );
        let result: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(
            headers[header::ETAG],
            format!("\"{}\"", result["etag"].as_str().unwrap())
        );
        receipts.push(json!({"partNumber":i+1,"etag":result["etag"]}));
        let mut changed = bytes.to_vec();
        changed[0] ^= 1;
        assert_eq!(
            send(
                &app,
                "PUT",
                url.path(),
                Some("legacy"),
                &[("content-length", &bytes.len().to_string())],
                changed
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{id}/parts"),
            "legacy",
            json!({"parts":[{"partNumber":1,"size":size-1}]})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let receipt = json!({"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),"fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len(),"parts":receipts});
    let app = router(AppState::new(pool.clone(), config, storage, reqwest::Client::new()).unwrap());
    let envelope = json!({"uploads":[receipt.clone()]});
    // A failed ownership insert must not poison the connection or lose parts.
    // The same immutable receipt must still finalize after the fault clears.
    pool_execute(&pool, "CREATE FUNCTION fail_candidate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected candidate allocation failure'; END $$;
        CREATE TRIGGER fail_candidate BEFORE INSERT ON nar_installations FOR EACH ROW EXECUTE FUNCTION fail_candidate();").await;
    let (_, failed) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        envelope.clone(),
    )
    .await;
    assert_eq!(failed["results"][0]["published"], false, "{failed}");
    assert_eq!(failed["results"][0]["status"], 500, "{failed}");
    pool_execute(
        &pool,
        "DROP TRIGGER fail_candidate ON nar_installations; DROP FUNCTION fail_candidate();",
    )
    .await;
    let (first, second) = tokio::join!(
        post(
            &app,
            "/_api/v1/uploads/finalize",
            "legacy",
            envelope.clone()
        ),
        post(&app, "/_api/v1/uploads/finalize", "legacy", envelope),
    );
    assert!(
        first.1["results"][0]["published"] == true || second.1["results"][0]["published"] == true
    );
    for (status, result) in [first, second] {
        assert_eq!(status, StatusCode::OK);
        let result = &result["results"][0];
        // A stale snapshot may ask the existing CLI to retry, never overwrite
        // a competing publication or produce an integrity error.
        assert!(
            result["published"] == true || result["status"] == 503,
            "{result}"
        );
    }
    for _ in 0..2 {
        let (status, result) = post(
            &app,
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":[receipt.clone()]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["results"][0]["published"], true, "{result}");
    }
    assert_eq!(
        post(
            &app,
            &format!("/_api/v1/uploads/{id}/abort"),
            "legacy",
            json!({})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, _, bytes) = send(
        &app,
        "GET",
        &format!("/main/{hash}.narinfo"),
        None,
        &[],
        vec![],
    )
    .await;
    let text = String::from_utf8(bytes).unwrap();
    let url = text
        .lines()
        .find_map(|line| line.strip_prefix("URL: "))
        .unwrap();
    assert!(url.starts_with("nar/"));
    let download = reqwest::Url::parse("http://backend.local/main/")
        .unwrap()
        .join(url)
        .unwrap();
    let (status, _, downloaded) = send(&app, "GET", download.path(), None, &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(downloaded, compressed);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let (_, completed) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipt.clone()]}),
    )
    .await;
    let (status, _) = post(
        &app,
        "/_api/v1/orgs/default/caches/main/paths/delete",
        "admin",
        json!({"storePathHashes":[hash]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // A completed result survives withdrawal and a later quota change. It
    // reports the original outcome, not a new publication or capacity charge.
    pool_execute(&pool, "UPDATE orgs SET storage_limit=0 WHERE id='default'").await;
    let (status, replay) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipt.clone()]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, completed);
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let mut changed = receipt;
    changed["fileHash"] = json!("f".repeat(64));
    let (_, rejected) = post(
        &app,
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[changed]}),
    )
    .await;
    assert_eq!(rejected["results"][0]["status"], 409);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn final_nar_digest_failure_cannot_complete_a_multipart_destination(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let mut config = Config::from_env();
    config.auth_token = "legacy".into();
    let storage = snowstead_server::storage::Storage::new(&config).unwrap();
    let state = AppState::new(
        pool.clone(),
        config,
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let mut seed = 0x76543210u32;
    let contents: Vec<u8> = (0..9 * 1024 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let raw = nar(&contents);
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    assert!(compressed.len() > 8 * 1024 * 1024);
    let hash = "d".repeat(32);
    let mut input = path_input(&hash, &raw, false);
    // A syntactically valid stream with matching compressed hash and sizes,
    // but the wrong final NAR digest. Failure occurs after the entire stream.
    input["narHash"] = json!(format!("sha256-{}", STANDARD.encode([0u8; 32])));
    let session = create(&app, "main", "legacy", input.clone()).await;
    let id = session["sessionId"].as_str().unwrap();
    let part_size = session["partSize"].as_u64().unwrap() as usize;
    let reservations: Vec<_> = compressed
        .chunks(part_size)
        .enumerate()
        .map(|(i, bytes)| json!({"partNumber":i+1,"size":bytes.len()}))
        .collect();
    let (status, reserved) = post(
        &app,
        &format!("/_api/v1/uploads/{id}/parts"),
        "legacy",
        json!({"parts":reservations}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reserved}");
    let mut receipts = Vec::new();
    for (i, bytes) in compressed.chunks(part_size).enumerate() {
        let (status, _, body) = send(
            &app,
            "PUT",
            &format!("/_api/v1/uploads/{id}/part/{}", i + 1),
            Some("legacy"),
            &[("content-length", &bytes.len().to_string())],
            bytes.to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let uploaded: Value = serde_json::from_slice(&body).unwrap();
        receipts.push(json!({"partNumber":i+1,"etag":uploaded["etag"]}));
    }
    let file_hash = hex::encode(Sha256::digest(&compressed));
    let (status, result) = tokio::time::timeout(std::time::Duration::from_secs(30), post(
        &app, "/_api/v1/uploads/finalize", "legacy",
        json!({"uploads":[{"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),"fileHash":file_hash,"fileSize":compressed.len(),"parts":receipts}]}),
    )).await.expect("failed verification must close both sides of the pipe");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["results"][0]["status"], 400, "{result}");
    assert_eq!(result["results"][0]["published"], false);
    state.finish_background().await;
    let key: String = sqlx::query_scalar("SELECT key FROM object_cleanup WHERE key LIKE $1")
        .bind(format!("nar/objects/%/{file_hash}/zstd.nar"))
        .fetch_one(&pool)
        .await
        .unwrap();
    // Retirement only queued deletion. No maintenance has run, so absence
    // proves the failed digest never completed the provider object.
    assert!(
        storage
            .head(false, &key)
            .await
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/main/{hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn batch_capacity_rejects_the_whole_incoming_set_and_retries_at_the_boundary(pool: PgPool) {
    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let app = router(
        AppState::new(
            pool.clone(),
            Config {
                auth_token: "legacy".into(),
                ..Default::default()
            },
            common::storage(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let mut receipts = Vec::new();
    let mut total = 0i64;
    for (hash, contents) in [
        ("8".repeat(32), b"first batch member".as_slice()),
        (
            "9".repeat(32),
            b"asymmetric second member with more bytes".as_slice(),
        ),
    ] {
        let raw = nar(contents);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let input = path_input(&hash, &raw, false);
        let session = create(&app, "main", "legacy", input.clone()).await;
        let id = session["sessionId"].as_str().unwrap();
        let (status, _) = post(
            &app,
            &format!("/_api/v1/uploads/{id}/parts"),
            "legacy",
            json!({"parts":[{"partNumber":1,"size":compressed.len()}]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, bytes) = send(
            &app,
            "PUT",
            &format!("/_api/v1/uploads/{id}/part/1"),
            Some("legacy"),
            &[("content-length", &compressed.len().to_string())],
            compressed.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        receipts.push(
            json!({"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),
            "fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len(),
            "parts":[{"partNumber":1,"etag":result["etag"]}]}),
        );
        total += compressed.len() as i64;
    }
    for (limit, admitted) in [(total - 1, false), (total, true)] {
        sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
            .bind(limit)
            .execute(&pool)
            .await
            .unwrap();
        let (status, result) = post(
            &app,
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":receipts}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for row in result["results"].as_array().unwrap() {
            assert_eq!(row["published"], admitted, "{result}");
            if !admitted {
                assert_eq!(row["status"], 413, "{result}");
            }
        }
        for hash in ["8".repeat(32), "9".repeat(32)] {
            assert_eq!(
                send(
                    &app,
                    "GET",
                    &format!("/main/{hash}.narinfo"),
                    None,
                    &[],
                    vec![]
                )
                .await
                .0,
                if admitted {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM published_paths")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, if admitted { 2 } else { 0 });
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn unresolved_canonical_writers_do_not_block_immutable_publication(pool: PgPool) {
    let storage = common::storage();
    let app = router(
        AppState::new(
            pool.clone(),
            Config {
                auth_token: "legacy".into(),
                jwt_secret: "test-jwt".into(),
                ..Default::default()
            },
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    for private in [false, true] {
        let name = if private { "secret" } else { "main" };
        let cache: i32 =
            sqlx::query_scalar("INSERT INTO caches(name,is_public) VALUES($1,$2) RETURNING id")
                .bind(name)
                .bind(!private)
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("INSERT INTO cache_protocols(cache_id,protocol) VALUES($1,'nix')")
            .bind(cache)
            .execute(&pool)
            .await
            .unwrap();
        for tombstone in [false, true] {
            let raw = nar(format!("canonical writer {private} {tombstone}").as_bytes());
            let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
            let hash = hex::encode(Sha256::digest(&compressed));
            let key = format!(
                "{}/{hash}/zstd.nar",
                if private { "nars/sha256" } else { "nar" }
            );
            storage
                .put(private, &key, b"old canonical bytes")
                .await
                .unwrap();
            if tombstone {
                sqlx::query("INSERT INTO nar_installations(key,operation_id,source_key,upload_id,file_hash,compression,is_private,file_size,phase) VALUES($1,'old',$1,'provider-upload',$2,'zstd',$3,$4,'legacy-unresolved')")
                    .bind(&key).bind(&hash).bind(private).bind(compressed.len() as i64).execute(&pool).await.unwrap();
            } else {
                sqlx::query("INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_hash,file_size,compression,status,r2_upload_key,r2_upload_id,expires_at) VALUES($1,$2,repeat('z',32),'/nix/store/old','sha256:test',1,$1,$3,'zstd','aborted',$4,'provider-upload',now()-interval '1 day')")
                    .bind(&hash).bind(cache).bind(compressed.len() as i64).bind(&key).execute(&pool).await.unwrap();
            }
            let store_hash = if tombstone { "a" } else { "b" }.repeat(32);
            let input = path_input(&store_hash, &raw, true);
            let published = upload_inline(&app, name, input.clone(), &compressed).await;
            assert_eq!(published["published"], true, "{published}");
            let mut bytes = Vec::new();
            use tokio::io::AsyncReadExt;
            storage
                .open(private, &key)
                .await
                .unwrap()
                .reader
                .read_to_end(&mut bytes)
                .await
                .unwrap();
            assert_eq!(bytes, b"old canonical bytes");
            assert_eq!(
                send(
                    &app,
                    "GET",
                    &format!("/{name}/{store_hash}.narinfo"),
                    Some(&token("default", name)),
                    &[],
                    vec![]
                )
                .await
                .0,
                StatusCode::OK
            );
            // Immutable publication must not reconcile or retire legacy ownership.
            let retained: i64 = if tombstone {
                sqlx::query_scalar("SELECT count(*) FROM nar_installations WHERE key=$1 AND operation_id='old' AND phase='legacy-unresolved'")
                .bind(&key)
                .fetch_one(&pool).await.unwrap()
            } else {
                sqlx::query_scalar("SELECT count(*) FROM upload_sessions WHERE id=$1 AND status='aborted' AND r2_upload_id='provider-upload'")
                .bind(&hash)
                .fetch_one(&pool).await.unwrap()
            };
            assert_eq!(retained, 1);
            let committed: String = sqlx::query_scalar(if private {
                "SELECT private_key FROM blob_objects WHERE file_hash=$1"
            } else {
                "SELECT public_key FROM blob_objects WHERE file_hash=$1"
            })
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_ne!(committed, key);
            assert!(committed.starts_with(if private {
                "nars/objects/"
            } else {
                "nar/objects/"
            }));
        }
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn batch_shared_bytes_preserve_public_and_private_delivery_after_queued_cleanup(
    pool: PgPool,
) {
    pool_execute(
        &pool,
        "INSERT INTO caches(name,is_public) VALUES('main',true),('secret',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        Config {
            auth_token: "legacy".into(),
            admin_secret: "admin".into(),
            jwt_secret: "test-jwt".into(),
            ..Default::default()
        },
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    let raw = nar(b"shared bytes in two independently authorized buckets");
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let hash = hex::encode(Sha256::digest(&compressed));
    let mut uploads = Vec::new();
    for (index, cache) in ["main", "secret", "main", "secret"].iter().enumerate() {
        let session = create(
            &app,
            cache,
            "legacy",
            path_input(&index.to_string().repeat(32), &raw, true),
        )
        .await;
        uploads.push(
            json!({"sessionId":session["sessionId"],"fileHash":hash,"fileSize":compressed.len()}),
        );
    }
    let (_, result) = send_inline_batch(
        &app,
        inline_frame(&json!(uploads), &vec![compressed.clone(); 4]),
    )
    .await;
    assert!(
        result["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["published"] == true),
        "{result}"
    );
    let (status, deleted) = post(
        &app,
        "/_api/v1/orgs/default/caches/main/paths/delete",
        "admin",
        json!({"storePathHashes":["0".repeat(32)]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    // Execute every queued deletion, including the unadopted group candidates.
    // Do not depend on the process-global maintenance scheduler in parallel tests.
    let retired: Vec<(bool, String)> = sqlx::query_as("SELECT is_private,key FROM object_cleanup")
        .fetch_all(&pool)
        .await
        .unwrap();
    for (private, key) in retired {
        storage.delete(private, &key).await.unwrap();
    }
    let credential = token("default", "*");
    for url in [
        format!("/nar/{hash}/zstd.nar"),
        format!("/private/secret/nar/{hash}/zstd.nar"),
    ] {
        let (status, _, bytes) = send(&app, "GET", &url, Some(&credential), &[], vec![]).await;
        assert_eq!(status, StatusCode::OK, "{url}");
        assert_eq!(bytes, compressed);
    }
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/private/secret/nar/{hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    state.finish_background().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn independent_publishers_recheck_quota_and_reuse_candidates_after_rollback(pool: PgPool) {
    use std::time::Duration;

    pool_execute(
        &pool,
        "INSERT INTO caches(name) VALUES('main'),('other');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;",
    )
    .await;
    let storage = common::storage();
    let mut apps = Vec::new();
    let mut pools = Vec::new();
    for _ in 0..2 {
        let independent = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        apps.push(router(
            AppState::new(
                independent.clone(),
                Config {
                    auth_token: "legacy".into(),
                    admin_secret: "admin".into(),
                    ..Default::default()
                },
                storage.clone(),
                reqwest::Client::new(),
            )
            .unwrap(),
        ));
        pools.push(independent);
    }
    let mut receipts = Vec::new();
    let mut files = Vec::new();
    for (index, contents) in [
        b"first independent publisher".as_slice(),
        b"second independent publisher with asymmetric content and size".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let raw = nar(contents);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let input = path_input(&if index == 0 { "a" } else { "b" }.repeat(32), &raw, false);
        let cache = if index == 0 { "main" } else { "other" };
        let session = create(&apps[index], cache, "legacy", input.clone()).await;
        let id = session["sessionId"].as_str().unwrap();
        let (status, result) = post(
            &apps[index],
            &format!("/_api/v1/uploads/{id}/parts"),
            "legacy",
            json!({"parts":[{"partNumber":1,"size":compressed.len()}]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        let (status, _, bytes) = send(
            &apps[index],
            "PUT",
            &format!("/_api/v1/uploads/{id}/part/1"),
            Some("legacy"),
            &[("content-length", &compressed.len().to_string())],
            compressed.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let part: Value = serde_json::from_slice(&bytes).unwrap();
        receipts.push(
            json!({"sessionId":id,"narHash":input["narHash"],"narSize":raw.len(),
            "fileHash":hex::encode(Sha256::digest(&compressed)),"fileSize":compressed.len(),
            "parts":[{"partNumber":1,"etag":part["etag"]}]}),
        );
        files.push(compressed);
    }
    let limit = files.iter().map(Vec::len).max().unwrap() as i64;
    let total = files.iter().map(|file| file.len() as i64).sum::<i64>();
    assert!(total > limit);
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(limit)
        .execute(&pool)
        .await
        .unwrap();

    // NAR fences reject publication, but permit both servers to finish storage
    // preparation. Each server has its own pool and local admission gates.
    let mut blocked = pool.begin().await.unwrap();
    for receipt in &receipts {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "nar:{}:zstd",
                receipt["fileHash"].as_str().unwrap()
            ))
            .execute(&mut *blocked)
            .await
            .unwrap();
    }
    for (app, receipt) in apps.iter().zip(&receipts) {
        let (status, result) = post(
            app,
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":[receipt]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["results"][0]["status"], 503, "{result}");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations WHERE phase='ready'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    // A repeated preparation would now fail: its original byte sources are gone.
    let sources: Vec<String> = sqlx::query_scalar("SELECT storage_key FROM upload_parts")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(sources.len(), 2);
    for key in sources {
        storage.delete(true, &key).await.unwrap();
        assert!(storage.head(true, &key).await.is_err());
    }
    blocked.rollback().await.unwrap();

    // Pause A after capacity admission, while it still owns the org fence.
    // Disable only this test trigger's lock timeout, so the barrier does not
    // depend on the host completing an assertion within the production timeout.
    pool_execute(
        &pool,
        "CREATE FUNCTION pause_publication() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.store_path_hash=repeat('a',32) THEN
            PERFORM set_config('lock_timeout','0',true);
            PERFORM pg_advisory_xact_lock(78431::bigint);
        END IF; RETURN NEW; END $$;
        CREATE TRIGGER pause_publication BEFORE INSERT ON published_paths
        FOR EACH ROW EXECUTE FUNCTION pause_publication();",
    )
    .await;
    let mut barrier = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(78431::bigint)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    let mut first = tokio::spawn({
        let app = apps[0].clone();
        let receipt = receipts[0].clone();
        async move {
            post(
                &app,
                "/_api/v1/uploads/finalize",
                "legacy",
                json!({"uploads":[receipt]}),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if first.is_finished() {
                panic!(
                    "publisher returned before the barrier: {:?}",
                    (&mut first).await.unwrap()
                );
            }
            if sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT FROM pg_locks
                WHERE locktype='advisory' AND classid=0 AND objid=78431 AND NOT granted)",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first publisher must reach the SQL barrier");
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["status"], 503, "{result}");
    barrier.rollback().await.unwrap();
    let (status, result) = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["published"], true, "{result}");

    // B needs to evict A. A later SQL error must roll back that eviction and
    // preserve B's ready candidate, not merely return a failed item result.
    pool_execute(
        &pool,
        "DROP TRIGGER pause_publication ON published_paths;
        CREATE FUNCTION fail_publication() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected publication failure'; END $$;
        CREATE TRIGGER fail_publication BEFORE INSERT ON published_paths
        FOR EACH ROW EXECUTE FUNCTION fail_publication();",
    )
    .await;
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["status"], 500, "{result}");
    assert_eq!(
        send(
            &apps[0],
            "GET",
            &format!("/main/{}.narinfo", "a".repeat(32)),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::OK
    );
    let retained: (i64, i64) =
        sqlx::query_as("SELECT sum(path_count)::bigint,sum(size)::bigint FROM caches")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, (1, files[0].len() as i64));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations WHERE phase='ready'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    pool_execute(&pool, "DROP TRIGGER fail_publication ON published_paths;").await;

    // Pinning A makes B inadmissible. Raising the limit to the exact combined
    // size then admits B, still without its deleted staging bytes.
    let (status, result) = post(&apps[0], "/_api/v1/orgs/default/caches/main/pins", "admin",
        json!({"name":"release","storePath":format!("/nix/store/{}-fixture", "a".repeat(32)),"keep":"forever"})).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["status"], 413, "{result}");
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(total)
        .execute(&pool)
        .await
        .unwrap();
    let (status, result) = post(
        &apps[1],
        "/_api/v1/uploads/finalize",
        "legacy",
        json!({"uploads":[receipts[1]]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["published"], true, "{result}");
    for (index, receipt) in receipts.iter().enumerate() {
        // Replay through the other instance must not charge or prepare again.
        let (status, result) = post(
            &apps[1 - index],
            "/_api/v1/uploads/finalize",
            "legacy",
            json!({"uploads":[receipt]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["results"][0]["published"], true, "{result}");
        let cache = if index == 0 { "main" } else { "other" };
        let hash = if index == 0 { "a" } else { "b" }.repeat(32);
        let (status, _, metadata) = send(
            &apps[index],
            "GET",
            &format!("/{cache}/{hash}.narinfo"),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8(metadata).unwrap().contains(&format!(
            "FileHash: sha256:{}",
            receipt["fileHash"].as_str().unwrap()
        )));
        let (status, _, bytes) = send(
            &apps[index],
            "GET",
            &format!("/nar/{}/zstd.nar", receipt["fileHash"].as_str().unwrap()),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, files[index]);
    }
    let retained: (i64, i64) =
        sqlx::query_as("SELECT sum(path_count)::bigint,sum(size)::bigint FROM caches")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, (2, total));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM nar_installations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    for independent in pools {
        independent.close().await;
    }
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn failed_publication_retains_candidate_until_session_expiry(pool: PgPool) {
    let storage = common::storage();
    let state = AppState::new(
        pool.clone(),
        Config {
            auth_token: "legacy".into(),
            ..Default::default()
        },
        storage.clone(),
        reqwest::Client::new(),
    )
    .unwrap();
    let app = router(state.clone());
    pool_execute(&pool, "INSERT INTO caches(name,is_public) VALUES('main',true),('secret',false);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;
        CREATE FUNCTION fail_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected publication failure'; END $$;
        CREATE TRIGGER fail_publication BEFORE INSERT ON published_paths FOR EACH ROW EXECUTE FUNCTION fail_publication();").await;
    let mut keys = Vec::new();
    for private in [false, true] {
        let raw = nar(format!("failed canonical publication {private}").as_bytes());
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let hash = hex::encode(Sha256::digest(&compressed));
        let result = upload_inline(
            &app,
            if private { "secret" } else { "main" },
            path_input(&"c".repeat(32), &raw, true),
            &compressed,
        )
        .await;
        assert_eq!(result["published"], false, "{result}");
        assert_eq!(result["status"], 500, "{result}");
        let key: String = sqlx::query_scalar(
            "SELECT key FROM nar_installations WHERE is_private=$1 AND key LIKE $2 AND phase='ready'",
        )
        .bind(private)
        .bind(format!("%/{hash}/zstd.nar"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(key.starts_with(if private {
            "nars/objects/"
        } else {
            "nar/objects/"
        }));
        assert!(storage.head(private, &key).await.is_ok());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM blob_objects WHERE file_hash=$1")
                .bind(&hash)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        // SQL failure keeps confirmed bytes reusable until session expiry.
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM nar_installations WHERE file_hash=$1"
            )
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM object_cleanup WHERE key=$1")
                .bind(&key)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        keys.push((private, key));
    }
    pool_execute(
        &pool,
        "DROP TRIGGER fail_publication ON published_paths;
        UPDATE upload_sessions SET expires_at=now()-interval '1 day';",
    )
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(snowstead_server::serve(listener, state, async {
        let _ = stopped.await;
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if sqlx::query_scalar::<_, i64>(
                "SELECT (SELECT count(*) FROM object_cleanup) + (SELECT count(*) FROM nar_installations)",
            )
                .fetch_one(&pool)
                .await
                .unwrap()
                == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for (private, key) in keys {
        assert_eq!(
            storage.head(private, &key).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn uncertain_immutable_completion_does_not_poison_retries_across_restart(pool: PgPool) {
    use axum::{extract::Request as AxumRequest, response::IntoResponse, routing::any};
    use snowstead_server::storage::Storage;
    let r2 = Config::from_env();
    let upstream = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
    assert_eq!(r2.r2_endpoint, upstream);
    assert!(upstream.starts_with("http://127.0.0.1:"));
    let config = Config {
        auth_token: "legacy".into(),
        ..Default::default()
    };
    let storage = Storage::new(&r2).unwrap();
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let proxy_app = Router::new().fallback(any(move |request: AxumRequest| {
        let upstream = upstream.clone();
        async move {
            let (parts, body) = request.into_parts();
            let canonical = parts.uri.path().contains("/nar/objects/");
            let completion = (parts.method == "PUT" && parts.uri.query().is_none())
                || (parts.method == "POST"
                    && parts.uri.query().is_some_and(|q| q.contains("uploadId=")));
            let response = reqwest::Client::new()
                .request(parts.method, format!("{upstream}{}", parts.uri))
                .headers(parts.headers)
                .body(to_bytes(body, 32 * 1024 * 1024).await.unwrap())
                .send()
                .await
                .unwrap();
            // The provider completes the write, but the caller receives an
            // error instead of confirmation. Abort cannot prove it never ran.
            if canonical && completion && response.status().is_success() {
                return (
                    StatusCode::FORBIDDEN,
                    "<Error><Code>AccessDenied</Code></Error>",
                )
                    .into_response();
            }
            let status = response.status();
            let headers = response.headers().clone();
            (status, headers, response.bytes().await.unwrap()).into_response()
        }
    }));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async {
        axum::serve(proxy, proxy_app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let mut interrupted = r2;
    interrupted.r2_endpoint = proxy_url;
    pool_execute(&pool,"INSERT INTO caches(name,is_public) VALUES('main',true); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    let app = router(
        AppState::new(
            pool.clone(),
            config.clone(),
            Storage::new(&interrupted).unwrap(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let raw = nar(b"ambiguous completion must remain protected");
    let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
    let healthy = router(
        AppState::new(
            pool.clone(),
            config.clone(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let retained_raw = nar(b"keep this published path if the next storage copy fails");
    let retained = zstd::stream::encode_all(retained_raw.as_slice(), 3).unwrap();
    let retained_hash = "a".repeat(32);
    assert_eq!(
        upload_inline(
            &healthy,
            "main",
            path_input(&retained_hash, &retained_raw, true),
            &retained
        )
        .await["published"],
        true
    );
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind(compressed.len() as i64)
        .execute(&pool)
        .await
        .unwrap();
    let hash = hex::encode(Sha256::digest(&compressed));
    let input = path_input(&"d".repeat(32), &raw, true);
    let failed = upload_inline(&app, "main", input.clone(), &compressed).await;
    assert_eq!(failed["published"], false, "{failed}");
    assert_eq!(failed["status"], 500, "{failed}");
    // Preparing bytes admits no retained capacity. Even an ambiguous provider
    // completion cannot withdraw an existing path before SQL publication.
    assert_eq!(
        send(
            &healthy,
            "GET",
            &format!("/main/{retained_hash}.narinfo"),
            None,
            &[],
            vec![]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM eviction_logs")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let uncertain: String = sqlx::query_scalar("SELECT key FROM object_cleanup WHERE key LIKE $1")
        .bind(format!("nar/objects/%/{hash}/zstd.nar"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(storage.head(false, &uncertain).await.is_ok());
    let source: Option<String> = sqlx::query_scalar(
        "SELECT storage_key FROM upload_parts WHERE session_id=$1 AND part_number=1",
    )
    .bind(failed["sessionId"].as_str().unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        source.is_none(),
        "inline bytes must not create a staged source"
    );
    assert!(
        storage
            .list(
                true,
                &format!("staging/{}", failed["sessionId"].as_str().unwrap()),
                None,
                1
            )
            .await
            .unwrap()
            .is_empty()
    );
    let restarted = router(
        AppState::new(
            pool.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    // Replay the same sealed session after recreating application state.
    let (status, _, retry) = send(
        &restarted,
        "POST",
        &format!(
            "/_api/v1/uploads/{}/inline?fileHash={hash}",
            failed["sessionId"].as_str().unwrap()
        ),
        Some("legacy"),
        &[("content-length", &compressed.len().to_string())],
        compressed.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let retry: Value = serde_json::from_slice(&retry).unwrap();
    assert_eq!(retry["published"], true, "{retry}");
    let committed: String =
        sqlx::query_scalar("SELECT public_key FROM blob_objects WHERE file_hash=$1")
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(committed, uncertain);
    assert!(storage.head(false, &uncertain).await.is_ok());
    assert_eq!(
        send(
            &restarted,
            "GET",
            &format!("/nar/{hash}/zstd.nar"),
            None,
            &[],
            vec![]
        )
        .await
        .2,
        compressed
    );
    stop.send(()).unwrap();
    proxy_task.await.unwrap();
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn ordered_batch_preparation_with_duplicate_paths_and_partial_failures_pool_one(
    pool: PgPool,
) {
    use axum::{extract::Request as AxumRequest, response::IntoResponse, routing::any};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    pool_execute(&pool,"INSERT INTO caches(name) VALUES ('inline'),('multipart'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches; UPDATE orgs SET storage_limit=1073741824 WHERE id='default';").await;
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    for inline in [true, false] {
        let upstream = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
        assert!(upstream.starts_with("http://127.0.0.1:"));
        let ids = Arc::new(Mutex::new((String::new(), String::new())));
        let overtaken = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let fast = Arc::new(tokio::sync::Notify::new());
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let delayed = Arc::new(AtomicBool::new(false));
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::from_env();
        config.r2_endpoint = format!("http://{}", proxy.local_addr().unwrap());
        let proxy_app = Router::new().fallback(any({
            let ids = ids.clone();
            let overtaken = overtaken.clone();
            let reads = reads.clone();
            let writes = writes.clone();
            let reached = reached.clone();
            let release = release.clone();
            move |request: AxumRequest| {
                let upstream = upstream.clone();
                let ids = ids.clone();
                let overtaken = overtaken.clone();
                let reads = reads.clone();
                let writes = writes.clone();
                let fast = fast.clone();
                let reached = reached.clone();
                let release = release.clone();
                let delayed = delayed.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let (slow_id, fast_id) = ids.lock().unwrap().clone();
                    if parts.method == "PUT" && parts.uri.path().contains("/objects/") {
                        writes.fetch_add(1, Ordering::SeqCst);
                    }
                    if parts.method == "GET" && !slow_id.is_empty() {
                        reads.fetch_add(1, Ordering::SeqCst);
                        if parts.uri.path().contains(&fast_id) {
                            fast.notify_one();
                        }
                        if parts.uri.path().contains(&slow_id)
                            && !delayed.swap(true, Ordering::SeqCst)
                        {
                            reached.notify_one();
                            // No DB connection may be held here: another preparation
                            // must reach storage even though the pool has one slot.
                            let concurrent =
                                tokio::time::timeout(Duration::from_secs(5), fast.notified())
                                    .await
                                    .is_ok();
                            overtaken.store(concurrent, Ordering::SeqCst);
                            release.notified().await;
                        }
                    }
                    let response = reqwest::Client::new()
                        .request(parts.method, format!("{upstream}{}", parts.uri))
                        .headers(parts.headers)
                        .body(to_bytes(body, 32 * 1024 * 1024).await.unwrap())
                        .send()
                        .await
                        .unwrap();
                    (
                        response.status(),
                        response.headers().clone(),
                        response.bytes().await.unwrap(),
                    )
                        .into_response()
                }
            }
        }));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let proxy_task = tokio::spawn(async {
            axum::serve(proxy, proxy_app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let storage = snowstead_server::storage::Storage::new(&config).unwrap();
        config.auth_token = "legacy".into();
        config.admin_secret = "admin".into();
        let state = AppState::new(single.clone(), config, storage, reqwest::Client::new()).unwrap();
        let app = router(state.clone());
        let cache = if inline { "inline" } else { "multipart" };
        let mut inputs = Vec::new();
        let mut payloads = Vec::new();
        // The first two sessions target the same path with different metadata.
        // A third path shares the winner's bytes: blob and path deduplication
        // must remain independent, including within one SQL statement.
        for index in 0..8 {
            let contents = if index == 2 {
                if inline { 0 } else { 1 }
            } else {
                index
            };
            let raw = nar(format!("{cache} different content {contents}").as_bytes());
            let mut input = path_input(
                &format!("{:032}", if index == 1 { 0 } else { index }),
                &raw,
                inline,
            );
            input["references"] = json!([format!("{}-reference-{index}", "f".repeat(32))]);
            input["deriver"] = json!(format!("derivation-{index}.drv"));
            payloads.push(zstd::stream::encode_all(raw.as_slice(), 3).unwrap());
            inputs.push(input);
        }
        let (status, created) = post(
            &app,
            &format!("/_api/v1/caches/{cache}/upload-streams/batch"),
            "legacy",
            json!({"paths":inputs}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let sessions = created["sessions"].as_array().unwrap();
        let mut uploads = Vec::new();
        for (index, (session, bytes)) in sessions.iter().zip(&payloads).enumerate() {
            let id = session["sessionId"].as_str().unwrap();
            let mut item = json!({"sessionId":id,"fileHash":hex::encode(Sha256::digest(bytes)),"fileSize":bytes.len()});
            if !inline {
                let (status, reserved) = post(
                    &app,
                    &format!("/_api/v1/uploads/{id}/parts"),
                    "legacy",
                    json!({"parts":[{"partNumber":1,"size":bytes.len()}]}),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{reserved}");
                let (status, _, uploaded) = send(
                    &app,
                    "PUT",
                    &format!("/_api/v1/uploads/{id}/part/1"),
                    Some("legacy"),
                    &[("content-length", &bytes.len().to_string())],
                    bytes.clone(),
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                let uploaded: Value = serde_json::from_slice(&uploaded).unwrap();
                item["narHash"] = inputs[index]["narHash"].clone();
                item["narSize"] = inputs[index]["narSize"].clone();
                item["parts"] = json!([{"partNumber":1,"etag":uploaded["etag"]}]);
            }
            uploads.push(item);
        }
        // Eight actual preparations, plus an independent missing-session item
        // for finalize. Inline has an eight-item wire cap, so corrupt metadata
        // in the last real session instead (checksum/envelope remain valid).
        if inline {
            sqlx::query("UPDATE upload_sessions SET nar_size=nar_size-1 WHERE id=$1")
                .bind(sessions[7]["sessionId"].as_str().unwrap())
                .execute(&pool)
                .await
                .unwrap();
        } else {
            // Reverse the duplicate sessions relative to creation order too.
            uploads.swap(0, 1);
            let mut missing = uploads[7].clone();
            missing["sessionId"] = json!("missing");
            uploads.insert(3, missing);
            // A SQL failure in one member must roll back the group, then let
            // independent members publish in input order without new byte I/O.
            pool_execute(&pool, "CREATE FUNCTION reject_batch_member() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                IF NEW.store_path_hash=repeat('0',31)||'6' THEN RAISE EXCEPTION 'injected member failure'; END IF;
                RETURN NEW; END $$;
                CREATE TRIGGER reject_batch_member BEFORE INSERT ON published_paths FOR EACH ROW EXECUTE FUNCTION reject_batch_member();").await;
        }
        *ids.lock().unwrap() = (
            uploads[0]["sessionId"].as_str().unwrap().to_owned(),
            uploads[1]["sessionId"].as_str().unwrap().to_owned(),
        );
        let (status, result) = tokio::time::timeout(Duration::from_secs(30), async {
            if inline {
                send_inline_batch(&app, inline_frame(&json!(uploads), &payloads)).await
            } else {
                let pending = tokio::spawn({
                    let app = app.clone();
                    let uploads = uploads.clone();
                    async move {
                        post(
                            &app,
                            "/_api/v1/uploads/finalize",
                            "legacy",
                            json!({"uploads":uploads}),
                        )
                        .await
                    }
                });
                tokio::time::timeout(Duration::from_secs(10), reached.notified())
                    .await
                    .unwrap();
                // Simulate expiration of execution leases while the ordered
                // buffer is held by its first member. Queued work has not
                // started and must not lose a lease before it runs.
                let queued: Vec<_> = uploads[5..].iter()
                    .map(|item| item["sessionId"].as_str().unwrap()).collect();
                sqlx::query("UPDATE nar_installations SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE session_id=ANY($1)")
                    .bind(&queued).execute(&pool).await.unwrap();
                // Disconnect with some batch members not yet streamed. The
                // owned batch must finish every reservation, not strand them.
                pending.abort();
                assert!(pending.await.unwrap_err().is_cancelled());
                release.notify_one();
                state.finish_background().await;
                post(
                    &app,
                    "/_api/v1/uploads/finalize",
                    "legacy",
                    json!({"uploads":uploads}),
                )
                .await
            }
        })
        .await
        .expect("batch must not deadlock with pool one");
        assert_eq!(status, StatusCode::OK, "{result}");
        if inline {
            assert_eq!(
                reads.load(Ordering::SeqCst),
                0,
                "inline preparation must not read storage"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                7,
                "each valid inline input gets one PUT; invalid NARs get none"
            );
        } else {
            assert!(
                overtaken.load(Ordering::SeqCst),
                "later preparation must overtake blocked first source read"
            );
            assert_eq!(
                reads.load(Ordering::SeqCst),
                8,
                "each sealed part is read once"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                8,
                "each input gets one final PUT"
            );
        }
        for (index, row) in result["results"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["sessionId"], uploads[index]["sessionId"]);
            if inline && index == 7 {
                assert_eq!(row["status"], 400, "{result}");
            } else if !inline && index == 3 {
                assert_eq!(row["status"], 404, "{result}");
            } else if !inline && index == 7 {
                assert_eq!(row["status"], 500, "{result}");
                assert_eq!(row["published"], false, "{result}");
            } else {
                assert_eq!(row["published"], true, "{result}");
            }
        }
        assert_eq!(result["results"][1]["alreadyExisted"], true);
        assert!(result["results"][0].get("alreadyExisted").is_none());
        let (stored_hash, references, deriver): (String, String, Option<String>) = sqlx::query_as("SELECT b.file_hash,p.references_json,p.deriver FROM published_paths p JOIN caches c ON c.id=p.cache_id JOIN blob_objects b ON b.id=p.blob_object_id WHERE c.name=$1 AND p.store_path_hash=$2")
            .bind(cache).bind("0".repeat(32)).fetch_one(&pool).await.unwrap();
        let winner = if inline { 0 } else { 1 };
        assert_eq!(stored_hash, hex::encode(Sha256::digest(&payloads[winner])));
        assert_eq!(
            serde_json::from_str::<Value>(&references).unwrap(),
            inputs[winner]["references"]
        );
        assert_eq!(deriver.as_deref(), inputs[winner]["deriver"].as_str());
        let (status, _, rendered) = send(
            &app,
            "GET",
            &format!("/{cache}/{}.narinfo", "0".repeat(32)),
            Some("legacy"),
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains(&format!("FileHash: sha256:{stored_hash}")));
        assert!(rendered.contains(&format!("Deriver: derivation-{winner}.drv")));
        let (status, _, detail) = send(
            &app,
            "GET",
            &format!("/_api/v1/orgs/default/caches/{cache}"),
            Some("admin"),
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let detail: Value = serde_json::from_slice(&detail).unwrap();
        let expected_bytes: usize = payloads
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 1 - winner && *index != if inline { 7 } else { 6 })
            .map(|(_, bytes)| bytes.len())
            .sum();
        assert_eq!(detail["paths"], 6);
        assert_eq!(
            detail["size"], expected_bytes,
            "logical bytes count shared blobs once per path"
        );
        // A completed replay must not resurrect a withdrawn duplicate path,
        // and withdrawing it must not remove the other path's shared bytes.
        let (status, deleted) = post(
            &app,
            &format!("/_api/v1/orgs/default/caches/{cache}/paths/delete"),
            "admin",
            json!({"storePathHashes":["0".repeat(32)]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        let (status, replay) = if inline {
            send_inline_batch(&app, inline_frame(&json!(uploads), &payloads)).await
        } else {
            post(
                &app,
                "/_api/v1/uploads/finalize",
                "legacy",
                json!({"uploads":uploads}),
            )
            .await
        };
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["results"][0], result["results"][0]);
        assert_eq!(replay["results"][1], result["results"][1]);
        for (hash, expected) in [
            ("0".repeat(32), StatusCode::NOT_FOUND),
            (format!("{:032}", 2), StatusCode::OK),
        ] {
            let (status, _, body) = send(
                &app,
                "GET",
                &format!("/{cache}/{hash}.narinfo"),
                Some("legacy"),
                &[],
                vec![],
            )
            .await;
            assert_eq!(status, expected);
            if status == StatusCode::OK {
                assert!(
                    String::from_utf8(body)
                        .unwrap()
                        .contains(&format!("FileHash: sha256:{stored_hash}"))
                );
            }
        }
        let (status, _, bytes) = send(
            &app,
            "GET",
            &format!("/nar/{stored_hash}/zstd.nar"),
            None,
            &[],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, payloads[winner]);
        stop.send(()).unwrap();
        proxy_task.await.unwrap();
    }
    single.close().await;
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
#[ignore = "requires scripts/with-r2.sh disposable S3 endpoint"]
async fn paused_immutable_copy_releases_pool_without_reserving_quota_or_publishing_stale_data(
    pool: PgPool,
) {
    use axum::{extract::Request as AxumRequest, response::IntoResponse, routing::any};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    let old_raw = nar(b"paused older immutable upload");
    let new_raw = nar(b"newer publication must survive the late old copy");
    let old = zstd::stream::encode_all(old_raw.as_slice(), 3).unwrap();
    let new = zstd::stream::encode_all(new_raw.as_slice(), 3).unwrap();
    pool_execute(&pool, "INSERT INTO caches(name) VALUES ('main'); INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;").await;
    sqlx::query("UPDATE orgs SET storage_limit=$1 WHERE id='default'")
        .bind((old.len() + new.len() - 1) as i64)
        .execute(&pool)
        .await
        .unwrap();
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let upstream = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT").unwrap();
    assert!(upstream.starts_with("http://127.0.0.1:"));
    let reached = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let paused = Arc::new(AtomicBool::new(false));
    let storage_work = Arc::new(AtomicUsize::new(0));
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::from_env();
    config.r2_endpoint = format!("http://{}", proxy.local_addr().unwrap());
    config.auth_token = "legacy".into();
    config.admin_secret = "admin".into();
    let proxy_app = Router::new().fallback(any({
        let reached = reached.clone();
        let release = release.clone();
        let paused = paused.clone();
        let storage_work = storage_work.clone();
        move |request: AxumRequest| {
            let upstream = upstream.clone();
            let reached = reached.clone();
            let release = release.clone();
            let paused = paused.clone();
            let storage_work = storage_work.clone();
            async move {
                let (parts, body) = request.into_parts();
                // S3 uses POST ?delete for source cleanup after publication;
                // count byte reads/writes, not that expected cleanup request.
                if matches!(parts.method.as_str(), "GET" | "PUT" | "POST")
                    && parts.uri.query() != Some("delete")
                {
                    storage_work.fetch_add(1, Ordering::SeqCst);
                }
                if (parts.method == "POST" || parts.method == "PUT")
                    && parts.uri.path().contains("/nar/objects/")
                    && !paused.swap(true, Ordering::SeqCst)
                {
                    reached.notify_one();
                    release.notified().await;
                }
                let response = reqwest::Client::new()
                    .request(parts.method, format!("{upstream}{}", parts.uri))
                    .headers(parts.headers)
                    .body(to_bytes(body, 32 * 1024 * 1024).await.unwrap())
                    .send()
                    .await
                    .unwrap();
                (
                    response.status(),
                    response.headers().clone(),
                    response.bytes().await.unwrap(),
                )
                    .into_response()
            }
        }
    }));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async {
        axum::serve(proxy, proxy_app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let storage = snowstead_server::storage::Storage::new(&config).unwrap();
    let app = router(
        AppState::new(
            single.clone(),
            config.clone(),
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let hash = "a".repeat(32);
    let pending = tokio::spawn({
        let app = app.clone();
        let input = path_input(&hash, &old_raw, true);
        let old = old.clone();
        async move { upload_inline(&app, "main", input, &old).await }
    });
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .expect("immutable copy must reach barrier");
    // The first provider request is the final immutable PUT. Inline NAR
    // verification must not stage, assemble, or read bytes from storage.
    assert_eq!(storage_work.load(Ordering::SeqCst), 1);
    // Every operation below uses the same one-slot application pool, with the
    // storage barrier still closed. No sleep or scheduler ordering is required.
    let stale_key = tokio::time::timeout(Duration::from_secs(10), async {
        let key: String =
            sqlx::query_scalar("SELECT key FROM nar_installations WHERE session_id IS NOT NULL")
                .fetch_one(&single)
                .await
                .unwrap();
        assert!(key.starts_with("nar/objects/"));
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT source_key IS NULL FROM nar_installations WHERE key=$1"
            )
            .bind(&key)
            .fetch_one(&single)
            .await
            .unwrap()
        );
        assert_eq!(
            send(&app, "GET", "/main/nix-cache-info", None, &[], vec![])
                .await
                .0,
            StatusCode::OK
        );
        let independent = upload_inline(
            &app,
            "main",
            path_input(&"f".repeat(32), &new_raw, true),
            &new,
        )
        .await;
        assert_eq!(independent["published"], true, "{independent}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
                .fetch_one(&single)
                .await
                .unwrap(),
            1
        );
        // Even deletion of an absent path invalidates its in-flight admission.
        let (status, deleted) = post(
            &app,
            "/_api/v1/orgs/default/caches/main/paths/delete",
            "admin",
            json!({"storePathHashes":[hash]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        let (status, _, body) = send(
            &app,
            "PUT",
            "/_api/v1/orgs/default",
            Some("admin"),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"storageLimit":2*new.len()})).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let newer = upload_inline(&app, "main", path_input(&hash, &new_raw, true), &new).await;
        assert_eq!(newer["published"], true, "{newer}");
        key
    })
    .await
    .expect("SQL, management and independent uploads must progress while copy is paused");
    release.notify_one();
    let stale = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale["published"], false, "{stale}");
    assert_eq!(stale["status"], 409, "{stale}");
    assert!(storage.head(false, &stale_key).await.is_ok());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM object_cleanup WHERE key=$1 AND NOT is_private"
        )
        .bind(&stale_key)
        .fetch_one(&single)
        .await
        .unwrap(),
        1
    );
    let new_hash = hex::encode(Sha256::digest(&new));
    let (status, _, bytes) = send(
        &app,
        "GET",
        &format!("/nar/{new_hash}/zstd.nar"),
        None,
        &[],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, new);
    let (status, _, metadata) = send(
        &app,
        "GET",
        &format!("/main/{hash}.narinfo"),
        None,
        &[],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8(metadata)
            .unwrap()
            .contains(&format!("FileHash: sha256:{new_hash}"))
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM published_paths")
            .fetch_one(&single)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM nar_installations WHERE session_id IS NOT NULL"
        )
        .fetch_one(&single)
        .await
        .unwrap(),
        0
    );
    // A transient org conflict must retain the verified immutable candidate.
    // A fresh server retries publication without reading or writing any bytes.
    paused.store(false, Ordering::SeqCst);
    let pending = tokio::spawn({
        let app = app.clone();
        let input = path_input(&"b".repeat(32), &new_raw, true);
        let new = new.clone();
        async move { upload_inline(&app, "main", input, &new).await }
    });
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .unwrap();
    let mut competing = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('org:default', 0))")
        .execute(&mut *competing)
        .await
        .unwrap();
    release.notify_one();
    let busy = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(busy["status"], 503, "{busy}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM nar_installations WHERE session_id=$1 AND phase='ready'"
        )
        .bind(busy["sessionId"].as_str().unwrap())
        .fetch_one(&single)
        .await
        .unwrap(),
        1
    );
    competing.rollback().await.unwrap();
    let before_replay = storage_work.load(Ordering::SeqCst);
    let restarted = router(
        AppState::new(
            single.clone(),
            config,
            storage.clone(),
            reqwest::Client::new(),
        )
        .unwrap(),
    );
    let uploads = json!([{
        "sessionId": busy["sessionId"],
        "fileHash": new_hash,
        "fileSize": new.len()
    }]);
    let (status, replay) = send_inline_batch(&restarted, inline_frame(&uploads, &[new])).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["results"][0]["published"], true, "{replay}");
    assert_eq!(storage_work.load(Ordering::SeqCst), before_replay);
    stop.send(()).unwrap();
    proxy_task.await.unwrap();
    single.close().await;
}
