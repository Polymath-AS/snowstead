use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output, Stdio},
    thread,
};

const TOKEN: &str = "secret-credential-do-not-log";

fn run(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home)
        .env("RUST_LOG", "trace,reqwest=trace,hyper=trace")
        .args(args)
        .output()
        .unwrap()
}

fn login(home: &std::path::Path, url: &str) {
    let output = manual_login(home, "test", url, TOKEN);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn manual_login(home: &std::path::Path, name: &str, url: &str, token: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home)
        .args(["login", "--token-stdin", "--name", name, "--url", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(token.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn push_reads_stdin_and_includes_each_paths_closure() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // Any real top-level store path satisfies the local check; nix itself is mocked.
    let root = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .find_map(|dir| {
            let dir = dir.to_str()?.strip_prefix("/nix/store/")?.to_owned();
            Some(format!("/nix/store/{}", dir.split('/').next()?))
        })
        .expect("run inside nix develop so PATH contains store paths");
    let dependency = format!("/nix/store/{}-dependency", "a".repeat(32));
    let nix = bin.join("nix");
    std::fs::write(
        &nix,
        format!("#!/bin/sh\nfor arg in \"$@\"; do\nif [ \"$arg\" = -r ]; then printf '%s\\n' {root} {dependency}; exit 0; fi\ndone\nexit 1\n"),
    )
    .unwrap();
    std::fs::set_permissions(&nix, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (url, request) = mock(200, json!({"missing": []}));
    login(home.path(), &url);
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home.path())
        .env("PATH", std::env::join_paths(paths).unwrap())
        .args(["push", "main"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{root}").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut hashes = vec![root[11..43].to_owned(), "a".repeat(32)];
    hashes.sort();
    assert_eq!(
        request.join().unwrap().1,
        json!({"cache":"main", "storePathHashes":hashes})
    );
}

/// A single-use local server also checks the exact hosted v1 request and body.
fn mock(status: u16, response: Value) -> (String, thread::JoinHandle<(String, Value)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while bytes.len() < header_end + length {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
        }
        let body = if length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap()
        };
        let body_text = response.to_string();
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_text}", body_text.len()).unwrap();
        (headers.lines().next().unwrap().into(), body)
    });
    (url, handle)
}

#[test]
fn login_preserves_camel_case_config_and_replaces_permissions() {
    let home = tempfile::tempdir().unwrap();
    login(home.path(), "http://localhost:1");
    let path = home.path().join(".config/snowstead/config.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let result = manual_login(
        home.path(),
        "other",
        "https://cache.example.com/",
        "other-secret",
    );
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("other-secret"));
    let config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(config["defaultServer"], "other");
    assert_eq!(config["servers"]["test"]["token"], TOKEN);
    assert_eq!(
        config["servers"]["other"]["server"],
        "https://cache.example.com"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::write(&path, b"not json").unwrap();
    assert!(
        !manual_login(home.path(), "third", "https://example.com", TOKEN)
            .status
            .success()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"not json");
}

#[test]
fn invalid_commands_fail_before_credentials_or_http() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["cache", "create", "main"],
        vec!["cache", "create", "main", "--protocols", "nix,nix"],
        vec!["cache", "create", "main", "--protocols", "nix,"],
        vec!["cache", "create", "main", "--protocols", "other"],
        vec!["cache", "set", "main"],
        vec!["cache", "set", "main", "--private", "--public"],
        vec!["push", "main", "/anything", "--jobs", "0"],
        vec!["push", "main", "/anything", "--compression-level", "20"],
        vec!["push", "main"],
        vec!["push", "main", ".#app"],
        vec![
            "push",
            "main",
            "/nix/store/00000000000000000000000000000000-app.drv",
        ],
        vec!["token", "create", "ci", "--expires", "0"],
    ] {
        let result = run(home.path(), &args);
        assert!(!result.status.success(), "{args:?}");
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains("No server specified"),
            "{args:?}"
        );
    }
}

#[test]
fn logs_are_opt_in_app_only_and_secrets_are_redacted() {
    let home = tempfile::tempdir().unwrap();
    for verbose in [false, true] {
        let (url, request) = mock(200, json!({"tokens": []}));
        login(home.path(), &url);
        let args = if verbose {
            vec!["token", "list", "--verbose"]
        } else {
            vec!["token", "list"]
        };
        let result = run(home.path(), &args);
        assert!(result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(stderr.contains("DEBUG"), verbose);
        assert!(!stderr.contains(TOKEN));
        assert!(!stderr.contains(&url));
        assert!(!stderr.contains("reqwest"));
        assert!(!stderr.contains("hyper"));
        assert!(String::from_utf8_lossy(&result.stdout).contains("No tokens found"));
        assert_eq!(
            request.join().unwrap().0,
            "GET /_api/v1/admin/tokens HTTP/1.1"
        );
    }
    let (url, request) = mock(403, json!({"error": TOKEN}));
    login(home.path(), &url);
    let result = run(home.path(), &["-v", "token", "list"]);
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("403"));
    assert!(!stderr.contains(TOKEN));
    request.join().unwrap();
}

#[test]
fn token_defaults_and_multiword_revoke_with_separator() {
    let home = tempfile::tempdir().unwrap();
    let (url, request) = mock(
        200,
        json!({"subject":"ci", "jti":"id", "caches":["*"], "perms":["push"], "expiresAt":null, "token":"new-token"}),
    );
    login(home.path(), &url);
    let result = run(home.path(), &["token", "create", "ci"]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("new-token"));
    assert_eq!(
        request.join().unwrap(),
        (
            "POST /_api/v1/admin/tokens HTTP/1.1".into(),
            json!({"subject":"ci", "caches":["*"], "perms":["push"], "expiresInDays":90})
        )
    );
    let (url, request) = mock(200, json!({}));
    login(home.path(), &url);
    assert!(
        run(
            home.path(),
            &[
                "--server",
                "test",
                "token",
                "revoke",
                "id",
                "employee",
                "offboarded",
                "--",
                "--verbose"
            ]
        )
        .status
        .success()
    );
    assert_eq!(
        request.join().unwrap(),
        (
            "POST /_api/v1/admin/tokens/id/revoke HTTP/1.1".into(),
            json!({"reason":"employee offboarded --verbose"})
        )
    );
}

#[test]
fn cache_protocols_and_visibility_use_v1_contract() {
    let home = tempfile::tempdir().unwrap();
    let (url, request) = mock(
        200,
        json!({"name":"main", "created":true, "private":true, "protocols":["nix", "go"]}),
    );
    login(home.path(), &url);
    assert!(
        run(
            home.path(),
            &[
                "cache",
                "create",
                "main",
                "--protocols",
                "nix,go",
                "--private"
            ]
        )
        .status
        .success()
    );
    assert_eq!(
        request.join().unwrap(),
        (
            "POST /_api/v1/admin/caches HTTP/1.1".into(),
            json!({"name":"main", "private":true, "protocols":["nix", "go"]})
        )
    );
}

#[test]
fn already_present_store_path_does_not_need_local_materialization() {
    let home = tempfile::tempdir().unwrap();
    let (url, request) = mock(
        200,
        json!({"missing":[], "upstream":[], "unchecked":[], "upstreams":[]}),
    );
    login(home.path(), &url);
    let result = run(
        home.path(),
        &[
            "push",
            "main",
            "/nix/store/00000000000000000000000000000000-snowstead-missing-local-fixture",
            "--no-deps",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 skipped"));
    assert_eq!(
        request.join().unwrap(),
        (
            "POST /_api/v1/get-missing-paths HTTP/1.1".into(),
            json!({"cache":"main", "storePathHashes":["00000000000000000000000000000000"]}),
        )
    );
}

#[test]
fn ci_credentials_require_a_pair_and_do_not_write_local_config() {
    let home = tempfile::tempdir().unwrap();
    let (url, request) = mock(200, json!({"tokens": []}));
    let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home.path())
        .env("SNOWSTEAD_TOKEN", TOKEN)
        .env("SNOWSTEAD_URL", &url)
        .args(["-v", "token", "list"])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(TOKEN));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(&url));
    request.join().unwrap();
    assert!(!home.path().join(".config/snowstead/config.json").exists());
    for missing in ["SNOWSTEAD_URL", "SNOWSTEAD_TOKEN"] {
        let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
            .env("HOME", home.path())
            .env("SNOWSTEAD_TOKEN", TOKEN)
            .env("SNOWSTEAD_URL", &url)
            .env_remove(missing)
            .args(["token", "list"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("together"));
        assert!(!String::from_utf8_lossy(&result.stderr).contains(TOKEN));
    }
    let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home.path())
        .env("SNOWSTEAD_TOKEN", TOKEN)
        .env("SNOWSTEAD_URL", &url)
        .args(["auth", "status"])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "auth status must describe local config only"
    );
}

#[test]
fn streaming_encoder_failure_aborts_before_exit_without_a_spool_directory() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let path = "/nix/store/00000000000000000000000000000000-snowstead-missing-stream-fixture";
    let metadata = json!({path:{"narHash":format!("sha256:{}", "0".repeat(64)),"narSize":4096,"references":[]}});
    let nix = bin.join("nix");
    std::fs::write(
        &nix,
        format!("#!/bin/sh\ncat <<'SNOWSTEAD_METADATA'\n{metadata}\nSNOWSTEAD_METADATA\n"),
    )
    .unwrap();
    std::fs::set_permissions(&nix, std::fs::Permissions::from_mode(0o755)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        for (endpoint, response) in [
            (
                "/_api/v1/get-missing-paths",
                json!({"missing":["00000000000000000000000000000000"]}),
            ),
            (
                "/_api/v1/caches/main/upload-streams/batch",
                json!({"sessions":[{"sessionId":"s1","partSize":8388608}]}),
            ),
            ("/_api/v1/uploads/s1/abort", json!({})),
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
            }
            let headers = String::from_utf8(bytes).unwrap();
            assert!(headers.starts_with(&format!("POST {endpoint} HTTP/1.1")));
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            if endpoint.ends_with("/batch") {
                let body: Value = serde_json::from_slice(&body).unwrap();
                assert!(body["paths"][0].get("fileHash").is_none());
                assert!(body["paths"][0].get("fileSize").is_none());
            }
            let body = response.to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home.path())
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("TMPDIR", home.path().join("no-spooling-here"))
        .env("SNOWSTEAD_URL", url)
        .env("SNOWSTEAD_TOKEN", TOKEN)
        .args(["push", "main", path, "--no-deps", "--jobs", "1"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("NAR encoding failed") || stderr.contains("nix-store --dump failed"));
    assert!(!stderr.contains(TOKEN));
    server.join().unwrap();
    assert!(!home.path().join("no-spooling-here").exists());
}

#[test]
fn push_uploads_before_delayed_session_creation_finishes() {
    streamed_session_creation(false);
}

#[test]
fn late_session_negotiation_failure_clears_live_sessions_after_completed_work() {
    streamed_session_creation(true);
}

fn streamed_session_creation(late_failure: bool) {
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // Resolve a real shell executable, rather than guessing from PATH's store
    // basenames: dev shells can include derivations and stale entries there.
    // This also works in Nix's read-only build sandbox without store writes.
    let root = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .flat_map(|dir| [dir.join("bash"), dir.join("sh")])
        .filter_map(|shell| std::fs::canonicalize(shell).ok())
        .filter(|shell| shell.is_file())
        .find_map(|shell| {
            let shell = shell.to_str()?.strip_prefix("/nix/store/")?;
            let basename = shell.split('/').next()?;
            let root = format!("/nix/store/{basename}");
            (!basename.ends_with(".drv") && std::path::Path::new(&root).is_dir()).then_some(root)
        })
        .expect("run inside nix develop so PATH contains a shell in a real store output");
    let nar = Command::new("nix-store")
        .args(["--dump", &root])
        .output()
        .unwrap();
    assert!(nar.status.success());
    let mut paths = vec![root.clone()];
    paths.extend((0..100).map(|i| format!("/nix/store/{i:032}-snowstead-absent-session-fixture")));
    let nar_hash = format!("sha256:{}", hex::encode(Sha256::digest(&nar.stdout)));
    let mut metadata = serde_json::Map::new();
    for (i, path) in paths.iter().enumerate() {
        metadata.insert(
            path.clone(),
            json!({
                "narHash": nar_hash,
                // Ensure the real output sorts first, regardless of its size.
                "narSize": nar.stdout.len() + usize::from(i != 0), "references": []
            }),
        );
    }
    let nix = bin.join("nix");
    std::fs::write(
        &nix,
        format!(
            "#!/bin/sh\ncat <<'METADATA'\n{}\nMETADATA\n",
            Value::Object(metadata)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&nix, std::fs::Permissions::from_mode(0o755)).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let uploaded = Arc::new((Mutex::new(0usize), Condvar::new()));
    let batches = Arc::new(Mutex::new(Vec::new()));
    let published = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let live = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let stalled = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let missing: Vec<_> = paths.iter().map(|p| p[11..43].to_owned()).collect();
    let server = thread::spawn({
        let (stop, uploaded, batches, published, live, stalled, url) = (
            stop.clone(),
            uploaded.clone(),
            batches.clone(),
            published.clone(),
            live.clone(),
            stalled.clone(),
            url.clone(),
        );
        move || {
            let mut handlers = Vec::new();
            while !stop.load(Ordering::SeqCst) {
                let (mut socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                let (uploaded, batches, published, live, stalled, url, missing) = (
                    uploaded.clone(),
                    batches.clone(),
                    published.clone(),
                    live.clone(),
                    stalled.clone(),
                    url.clone(),
                    missing.clone(),
                );
                handlers.push(thread::spawn(move || {
                    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        socket.read_exact(&mut byte).unwrap();
                        headers.push(byte[0]);
                    }
                    let headers = String::from_utf8(headers).unwrap();
                    let length: usize = headers.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                    }).unwrap();
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).unwrap();
                    let mut status = 200;
                    let response = if headers.starts_with("PUT /part ") {
                        assert!(!headers.contains(TOKEN), "signed PUT must not carry API credentials");
                        assert!(!body.is_empty());
                        *uploaded.0.lock().unwrap() += 1;
                        uploaded.1.notify_all();
                        json!({})
                    } else {
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        if headers.starts_with("POST /_api/v1/get-missing-paths ") {
                            json!({"missing": missing})
                        } else if headers.starts_with("POST /_api/v1/caches/main/upload-streams/batch ") {
                            let count = body["paths"].as_array().unwrap().len();
                            let index = {
                                let mut batches = batches.lock().unwrap();
                                batches.push(count);
                                batches.len()
                            };
                            if index == 2 {
                                // Do not finish creation until a real upload arrives.
                                // The old all-sessions-first pipeline hits this timeout.
                                let (count, timeout) = uploaded.1.wait_timeout_while(
                                    uploaded.0.lock().unwrap(), Duration::from_secs(5), |n| *n == 0,
                                ).unwrap();
                                assert!(!timeout.timed_out() && *count > 0,
                                    "all-session creation blocked the first upload");
                            }
                            json!({"sessions": body["paths"].as_array().unwrap().iter().map(|p| {
                                live.lock().unwrap().insert(p["storePathHash"].as_str().unwrap().to_owned());
                                // Reject the later response only after earlier work has
                                // finished. Even invalid responses own real sessions.
                                json!({"sessionId":p["storePathHash"], "partSize":if late_failure && index == 2 {0} else {8388608}})
                            }
                            ).collect::<Vec<_>>()})
                        } else if headers.starts_with("POST /_api/v1/uploads/parts ") {
                            json!({"results":body["uploads"].as_array().unwrap().iter().map(|u|
                                json!({"sessionId":u["sessionId"], "parts":u["parts"].as_array().unwrap().iter().map(|p|
                                    json!({"partNumber":p["partNumber"], "url":format!("{url}/part"), "headers":{}})
                                ).collect::<Vec<_>>()})
                            ).collect::<Vec<_>>()})
                        } else if headers.lines().next().unwrap().ends_with("/abort HTTP/1.1") {
                            let id = headers.split_whitespace().nth(1).unwrap()
                                .strip_prefix("/_api/v1/uploads/").unwrap()
                                .strip_suffix("/abort").unwrap();
                            if late_failure {
                                let active = live.lock().unwrap().contains(id);
                                // Already-terminal requests are slow, while the first
                                // abort of the final live session loses its response.
                                // A bounded cleanup must spend its slots on live work,
                                // not replay the entire history of completed sessions.
                                let first_live_abort = active && id == format!("{:032}", 99)
                                    && stalled.lock().unwrap().insert(id.to_owned());
                                if !active || first_live_abort {
                                    thread::sleep(Duration::from_secs(6));
                                }
                                if first_live_abort {
                                    status = 503;
                                } else {
                                    live.lock().unwrap().remove(id);
                                }
                            } else {
                                live.lock().unwrap().remove(id);
                            }
                            json!({})
                        } else {
                            assert!(headers.starts_with("POST /_api/v1/uploads/finalize "));
                            json!({"results":body["uploads"].as_array().unwrap().iter().map(|u| {
                                assert!(published.lock().unwrap().insert(u["sessionId"].as_str().unwrap().to_owned()));
                                live.lock().unwrap().remove(u["sessionId"].as_str().unwrap());
                                json!({"sessionId":u["sessionId"], "published":true})
                            }).collect::<Vec<_>>()})
                        }
                    };
                    let body = response.to_string();
                    // A timed-out cleanup can close the connection before our
                    // deliberately stalled response is ready.
                    let sent = write!(socket, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nETag: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    if !late_failure {
                        sent.unwrap();
                    }
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        }
    });
    let mut executable_paths = vec![bin];
    executable_paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home.path())
        .env("PATH", std::env::join_paths(executable_paths).unwrap())
        .env("SNOWSTEAD_URL", url)
        .env("SNOWSTEAD_TOKEN", TOKEN)
        .args([
            "push",
            "main",
            "--no-deps",
            "--jobs",
            if late_failure { "1" } else { "32" },
        ])
        .args(&paths)
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert!(
        !result.status.success(),
        "the absent fixtures must fail encoding"
    );
    if late_failure {
        assert!(String::from_utf8_lossy(&result.stderr).contains("invalid multipart part size"));
    } else {
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("1 pushed") && stdout.contains("100 failed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(*batches.lock().unwrap(), [100, 1]);
    assert!(*uploaded.0.lock().unwrap() > 0);
    assert_eq!(published.lock().unwrap().len(), 1);
    assert!(
        live.lock().unwrap().is_empty(),
        "CLI exit left live upload reservations"
    );
}
