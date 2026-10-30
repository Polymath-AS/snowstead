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
fn closure_accepts_a_flake_installable_without_a_local_file() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let nix = bin.join("nix");
    let hash = "a".repeat(32);
    std::fs::write(&nix, format!("#!/bin/sh\nfor arg in \"$@\"; do\nif [ \"$arg\" = '.#app' ]; then echo /nix/store/{hash}-app; exit 0; fi\ndone\nexit 1\n")).unwrap();
    std::fs::set_permissions(&nix, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (url, request) = mock(200, json!({"missing": []}));
    login(home.path(), &url);
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home.path())
        .env("PATH", std::env::join_paths(paths).unwrap())
        .args(["push", "main", "--closure", ".#app"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        request.join().unwrap().1,
        json!({"cache":"main", "storePathHashes":[hash]})
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
