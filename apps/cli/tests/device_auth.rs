use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

const DEVICE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "private-cache-jwt-never-print";

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home)
        .env_remove("SNOWSTEAD_URL")
        .env_remove("SNOWSTEAD_TOKEN")
        .env("RUST_LOG", "trace,reqwest=trace,hyper=trace")
        .args(args)
        .output()
        .unwrap()
}

fn config_path(home: &Path) -> std::path::PathBuf {
    home.join(".config/snowstead/config.json")
}

fn seed(home: &Path) -> Vec<u8> {
    let path = config_path(home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec(&json!({"defaultServer":"existing", "servers": {
        "existing":{"server":"https://cache.example/old", "token":"old-secret"},
        "other":{"server":"https://cache.example/other", "token":"other-secret"}
    }}))
    .unwrap();
    std::fs::write(path, &bytes).unwrap();
    bytes
}

fn device_server(
    replies: Vec<(u16, Value)>,
    expires: u64,
) -> (String, thread::JoinHandle<Vec<Instant>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let origin = url.clone();
    let handle = thread::spawn(move || {
        let start = json!({"deviceCode":DEVICE, "userCode":"ABCD-2345", "verificationUri":format!("{origin}/auth/device"), "expiresIn":expires, "interval":1});
        let mut times = vec![];
        for (i, (status, body)) in std::iter::once((200, start)).chain(replies).enumerate() {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut bytes = vec![];
            let header_end = loop {
                let mut buf = [0; 4096];
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            while bytes.len() < header_end + length {
                let mut buf = [0; 4096];
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
            }
            let request: Value =
                serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
            if i == 0 {
                assert!(headers.starts_with("POST /auth/device/start HTTP/1.1"));
                assert_eq!(request, json!({}));
            } else {
                assert!(headers.starts_with("POST /auth/device/token HTTP/1.1"));
                assert_eq!(request, json!({"deviceCode":DEVICE}));
            }
            assert!(!headers.to_lowercase().contains("authorization:"));
            times.push(Instant::now());
            let body = body.to_string();
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        times
    });
    (url, handle)
}

fn success() -> Value {
    json!({"server":"https://cache.example/org", "token":TOKEN, "name":"org-slug", "orgName":"Example organization", "expiresAt":"2027-01-01T00:00:00Z"})
}

fn assert_no_secrets(output: &Output, origin: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in [&stdout, &stderr] {
        for secret in [DEVICE, TOKEN, "/auth/device/token", "/auth/device/start"] {
            assert!(!text.contains(secret), "secret leaked: {text}");
        }
    }
    assert!(!stderr.contains(origin));
    assert!(!stderr.contains("reqwest"));
}

#[test]
fn pending_then_success_is_headless_and_preserves_profiles() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    seed(home.path());
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let marker = home.path().join("opener-ran");
    for opener in ["xdg-open", "open"] {
        let path = bin.join(opener);
        std::fs::write(&path, format!("#!/bin/sh\n: > '{}'\n", marker.display())).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (url, server) = device_server(
        vec![
            (400, json!({"error":"authorization_pending"})),
            (200, success()),
        ],
        600,
    );
    let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
        .env("HOME", home.path())
        .env("PATH", bin)
        .args(["-v", "login", "--no-browser", "--url", &url])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let times = server.join().unwrap();
    assert!(
        times
            .windows(2)
            .all(|pair| pair[1].duration_since(pair[0]) >= Duration::from_secs(1))
    );
    assert!(!marker.exists());
    assert_no_secrets(&result, &url);
    assert!(String::from_utf8_lossy(&result.stdout).contains("ABCD-2345"));
    let path = config_path(home.path());
    let config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(config["defaultServer"], "org-slug");
    assert_eq!(config["servers"]["org-slug"]["token"], TOKEN);
    assert_eq!(config["servers"]["existing"]["token"], "old-secret");
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn denial_expiry_and_unknown_errors_never_overwrite_credentials() {
    for error in ["access_denied", "expired_token", "invalid_grant", TOKEN] {
        let home = tempfile::tempdir().unwrap();
        let before = seed(home.path());
        let (url, server) = device_server(vec![(400, json!({"error":error}))], 600);
        let result = run(
            home.path(),
            &[
                "-v",
                "login",
                "--no-browser",
                "--url",
                &url,
                "--name",
                "existing",
            ],
        );
        assert!(!result.status.success());
        server.join().unwrap();
        assert_no_secrets(&result, &url);
        assert_eq!(std::fs::read(config_path(home.path())).unwrap(), before);
    }
    let home = tempfile::tempdir().unwrap();
    let before = seed(home.path());
    let (url, server) = device_server(vec![], 1);
    assert!(
        !run(home.path(), &["login", "--no-browser", "--url", &url])
            .status
            .success()
    );
    server.join().unwrap();
    assert_eq!(std::fs::read(config_path(home.path())).unwrap(), before);
}

#[test]
fn slow_down_backs_off_and_explicit_name_wins() {
    let home = tempfile::tempdir().unwrap();
    let mut authorized = success();
    authorized["expiresAt"] = Value::Null;
    let (url, server) = device_server(
        vec![(429, json!({"error":"slow_down"})), (200, authorized)],
        600,
    );
    let result = run(
        home.path(),
        &["login", "--no-browser", "--url", &url, "--name", "custom"],
    );
    assert!(result.status.success());
    let times = server.join().unwrap();
    assert!(times[2].duration_since(times[1]) >= Duration::from_secs(6));
    let config: Value =
        serde_json::from_slice(&std::fs::read(config_path(home.path())).unwrap()).unwrap();
    assert_eq!(config["defaultServer"], "custom");
    assert_eq!(config["servers"]["custom"]["token"], TOKEN);
}

#[test]
fn status_is_local_and_logout_preserves_other_profiles() {
    let home = tempfile::tempdir().unwrap();
    let before = seed(home.path());
    let status = run(home.path(), &["auth", "status"]);
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("not been verified"));
    assert_eq!(std::fs::read(config_path(home.path())).unwrap(), before);
    assert!(
        run(home.path(), &["logout", "--server", "other"])
            .status
            .success()
    );
    let config: Value =
        serde_json::from_slice(&std::fs::read(config_path(home.path())).unwrap()).unwrap();
    assert_eq!(config["defaultServer"], "existing");
    assert_eq!(config["servers"].as_object().unwrap().len(), 1);
    assert!(run(home.path(), &["logout"]).status.success());
    assert!(!run(home.path(), &["auth", "status"]).status.success());
}

#[test]
fn insecure_web_origins_and_positional_tokens_are_rejected() {
    let home = tempfile::tempdir().unwrap();
    for url in [
        "http://example.com",
        "https://example.com/path",
        "https://user:password@example.com",
        "https://example.com?secret=1",
    ] {
        let result = run(home.path(), &["login", "--url", url, "--no-browser"]);
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(url));
    }
    assert!(
        !run(
            home.path(),
            &["login", "name", "https://example.com", TOKEN]
        )
        .status
        .success()
    );
    assert!(
        !run(home.path(), &["login", "--token-stdin"])
            .status
            .success()
    );
}

#[test]
fn browser_opener_is_attempted_and_failure_keeps_manual_instructions() {
    use std::os::unix::fs::PermissionsExt;
    for exit in [0, 1] {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let marker = home.path().join("opener-ran");
        for opener in ["xdg-open", "open"] {
            let path = bin.join(opener);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\nprintf '%s' \"$1\" > '{}'\nexit {exit}\n",
                    marker.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let (url, server) = device_server(vec![(200, success())], 600);
        let result = Command::new(env!("CARGO_BIN_EXE_snowstead"))
            .env("HOME", home.path())
            .env("PATH", bin)
            .args(["login", "--url", &url])
            .output()
            .unwrap();
        assert!(result.status.success());
        server.join().unwrap();
        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            format!("{url}/auth/device")
        );
        assert_eq!(
            String::from_utf8_lossy(&result.stderr).contains("manually"),
            exit != 0
        );
        assert_no_secrets(&result, &url);
    }
}
