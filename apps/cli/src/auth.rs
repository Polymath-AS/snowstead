use crate::config;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Args;
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{Read, Write},
    process::Stdio,
    time::Duration,
};
use tokio::time::{Instant, sleep_until, timeout};

#[derive(Args)]
pub struct Login {
    /// Web origin for browser login, or cache base URL with --token-stdin.
    #[arg(long, required_if_eq("token_stdin", "true"))]
    url: Option<String>,
    /// Override the organization slug used as the local profile name.
    #[arg(long, required_if_eq("token_stdin", "true"))]
    name: Option<String>,
    /// Print instructions without launching a browser (for SSH/headless use).
    #[arg(long, conflicts_with = "token_stdin")]
    no_browser: bool,
    /// Read a manual cache token from standard input, without remote validation.
    #[arg(long)]
    token_stdin: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Started {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Authorized {
    server: String,
    token: String,
    name: String,
    org_name: String,
    expires_at: Option<String>,
}

pub fn status(profile: Option<&str>) -> Result<()> {
    let (name, server) = config::server_with_source(profile)?;
    // Validate saved addresses too: never display embedded URL credentials.
    let url = config::validate_url(&server.server)?;
    match name {
        Some(name) => println!("Credential source: saved profile '{}'", printable(&name)),
        None => println!("Credential source: SNOWSTEAD_TOKEN / SNOWSTEAD_URL"),
    }
    println!("API address: {}", printable(url.as_str()));
    println!(
        "Offline only. Credentials and claims have not been verified remotely; JWT signatures and revocation have not been checked."
    );
    let claims = status_claims(&server.token);
    println!(
        "Permissions (unverified claims): {}",
        claim_list(claims.as_ref().and_then(|c| c.perms.as_deref()))
    );
    println!(
        "Cache scope (unverified claims): {}",
        claim_list(claims.as_ref().and_then(|c| c.caches.as_deref()))
    );
    println!(
        "Organization (unverified claim): {}",
        claims
            .as_ref()
            .and_then(|c| c.org.as_deref())
            .map(printable)
            .unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Expiry (unverified claim): {}",
        claims
            .and_then(|c| c.exp)
            .map(|exp| format!("{exp} (Unix seconds)"))
            .unwrap_or_else(|| "unknown".into())
    );
    Ok(())
}

// Decode only the fields we display. This is deliberately not an authentication
// parser: no key, signature verification, network request, or inferred admin role.
#[derive(Deserialize)]
struct StatusClaims {
    perms: Option<Vec<String>>,
    caches: Option<Vec<String>>,
    org: Option<String>,
    exp: Option<i64>,
}

fn status_claims(token: &str) -> Option<StatusClaims> {
    if token.len() > 64 * 1024 {
        return None;
    }
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() || signature.is_empty() {
        return None;
    }
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if !header.is_object() || URL_SAFE_NO_PAD.decode(signature).is_err() {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

fn claim_list(values: Option<&[String]>) -> String {
    match values {
        None => "unknown".into(),
        Some([]) => "none".into(),
        Some(values) => values
            .iter()
            .map(|v| printable(v))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

pub fn logout(profile: Option<&str>) -> Result<()> {
    let name = config::logout(profile)?;
    println!("Removed local profile '{name}' (remote token not revoked)");
    Ok(())
}

pub async fn login(options: &Login) -> Result<()> {
    if options
        .name
        .as_ref()
        .is_some_and(|name| name.trim().is_empty())
    {
        bail!("Profile name must not be empty");
    }
    if options.token_stdin {
        let mut token = String::new();
        std::io::stdin()
            .take(1024 * 1024)
            .read_to_string(&mut token)
            .context("Could not read token from standard input")?;
        let name = options
            .name
            .as_deref()
            .context("--token-stdin requires --name")?;
        let url = options
            .url
            .as_deref()
            .context("--token-stdin requires --url")?;
        config::login(name, url, token.trim())?;
        println!("Configured local profile '{name}'. Remote credentials have not been verified.");
        return Ok(());
    }
    let origin = config::validate_url(options.url.as_deref().unwrap_or("https://snowstead.com"))?;
    let loopback = origin.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (origin.scheme() != "https" && !loopback) || origin.path() != "/" {
        bail!("Web origin must use HTTPS (HTTP is allowed only on loopback), with no path");
    }
    let origin = origin.as_str().trim_end_matches('/');
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(crate::api::user_agent())
        .build()?;
    // Fail on an unreadable config or unwritable directory now: once the
    // server mints a token, a failed save would orphan it.
    config::preflight()?;
    // A backstop over start, the browser opener, all polling, and the final
    // poll's response read; the device code's own deadline ends the login first.
    timeout(
        Duration::from_secs(660),
        device_login(&client, origin, options),
    )
    .await
    .context("Device login expired. Run snowstead login again")?
}

/// What one request to the device token endpoint means for the login.
enum Poll {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Invalid,
    /// The server or network failed; the approval itself is unaffected.
    Transient,
    /// An answer this client cannot act on.
    Unexpected,
    Authorized(Authorized),
}

/// `body` is `None` when the response was not JSON.
fn classify(status: reqwest::StatusCode, body: Option<serde_json::Value>) -> Poll {
    use reqwest::StatusCode;
    if status.is_server_error() {
        return Poll::Transient;
    }
    let Some(body) = body else {
        // A bare 429 comes from a rate limiter in front of the service.
        return if status == StatusCode::TOO_MANY_REQUESTS {
            Poll::SlowDown
        } else {
            Poll::Transient
        };
    };
    if status == StatusCode::OK {
        return match serde_json::from_value::<Authorized>(body) {
            Ok(authorized)
                if !authorized.org_name.is_empty()
                    && authorized
                        .expires_at
                        .as_ref()
                        .is_none_or(|value| !value.is_empty()) =>
            {
                Poll::Authorized(authorized)
            }
            _ => Poll::Unexpected,
        };
    }
    if status != StatusCode::BAD_REQUEST && status != StatusCode::TOO_MANY_REQUESTS {
        return Poll::Unexpected;
    }
    match body["error"].as_str() {
        Some("authorization_pending") if status == StatusCode::BAD_REQUEST => Poll::Pending,
        Some("slow_down") => Poll::SlowDown,
        Some("access_denied") => Poll::Denied,
        Some("expired_token") => Poll::Expired,
        Some("invalid_grant") => Poll::Invalid,
        _ => Poll::Unexpected,
    }
}

// Each poll gets its own short deadline, so a stalled request counts as one
// transient failure and the final poll can outlive the device code's deadline.
const POLL_TIMEOUT: Duration = Duration::from_secs(10);
// Consecutive transient polls tolerated before giving up on the login.
const TRANSIENT_LIMIT: u32 = 5;

async fn poll(client: &reqwest::Client, origin: &str, device_code: &str) -> Poll {
    let exchange = async {
        let response = client
            .post(format!("{origin}/auth/device/token"))
            .json(&json!({"deviceCode": device_code}))
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        Ok::<_, reqwest::Error>((status, serde_json::from_slice(&bytes).ok()))
    };
    match timeout(POLL_TIMEOUT, exchange).await {
        Ok(Ok((status, body))) => classify(status, body),
        Ok(Err(_)) | Err(_) => Poll::Transient,
    }
}

/// Server-supplied text is shown without control characters.
fn printable(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

async fn device_login(client: &reqwest::Client, origin: &str, options: &Login) -> Result<()> {
    let requested = Instant::now();
    let response = client
        .post(format!("{origin}/auth/device/start"))
        .json(&json!({}))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        bail!("Too many login attempts. Wait a minute, then run snowstead login again");
    }
    if response.status() != reqwest::StatusCode::OK {
        bail!("Could not start device login");
    }
    let started: Started = response
        .json()
        .await
        .context("Invalid device login response")?;
    let code = started.user_code.as_bytes();
    if started.device_code.len() != 64
        || !started
            .device_code
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || code.len() != 9
        || code[4] != b'-'
        || !code
            .iter()
            .enumerate()
            .all(|(i, c)| i == 4 || c.is_ascii_alphanumeric())
        || !code.iter().any(u8::is_ascii_alphabetic)
        || !code.iter().any(u8::is_ascii_digit)
        || started.verification_uri != format!("{origin}/auth/device")
        || started.expires_in == 0
        || started.interval == 0
    {
        bail!("Invalid device login response");
    }
    let deadline = requested + Duration::from_secs(started.expires_in.min(600));
    println!(
        "Open {} and enter code: {}",
        started.verification_uri, started.user_code
    );
    println!("You can use a browser on another device. Waiting for approval...");
    std::io::stdout()
        .flush()
        .context("Could not print login instructions")?;
    if !options.no_browser && !open_browser(&started.verification_uri).await {
        eprintln!("Could not open a browser. Open the verification URL above manually.");
    }
    let mut interval = started.interval.min(600);
    let mut transient = 0;
    loop {
        // The last poll happens at the deadline itself: an approval given
        // during the final interval still completes the login.
        let next = Instant::now() + Duration::from_secs(interval);
        let last = next >= deadline;
        sleep_until(next.min(deadline)).await;
        match poll(client, origin, &started.device_code).await {
            Poll::Authorized(authorized) => {
                let name = options.name.as_deref().unwrap_or(&authorized.name);
                config::login(name, &authorized.server, &authorized.token)?;
                println!(
                    "Signed in to {}. Saved local profile '{name}'.",
                    printable(&authorized.org_name)
                );
                match &authorized.expires_at {
                    Some(expires_at) => println!("Token expires {}.", printable(expires_at)),
                    None => println!("Token does not expire."),
                }
                return Ok(());
            }
            Poll::Pending => transient = 0,
            Poll::SlowDown => {
                transient = 0;
                interval = interval.saturating_add(5).min(600);
            }
            Poll::Denied => bail!("Device login was denied"),
            Poll::Expired => bail!("Device login expired. Run snowstead login again"),
            Poll::Invalid => bail!("Device login is invalid. Run snowstead login again"),
            Poll::Unexpected => bail!("Unexpected device login response"),
            Poll::Transient => {
                transient += 1;
                if transient > TRANSIENT_LIMIT {
                    bail!("Device login request failed repeatedly. Run snowstead login again");
                }
            }
        }
        if last {
            bail!("Device login expired. Run snowstead login again");
        }
    }
}

async fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut command = tokio::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = tokio::process::Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = tokio::process::Command::new("xdg-open");
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    matches!(timeout(Duration::from_secs(3), command.status()).await, Ok(Ok(status)) if status.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn poll_classification_separates_transient_failures_from_final_answers() {
        let error = |code: &str| Some(json!({"error": code}));
        let authorized = json!({"server":"https://cache.example/org", "token":"t", "name":"org", "orgName":"Org", "expiresAt":null});
        for status in [500, 502, 503, 504] {
            let status = StatusCode::from_u16(status).unwrap();
            assert!(matches!(classify(status, None), Poll::Transient));
            assert!(matches!(
                classify(status, error("access_denied")),
                Poll::Transient
            ));
        }
        // A proxy's HTML page is not an answer from the login service.
        assert!(matches!(classify(StatusCode::OK, None), Poll::Transient));
        assert!(matches!(
            classify(StatusCode::BAD_REQUEST, None),
            Poll::Transient
        ));
        assert!(matches!(
            classify(StatusCode::TOO_MANY_REQUESTS, None),
            Poll::SlowDown
        ));
        assert!(matches!(
            classify(StatusCode::TOO_MANY_REQUESTS, error("slow_down")),
            Poll::SlowDown
        ));
        let bad = StatusCode::BAD_REQUEST;
        assert!(matches!(
            classify(bad, error("authorization_pending")),
            Poll::Pending
        ));
        assert!(matches!(
            classify(bad, error("access_denied")),
            Poll::Denied
        ));
        assert!(matches!(
            classify(bad, error("expired_token")),
            Poll::Expired
        ));
        assert!(matches!(
            classify(bad, error("invalid_grant")),
            Poll::Invalid
        ));
        assert!(matches!(classify(bad, error("other")), Poll::Unexpected));
        assert!(matches!(
            classify(
                StatusCode::TOO_MANY_REQUESTS,
                error("authorization_pending")
            ),
            Poll::Unexpected
        ));
        assert!(matches!(
            classify(StatusCode::FORBIDDEN, error("access_denied")),
            Poll::Unexpected
        ));
        assert!(matches!(
            classify(StatusCode::OK, Some(authorized.clone())),
            Poll::Authorized(_)
        ));
        for (field, value) in [
            ("orgName", json!("")),
            ("expiresAt", json!("")),
            ("token", json!(null)),
        ] {
            let mut body = authorized.clone();
            body[field] = value;
            assert!(matches!(
                classify(StatusCode::OK, Some(body)),
                Poll::Unexpected
            ));
        }
    }
}
