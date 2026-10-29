use crate::config;
use anyhow::{Context, Result, bail};
use clap::Args;
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{Read, Write},
    process::Stdio,
    time::Duration,
};
use tokio::time::{Instant, sleep, timeout};

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
        .build()?;
    // This outer deadline covers start, the browser opener, all polling, and response reads.
    timeout(
        Duration::from_secs(600),
        device_login(&client, origin, options),
    )
    .await
    .context("Device login expired. Run snowstead login again")?
}

async fn device_login(client: &reqwest::Client, origin: &str, options: &Login) -> Result<()> {
    let requested = Instant::now();
    let response = client
        .post(format!("{origin}/auth/device/start"))
        .json(&json!({}))
        .send()
        .await?;
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
    loop {
        if Instant::now() + Duration::from_secs(interval) >= deadline {
            sleep(deadline.saturating_duration_since(Instant::now())).await;
            bail!("Device login expired. Run snowstead login again");
        }
        sleep(Duration::from_secs(interval)).await;
        let response = timeout(deadline.saturating_duration_since(Instant::now()), async {
            let response = client
                .post(format!("{origin}/auth/device/token"))
                .json(&json!({"deviceCode": started.device_code}))
                .send()
                .await?;
            let status = response.status();
            let body: serde_json::Value = response.json().await?;
            Ok::<_, reqwest::Error>((status, body))
        })
        .await
        .context("Device login expired. Run snowstead login again")??;
        match response {
            (reqwest::StatusCode::OK, body) => {
                let authorized: Authorized =
                    serde_json::from_value(body).context("Invalid device token response")?;
                if authorized.org_name.is_empty()
                    || authorized
                        .expires_at
                        .as_ref()
                        .is_some_and(|value| value.is_empty())
                {
                    bail!("Invalid device token response");
                }
                let name = options.name.as_deref().unwrap_or(&authorized.name);
                config::login(name, &authorized.server, &authorized.token)?;
                println!("Signed in. Saved local profile '{name}'.");
                return Ok(());
            }
            (status, body)
                if status == reqwest::StatusCode::BAD_REQUEST
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                match body["error"].as_str() {
                    Some("authorization_pending") if status == reqwest::StatusCode::BAD_REQUEST => {
                    }
                    Some("slow_down") => interval = interval.saturating_add(5).min(600),
                    Some("access_denied") => bail!("Device login was denied"),
                    Some("expired_token") => {
                        bail!("Device login expired. Run snowstead login again")
                    }
                    Some("invalid_grant") => {
                        bail!("Device login is invalid. Run snowstead login again")
                    }
                    _ => bail!("Unexpected device login response"),
                }
            }
            _ => bail!("Device login request failed"),
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
