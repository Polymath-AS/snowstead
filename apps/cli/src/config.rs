use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub struct Server {
    pub server: String,
    pub token: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_server: Option<String>,
    #[serde(default)]
    servers: BTreeMap<String, Server>,
}

fn path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/snowstead/config.json"))
}

fn load() -> Result<Config> {
    match fs::read(path()?) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("Invalid Snowstead config JSON"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(_) => bail!("Could not read Snowstead config"),
    }
}

pub fn login(name: &str, server: &str, token: &str) -> Result<()> {
    validate_url(server)?;
    if name.trim().is_empty() || token.trim().is_empty() {
        bail!("Server name and token must not be empty");
    }
    let mut config = load()?;
    config.default_server = Some(name.into());
    config.servers.insert(
        name.into(),
        Server {
            server: server.trim_end_matches('/').into(),
            token: token.into(),
        },
    );
    save(&config)
}

pub fn validate_url(server: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(server).map_err(|_| anyhow::anyhow!("Invalid server URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("Server must be an HTTP(S) URL without credentials, query, or fragment");
    }
    Ok(url)
}

fn save(config: &Config) -> Result<()> {
    let path = path()?;
    let dir = path.parent().context("Invalid config directory")?;
    fs::create_dir_all(dir).context("Could not create config directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .context("Could not secure config directory")?;
    }
    // NamedTempFile starts owner-only and stays on the same filesystem for rename.
    let mut file =
        tempfile::NamedTempFile::new_in(dir).context("Could not create private config file")?;
    serde_json::to_writer_pretty(&mut file, &config).context("Could not encode config")?;
    file.write_all(b"\n").context("Could not write config")?;
    file.as_file().sync_all().context("Could not sync config")?;
    file.persist(&path)
        .map_err(|_| anyhow::anyhow!("Could not replace config"))?;
    tracing::debug!(target: "snowstead", "Saved server credentials to private config");
    Ok(())
}

pub fn server(name: Option<&str>) -> Result<Server> {
    let token = std::env::var("SNOWSTEAD_TOKEN");
    let url = std::env::var("SNOWSTEAD_URL");
    match (token, url) {
        (Ok(token), Ok(server)) if !token.trim().is_empty() => {
            validate_url(&server)?;
            return Ok(Server {
                server: server.trim_end_matches('/').into(),
                token,
            });
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => (),
        _ => bail!("Set SNOWSTEAD_TOKEN and SNOWSTEAD_URL together, with nonempty values"),
    }
    Ok(local_server(name)?.1)
}

pub fn local_server(name: Option<&str>) -> Result<(String, Server)> {
    let config = load()?;
    let key = name
        .or(config.default_server.as_deref())
        .context("No server specified and no default configured. Run: snowstead login")?;
    let server = config
        .servers
        .get(key)
        .cloned()
        .context("Server not found in config. Run: snowstead login")?;
    Ok((key.into(), server))
}

pub fn logout(name: Option<&str>) -> Result<()> {
    let (key, _) = local_server(name)?;
    let mut config = load()?;
    config.servers.remove(&key);
    if config.default_server.as_deref() == Some(&key) {
        config.default_server = config.servers.keys().next().cloned();
    }
    save(&config)?;
    println!("Removed local profile '{key}' (remote token not revoked)");
    Ok(())
}
