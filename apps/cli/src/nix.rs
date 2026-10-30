use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct PathInfo {
    pub store_path: String,
    pub store_path_hash: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub deriver: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(default)]
    path: Option<String>,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
}

#[cfg_attr(snowstead_hotpath, hotpath::measure)]
async fn query(args: &[&str], paths: &[String]) -> Result<Vec<u8>> {
    let output = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(args)
        .arg("--")
        .args(paths)
        .kill_on_drop(true)
        .output()
        .await
        .context("Could not run nix path-info")?;
    if !output.status.success() {
        // Nix stderr can include arbitrary user input; don't forward it to logs.
        bail!(
            "nix path-info failed (exit {})",
            output.status.code().unwrap_or(-1)
        );
    }
    Ok(output.stdout)
}

/// Nix's own "is not valid" error is withheld from output, so name the
/// unbuilt path here instead of reporting a bare nix exit code.
fn ensure_local(paths: &[String]) -> Result<()> {
    for path in paths {
        if std::fs::symlink_metadata(path).is_err() {
            bail!(
                "{path} is not in the local Nix store; build it first (for example with nix build)"
            );
        }
    }
    Ok(())
}

/// The runtime closure of every root: the roots and everything they reference.
#[cfg_attr(snowstead_hotpath, hotpath::measure)]
pub async fn closure(roots: &[String]) -> Result<Vec<String>> {
    ensure_local(roots)?;
    let mut paths = BTreeSet::new();
    for chunk in roots.chunks(500) {
        let bytes = query(&["path-info", "-r"], chunk).await?;
        let output = String::from_utf8(bytes).context("Invalid UTF-8 from nix path-info")?;
        paths.extend(
            output
                .lines()
                .filter(|line| !line.is_empty())
                .map(str::to_owned),
        );
    }
    if paths.is_empty() {
        bail!("nix path-info returned an empty closure");
    }
    tracing::debug!(target: "snowstead", paths = paths.len(), "Resolved closure");
    Ok(paths.into_iter().collect())
}

/// Resolve filesystem aliases only; never evaluate a flake or build an installable.
/// A direct store path may already exist remotely without being materialized locally.
pub fn resolve(path: &str) -> Result<String> {
    if let Some(basename) = path.strip_prefix("/nix/store/")
        && !basename.is_empty()
        && !basename.contains('/')
        && basename.contains('-')
    {
        return Ok(path.to_owned());
    }
    let hint = "pass a store path or a link to one, such as ./result; for a flake output, \
                run nix build --print-out-paths <installable> | snowstead push <cache>";
    let resolved = std::fs::canonicalize(path)
        .with_context(|| format!("{path} is not an existing store path; {hint}"))?;
    let resolved = resolved.to_str().context("Store path is not UTF-8")?;
    if !resolved.starts_with("/nix/store/") || resolved[11..].contains('/') {
        bail!("{path} is not a top-level /nix/store path; {hint}");
    }
    Ok(resolved.to_owned())
}

#[cfg_attr(snowstead_hotpath, hotpath::measure)]
pub async fn path_infos(paths: &[String]) -> Result<HashMap<String, PathInfo>> {
    let mut result = HashMap::new();
    for chunk in paths.chunks(500) {
        tracing::debug!(target: "snowstead", paths = chunk.len(), "Querying Nix path metadata");
        let bytes = match query(&["path-info", "--json"], chunk).await {
            Ok(bytes) => bytes,
            Err(error) => {
                ensure_local(chunk)?;
                return Err(error);
            }
        };
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).context("Invalid nix path-info JSON")?;
        let entries: HashMap<String, Entry> = if value.is_object() {
            serde_json::from_value(value).context("Invalid nix path-info object")?
        } else {
            let entries: Vec<Entry> =
                serde_json::from_value(value).context("Invalid nix path-info array")?;
            entries
                .into_iter()
                .map(|mut entry| {
                    let path = entry
                        .path
                        .take()
                        .context("Missing path in nix path-info array")?;
                    Ok((path, entry))
                })
                .collect::<Result<_>>()?
        };
        for path in chunk {
            let entry = entries
                .get(path)
                .context("nix path-info returned no metadata for a requested path")?;
            let basename = path.rsplit('/').next().context("Invalid store path")?;
            let (hash, _) = basename
                .split_once('-')
                .context("Invalid store path basename")?;
            let references = entry
                .references
                .iter()
                .map(|reference| {
                    reference
                        .rsplit('/')
                        .next()
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .context("Invalid reference path")
                })
                .collect::<Result<_>>()?;
            result.insert(
                path.clone(),
                PathInfo {
                    store_path: path.clone(),
                    store_path_hash: hash.into(),
                    nar_hash: entry.nar_hash.clone(),
                    nar_size: entry.nar_size,
                    references,
                    deriver: entry.deriver.clone(),
                },
            );
        }
    }
    Ok(result)
}
