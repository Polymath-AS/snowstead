mod api;
mod auth;
mod batch;
mod config;
#[cfg(any(snowstead_hotpath, snowstead_local))]
mod local;
mod nar;
mod nix;
mod progress;
mod push;
mod push_job;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::io::IsTerminal;

#[derive(Parser)]
#[command(
    name = "snowstead",
    about = "Snowstead binary cache CLI",
    version,
    arg_required_else_help = true
)]
struct Cli {
    #[arg(long, global = true)]
    server: Option<String>,
    #[arg(long, short = 'v', global = true)]
    verbose: bool,
    /// Print the push result as one JSON object on stdout; diagnostics stay on stderr.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Benchmark local NAR preparation without credentials or network requests.
    #[cfg(any(snowstead_hotpath, snowstead_local))]
    Local(local::Options),
    /// Sign in using a browser, including from an SSH session.
    Login(auth::Login),
    /// Show locally configured authentication (no remote verification).
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Remove the selected local profile, without revoking its remote token.
    Logout,
    /// Push store paths and their runtime closures.
    Push {
        cache: String,
        /// Store paths or links to them (such as ./result); read from stdin when omitted.
        paths: Vec<String>,
        /// Push only the given paths, not the paths they reference.
        #[arg(long)]
        no_deps: bool,
        /// Upload .drv files (build recipes) instead of rejecting them.
        #[arg(long)]
        allow_drv: bool,
        /// Prepare transfers independently and retain a resumable push job.
        #[arg(long, conflicts_with = "resume")]
        resumable: bool,
        /// Resume a push job without repeating completed transfers or passing paths.
        #[arg(long, conflicts_with_all = ["paths", "no_deps", "allow_drv"])]
        resume: Option<String>,
        #[arg(long, default_value = "32", value_parser = positive)]
        jobs: usize,
        #[arg(long, default_value = "3", value_parser = clap::value_parser!(i32).range(1..=19))]
        compression_level: i32,
    },
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand)]
enum AuthCommand {
    Status,
}

#[derive(Args)]
struct Visibility {
    #[arg(long, conflicts_with = "public")]
    private: bool,
    #[arg(long)]
    public: bool,
}

#[derive(Subcommand)]
enum CacheCommand {
    Create {
        name: String,
        #[arg(long, required = true, value_parser = protocols)]
        protocols: Vec<String>,
        #[command(flatten)]
        visibility: Visibility,
    },
    Set {
        name: String,
        #[arg(long, value_parser = protocols)]
        protocols: Vec<String>,
        #[command(flatten)]
        visibility: Visibility,
    },
    List,
}

#[derive(Subcommand)]
enum TokenCommand {
    Create {
        subject: String,
        #[arg(long, default_value = "*", value_parser = nonempty_csv)]
        caches: String,
        #[arg(long, default_value = "push", value_parser = nonempty_csv)]
        perms: String,
        #[arg(long, default_value = "90", value_parser = positive)]
        expires: usize,
    },
    List,
    Revoke {
        jti: String,
        #[arg(required = true, num_args = 1..)]
        reason: Vec<String>,
    },
}

fn positive(value: &str) -> std::result::Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| "must be a positive integer".into())
}

fn nonempty_csv(value: &str) -> std::result::Result<String, String> {
    if value.split(',').any(|s| s.trim().is_empty()) {
        return Err("must be a nonempty comma-separated list".into());
    }
    Ok(value.into())
}

fn protocols(value: &str) -> std::result::Result<String, String> {
    let values: Vec<_> = value.split(',').map(str::trim).collect();
    if values.is_empty()
        || values
            .iter()
            .any(|p| !matches!(*p, "nix" | "go" | "sccache"))
        || values
            .iter()
            .enumerate()
            .any(|(i, p)| values[..i].contains(p))
    {
        return Err("must be a unique comma-separated list of nix, go, or sccache".into());
    }
    Ok(values.join(","))
}

fn csv(value: &str) -> Vec<&str> {
    value.split(',').map(str::trim).collect()
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("unknown")
}
fn list(value: &Value, key: &str) -> String {
    value[key]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}
fn expiry(value: &Value) -> &str {
    value["expiresAt"].as_str().unwrap_or("never")
}

/// Why a command failed, as far as typed errors can tell. Each class has a
/// stable exit code; clap exits with 2 for usage errors on its own.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Failure {
    Generic,
    /// The push finished, but some store paths failed to upload.
    PartialPush,
    /// The server answered 401 or 403.
    Auth,
    /// Interrupted by Ctrl-C or SIGTERM.
    Cancelled,
}
impl Failure {
    fn of(error: &anyhow::Error) -> Self {
        for cause in error.chain() {
            if cause.is::<push::Cancelled>() {
                return Self::Cancelled;
            }
            if cause.is::<PartialPush>() {
                return Self::PartialPush;
            }
            if cause
                .downcast_ref::<api::HttpError>()
                .is_some_and(|http| matches!(http.status, 401 | 403))
            {
                return Self::Auth;
            }
        }
        Self::Generic
    }
    fn exit_code(self) -> i32 {
        match self {
            Self::Generic => 1,
            Self::PartialPush => 3,
            Self::Auth => 4,
            Self::Cancelled => 130,
        }
    }
}

#[derive(Debug)]
struct PartialPush;
impl std::fmt::Display for PartialPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Some store paths failed to upload")
    }
}
impl std::error::Error for PartialPush {}

fn main() {
    #[cfg(snowstead_hotpath)]
    let profile = hotpath::HotpathGuardBuilder::new("snowstead").build();
    let result = async_main();
    // Drop the Tokio runtime first: Hotpath flushes each worker's final
    // measurement batch when that thread exits, before writing the report.
    #[cfg(snowstead_hotpath)]
    drop(profile);
    if let Err(error) = result {
        // Never format an anyhow chain: transport errors can contain signed URLs.
        let message = if let Some(error) = error
            .chain()
            .find_map(|e| e.downcast_ref::<reqwest::Error>())
        {
            match error.status() {
                Some(status) => format!("HTTP request failed ({status})"),
                None => "HTTP request failed (connection or response error)".into(),
            }
        } else {
            error.to_string()
        };
        eprintln!("Error: {message}");
        let failure = Failure::of(&error);
        std::process::exit(failure.exit_code());
    }
}

/// The store paths to push, from arguments or else stdin, without consulting Nix.
fn push_roots(paths: Vec<String>, allow_drv: bool) -> Result<Vec<String>> {
    let paths = if paths.is_empty() {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            bail!("No store paths given; pass them as arguments or on stdin");
        }
        std::io::read_to_string(stdin)?
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    } else {
        paths
    };
    if paths.is_empty() {
        bail!("No store paths given on stdin");
    }
    let roots = paths
        .iter()
        .map(|p| nix::resolve(p))
        .collect::<Result<Vec<_>>>()?;
    if !allow_drv && let Some(drv) = roots.iter().find(|p| p.ends_with(".drv")) {
        bail!(
            "{drv} is a derivation, not a build output; push outputs from \
             nix build --print-out-paths, or pass --allow-drv to upload derivations"
        );
    }
    Ok(roots)
}

#[tokio::main]
async fn async_main() -> Result<()> {
    let cli = Cli::parse();
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("off,snowstead=debug")
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
    }
    run(cli).await
}

#[cfg_attr(snowstead_hotpath, hotpath::measure)]
async fn run(mut cli: Cli) -> Result<()> {
    // Validate command combinations before loading credentials or making requests.
    if let Command::Push {
        paths,
        allow_drv,
        resume,
        ..
    } = &mut cli.command
    {
        if let Some(id) = resume {
            api::segment(id)?;
        } else {
            *paths = push_roots(std::mem::take(paths), *allow_drv)?;
        }
    }
    match &cli.command {
        Command::Cache {
            command: CacheCommand::Create { protocols, .. },
        } if protocols.is_empty() => {
            bail!("cache create requires --protocols nix|go|sccache (comma-separated)")
        }
        Command::Cache {
            command:
                CacheCommand::Set {
                    protocols,
                    visibility,
                    ..
                },
        } if protocols.is_empty() && !visibility.private && !visibility.public => {
            bail!("cache set requires --private, --public, or --protocols")
        }
        _ => (),
    }
    if let Command::Cache {
        command: CacheCommand::Create { protocols, .. } | CacheCommand::Set { protocols, .. },
    } = &cli.command
    {
        let joined = protocols.join(",");
        if !joined.is_empty() {
            self::protocols(&joined).map_err(anyhow::Error::msg)?;
        }
    }
    match &cli.command {
        #[cfg(any(snowstead_hotpath, snowstead_local))]
        Command::Local(options) => return local::run(options).await,
        Command::Login(options) => return auth::login(options).await,
        Command::Logout => return auth::logout(cli.server.as_deref()),
        Command::Auth {
            command: AuthCommand::Status,
        } => return auth::status(cli.server.as_deref()),
        _ => (),
    }
    let json = cli.json;
    let server = config::server(cli.server.as_deref())?;
    let client = api::Client::new(&server)?;
    tracing::debug!(target: "snowstead", "Starting authenticated command");
    match cli.command {
        #[cfg(any(snowstead_hotpath, snowstead_local))]
        Command::Local(_) => unreachable!(),
        Command::Login(_) | Command::Auth { .. } | Command::Logout => unreachable!(),
        Command::Push {
            cache,
            paths,
            no_deps,
            allow_drv: _,
            resumable,
            resume,
            jobs,
            compression_level,
        } => {
            let progress = progress::Progress::new(json, cli.verbose);
            let options = push::Options {
                jobs,
                level: compression_level,
                progress: &progress,
            };
            // A push that stops early still reports what it had published.
            let (summary, stopped) = if resumable || resume.is_some() {
                let summary =
                    push_job::push(&client, &cache, paths, no_deps, resume.as_deref(), &options)
                        .await?;
                (summary, None)
            } else {
                let paths = if no_deps {
                    paths
                } else {
                    progress.phase("Resolving closure...");
                    let paths = nix::closure(&paths).await?;
                    progress.phase(&format!("Found {} paths in closure", paths.len()));
                    paths
                };
                progress.phase("Checking remote availability...");
                tracing::debug!(target: "snowstead", paths = paths.len(), jobs, compression_level, "Starting push");
                match push::push(&client, &cache, paths, &options).await {
                    Ok(summary) => (summary, None),
                    Err(push::Stopped {
                        partial: Some(summary),
                        error,
                    }) => (summary, Some(error)),
                    Err(push::Stopped {
                        partial: None,
                        error,
                    }) => return Err(error),
                }
            };
            let (state, message) = if summary.cancelled {
                ("idle", "Push cancelled")
            } else if summary.failed > 0 || stopped.is_some() {
                ("error", "Push failed")
            } else {
                ("done", "Push complete")
            };
            progress.finish(state, message);
            if json {
                println!("{}", serde_json::to_string(&summary)?);
            } else {
                println!(
                    "Done: {} pushed, {} skipped ({} served upstream), {} failed",
                    summary.pushed, summary.skipped, summary.upstream, summary.failed
                );
            }
            for error in &summary.errors {
                eprintln!("Error: {}: {}", error.path, error.message);
            }
            if let Some(error) = stopped {
                return Err(error);
            }
            if summary.failed > 0 {
                return Err(PartialPush.into());
            }
        }
        Command::Cache { command } => match command {
            CacheCommand::List => {
                let result = client.admin_get("/_api/v1/admin/caches").await?;
                for cache in result["caches"]
                    .as_array()
                    .context("Invalid cache list response")?
                {
                    println!(
                        "{}  {}  protocols={}  created={}",
                        text(cache, "name"),
                        if cache["private"] == true {
                            "private"
                        } else {
                            "public"
                        },
                        list(cache, "protocols"),
                        text(cache, "createdAt")
                    );
                }
            }
            CacheCommand::Create {
                name,
                protocols,
                visibility,
            }
            | CacheCommand::Set {
                name,
                protocols,
                visibility,
            } => {
                let mut body = json!({"name": name});
                if visibility.private || visibility.public {
                    body["private"] = json!(visibility.private);
                }
                if !protocols.is_empty() {
                    body["protocols"] = json!(csv(&protocols.join(",")));
                }
                let result = client.admin_post("/_api/v1/admin/caches", body).await?;
                let action = if result["created"] == true {
                    "created"
                } else if result["changed"] == true {
                    "updated"
                } else {
                    "already exists"
                };
                println!(
                    "Cache '{}' {action} ({}; protocols={})",
                    text(&result, "name"),
                    if result["private"] == true {
                        "private"
                    } else {
                        "public"
                    },
                    list(&result, "protocols")
                );
            }
        },
        Command::Token { command } => match command {
            TokenCommand::Create {
                subject,
                caches,
                perms,
                expires,
            } => {
                let result = client.admin_post("/_api/v1/admin/tokens", json!({"subject": subject, "caches": csv(&caches), "perms": csv(&perms), "expiresInDays": expires})).await?;
                println!(
                    "Token created for '{}'\n  JTI:     {}\n  Caches:  {}\n  Perms:   {}\n  Expires: {}\n\n{}",
                    text(&result, "subject"),
                    text(&result, "jti"),
                    list(&result, "caches"),
                    list(&result, "perms"),
                    expiry(&result),
                    text(&result, "token")
                );
            }
            TokenCommand::List => {
                let result = client.admin_get("/_api/v1/admin/tokens").await?;
                let tokens = result["tokens"]
                    .as_array()
                    .context("Invalid token list response")?;
                if tokens.is_empty() {
                    println!("No tokens found");
                }
                for token in tokens {
                    let status = token["revokedAt"]
                        .as_str()
                        .map(|s| format!("revoked ({s})"))
                        .unwrap_or_else(|| "active".into());
                    println!(
                        "{}  {}  [{}]  caches=[{}]  {}  expires={}",
                        text(token, "jti"),
                        text(token, "subject"),
                        list(token, "perms"),
                        list(token, "caches"),
                        status,
                        expiry(token)
                    );
                }
            }
            TokenCommand::Revoke { jti, reason } => {
                // Restrict this path component instead of allowing path/query injection.
                if !jti
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    || jti.is_empty()
                {
                    bail!("Invalid token JTI");
                }
                client
                    .admin_post(
                        &format!("/_api/v1/admin/tokens/{jti}/revoke"),
                        json!({"reason": reason.join(" ")}),
                    )
                    .await?;
                println!("Token {jti} revoked");
            }
        },
    }
    Ok(())
}
