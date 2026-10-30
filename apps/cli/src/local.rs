//! Development-only, sequential local pipeline: no HTTP client or credentials.
use crate::{nar, nix};
use anyhow::{Result, ensure};
use clap::Args;
use serde_json::json;
use std::{path::Path, time::Instant};

#[derive(Args)]
pub struct Options {
    #[arg(required_unless_present = "closure", conflicts_with = "closure")]
    paths: Vec<String>,
    #[arg(long)]
    closure: Option<String>,
    /// Measured passes after one unreported warm-up pass.
    #[arg(long, default_value = "5", value_parser = crate::positive)]
    rounds: usize,
    /// Use nix-store --dump, with the same Zig hashing/compression into io::sink.
    #[arg(long)]
    upstream: bool,
    /// Zero measures raw NAR serialization and hashing without compression.
    #[arg(long, default_value = "3", value_parser = clap::value_parser!(i32).range(0..=19))]
    compression_level: i32,
    /// Additional zstd workers per path; zero runs on the producer thread.
    #[arg(long, default_value = "0", value_parser = clap::value_parser!(i32).range(0..=4))]
    threads: i32,
}

pub async fn run(options: &Options) -> Result<()> {
    let start = Instant::now();
    let mut paths = match &options.closure {
        Some(root) => nix::closure(&[nix::resolve(root)?]).await?,
        None => options
            .paths
            .iter()
            .map(|p| nix::resolve(p))
            .collect::<Result<Vec<_>>>()?,
    };
    paths.sort();
    paths.dedup();
    let resolve_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let infos = nix::path_infos(&paths).await?;
    println!(
        "{}",
        json!({"stage": "metadata", "paths": paths.len(), "resolveMs": resolve_ms,
        "metadataMs": start.elapsed().as_secs_f64() * 1000.0,
        "narBytes": infos.values().map(|i| i.nar_size).sum::<u64>()})
    );

    // Hotpath reports include warm-up; throughput rows below do not.
    for round in 0..=options.rounds {
        let start = Instant::now();
        let mut nar_bytes = 0u64;
        let mut file_bytes = 0u64;
        for path in &paths {
            let info = &infos[path];
            let encode = if options.upstream {
                nar::dump_nix
            } else {
                nar::dump
            };
            let digest = encode(
                Path::new(path),
                info.nar_size,
                options.compression_level,
                options.threads,
                &mut std::io::sink(),
            )?;
            ensure!(
                digest.nar_size == info.nar_size
                    && Some(digest.nar_hash) == nar::parse_hash(&info.nar_hash),
                "NAR differs from Nix metadata for {path}"
            );
            nar_bytes += digest.nar_size;
            file_bytes += digest.file_size;
        }
        let seconds = start.elapsed().as_secs_f64();
        if round > 0 {
            println!(
                "{}",
                json!({"stage": "prepare", "round": round,
                "encoder": if options.upstream { "nix-store" } else { "native" },
                "level": options.compression_level, "threads": options.threads,
                "paths": paths.len(), "narBytes": nar_bytes, "fileBytes": file_bytes,
                "seconds": seconds, "mbPerSecond": nar_bytes as f64 / 1e6 / seconds})
            );
        }
    }
    Ok(())
}
