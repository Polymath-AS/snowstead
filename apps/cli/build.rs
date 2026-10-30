use std::{env, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let archive = root.join("../../pkg/nix-archive/src/root.zig");
    println!("cargo:rerun-if-changed=native");
    println!("cargo:rerun-if-changed=../../pkg/nix-archive");
    println!("cargo:rerun-if-env-changed=ZIG");
    let target = match env::var("TARGET").unwrap().as_str() {
        "x86_64-unknown-linux-gnu" => "x86_64-linux-gnu",
        "aarch64-unknown-linux-gnu" => "aarch64-linux-gnu",
        "x86_64-apple-darwin" => "x86_64-macos-none",
        "aarch64-apple-darwin" => "aarch64-macos-none",
        other => panic!("unsupported CLI target: {other}"),
    };
    let fast_cpu = if target.starts_with("x86_64") {
        "baseline+avx2+sha"
    } else {
        "baseline+sha2"
    };
    for (name, cpu) in [
        ("snowstead_nar", "baseline"),
        ("snowstead_nar_fast", fast_cpu),
    ] {
        let status = Command::new(env::var_os("ZIG").unwrap_or_else(|| "zig".into()))
            .args([
                "build-lib",
                "-static",
                "-OReleaseFast",
                "-fPIC",
                "-fomit-frame-pointer",
                "-fno-compiler-rt",
                "-lc",
                "-target",
                target,
            ])
            .arg(format!("-mcpu={cpu}"))
            .args(["--dep", "nix-archive"])
            .arg(format!("-Mroot={}", root.join("native/nar.zig").display()))
            .arg(format!("-mcpu={cpu}"))
            .arg(format!("-Mnix-archive={}", archive.display()))
            .arg(format!(
                "-femit-bin={}",
                out.join(format!("lib{name}.a")).display()
            ))
            .arg("--cache-dir")
            .arg(out.join("zig-cache"))
            .arg("--global-cache-dir")
            .arg(out.join("zig-global-cache"))
            .status()
            .expect("running Zig 0.17 (use nix develop)");
        assert!(status.success(), "building {name}");
        println!("cargo:rustc-link-lib=static={name}");
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    pkg_config::Config::new()
        .atleast_version("1.5")
        .probe("libzstd")
        .expect("libzstd (use nix develop)");
}
