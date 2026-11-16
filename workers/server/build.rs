use std::{env, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=proto");
    let mut proto = tonic_prost_build::Config::new();
    proto.protoc_executable(protoc_bin_vendored::protoc_bin_path().unwrap());
    let mut descriptors = proto
        .load_fds(
            &[
                root.join("proto/build/bazel/remote/execution/v2/remote_execution.proto"),
                root.join("proto/google/bytestream/bytestream.proto"),
            ],
            &[
                root.join("proto"),
                protoc_bin_vendored::include_path().unwrap(),
            ],
        )
        .expect("load Bazel remote cache protocol");
    // Upstream prose uses protobuf, not Rustdoc, markup. Keep its documentation
    // in the vendored sources without copying it into generated Rust APIs.
    for file in &mut descriptors.file {
        if let Some(info) = &mut file.source_code_info {
            for location in &mut info.location {
                location.leading_comments = None;
                location.trailing_comments = None;
                location.leading_detached_comments.clear();
            }
        }
    }
    tonic_prost_build::configure()
        .compile_fds_with_config(descriptors, proto)
        .expect("compile Bazel remote cache protocol");
    println!("cargo:rerun-if-changed=native");
    println!("cargo:rerun-if-changed=../../pkg/nix-archive");
    println!("cargo:rerun-if-changed=../../pkg/snitch");
    println!("cargo:rerun-if-env-changed=ZIG");
    let profiling = env::var_os("CARGO_FEATURE_PROFILING").is_some();
    std::fs::write(
        out.join("snitch_options.zig"),
        format!("pub const snitch = {profiling};\npub const snitch_timing = true;\npub const snitch_memory = true;\n"),
    ).unwrap();
    let target = match env::var("TARGET").unwrap().as_str() {
        "x86_64-unknown-linux-gnu" => "x86_64-linux-gnu",
        "aarch64-unknown-linux-gnu" => "aarch64-linux-gnu",
        "x86_64-apple-darwin" => "x86_64-macos-none",
        "aarch64-apple-darwin" => "aarch64-macos-none",
        other => panic!("unsupported server target: {other}"),
    };
    let fast_cpu = if target.starts_with("x86_64") {
        "baseline+avx2+sha"
    } else {
        "baseline+sha2"
    };
    for (name, cpu) in [
        ("snowstead_verify", "baseline"),
        ("snowstead_verify_fast", fast_cpu),
    ] {
        let status = Command::new(env::var_os("ZIG").unwrap_or_else(|| "zig".into()))
            .args([
                "build-lib",
                "-static",
                "-OReleaseSafe",
                "-fPIC",
                "-fcompiler-rt",
                "-lc",
                "-target",
                target,
            ])
            .arg(format!("-mcpu={cpu}"))
            .args(["--dep", "nix-archive", "--dep", "snitch"])
            .arg(format!(
                "-Mroot={}",
                root.join("native/verify.zig").display()
            ))
            .arg(format!("-mcpu={cpu}"))
            .args(["--dep", "snitch"])
            .arg(format!(
                "-Mnix-archive={}",
                root.join("../../pkg/nix-archive/src/root.zig").display()
            ))
            .args(["--dep", "build_options"])
            .arg(format!(
                "-Msnitch={}",
                root.join("../../pkg/snitch/src/snitch.zig").display()
            ))
            .arg(format!(
                "-Mbuild_options={}",
                out.join("snitch_options.zig").display()
            ))
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
