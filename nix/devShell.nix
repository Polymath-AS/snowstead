{ pkgs, cliPkgs }:

pkgs.mkShell {
  ZSTD_SYS_USE_PKG_CONFIG = "1";
  RUST_SRC_PATH = "${cliPkgs.rustPlatform.rustLibSrc}";
  packages = [
    pkgs.nodejs_22
    pkgs.pnpm
    pkgs.wrangler
    cliPkgs.cargo
    cliPkgs.rustc
    cliPkgs.clippy
    cliPkgs.rustfmt
    cliPkgs.rust-analyzer
    cliPkgs.zig_0_17
    pkgs.pkg-config
    pkgs.zstd
    # The GOCACHEPROG helper and real compiler-client checks.
    pkgs.go
    pkgs.sccache
    pkgs.stdenv.cc
    # Tests run against a throwaway cluster (scripts/with-postgres.sh).
    pkgs.postgresql
    # Disposable S3 endpoint for the R2-backed server's real-client tests.
    pkgs.minio
    pkgs.minio-client
    pkgs.jq
  ];
}
