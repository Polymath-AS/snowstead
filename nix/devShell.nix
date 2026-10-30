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
    # The GOCACHEPROG helper and real Terraform build gate.
    pkgs.go
    pkgs.stdenv.cc
    pkgs.time
    # Tests run against a throwaway cluster (scripts/with-postgres.sh).
    pkgs.postgresql
    # scripts/load-test.sh
    pkgs.oha
    pkgs.jq
  ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.poop ];
}
