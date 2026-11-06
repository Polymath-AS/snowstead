{ lib, rustPlatform, zig_0_17, pkg-config, zstd, cacert, src }:

rustPlatform.buildRustPackage {
  pname = "snowstead-server";
  version = "0.1.0";
  src = lib.cleanSourceWith {
    inherit src;
    filter = path: type:
      let
        rel = lib.removePrefix "${toString src}/" (toString path);
        top = builtins.head (lib.splitString "/" rel);
      in
      lib.cleanSourceFilter path type
      && !(builtins.elem (baseNameOf path) [ "node_modules" "target" ".zig-cache" "zig-out" ])
      && (builtins.elem top [ "Cargo.toml" "Cargo.lock" "LICENSE" ]
        || rel == "apps" || rel == "apps/cli" || lib.hasPrefix "apps/cli/" rel
        || rel == "workers" || rel == "workers/server" || lib.hasPrefix "workers/server/" rel
        || rel == "pkg" || rel == "pkg/nix-archive" || lib.hasPrefix "pkg/nix-archive/" rel
        || rel == "pkg/snitch" || lib.hasPrefix "pkg/snitch/" rel);
  };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "--package" "snowstead-server" ];
  # Database contract tests run separately with scripts/with-postgres.sh.
  cargoTestFlags = [ "--package" "snowstead-server" "--lib" ];
  nativeBuildInputs = [ zig_0_17 pkg-config ];
  buildInputs = [ zstd ];
  SQLX_OFFLINE = "true";
  SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  ZSTD_SYS_USE_PKG_CONFIG = "1";
  dontUseZigBuild = true;
  dontUseZigCheck = true;
  dontUseZigInstall = true;
  meta.mainProgram = "snowstead-server";
}
