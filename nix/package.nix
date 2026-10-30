{
  lib,
  rustPlatform,
  zig_0_17,
  pkg-config,
  makeWrapper,
  zstd,
  nix,
  src,
}:

rustPlatform.buildRustPackage {
  pname = "snowstead";
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
        || rel == "pkg" || rel == "pkg/nix-archive" || lib.hasPrefix "pkg/nix-archive/" rel);
  };

  cargoLock.lockFile = ../Cargo.lock;
  nativeBuildInputs = [ zig_0_17 pkg-config makeWrapper ];
  buildInputs = [ zstd ];
  nativeCheckInputs = [ nix ];
  ZSTD_SYS_USE_PKG_CONFIG = "1";
  dontUseZigBuild = true;
  dontUseZigCheck = true;
  dontUseZigInstall = true;

  postInstall = ''
    wrapProgram $out/bin/snowstead --prefix PATH : ${lib.makeBinPath [ nix ]}
  '';
  meta.mainProgram = "snowstead";
}
