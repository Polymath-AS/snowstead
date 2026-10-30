{
  description = "Snowstead – Cloudflare-native Nix binary cache";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Keep the native CLI toolchain separate from the existing Worker tooling.
    nixpkgs-cli.url = "github:NixOS/nixpkgs/a7868a727837f3c09cee2ce0ca671c76b1589fed";
  };

  outputs = { self, nixpkgs, nixpkgs-cli }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});

      pnpmDepsFor = pkgs: pkgs.fetchPnpmDeps {
        pname = "snowstead";
        version = "0.0.0";
        src = self;
        hash = "sha256-c2eVjvCOW9LKHfltidqcRxQodg+4bXeU+2WwX1XTnjE=";
        fetcherVersion = 3;
      };
    in
    {
      packages = forAllSystems (host:
        let pkgs = nixpkgs-cli.legacyPackages.${host.stdenv.hostPlatform.system};
        in rec {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "snowstead";
          version = "0.1.0";
          src = pkgs.lib.cleanSourceWith {
            src = self;
            filter = path: type:
              let
                rel = pkgs.lib.removePrefix "${toString self}/" (toString path);
                top = builtins.head (pkgs.lib.splitString "/" rel);
              in
              pkgs.lib.cleanSourceFilter path type
              && !(builtins.elem (baseNameOf path) [ "node_modules" "target" ".zig-cache" "zig-out" ])
              && (builtins.elem top [ "Cargo.toml" "Cargo.lock" "LICENSE" ]
                || rel == "apps" || rel == "apps/cli" || pkgs.lib.hasPrefix "apps/cli/" rel
                || rel == "pkg" || rel == "pkg/nix-archive" || pkgs.lib.hasPrefix "pkg/nix-archive/" rel);
          };

          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.zig_0_17 pkgs.pkg-config pkgs.makeWrapper ];
          buildInputs = [ pkgs.zstd ];
          nativeCheckInputs = [ pkgs.nix ];
          ZSTD_SYS_USE_PKG_CONFIG = "1";
          dontUseZigBuild = true;
          dontUseZigCheck = true;
          dontUseZigInstall = true;

          postInstall = ''
            wrapProgram $out/bin/snowstead --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nix ]}
          '';
          meta.mainProgram = "snowstead";
        };

        hotpath = default.overrideAttrs (old: {
          pname = "snowstead-hotpath";
          cargoBuildFlags = [ "--example" "snowstead" ];
          env = old.env // {
            RUSTFLAGS = (old.env.RUSTFLAGS or "") + " --cfg snowstead_hotpath";
          };
          # This package builds only the profiling example; default runs the CLI tests.
          doCheck = false;
          installPhase = ''
            runHook preInstall
            install -Dm755 target/${pkgs.stdenv.targetPlatform.rust.cargoShortTarget}/release/examples/snowstead $out/bin/snowstead
            runHook postInstall
          '';
          meta = old.meta // { mainProgram = "snowstead"; };
        });
      });

      devShells = forAllSystems (pkgs:
        let cliPkgs = nixpkgs-cli.legacyPackages.${pkgs.stdenv.hostPlatform.system};
        in {
        default = pkgs.mkShell {
          ZSTD_SYS_USE_PKG_CONFIG = "1";
          packages = [
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.wrangler
            cliPkgs.cargo
            cliPkgs.rustc
            cliPkgs.clippy
            cliPkgs.rustfmt
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
        };
      });

      checks = forAllSystems (pkgs: {
        cli = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        default = pkgs.stdenv.mkDerivation {
          name = "snowstead-check";
          src = self;

          nativeBuildInputs = [
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.pnpmConfigHook
          ];

          pnpmDeps = pnpmDepsFor pkgs;

          buildPhase = ''
            # Domain package: full check (tsc + unit tests)
            pnpm --filter @snowstead/cache-domain check

            # Services: type-check only (integration tests need workerd/Postgres).
            pnpm --filter @snowstead/cache-core --filter './workers/*' exec tsc --noEmit
          '';

          installPhase = ''
            touch $out
          '';
        };
      });
    };
}
