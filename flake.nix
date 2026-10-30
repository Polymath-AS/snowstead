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
        default = pkgs.callPackage ./nix/package.nix { src = self; };

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

      devShells = forAllSystems (pkgs: {
        default = import ./nix/devShell.nix {
          inherit pkgs;
          cliPkgs = nixpkgs-cli.legacyPackages.${pkgs.stdenv.hostPlatform.system};
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
