{
  description = "Snowstead – Cloudflare-native Nix binary cache";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Keep the native CLI toolchain separate from the existing Worker tooling.
    nixpkgs-cli.url = "github:NixOS/nixpkgs/a7868a727837f3c09cee2ce0ca671c76b1589fed";
    crane.url = "github:ipetkov/crane";
    nixpkgs-host.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-cli,
      crane,
      nixpkgs-host,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});

      pnpmDepsFor =
        pkgs:
        pkgs.fetchPnpmDeps {
          pname = "snowstead";
          version = "0.0.0";
          src = self;
          hash = "sha256-VBIneLuePGMnxVgwWN4FFD6cLzJzt7SzPrjQYAE5hVI=";
          fetcherVersion = 3;
        };
    in
    {
      nixosModules = {
        host = import ./infra/modules/host.nix;
        server = import ./infra/modules/service.nix;
      };

      packages = forAllSystems (
        host:
        let
          pkgs = nixpkgs-cli.legacyPackages.${host.stdenv.hostPlatform.system};
          craneLib = crane.mkLib pkgs;
        in
        rec {
          default = pkgs.callPackage ./nix/package.nix {
            src = self;
            inherit craneLib;
          };
          server = pkgs.callPackage ./nix/server.nix {
            src = self;
            inherit craneLib;
          };

          server-hotpath = server.override { features = [ "profiling" ]; };
          hotpath = default.override { hotpath = true; };
        }
      );

      devShells = forAllSystems (pkgs: {
        default = import ./nix/devShell.nix {
          inherit pkgs;
          cliPkgs = nixpkgs-cli.legacyPackages.${pkgs.stdenv.hostPlatform.system};
        };
      });

      checks = forAllSystems (
        pkgs:
        {
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
              # Runtime integration tests run separately with disposable services.
              pnpm --filter @snowstead/gateway-worker check
            '';

            installPhase = ''
              touch $out
            '';
          };
        }
        // nixpkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          host = import ./infra/tests/host.nix {
            pkgs = nixpkgs-host.legacyPackages.x86_64-linux;
          };
          service = import ./infra/tests/server.nix {
            pkgs = nixpkgs-host.legacyPackages.x86_64-linux;
            serverPackage = self.packages.x86_64-linux.server;
          };
        }
      );
    };
}
