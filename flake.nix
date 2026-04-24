{
  description = "Helios – Cloudflare-native Nix binary cache";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});

      pnpmDepsFor = pkgs: pkgs.fetchPnpmDeps {
        pname = "helios";
        version = "0.0.0";
        src = self;
        hash = "sha256-FsWEGFPLmT7jU7QIv2FGqVHOdNMUqvqmnWmog2Wpfuw=";
        fetcherVersion = 3;
      };
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          pname = "helios";
          version = "0.0.0";
          src = self;

          nativeBuildInputs = [
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.pnpmConfigHook
            pkgs.makeWrapper
          ];

          pnpmDeps = pnpmDepsFor pkgs;

          buildPhase = ''
            pnpm --filter @helios/cli exec tsc
          '';

          installPhase = ''
            mkdir -p $out/lib/helios $out/bin

            # Copy the full workspace structure so pnpm symlinks resolve
            cp -r apps $out/lib/helios/apps
            cp -r packages $out/lib/helios/packages
            cp -r workers $out/lib/helios/workers
            cp -r node_modules $out/lib/helios/node_modules
            cp package.json $out/lib/helios/package.json

            makeWrapper ${pkgs.nodejs_22}/bin/node $out/bin/helios \
              --add-flags "$out/lib/helios/apps/cli/dist/main.js" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nix pkgs.zstd ]}
          '';
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.wrangler
          ];
        };
      });

      checks = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          name = "helios-check";
          src = self;

          nativeBuildInputs = [
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.pnpmConfigHook
          ];

          pnpmDeps = pnpmDepsFor pkgs;

          buildPhase = ''
            # Domain package: full check (tsc + unit tests)
            pnpm --filter @helios/cache-domain check

            # Worker: type-check only (integration tests need workerd runtime)
            pnpm --filter @helios/cache-worker exec tsc --noEmit
          '';

          installPhase = ''
            touch $out
          '';
        };
      });
    };
}
