{
  description = "Snowstead – Cloudflare-native Nix binary cache";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
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
      packages = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          pname = "snowstead";
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
            pnpm --filter @snowstead/cli exec tsc
          '';

          installPhase = ''
            mkdir -p $out/lib/snowstead $out/bin

            # Copy the full workspace structure so pnpm symlinks resolve
            cp -r apps $out/lib/snowstead/apps
            cp -r packages $out/lib/snowstead/packages
            cp -r workers $out/lib/snowstead/workers
            cp -r node_modules $out/lib/snowstead/node_modules
            cp package.json $out/lib/snowstead/package.json

            makeWrapper ${pkgs.nodejs_22}/bin/node $out/bin/snowstead \
              --add-flags "$out/lib/snowstead/apps/cli/dist/main.js" \
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
            # Tests run against a throwaway cluster (scripts/with-postgres.sh).
            pkgs.postgresql
            # scripts/load-test.sh
            pkgs.oha
            pkgs.jq
          ];
        };
      });

      checks = forAllSystems (pkgs: {
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
