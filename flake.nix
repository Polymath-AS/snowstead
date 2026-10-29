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
        default = pkgs.stdenvNoCC.mkDerivation {
          pname = "snowstead";
          version = "0.0.0";
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = ./apps/cli/src;
          };

          nativeBuildInputs = [
            pkgs.esbuild
            pkgs.makeWrapper
          ];

          buildPhase = ''
            runHook preBuild
            # The CLI has only Node built-ins at runtime; domain imports are types.
            esbuild apps/cli/src/main.ts --bundle --platform=node --format=esm \
              --target=node22 --outfile=dist/main.js
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib/snowstead $out/bin
            cp dist/main.js $out/lib/snowstead/main.mjs

            makeWrapper ${pkgs.nodejs-slim_22}/bin/node $out/bin/snowstead \
              --add-flags "$out/lib/snowstead/main.mjs" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.zstd ]}
            runHook postInstall
          '';

          doInstallCheck = true;
          installCheckPhase = ''
            runHook preInstallCheck
            $out/bin/snowstead --help
            runHook postInstallCheck
          '';
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.wrangler
            # The GOCACHEPROG helper and real Terraform build gate.
            pkgs.go
            pkgs.stdenv.cc
            pkgs.time
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
