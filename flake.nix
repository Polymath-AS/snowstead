{
  description = "Helios – Cloudflare-native Nix binary cache";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});
    in
    {
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

          pnpmDeps = pkgs.fetchPnpmDeps {
            pname = "helios";
            version = "0.0.0";
            src = self;
            hash = "sha256-kcyj1DbZfzUU8OyPh4vAjKEnJdEJwhEOBqqAZCaCCZI=";
            fetcherVersion = 3;
          };

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
