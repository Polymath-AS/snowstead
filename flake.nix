{
  description = "Snowstead – Cloudflare-native Nix binary cache";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Keep the native CLI toolchain separate from the existing Worker tooling.
    nixpkgs-cli.url = "github:NixOS/nixpkgs/a7868a727837f3c09cee2ce0ca671c76b1589fed";
    nixpkgs-host.url = "github:NixOS/nixpkgs/nixos-26.05";
    deploy-rs = {
      url = "github:serokell/deploy-rs";
      inputs.nixpkgs.follows = "nixpkgs-host";
    };
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs-host";
    };
    ragenix = {
      url = "github:yaxitech/ragenix";
      inputs.nixpkgs.follows = "nixpkgs-host";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-cli,
      nixpkgs-host,
      deploy-rs,
      disko,
      ragenix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});
      hosts = import ./infra/hosts.nix;

      pnpmDepsFor =
        pkgs:
        pkgs.fetchPnpmDeps {
          pname = "snowstead";
          version = "0.0.0";
          src = self;
          hash = "sha256-c2eVjvCOW9LKHfltidqcRxQodg+4bXeU+2WwX1XTnjE=";
          fetcherVersion = 3;
        };
    in
    {
      nixosConfigurations.staging = nixpkgs-host.lib.nixosSystem {
        system = "x86_64-linux";
        specialArgs = {
          inventory = hosts.staging;
          serverPackage = self.packages.x86_64-linux.server;
        };
        modules = [
          disko.nixosModules.disko
          ragenix.nixosModules.default
          ./infra/hosts/staging/configuration.nix
        ];
      };

      deploy.nodes = nixpkgs.lib.mapAttrs (name: inventory: {
        hostname = inventory.address;
        sshUser = "deploy";
        sshOpts = [
          "-o"
          "BatchMode=yes"
          "-o"
          "StrictHostKeyChecking=yes"
        ];
        user = "root";
        magicRollback = true;
        autoRollback = true;
        activationTimeout = 360;
        confirmTimeout = 60;
        remoteBuild = false;
        profiles.service.path =
          deploy-rs.lib.x86_64-linux.activate.custom self.packages.x86_64-linux."${name}-bundle"
            "$PROFILE/bin/snowstead-activate";
      }) { staging = hosts.staging; };

      # Machine-readable deployment preflight. Unconfigured inventory fails closed.
      deploymentReady = nixpkgs.lib.mapAttrs (
        name: host:
        # The initial Rust slice is not a hosted-service replacement. Removing
        # this production gate requires verified protocol/operational parity.
        name != "production"
        && host.deploymentReady
        && !(nixpkgs.lib.hasSuffix ".invalid" host.address)
        && !(nixpkgs.lib.hasSuffix ".invalid" host.hostname)
        && builtins.match "[a-zA-Z0-9.-]+" host.hostname != null
        && !(nixpkgs.lib.hasSuffix ".invalid" host.publicHostname)
        && builtins.match "[a-zA-Z0-9.-]+" host.publicHostname != null
      ) hosts;

      packages = forAllSystems (
        host:
        let
          pkgs = nixpkgs-cli.legacyPackages.${host.stdenv.hostPlatform.system};
        in
        rec {
          default = pkgs.callPackage ./nix/package.nix { src = self; };
          server = pkgs.callPackage ./nix/server.nix { src = self; };

          server-observability = server.overrideAttrs (old: {
            pname = "snowstead-server-observability";
            cargoBuildFlags = old.cargoBuildFlags ++ [
              "--features"
              "observability"
            ];
            cargoTestFlags = old.cargoTestFlags ++ [
              "--features"
              "observability"
            ];
          });

          server-hotpath = server.overrideAttrs (old: {
            pname = "snowstead-server-hotpath";
            cargoBuildFlags = old.cargoBuildFlags ++ [
              "--features"
              "profiling"
            ];
            cargoTestFlags = old.cargoTestFlags ++ [
              "--features"
              "profiling"
            ];
            RUST_MIN_STACK = "16777216";
          });

          hotpath = default.overrideAttrs (old: {
            pname = "snowstead-hotpath";
            cargoBuildFlags = [
              "--example"
              "snowstead"
            ];
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
            meta = old.meta // {
              mainProgram = "snowstead";
            };
          });
        }
        // nixpkgs.lib.optionalAttrs (host.stdenv.hostPlatform.system == "x86_64-linux") (
          (nixpkgs.lib.mapAttrs' (name: inventory: {
            name = "${name}-bundle";
            value = import ./infra/bundle.nix {
              pkgs = nixpkgs-host.legacyPackages.x86_64-linux;
              serverPackage = self.packages.x86_64-linux.server;
              inherit inventory;
            };
          }) hosts)
        )
      );

      devShells = forAllSystems (pkgs: {
        default = import ./nix/devShell.nix {
          inherit pkgs;
          cliPkgs = nixpkgs-cli.legacyPackages.${pkgs.stdenv.hostPlatform.system};
        };
        infra = pkgs.mkShell {
          packages = [
            deploy-rs.packages.${pkgs.stdenv.hostPlatform.system}.default
            ragenix.packages.${pkgs.stdenv.hostPlatform.system}.default
            pkgs.age
            pkgs.openssh
            pkgs.jq
          ];
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
              # Domain package: full check (tsc + unit tests)
              pnpm --filter @snowstead/cache-domain check

              # Services: type-check only (integration tests need workerd/Postgres).
              pnpm --filter @snowstead/cache-core --filter './workers/*' --filter '!@snowstead/server' exec tsc --noEmit
            '';

            installPhase = ''
              touch $out
            '';
          };
        }
        // nixpkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          deployment = (deploy-rs.lib.x86_64-linux.deployChecks self.deploy).deploy-schema;
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
