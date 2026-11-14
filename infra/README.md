# Self-host deployment

This directory contains reusable standalone server units, a TLS proxy bundle,
host hardening modules, and isolated VM tests. It contains no hosted inventory
or provider resources. Supply your own machine configuration and inventory.

Build the standalone API with `nix build .#server`. Copy `examples/host.nix`
to your own configuration, set your hostnames and limits, and explicitly enable
`deploymentReady` only after provisioning and checking the host.

Import `bundle.nix` with `pkgs`, `serverPackage`, and your inventory to build
Ubuntu/systemd units and `snowstead-activate`. The activation command installs
the API and TLS proxy units and starts both. It does not run migrations.
`bootstrap.sh` creates service users and the runtime directory on an existing
systemd Linux host with Nix installed. Review `harden.sh` before use: it limits
SSH to Tailscale and HTTPS to Cloudflare ranges, with a timed rollback.

For NixOS, import `modules/host.nix` for the optional hardened machine baseline.
Set `services.snowstead-host.operatorKeys` to your own SSH public keys.
Import `modules/service.nix` with explicit `serverPackage` and `inventory`
module arguments for the standalone API and proxy. Do not combine these units
with another API service on port 8080. The host module uses a journald drop-in
so both the test input and newer nixpkgs releases can import it.

Provision root-owned mode-0600 files under `/etc/snowstead`: `environment`,
`migration`, `origin-certificate`, `origin-key`, and `origin-client-ca`.
The proxy requires a matching origin certificate and client CA for authenticated
origin pulls. Never embed secret values in Nix expressions or the Nix store.
Configure ordering in your machine module if your secret manager writes files
during activation. These modules do not discover encrypted files automatically.

Run `snowstead-server migrate` with separate database migration credentials
only after checking the target and backup. Before replacing a release, run the
candidate's `snowstead-server check-upload-cutover` with the runtime environment.
It must succeed before activation. See [cutover cautions](../docs.md#deployment).
Keep the previous package and a tested recovery procedure available.

`tests/server.nix` imports only example inventory. `tests/host.nix` checks the
generic host firewall and SSH policy on an isolated VM network. Neither test
uses live provider resources or hosted credentials.
