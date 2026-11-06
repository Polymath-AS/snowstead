{
  lib,
  pkgs,
  serverPackage,
  inventory,
  ...
}:
let
  # Keep one source for the tested nginx configuration and hardened units.
  # NixOS owns their installation/lifecycle; snowstead-activate is never run.
  bundle = import ../bundle.nix { inherit pkgs serverPackage inventory; };
in
{
  users.groups.snowstead = { };
  users.groups.snowstead-proxy = { };
  users.users.snowstead = {
    isSystemUser = true;
    group = "snowstead";
  };
  users.users.snowstead-proxy = {
    isSystemUser = true;
    group = "snowstead-proxy";
  };
  systemd.tmpfiles.rules = [ "d /etc/snowstead 0700 root root -" ];
  systemd.packages = [ bundle ];
  systemd.services.snowstead = {
    enable = inventory.deploymentReady;
    wantedBy = [ "multi-user.target" ];
    restartTriggers = [ bundle ];
    serviceConfig.ExecStartPost = "${pkgs.curl}/bin/curl --fail --silent --show-error --retry 20 --retry-all-errors --retry-delay 1 --retry-max-time 90 --max-time 5 http://127.0.0.1:8080/healthz";
  };
  systemd.services.snowstead-proxy = {
    enable = inventory.deploymentReady;
    wantedBy = [ "multi-user.target" ];
    restartTriggers = [ bundle ];
  };
  # Encrypted runtime files are optional during host bootstrap. Provision or
  # encrypt the files before enabling the application; never embed plaintext.
  age.identityPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];
  age.secrets =
    lib.mapAttrs'
      (
        name: _:
        lib.nameValuePair "snowstead-${name}" {
          file = ../secrets + "/${name}.age";
          path = "/etc/snowstead/${name}";
          mode = "0600";
        }
      )
      (
        lib.filterAttrs (name: _: builtins.pathExists (../secrets + "/${name}.age")) {
          environment = null;
          migration = null;
          origin-certificate = null;
          origin-key = null;
          origin-client-ca = null;
        }
      );
  systemd.services.snowstead.after = [ "agenix.service" ];
  systemd.services.snowstead-proxy.after = [ "agenix.service" ];
}
