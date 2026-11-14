{
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
  # Provision /etc/snowstead runtime files with the host's secret manager.
  # Consumers must add ordering for that manager when it writes at activation.
}
