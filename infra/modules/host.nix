{
  config,
  lib,
  pkgs,
  ...
}:
let
  cloudflare = builtins.fromJSON (builtins.readFile ../cloudflare-ips.json);
in
{
  options.services.snowstead-host.operatorKeys = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    description = "SSH public keys authorized for the deployment user.";
  };
  config = {
    nix.settings = {
      experimental-features = [
        "nix-command"
        "flakes"
      ];
      trusted-users = [
        "root"
        "deploy"
      ];
      max-jobs = 0; # Build on the operator's machine, never on this VPS.
    };
    nix.gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 30d";
    };
    users.mutableUsers = false;
    users.users.deploy = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = config.services.snowstead-host.operatorKeys;
    };
    security.sudo.wheelNeedsPassword = false;
    services.openssh = {
      enable = true;
      openFirewall = false;
      settings = {
        AllowUsers = [ "deploy" ];
        PermitRootLogin = "no";
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        AllowTcpForwarding = false;
        AllowStreamLocalForwarding = false;
        X11Forwarding = false;
        AllowAgentForwarding = false;
        PermitTunnel = "no";
      };
    };
    services.tailscale.enable = true;
    networking.nftables.enable = true;
    networking.firewall = {
      enable = true;
      allowedUDPPorts = [ 41641 ];
      interfaces.tailscale0.allowedTCPPorts = [ 22 ];
      extraInputRules = ''
        ip saddr { ${lib.concatStringsSep ", " cloudflare.ipv4_cidrs} } tcp dport 443 accept
        ip6 saddr { ${lib.concatStringsSep ", " cloudflare.ipv6_cidrs} } tcp dport 443 accept
      '';
    };
    environment.etc."systemd/journald.conf.d/10-snowstead.conf".text = ''
      [Journal]
      SystemMaxUse=64M
      RuntimeMaxUse=16M
    '';
    boot.kernel.sysctl."vm.swappiness" = 10;
    environment.systemPackages = [
      pkgs.curl
      pkgs.htop
    ];
    time.timeZone = "UTC";
  };
}
