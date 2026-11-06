{ lib, pkgs, ... }:
let
  cloudflare = builtins.fromJSON (builtins.readFile ../cloudflare-ips.json);
in
{
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
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKYZX17OSEH3mKJsP4oFuaGtr8F5TF/3/RXOCw2cBgps"
    ];
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
  services.journald.extraConfig = ''
    SystemMaxUse=64M
    RuntimeMaxUse=16M
  '';
  boot.kernel.sysctl."vm.swappiness" = 10;
  environment.systemPackages = [
    pkgs.curl
    pkgs.htop
  ];
  time.timeZone = "UTC";
}
