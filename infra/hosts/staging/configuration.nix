{ modulesPath, ... }:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    ./disk-config.nix
    ../../modules/host.nix
    ../../modules/service.nix
  ];
  networking = {
    hostName = "snowstead-service-fra1";
    useDHCP = false;
    usePredictableInterfaceNames = false;
    interfaces.eth0 = {
      ipv4.addresses = [
        {
          address = "164.90.237.106";
          prefixLength = 20;
        }
        {
          address = "10.19.0.5";
          prefixLength = 16;
        }
      ];
      ipv6.addresses = [
        {
          address = "2a03:b0c0:3:f0:0:3:3a73:e000";
          prefixLength = 64;
        }
      ];
    };
    interfaces.eth1.ipv4.addresses = [
      {
        address = "10.114.0.2";
        prefixLength = 20;
      }
    ];
    defaultGateway = {
      address = "164.90.224.1";
      interface = "eth0";
    };
    defaultGateway6 = {
      address = "2a03:b0c0:3:f0::1";
      interface = "eth0";
    };
    nameservers = [
      "1.1.1.1"
      "1.0.0.1"
    ];
  };
  boot.loader.grub.enable = true;
  boot.kernelParams = [ "console=ttyS0,115200n8" ];
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "sd_mod"
  ];
  nixpkgs.hostPlatform = "x86_64-linux";
  system.stateVersion = "26.05";
}
