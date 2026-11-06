{ ... }:
{
  # Confirmed on the current DigitalOcean Droplet: BIOS boot, virtio /dev/vda.
  # DESTRUCTIVE: only nixos-anywhere/disko installation applies this layout.
  disko.devices.disk.system = {
    type = "disk";
    device = "/dev/vda";
    imageSize = "10G"; # Match the real disk; Disko's 2G image default is too small.
    content = {
      type = "gpt";
      partitions = {
        boot = {
          size = "1M";
          type = "EF02";
        };
        swap = {
          size = "1G";
          content.type = "swap";
        };
        root = {
          size = "100%";
          content = {
            type = "filesystem";
            format = "ext4";
            mountpoint = "/";
          };
        };
      };
    };
  };
}
