{ pkgs }:
pkgs.testers.runNixOSTest {
  name = "snowstead-host";
  nodes.machine = {
    imports = [ ../modules/host.nix ];
    virtualisation.memorySize = 512;
  };
  nodes.client = { pkgs, ... }: {
    environment.systemPackages = [ pkgs.netcat-openbsd ];
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("nftables.service")
    client.wait_for_unit("multi-user.target")
    # A reachable SSH listener must not be accessible on the public interface.
    machine.succeed("ss -ltn | grep ':22 '")
    client.fail("nc -z -w 2 machine 22")
    ssh_policy = machine.succeed("${pkgs.openssh}/bin/sshd -T -f /etc/ssh/sshd_config").lower().splitlines()
    assert "permitrootlogin no" in ssh_policy, ssh_policy
    assert "passwordauthentication no" in ssh_policy, ssh_policy
    machine.succeed("su -s /bin/sh deploy -c 'sudo -n true'")
    # Simulate tailnet ingress on the VM network without a live tailnet/key.
    # Rename its already-addressed NIC; the firewall matches interface names.
    machine.succeed("systemctl stop tailscaled; ip link set eth1 down; ip link set eth1 name tailscale0; ip link set tailscale0 up")
    client.succeed("nc -z -w 5 machine 22")
    # Exercise blocked ports against real listeners, not connection refusal.
    machine.succeed("systemd-run --unit=test-backend ${pkgs.python3}/bin/python3 -m http.server 8080 --bind 0.0.0.0")
    machine.wait_for_open_port(8080)
    machine.succeed("curl --fail http://127.0.0.1:8080/")
    client.fail("nc -z -w 2 machine 8080")
    machine.succeed("systemd-run --unit=test-origin ${pkgs.python3}/bin/python3 -m http.server 443 --bind 0.0.0.0")
    machine.wait_for_open_port(443)
    client.fail("nc -z -w 2 machine 443")
    # On this isolated VLAN, use an allowed source to distinguish an allowlist
    # from a broken configuration that simply blocks all HTTPS.
    client.succeed("ip addr add 173.245.48.1/32 dev eth1")
    machine.succeed("ip route add 173.245.48.1/32 via 192.168.1.1 dev tailscale0")
    client.succeed("nc -4 -s 173.245.48.1 -z -w 5 machine 443")
  '';
}
