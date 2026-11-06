#!/usr/bin/env bash
set -euo pipefail

# Run after bootstrap and Tailscale enrollment, from an existing tailnet SSH
# session. Requires a second session to verify access and cancel rollback.
[[ $EUID == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
source_dir=$(dirname "$(readlink -f "$0")")
for command in nft tailscale python3 sshd; do command -v "$command" >/dev/null; done
id deploy >/dev/null
sudo -n -u deploy test -s /home/deploy/.ssh/authorized_keys
tailscale_ip=$(tailscale ip -4)
tailscale_ip6=$(tailscale ip -6)
python3 - "$tailscale_ip" "$tailscale_ip6" <<'PY'
import ipaddress, sys
assert ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network('100.64.0.0/10')
assert ipaddress.ip_address(sys.argv[2]) in ipaddress.ip_network('fd7a:115c:a1e0::/48')
PY
if systemctl is-active --quiet snowstead-hardening-rollback.timer; then
  echo 'A hardening rollback is already armed; verify or roll it back first.' >&2
  exit 1
fi

backup=/var/backups/snowstead-host/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$backup"
files=(
  /etc/ssh/sshd_config.d/00-snowstead.conf
  /etc/systemd/system/ssh.socket.d/99-snowstead.conf
  /etc/snowstead-host/firewall.nft
  /usr/local/sbin/snowstead-firewall
  /etc/systemd/system/snowstead-firewall.service
)
printf '%s\n' "${files[@]}" > "$backup/files"
for file in "${files[@]}"; do
  if [[ -e $file ]]; then
    mkdir -p "$backup$(dirname "$file")"
    cp -a "$file" "$backup$file"
  fi
done
systemctl is-enabled snowstead-firewall.service > "$backup/firewall-enabled" 2>/dev/null || true
nft list table inet snowstead > "$backup/firewall-previous.nft" 2>/dev/null || true
cat > "$backup/rollback" <<'SH'
#!/usr/bin/env bash
set -eu
backup=$(dirname "$(readlink -f "$0")")
systemctl disable --now snowstead-firewall.service || true
nft delete table inet snowstead 2>/dev/null || true
while IFS= read -r file; do
  if [[ -e $backup$file ]]; then cp -a "$backup$file" "$file"; else rm -f "$file"; fi
done < "$backup/files"
if [[ -s $backup/firewall-previous.nft ]]; then nft -f "$backup/firewall-previous.nft"; fi
systemctl daemon-reload
if grep -qx enabled "$backup/firewall-enabled"; then systemctl enable --now snowstead-firewall.service; fi
/usr/sbin/sshd -t
systemctl restart ssh.socket
systemctl restart ssh.service
SH
chmod 0700 "$backup/rollback"
systemd-run --collect --unit=snowstead-hardening-rollback --on-active=5m "$backup/rollback"
trap 'echo "Hardening failed; running rollback." >&2; "$backup/rollback"' ERR

install -d -m 0755 /etc/snowstead-host /etc/ssh/sshd_config.d /etc/systemd/system/ssh.socket.d
python3 - "$source_dir/cloudflare-ips.json" > /etc/snowstead-host/firewall.nft <<'PY'
import ipaddress, json, sys
ranges = json.load(open(sys.argv[1]))
for version, key in [(4, 'ipv4_cidrs'), (6, 'ipv6_cidrs')]:
    assert ranges[key]
    for cidr in ranges[key]:
        net = ipaddress.ip_network(cidr)
        assert net.version == version and net.prefixlen > 0
print('table inet snowstead {')
for name, key, kind in [('cloudflare4', 'ipv4_cidrs', 'ipv4_addr'), ('cloudflare6', 'ipv6_cidrs', 'ipv6_addr')]:
    print(f'  set {name} {{ type {kind}; flags interval; elements = {{ ' + ', '.join(ranges[key]) + ' }; }')
print('''  chain input {
    type filter hook input priority -10; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    meta l4proto { icmp, ipv6-icmp } accept
    udp dport 41641 accept
    iifname "tailscale0" tcp dport 22 accept
    ip saddr @cloudflare4 tcp dport 443 accept
    ip6 saddr @cloudflare6 tcp dport 443 accept
  }
  chain forward {
    type filter hook forward priority -10; policy drop;
  }
}''')
PY
cat > /usr/local/sbin/snowstead-firewall <<'SH'
#!/usr/bin/env bash
set -euo pipefail
rules=$(mktemp)
trap 'rm -f "$rules"' EXIT
if /usr/sbin/nft list table inet snowstead >/dev/null 2>&1; then
  echo 'delete table inet snowstead' > "$rules"
fi
cat /etc/snowstead-host/firewall.nft >> "$rules"
/usr/sbin/nft --check -f "$rules"
/usr/sbin/nft -f "$rules"
SH
chmod 0755 /usr/local/sbin/snowstead-firewall
cat > /etc/systemd/system/snowstead-firewall.service <<'UNIT'
[Unit]
Description=Snowstead host firewall (preserves Tailscale-managed tables)
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target ssh.socket shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/snowstead-firewall
ExecReload=/usr/local/sbin/snowstead-firewall

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/ssh/sshd_config.d/00-snowstead.conf <<SSH
ListenAddress $tailscale_ip
ListenAddress $tailscale_ip6
PermitRootLogin no
AllowUsers deploy
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
MaxAuthTries 3
LoginGraceTime 30
SSH
cat > /etc/systemd/system/ssh.socket.d/99-snowstead.conf <<SOCKET
[Socket]
ListenStream=
ListenStream=$tailscale_ip:22
ListenStream=[$tailscale_ip6]:22
FreeBind=yes
SOCKET
/usr/sbin/sshd -t
systemctl daemon-reload
systemctl enable --now snowstead-firewall.service
systemctl reload snowstead-firewall.service
systemctl restart ssh.socket
systemctl restart ssh.service
echo "Hardening applied; rollback is armed for five minutes: $backup/rollback"
echo 'Verify NEW tailnet SSH, sudo, and Nix store access from a second session.'
echo 'Only then confirm: sudo systemctl stop snowstead-hardening-rollback.timer'
