#!/usr/bin/env bash
# Read-only host checks and optional encrypted recovery backup. Never installs.
set -euo pipefail
umask 077
if [[ $# -gt 1 || ${1:-} == -* ]]; then
  echo 'Usage: bash infra/prepare-nixos.sh [private-backup.tar.gz.age]' >&2
  exit 2
fi
host=$(nix eval --raw .#deploy.nodes.staging.hostname)
ssh=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 "deploy@$host")
"${ssh[@]}" 'set -eu
  sudo -n true
  uname -srm
  free -m
  lsblk -b -o NAME,SIZE,TYPE,MOUNTPOINTS
  test ! -d /sys/firmware/efi
  test -b /dev/vda
  sudo -n test -s /etc/ssh/ssh_host_ed25519_key
  sudo -n test -s /var/lib/tailscale/tailscaled.state
  sudo -n test -d /etc/snowstead
  echo "BIOS disk, sudo, SSH identity, and Tailscale state checked."
'
if [[ $# == 1 ]]; then
  output=$1
  [[ ! -e $output ]] || { echo 'Refusing to overwrite a backup.' >&2; exit 1; }
  recipient=$(nix eval --raw .#nixosConfigurations.staging.config.users.users.deploy.openssh.authorizedKeys.keys --apply builtins.head)
  temporary=$(mktemp "${output}.tmp.XXXXXX")
  trap 'rm -f -- "$temporary"' EXIT
  # Only encrypted bytes reach disk here; never put these files in the store.
  "${ssh[@]}" 'sudo -n tar -C / -czf - etc/ssh etc/snowstead var/lib/tailscale/tailscaled.state home/deploy/.ssh' \
    | age --recipient "$recipient" > "$temporary"
  # Atomic no-clobber publish, including when another process creates output.
  ln -- "$temporary" "$output"
  echo "Encrypted recovery backup: $output"
fi
echo 'Preparation only: VPS size, installed OS, runtime secrets, DNS, and traffic are unchanged.'
