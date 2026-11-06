#!/usr/bin/env bash
set -euo pipefail

# Run explicitly as root on an already provisioned systemd Linux host after
# installing Determinate Nix. Does not install an OS, touch disks or networking,
# install secrets, migrate databases, or start the application.
if [[ $EUID != 0 ]]; then
  echo 'Run bootstrap as root.' >&2
  exit 1
fi
test -d /run/systemd/system
test -x /nix/var/nix/profiles/default/bin/nix
for user in snowstead snowstead-proxy; do
  if ! getent group "$user" >/dev/null; then groupadd --system "$user"; fi
  if ! id "$user" >/dev/null 2>&1; then
    useradd --system --gid "$user" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$user"
  fi
done
install -d -o root -g root -m 0700 /etc/snowstead
echo 'Host directories and service users are ready. Install runtime secrets before deployment.'
