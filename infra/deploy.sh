#!/usr/bin/env bash
set -euo pipefail

target=${1:-}
case "$target" in
  staging) ;;
  *) echo 'Usage: infra/deploy.sh staging [--migrate]' >&2; exit 2 ;;
esac
if [[ $# -gt 2 || (${2:-} != '' && ${2:-} != --migrate) ]]; then
  echo 'Only --migrate is supported; ledger rebaselining is a separate operator action.' >&2
  exit 2
fi
if [[ $(nix eval --json ".#deploymentReady.$target") != true ]]; then
  echo "$target inventory is not configured; refusing deployment." >&2
  exit 1
fi
if ! git diff --quiet HEAD -- || [[ -n $(git ls-files --others --exclude-standard) ]]; then
  echo 'Deploy only a clean, committed checkout.' >&2
  exit 1
fi

export NIX_SSHOPTS='-o BatchMode=yes -o StrictHostKeyChecking=yes'
host=$(nix eval --raw ".#deploy.nodes.$target.hostname")
if ! ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "deploy@$host" \
  '. /etc/os-release; test "$ID" = ubuntu && test -d /run/systemd/system && systemctl is-active --quiet nix-daemon.service && sudo -n true'; then
  echo 'Target must be bootstrapped Ubuntu with an active Nix daemon and operator sudo.' >&2
  exit 1
fi
closure=$(nix build --no-link --print-out-paths ".#deploy.nodes.$target.profiles.service.path")
# This locally built closure is unsigned. Match deploy-rs's copy policy for
# this trusted SSH destination; do not disable verification for substituters.
nix copy --no-check-sigs --to "ssh-ng://deploy@$host" "$closure"

# Verify access and runtime files before touching the schema or activating.
# SSH host keys must already be pinned by the operator or protected CI job.
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "deploy@$host" \
  'sudo -n test -s /etc/snowstead/environment && sudo -n test -s /etc/snowstead/origin-certificate && sudo -n test -s /etc/snowstead/origin-key && sudo -n test -s /etc/snowstead/origin-client-ca'

if [[ ${2:-} == --migrate ]]; then
  server=$(nix build --no-link --print-out-paths .#server)
  nix copy --no-check-sigs --to "ssh-ng://deploy@$host" "$server"
  # Run the candidate binary with separate DDL credentials, never the current
  # binary or the runtime role. Failure stops deployment; no down migrations.
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "deploy@$host" \
    "sudo -n systemd-run --unit=snowstead-migrate --wait --collect --pipe --property=Type=exec --property=User=snowstead --property=Group=snowstead --property=EnvironmentFile=/etc/snowstead/migration --property=Environment=DATABASE_MAX_CONNECTIONS=1 --property=NoNewPrivileges=yes --property=ProtectSystem=strict --property=ProtectHome=yes --property=PrivateTmp=yes '$server/bin/snowstead-server' migrate"
fi

# Activation contains readiness checks, so failure triggers deploy-rs rollback.
# The named checks have already run in CI; do not rerun unrelated flake checks.
deploy --skip-checks ".#$target"
