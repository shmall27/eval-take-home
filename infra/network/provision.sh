#!/usr/bin/env bash
# Provision the reusable range network fabric on the nested Proxmox node.
#
# Run this ON `vanilla` (copy infra/network/ there, or run from a checkout):
#     bash infra/network/provision.sh
#
# Idempotent and re-runnable. It:
#   1. pushes segments.json + node_build.sh into the Proxmox node and runs them
#      there (bridges vmbr2/3/4, offline-baked router + test images, router VM);
#   2. configures the router (IPs, DHCP+DNS, nftables) through the guest agent.
#
# No secrets are copied into the repo. The router root password is generated once
# and kept on vanilla at ~/cathedral/router-root-password (console debug only;
# the router has no network login path). The API token stays at
# ~/cathedral/pve-api-token.json.
#
# Note: every `lxc` call needs </dev/null or it eats the rest of the script.
set -euo pipefail
export PATH=/snap/bin:$PATH

HERE="$(cd "$(dirname "$0")" && pwd)"
VM=cathedral-pve
STATE="$HOME/cathedral"
NODE_DIR=/root/netbuild
PWFILE="$STATE/router-root-password"

[ -f "$HERE/segments.json" ] || { echo "segments.json not found next to provision.sh"; exit 1; }
[ -f "$STATE/pve-api-token.json" ] || { echo "missing $STATE/pve-api-token.json"; exit 1; }

umask 077
[ -f "$PWFILE" ] || python3 -c "import secrets;print(secrets.token_urlsafe(18))" > "$PWFILE"

echo "=== 1. push builder into node and run it ==="
lxc exec "$VM" -- mkdir -p "$NODE_DIR" </dev/null
lxc file push -q "$HERE/segments.json" "$VM$NODE_DIR/segments.json" </dev/null
lxc file push -q "$HERE/node_build.sh" "$VM$NODE_DIR/node_build.sh" </dev/null
lxc exec "$VM" -- bash "$NODE_DIR/node_build.sh" "$(cat "$PWFILE")" </dev/null

echo
echo "=== 2. configure router through the guest agent ==="
python3 "$HERE/configure_router.py" "$HERE/segments.json" "$HERE/firewall-allow.rules"

echo
echo "=== provision.sh complete ==="
