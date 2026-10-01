#!/usr/bin/env bash
# Save a PNG of a VM's display. Run as root on the Proxmox node.
#   ./screenshot.sh <vmid> [out.png]
set -euo pipefail
VMID=$1; OUT=${2:-/tmp/vm-$1.png}
pvesh create "/nodes/$(hostname)/qemu/$VMID/monitor" --command "screendump $OUT -f png" >/dev/null
echo "$OUT"
