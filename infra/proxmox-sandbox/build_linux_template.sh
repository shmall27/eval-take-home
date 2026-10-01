#!/usr/bin/env bash
# Build a Linux template for inspect_proxmox_sandbox, run ON the Proxmox node
# (`lxc exec cathedral-pve -- bash build_linux_template.sh`).
#
# Why a custom template: the provider's built-in images run a large cloud-init
# apt install on first boot, which needs guest internet. Our range is egress-
# locked, so we bake qemu-guest-agent into the image offline instead (apt via the
# node's allowlisted proxy at BUILD time only). The resulting guest needs no
# network at run time; Inspect reaches it over the guest-agent serial channel.
#
# The provider finds a template by requiring BOTH an `inspect` tag and the tag
# passed as existing_vm_template_tag. We set tags "inspect,<TAG>".
set -euo pipefail
VMID=${VMID:-9001}
TAG=${TAG:-inspect-debian13-qga}
PROXY=${PROXY:-http://10.77.0.1:3128}
URL=${URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}
WORK=/var/lib/vz/template/cache
IMG="$WORK/$(basename "$URL")"

export http_proxy="$PROXY" https_proxy="$PROXY"
mkdir -p "$WORK"
[ -f "$IMG" ] || { wget -q "$URL" -O "$IMG.part" && mv "$IMG.part" "$IMG"; }

printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' "$PROXY" "$PROXY" > /tmp/80proxy
virt-customize -a "$IMG" \
  --copy-in /tmp/80proxy:/etc/apt/apt.conf.d/ \
  --install qemu-guest-agent \
  --run-command 'systemctl enable qemu-guest-agent' \
  --run-command 'touch /etc/cloud/cloud-init.disabled' \
  --delete /etc/apt/apt.conf.d/80proxy

qm destroy "$VMID" --purge 2>/dev/null || true
qm create "$VMID" --name "tpl-${TAG#inspect-}" --ostype l26 --machine q35 --cpu host \
  --cores 2 --memory 2048 --scsihw virtio-scsi-single --agent enabled=1 --serial0 socket
qm set "$VMID" --scsi0 "local:0,import-from=$IMG"
qm set "$VMID" --boot order=scsi0 --tags "inspect,$TAG"
qm template "$VMID"
qm config "$VMID" | grep -E "^(name|scsi0|tags|template|agent)"
