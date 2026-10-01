#!/usr/bin/env bash
# Build a sysprepped Windows Server template on the Proxmox node.
#
# Run as root ON THE PROXMOX NODE, from a directory holding this script, the
# two .tmpl files, setup.ps1, SetupComplete.cmd, and a file `.adminpw` with the
# template's local Administrator password (letters, digits, - and _ only).
#
#   VMID=9000 NAME=tpl-win2022 ./build_template.sh
#
# The install is fully unattended and ends with sysprep powering the VM off;
# the script waits for that, removes the install media, and converts the VM to
# a template. Progress can be watched with ./screenshot.sh <vmid>.
set -euo pipefail
cd "$(dirname "$0")"

VMID=${VMID:-9000}
NAME=${NAME:-tpl-win2022}
WIN_ISO=${WIN_ISO:-win2022-eval.iso}
VIRTIO_ISO=${VIRTIO_ISO:-virtio-win-0.1.302.iso}
DRIVER_OS=${DRIVER_OS:-2k22}          # folder name on the VirtIO CD
IMAGE_INDEX=${IMAGE_INDEX:-2}         # eval ISO: 1 Std Core, 2 Std Desktop, 3 DC Core, 4 DC Desktop
BRIDGE=${BRIDGE:-vmbr1}               # isolated; the build needs no network
TIMEOUT_MIN=${TIMEOUT_MIN:-120}
ISO_DIR=/var/lib/vz/template/iso
ANSWER_ISO=win-answer-$VMID.iso

for f in "$ISO_DIR/$WIN_ISO" "$ISO_DIR/$VIRTIO_ISO" .adminpw; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done
PW=$(tr -d '\r\n' < .adminpw)
[[ "$PW" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "password has characters unsafe for XML/sed" >&2; exit 1; }
if qm status "$VMID" >/dev/null 2>&1; then echo "VM $VMID already exists" >&2; exit 1; fi

# --- answer CD: autounattend.xml + first-logon script + clone-time files -------
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
paths=""; n=0
for letter in D E F G H; do
  for drv in vioscsi NetKVM Balloon; do
    n=$((n + 1))
    paths+="        <PathAndCredentials wcm:action=\"add\" wcm:keyValue=\"$n\"><Path>$letter:\\\\$drv\\\\$DRIVER_OS\\\\amd64</Path></PathAndCredentials>"$'\n'
  done
done
python3 - "$work" "$PW" "$IMAGE_INDEX" "${paths%$'\n'}" <<'PY'
import sys
work, pw, index, paths = sys.argv[1:5]
paths = paths.replace("\\\\", "\\")
for name in ("autounattend.xml", "clone-unattend.xml"):
    s = open(name + ".tmpl").read()
    s = s.replace("@@ADMIN_PASSWORD@@", pw).replace("@@IMAGE_INDEX@@", index).replace("@@DRIVER_PATHS@@", paths)
    assert "@@" not in s, name
    open(f"{work}/{name}", "w", newline="\r\n").write(s)
PY
cp setup.ps1 SetupComplete.cmd "$work/"
genisoimage -quiet -J -r -V ANSWER -o "$ISO_DIR/$ANSWER_ISO" "$work"

# --- VM: BIOS boot so the install CD starts without a keypress on a blank disk -
qm create "$VMID" --name "$NAME" --ostype win11 --machine q35 --bios seabios \
  --cpu host --cores 4 --memory 8192 --balloon 0 \
  --scsihw virtio-scsi-single --scsi0 local:64,format=qcow2,discard=on,ssd=1,iothread=1 \
  --net0 "virtio,bridge=$BRIDGE" --agent enabled=1 --vga std --tablet 1 \
  --sata0 "local:iso/$WIN_ISO,media=cdrom" \
  --sata1 "local:iso/$VIRTIO_ISO,media=cdrom" \
  --sata2 "local:iso/$ANSWER_ISO,media=cdrom" \
  --boot 'order=scsi0;sata0'
qm start "$VMID"
echo "$(date -u +%T) install started"

# --- wait for sysprep to power it off ------------------------------------------
deadline=$(( $(date +%s) + TIMEOUT_MIN * 60 ))
while [ "$(qm status "$VMID" | awk '{print $2}')" != "stopped" ]; do
  if [ "$(date +%s)" -gt "$deadline" ]; then
    echo "$(date -u +%T) TIMEOUT: VM still running after ${TIMEOUT_MIN} min; left in place for inspection" >&2
    exit 2
  fi
  sleep 15
done
echo "$(date -u +%T) guest powered off"

# --- seal ----------------------------------------------------------------------
qm set "$VMID" --delete sata0,sata1,sata2 >/dev/null
qm set "$VMID" --boot order=scsi0 --description "Windows Server template (sysprepped). Built $(date -u +%F). Clone, do not start." >/dev/null
rm -f "$ISO_DIR/$ANSWER_ISO"           # it holds the plaintext password
qm template "$VMID"
echo "$(date -u +%T) template $VMID ($NAME) ready"
