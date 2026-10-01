#!/usr/bin/env bash
# Node-side builder for the range network fabric. Runs INSIDE the Proxmox node
# (`cathedral-pve`), invoked by provision.sh via `lxc exec`. Idempotent: safe to
# re-run. Does everything that must happen on the node itself:
#
#   1. create the segment bridges (vmbr2/3/4) from segments.json, persistently
#      in /etc/network/interfaces.d/ (sourced by /etc/network/interfaces), and
#      apply with `ifreload -a`;
#   2. fetch + offline-bake the Debian cloud image into a router image and a
#      throwaway test-guest image (packages added through the egress proxy at
#      build time only; neither VM ever gets egress at run time);
#   3. create and start the router VM (VMID 9200) with one NIC on each segment
#      bridge and NONE on vmbr0.
#
# Guest-side configuration (IPs, DHCP+DNS, nftables) is done separately through
# the QEMU guest agent by configure_router.py; this script only lays the metal.
#
# Usage (on the node):  bash node_build.sh <router-root-password>
set -euo pipefail

ROUTER_VMID=9200
HERE="$(cd "$(dirname "$0")" && pwd)"
SEG="$HERE/segments.json"
BUILD=/root/netbuild
BASE="$BUILD/debian-13-genericcloud-amd64.qcow2"
ROUTER_IMG="$BUILD/router-$ROUTER_VMID.qcow2"
TEST_IMG="$BUILD/test-guest.qcow2"
STORAGE=local
PROXY=http://10.77.0.1:3128
MIRROR=https://chuangtzu.ftp.acc.umu.se/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
ROUTER_PW="${1:?router root password required}"

mkdir -p "$BUILD"
command -v virt-customize >/dev/null || { echo "installing libguestfs-tools"; \
  http_proxy=$PROXY https_proxy=$PROXY DEBIAN_FRONTEND=noninteractive apt-get -q update >/dev/null 2>&1 || true; \
  http_proxy=$PROXY https_proxy=$PROXY DEBIAN_FRONTEND=noninteractive apt-get -q -y install libguestfs-tools >/dev/null 2>&1; }

# --- 1. segment bridges ------------------------------------------------------
# Generated from segments.json so the bridge set always matches the contract.
python3 - "$SEG" > /etc/network/interfaces.d/range-segments <<'PY'
import json, sys
segs = json.load(open(sys.argv[1]))
print("# Managed by infra/network/node_build.sh - range segment bridges.")
print("# Isolated L2: no bridge-ports (no uplink), no address, no gateway; IPv6")
print("# disabled so the node holds no address here. Mirrors vmbr1.\n")
for s in segs:
    b = s["bridge"]
    print(f"auto {b}")
    print(f"iface {b} inet manual")
    print( "        bridge-ports none")
    print( "        bridge-stp off")
    print( "        bridge-fd 0")
    print(f"        post-up echo 1 > /proc/sys/net/ipv6/conf/{b}/disable_ipv6")
    print()
PY
grep -q 'interfaces.d' /etc/network/interfaces || echo "source /etc/network/interfaces.d/*" >> /etc/network/interfaces
ifreload -a
echo "bridges after ifreload:"; ip -br link show type bridge | awk '{print "  "$1}'

# --- 2. base image -----------------------------------------------------------
if [ ! -f "$BASE" ]; then
  echo "downloading Debian cloud image"
  curl -fsS -x "$PROXY" -o "$BASE.part" "$MIRROR"
  mv "$BASE.part" "$BASE"
fi

# bake() OUT EXTRA_VIRT_CUSTOMIZE_ARGS...  -- copy base, add packages via proxy
bake() {
  local out="$1"; shift
  cp -f "$BASE" "$out"
  LIBGUESTFS_BACKEND=direct http_proxy=$PROXY https_proxy=$PROXY \
  virt-customize -a "$out" \
    --write '/etc/apt/apt.conf.d/80proxy:Acquire::http::Proxy "http://10.77.0.1:3128";
Acquire::https::Proxy "http://10.77.0.1:3128";' \
    --network \
    "$@" \
    --run-command 'rm -f /etc/apt/apt.conf.d/80proxy' \
    --run-command 'touch /etc/cloud/cloud-init.disabled'
}

# --- 2a. router image: router + DHCP/DNS server packages, no DHCP client ------
if [ ! -f "$ROUTER_IMG" ]; then
  echo "baking router image"
  bake "$ROUTER_IMG" \
    --install qemu-guest-agent,dnsmasq,nftables \
    --hostname range-router \
    --root-password "password:$ROUTER_PW" \
    --run-command 'systemctl enable qemu-guest-agent dnsmasq nftables systemd-networkd' \
    --run-command 'systemctl disable systemd-networkd-wait-online.service || true' \
    --run-command 'systemctl mask ssh.service || true' \
    --run-command 'printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-router.conf' \
    --run-command 'rm -f /etc/dnsmasq.d/*' \
    --run-command 'printf "#!/usr/sbin/nft -f\n# replaced by configure_router.py\n" > /etc/nftables.conf'
fi

# --- 2b. test-guest image: DHCP client + guest agent, for verification --------
if [ ! -f "$TEST_IMG" ]; then
  echo "baking test-guest image"
  bake "$TEST_IMG" \
    --install qemu-guest-agent \
    --hostname range-test \
    --run-command 'systemctl enable qemu-guest-agent systemd-networkd systemd-resolved' \
    --run-command 'systemctl disable systemd-networkd-wait-online.service || true' \
    --run-command 'ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf' \
    --write '/etc/systemd/network/10-dhcp.network:[Match]
Type=ether

[Network]
DHCP=yes
IPv6AcceptRA=no'
fi

# --- 3. router VM ------------------------------------------------------------
if qm status "$ROUTER_VMID" >/dev/null 2>&1; then
  echo "router VM $ROUTER_VMID already exists; leaving it in place"
else
  echo "creating router VM $ROUTER_VMID"
  # Build the --netN flags (one per segment, deterministic MAC from gateway IP),
  # in segments.json order: net0->first bridge, etc. NO NIC on vmbr0.
  mapfile -t NETS < <(python3 - "$SEG" <<'PY'
import json, sys
for i, s in enumerate(json.load(open(sys.argv[1]))):
    a, b, c, d = (int(x) for x in s["gateway_ip"].split("."))
    mac = "52:54:00:%02x:%02x:%02x" % (b, c, d)
    print(f"--net{i}")
    print(f"virtio,bridge={s['bridge']},macaddr={mac}")
PY
)
  qm create "$ROUTER_VMID" --name range-router --memory 1024 --cores 1 --cpu host \
    --ostype l26 --scsihw virtio-scsi-single --agent enabled=1 --onboot 1 \
    --serial0 socket --vga serial0 "${NETS[@]}"
  qm set "$ROUTER_VMID" --scsi0 "$STORAGE:0,import-from=$ROUTER_IMG"
  qm set "$ROUTER_VMID" --boot order=scsi0
  qm start "$ROUTER_VMID"
fi
echo "node_build.sh done"
