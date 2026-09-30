#!/usr/bin/env bash
# Record of how the nested Proxmox range host was built on `vanilla`.
#
# These are the steps that were run, in order, consolidated from the original
# session. The consolidated script has NOT been re-run end to end; treat it as
# documentation you can follow, not a tested installer. Requires: membership of
# the `lxd` group on a host with nested KVM. No sudo.
#
# Note: every `lxc` call in a script needs </dev/null or it eats the script.
set -euo pipefail
export PATH=/snap/bin:$PATH
HERE="$(cd "$(dirname "$0")" && pwd)"
VM=cathedral-pve
STATE=~/cathedral
POOL_DIR=/data/users/sam/cathedral/lxd-pool

# --- 1. storage pool (NOCOW: VM images on btrfs fragment badly with CoW) ------
mkdir -p "$POOL_DIR" && chattr +C "$POOL_DIR"
lxc storage create cathedral dir source="$POOL_DIR" </dev/null

# --- 2. private bridge; the host's FORWARD policy (Docker) drops its traffic --
lxc network create cathbr0 ipv4.address=10.77.0.1/24 ipv4.nat=true \
  ipv4.dhcp.ranges=10.77.0.100-10.77.0.200 ipv6.address=none dns.domain=cathedral.lab </dev/null

# --- 3. allowlisted egress proxy as a user service (needs linger) -------------
mkdir -p "$STATE" ~/.config/systemd/user && chmod 700 "$STATE"
cp "$HERE/egress_proxy.py" "$HERE/smoke_api.py" "$STATE/"
[ -f "$STATE/egress-allowlist.txt" ] || cp "$HERE/egress-allowlist.txt" "$STATE/"
cp "$HERE/cathedral-egress-proxy.service" ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now cathedral-egress-proxy

# --- 4. Debian 13 VM ----------------------------------------------------------
lxc init images:debian/13 $VM --vm -s cathedral -n cathbr0 \
  -c limits.cpu=16 -c limits.memory=48GiB -c security.secureboot=false \
  -c boot.autostart=true -d root,size=300GiB </dev/null
lxc config device set $VM eth0 ipv4.address=10.77.0.10 </dev/null
lxc start $VM </dev/null
wait_agent() { until lxc exec $VM -- true </dev/null 2>/dev/null; do sleep 3; done; }
wait_agent

umask 077
[ -f "$STATE/id_ed25519" ] || ssh-keygen -q -t ed25519 -N "" -C cathedral-range-host -f "$STATE/id_ed25519"
[ -f "$STATE/pve-root-password" ] || python3 -c "import secrets;print(secrets.token_urlsafe(24))" > "$STATE/pve-root-password"
lxc exec $VM -- mkdir -p /root/.ssh </dev/null
lxc file push -q --mode 600 "$STATE/id_ed25519.pub" $VM/root/.ssh/authorized_keys </dev/null

# --- 5. Proxmox kernel (official "Install Proxmox VE on Debian 13 Trixie") ----
lxc exec $VM -- bash -s <<'GUEST'
set -e
export DEBIAN_FRONTEND=noninteractive https_proxy=http://10.77.0.1:3128 http_proxy=http://10.77.0.1:3128
cat > /etc/apt/apt.conf.d/80proxy <<P
Acquire::http::Proxy "http://10.77.0.1:3128";
Acquire::https::Proxy "http://10.77.0.1:3128";
P
hostnamectl set-hostname cathedral-pve
cat > /etc/hosts <<H
127.0.0.1       localhost
10.77.0.10      cathedral-pve.cathedral.lab cathedral-pve

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
H
apt-get -q update && apt-get -q -y install wget curl ca-certificates openssh-server
cat > /etc/apt/sources.list.d/pve-install-repo.sources <<EOL
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOL
wget -q https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg -O /usr/share/keyrings/proxmox-archive-keyring.gpg
echo "136673be77aba35dcce385b28737689ad64fd785a797e57897589aed08db6e45  /usr/share/keyrings/proxmox-archive-keyring.gpg" | sha256sum -c -
apt-get -q update && apt-get -q -y full-upgrade
apt-get -q -y install proxmox-default-kernel
GUEST
lxc restart $VM </dev/null && wait_agent

# --- 6. Proxmox VE packages ---------------------------------------------------
# pve-manager's postinst runs `pveam update`, which hangs on a no-route network.
# From a second shell: lxc exec cathedral-pve -- pkill -x pveam   (it is `|| true`)
lxc exec $VM -- bash -s <<'GUEST'
set -e
export DEBIAN_FRONTEND=noninteractive
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
echo "postfix postfix/mailname string cathedral-pve.cathedral.lab" | debconf-set-selections
apt-get -q -y install proxmox-ve postfix open-iscsi chrony
apt-get -q -y remove linux-image-amd64 'linux-image-6.12*'
update-grub
apt-get -q -y remove os-prober || true
GUEST

# --- 7. network, repos, proxy, storage, credentials ---------------------------
printf 'root:%s\n' "$(cat "$STATE/pve-root-password")" | lxc exec $VM -- bash -c 'umask 077; cat > /root/.rootpw'
lxc exec $VM -- bash -s <<'GUEST'
set -e
rm -f /etc/network/interfaces.new   # staged by the installer; would overwrite ours at boot
cat > /etc/network/interfaces <<N
auto lo
iface lo inet loopback

iface enp5s0 inet manual

# Management bridge. Uplink is the range host's private bridge (no forwarded
# route to the internet; egress only via the allowlisted proxy).
auto vmbr0
iface vmbr0 inet static
        address 10.77.0.10/24
        gateway 10.77.0.1
        bridge-ports enp5s0
        bridge-stp off
        bridge-fd 0

# Isolated range bridge. No ports, no address, no gateway: guests attached
# here can reach each other and nothing else. IPv6 is disabled so the node
# gets no link-local address here (guests must not reach the hypervisor).
auto vmbr1
iface vmbr1 inet manual
        bridge-ports none
        bridge-stp off
        bridge-fd 0
        post-up echo 1 > /proc/sys/net/ipv6/conf/vmbr1/disable_ipv6

source /etc/network/interfaces.d/*
N
rm -f /etc/systemd/network/enp5s0.network
systemctl disable systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service 2>/dev/null || true
systemctl disable systemd-resolved.service 2>/dev/null || true
rm -f /etc/resolv.conf
printf 'search cathedral.lab\nnameserver 10.77.0.1\n' > /etc/resolv.conf

f=/etc/apt/sources.list.d/pve-enterprise.sources   # no subscription
[ -f "$f" ] && ! grep -q '^Enabled: false' "$f" && sed -i '/^Types:/i Enabled: false' "$f"
grep -q '^http_proxy' /etc/pve/datacenter.cfg 2>/dev/null || echo 'http_proxy: http://10.77.0.1:3128' >> /etc/pve/datacenter.cfg
pvesm set local --content iso,vztmpl,backup,images,snippets,rootdir   # qcow2 VM disks with snapshots

chpasswd < /root/.rootpw && shred -u /root/.rootpw
pveum user add harness@pve --comment "eval harness automation" 2>/dev/null || true
pveum acl modify / --users harness@pve --roles Administrator
pveum user token add harness@pve harness --privsep 0 --output-format json > /root/.harness-token.json
GUEST
lxc file pull -q $VM/root/.harness-token.json "$STATE/pve-api-token.json" </dev/null
lxc exec $VM -- shred -u /root/.harness-token.json </dev/null
chmod 600 "$STATE/pve-api-token.json"
lxc restart $VM </dev/null && wait_agent

# --- 8. verify ----------------------------------------------------------------
until [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://10.77.0.10:8006/)" = 200 ]; do sleep 3; done
python3 "$STATE/smoke_api.py" "$STATE/pve-api-token.json"
