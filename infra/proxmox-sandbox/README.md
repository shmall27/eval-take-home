# Proxmox sandbox (the Linux-host target)

The eval's real sandbox is Proxmox, driven by `inspect_proxmox_sandbox` from the
harness running **on vanilla** (the Proxmox API is local there, no tunnel). The
smoke task passes end to end: `harness/smoke_proxmox.py`, accuracy 1.0 against
GLM-5.3, ~40 s, with the cloned VM torn down afterward.

## Important: the PyPI package is a stub

`inspect-proxmox-sandbox==0.0.1` on PyPI is empty. The real provider (0.11.0)
ships only from GitHub and is pinned to a commit in `pyproject.toml` / `uv.lock`.

## Template with the guest agent baked in

`build_linux_template.sh` builds template 9001, tagged `inspect;inspect-debian13-qga`.
The provider's built-in images apt-install the guest agent on first boot, which
needs guest internet; our range is egress-locked, so we bake it in offline (apt
via the node's allowlisted proxy at build time). Our Windows template (9000) also
has the agent and can be used with `uefi_boot=True`.

Key provider facts (installed 0.11.0):
- Finds a template by requiring BOTH an `inspect` tag and the specific tag.
- Authenticates with user + realm + password (PAM), not a token.
- Downloads any built-in image on the **harness host** (vanilla has internet) and
  uploads via the API, so the node needs no image egress.
- For a single-VM file-read CTF, no network is needed: set `sdn_config=None` and
  `nics=()`, and Inspect talks to the guest over the agent serial channel. This
  avoids SDN and dnsmasq entirely.

## Run it (on vanilla)

```
cd ~/cathedral-take-home
export PROXMOX_HOST=10.77.0.10 PROXMOX_PORT=8006 PROXMOX_USER=root PROXMOX_REALM=pam \
       PROXMOX_NODE=cathedral-pve PROXMOX_VERIFY_TLS=0 PROXMOX_IMAGE_STORAGE=local
export PROXMOX_PASSWORD="$(cat ~/cathedral/pve-root-password)"
uv run inspect eval harness/smoke_proxmox.py --model openrouter/z-ai/glm-5.3
```

## For multi-host ranges later

A real range needs networking, so it needs SDN. Install dnsmasq on the node
(`apt-get install dnsmasq` via the proxy) for Proxmox IPAM, then use
`sdn_config="auto"` or an explicit `SdnConfig`, and give VMs `nics`. Static IPs
need a November 2025 Proxmox patch; otherwise use SDN DHCP.

## Networking (SDN) — available and verified

Multi-host ranges with networking now work. `harness/net_check.py` stands up two
VMs on one SDN vnet and passes (accuracy 1.0): both get DHCP leases, reach each
other, and cannot reach the internet or the hypervisor.

What it took:

- **dnsmasq on the node** for Proxmox SDN IPAM (`apt-get install dnsmasq` via the
  proxy, then `systemctl disable --now dnsmasq` so Proxmox runs its own per-vnet
  instances).
- **Template brings its own NIC config.** Cloud-init is disabled, so the template
  bakes a systemd-networkd rule that DHCPs any ethernet (`build_linux_template.sh`).
  It also now includes ping, curl, netcat, dnsutils, and python3.
- **Containment firewall fix.** The node's `range-containment.nft` dropped all
  input except on vmbr0, which also dropped the guest's DHCP request to the SDN
  dnsmasq (it listens on the vnet bridge). It now permits DHCP and DNS (udp 53/67,
  tcp 53) while still dropping everything else from a range bridge, so the control
  plane stays unreachable. The old ARP-drop table was removed as redundant and
  SDN-breaking (the input chain already blocks the data plane).

Config pattern for a networked range (see `net_check.py`): an `SdnConfig` with a
`VnetConfig` whose `SubnetConfig` has `snat=False` (no egress) and a DHCP range,
and `VmConfig`s with `nics=(VmNicConfig(vnet_alias=...),)`.

Run it (on vanilla, with the PROXMOX_* env):
```
uv run inspect eval harness/net_check.py --model openrouter/z-ai/glm-5.3
```
