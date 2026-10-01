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
