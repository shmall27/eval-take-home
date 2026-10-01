# Proxmox sandbox: status

**Done (2026-10-01): the smoke task runs green on the Proxmox sandbox, on vanilla.**
See [`infra/proxmox-sandbox/README.md`](../infra/proxmox-sandbox/README.md).

- Harness runs on vanilla (uv env from the committed lock; GLM-5.3 verified).
- Real provider installed (PyPI was a stub; pinned to a GitHub commit).
- Guest-agent-baked Debian template built (9001, tags `inspect;inspect-debian13-qga`).
- `harness/smoke_proxmox.py`: one VM, no network, accuracy 1.0, clone torn down.

Remaining for a real multi-host range (not the smoke): install dnsmasq on the node
for SDN IPAM, use `sdn_config`, give VMs NICs, and for Windows rebuild the template
as UEFI. The Windows static-IP path needs a Nov-2025 Proxmox patch.
