# Running on the Proxmox sandbox (status + remaining steps)

## What is proven

- **Harness + model on vanilla (the Linux execution host):** `uv sync` from the
  committed lock reproduces the env on vanilla, and GLM-5.3 answers through
  Inspect from vanilla. Repo lives at `~/cathedral-take-home` on vanilla.
- **Smoke task green on Docker (Mac only):** the agent finds the flag, scorer
  returns 1.0.

## Important correction (2026-10-01)

The PyPI `inspect-proxmox-sandbox==0.0.1` is an empty stub (a 22-byte
`__init__.py`). The real provider is `0.11.0` and ships only from GitHub. The
dependency is now pinned to a specific commit of
`github.com/UKGovernmentBEIS/inspect_proxmox_sandbox` in `pyproject.toml` /
`uv.lock`. It registers the sandbox type **`proxmox`** and includes real SDN,
storage, built-in-VM, cloud-init ISO, and guest-agent code.

## Remaining to run the smoke task on Proxmox (not yet done)

The provider provisions its own VMs, so this is an iterative setup, not a
one-liner. Run the harness **on vanilla** (the API at 10.77.0.10 is local there;
no tunnel needed).

1. **Provider connection.** Set `PROXMOX_CONFIG_FILE` (instances JSON) or the
   `PROXMOX_HOST/PORT/USER/REALM/PASSWORD` or token, `PROXMOX_NODE=cathedral-pve`,
   `PROXMOX_VERIFY_TLS=false`, `PROXMOX_IMAGE_STORAGE=local`. Confirm whether it
   accepts an API token or wants a PAM user+password.
2. **Storage:** `import` content type added to `local`. Done.
3. **SDN + dnsmasq on the node.** The provider configures Proxmox SDN itself and
   needs dnsmasq for IPAM DHCP/DNS. `libpve-network` is present; dnsmasq is not.
   Install it on the node via `lxc exec cathedral-pve -- apt-get install dnsmasq`
   (goes through the allowlisted proxy; dnsmasq is in the Debian repos). No
   vanilla sudo needed; we have root inside the node via `lxc exec`.
4. **Image egress.** The provider builds VMs from base images it fetches. The
   node has no direct internet, only the allowlisted proxy. Identify the image
   source host and add it to `~/cathedral/egress-allowlist.txt`, or pre-seed the
   image into `local`.
5. **Static IPs** need a November 2025 Proxmox patch; otherwise use the
   provider's SDN DHCP.
6. **Switch the task:** set `tasks/smoke/eval.yaml` sandbox to
   `type: proxmox` with the provider's config, and run the same `inspect eval`.

## The Docker-on-vanilla alternative

Docker on vanilla is blocked: the `sam` account is not in the `docker` group, so
it needs `sudo usermod -aG docker sam` (then re-login). With that, the Docker
smoke path works on vanilla immediately, matching the Mac. The Proxmox sandbox is
the real target; Docker is only the fast dev loop.
