# Running the smoke task on the Proxmox sandbox

The smoke task is green on Docker. To run the *same* task on
`inspect_proxmox_sandbox` against our nested Proxmox (`cathedral-pve`, 10.77.0.10),
reconcile these before switching `tasks/smoke/eval.yaml`'s sandbox to `proxmox`:

1. **Storage content types.** The provider expects `import` among the allowed
   types on `local`. We set most already; add it:
   `pvesm set local --content iso,vztmpl,backup,snippets,images,rootdir,import`.
2. **Guest agent on every image.** Our Windows template has it. A Linux image for
   the agent host needs qemu-guest-agent (the provider ships ubuntu24.04,
   debian13, kali2025.4 built-ins, which already include it).
3. **Windows template is BIOS.** The provider's Windows path wants
   `uefi_boot=True` and `os_type=win11` (plus a vTPM for 11). Rebuild the template
   as UEFI, or use a Linux agent host for now.
4. **Static IPs need a Nov 2025 Proxmox patch.** Check it against our 9.2 build,
   or rely on the provider's SDN DHCP instead of static IPs.
5. **Networking is the provider's SDN**, not our `vmbr2-4` + router fabric. The
   provider defines vnets/subnets per eval (CIDR, gateway, DHCP). Our fabric is
   not used by this path; its containment lessons carry, the implementation does
   not.
6. **Reach the API.** From the Mac, tunnel: `ssh -f -N -L 8006:10.77.0.10:8006 vanilla`.
   Point `PROXMOX_CONFIG_FILE` at an instance JSON using `https://localhost:8006`
   and the `harness@pve!harness` token on vanilla. Or run Inspect on vanilla.

Then set, in `tasks/smoke/eval.yaml`:
```yaml
sandbox:
  type: proxmox
  config: <proxmox sandbox config>
```
and run the same `inspect eval` command. The task body does not change.
