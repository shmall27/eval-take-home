# Range host: nested Proxmox VE on `vanilla`

The cyber range runs on Proxmox VE 9.2, installed as a virtual machine on the
Threadripper build machine (`vanilla`, Ubuntu 24.04). Ubuntu is untouched:
Proxmox lives inside an LXD virtual machine with nested KVM, and everything was
set up without sudo.

```
Mac ──ssh──> vanilla (Ubuntu, shared build machine)
               ├─ cathbr0 10.77.0.1/24   LXD bridge, host-only (no forwarded route out)
               ├─ egress proxy 10.77.0.1:3128   allowlisted + logged, systemd user unit
               └─ LXD VM "cathedral-pve" 10.77.0.10   Proxmox VE 9.2, 16 vCPU / 48 GiB / 300 GiB
                    ├─ vmbr0  management, uplink to cathbr0
                    └─ vmbr1  isolated range bridge (no ports, no address, no gateway)
```

## Access

Web interface, from the Mac:

```
ssh -F /dev/null -N -L 8006:10.77.0.10:8006 sam@vanilla
# then open https://localhost:8006   user: root   realm: Linux PAM
```

`-F /dev/null` matters only if you add `ClearAllForwardings`; a plain
`ssh -N -L 8006:10.77.0.10:8006 vanilla` also works.

Everything sensitive lives on `vanilla` in `~/cathedral/` (mode 700), never in
this repo:

| File | What |
|---|---|
| `pve-root-password` | Proxmox `root@pam` password (web login) |
| `pve-api-token.json` | API token `harness@pve!harness` for automation |
| `id_ed25519` | SSH key for `root@10.77.0.10` (fallback to `lxc exec`) |
| `egress-allowlist.txt` | Hostname suffixes the proxy will reach |
| `egress.log` | Every proxied request with ALLOW/DENY verdict |

Shell on the Proxmox node, from `vanilla`: `lxc exec cathedral-pve -- bash`.

API from `vanilla`:

```
curl -sk -H "Authorization: PVEAPIToken=harness@pve!harness=<value>" \
  https://10.77.0.10:8006/api2/json/version
```

## Containment

Agentic cyber runs have produced unsanctioned actions in permissive setups, so
isolation here is a default, not an option.

- **No route out.** The host's forwarding policy drops traffic from `cathbr0`
  (Docker sets FORWARD to DROP). Verified: direct ping and TCP from the Proxmox
  node to 1.1.1.1 both fail.
- **One egress point.** `egress_proxy.py` serves only `10.77.0.0/24`, reaches
  only allowlisted hostnames (currently `debian.org`, `proxmox.com`), and logs
  every request. Verified: `example.com` returns 403. Stop the unit
  (`systemctl --user stop cathedral-egress-proxy`) and there is no egress at all.
- **Range guests are one layer further in.** `vmbr1` has no uplink, and the
  Proxmox node holds no IPv4 or IPv6 address on it, so guests there have no
  path to the proxy, the management address, or `vanilla`. This is by
  construction; it has not yet been probed from inside a real guest.
- **Not on the LAN.** The Proxmox web interface is reachable only from
  `vanilla` itself or through an SSH tunnel.

To let provisioning reach a new site (for example a cloud image mirror), add
its domain to `~/cathedral/egress-allowlist.txt`; it applies immediately.

## Verified

`smoke_api.py` drives the API with the automation token: create a throwaway VM
on `vmbr1`, start it under nested KVM, snapshot with RAM, roll back, destroy.

| Step | Time |
|---|---|
| create | 0.3 s |
| start (nested KVM) | 0.6 s |
| snapshot with RAM | 1.2 s |
| rollback | 0.9 s |
| next operation accepted after a live rollback | ~30 s |

The last row matters for the harness. After a live rollback, Proxmox's cleanup
handler for the replaced QEMU process holds the VM's lock, and state-changing
calls fail with a lock timeout until it releases. Reads still work. The
harness should retry on lock timeout, or reset by rolling back a stopped VM.
These timings are for an empty 512 MB guest; real guests will be slower.

## Known limitations

- **Nested virtualization.** Range guests run two hypervisors deep. Fine for
  Linux; Windows guests will be noticeably slower than bare metal.
- **Shared machine.** `vanilla` has other users. The VM is capped at 16 vCPU
  and 48 GiB (memory is allocated lazily; idle use is about 2 GiB). Adjust with
  `lxc config set cathedral-pve limits.cpu=… limits.memory=…` and restart.
- **Template index.** `pveam update` works only through the proxy setting in
  `/etc/pve/datacenter.cfg`, and only for allowlisted hosts.
- **Token scope.** `harness@pve` has the Administrator role on `/`. Narrow it
  once the harness's actual needs are known.
- **Self-signed certificate** on the web interface and API.

## Teardown

Removes everything this setup created on `vanilla`:

```
lxc delete -f cathedral-pve
lxc network delete cathbr0
lxc storage delete cathedral
systemctl --user disable --now cathedral-egress-proxy
rm -rf ~/cathedral ~/.config/systemd/user/cathedral-egress-proxy.service /data/users/sam/cathedral
```

## How it was built

`provision.sh` records the steps in order. Two things it works around:

1. `pve-manager`'s install script runs `pveam update`, which tries the internet
   directly and hangs for minutes on a no-route network. It is optional
   (`|| true` in the script), so it was killed.
2. Proxmox stages `/etc/network/interfaces.new` during install and applies it
   over `/etc/network/interfaces` at next boot. Remove it before writing the
   bridge config, or the bridges vanish on reboot.
