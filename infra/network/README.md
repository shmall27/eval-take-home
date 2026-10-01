# Range network fabric

Reusable, prompt-agnostic network fabric for the contained cyber-eval range on
the nested Proxmox node (`cathedral-pve` on host `vanilla`). It stands up several
isolated L2 segments and one tiny Linux router/firewall VM that provides
inter-segment routing, a stateful firewall (default-deny between segments), and
per-segment DHCP + DNS — with **no internet egress and no path to the hypervisor
or range host**. Everything survives a node reboot and is reproducible from
scripts.

Read [`../../docs/range-contract-v0.md`](../../docs/range-contract-v0.md) first;
this implements it. [`segments.json`](segments.json) is the source of truth the
Rust range compiler consumes.

## Topology

```
Proxmox node cathedral-pve (10.77.0.10)
  vmbr0  management  ── uplink to range host (the only bridge the node answers on)
  vmbr1  legacy isolated range bridge (pre-existing, unused by this fabric)
  vmbr2  dmz     10.78.10.0/24   no uplink ─┐
  vmbr3  user    10.78.20.0/24   no uplink ─┤  all three terminate ONLY on the
  vmbr4  server  10.78.30.0/24   no uplink ─┘  router VM; node holds no IP here

  VM 9200 "range-router"  (1 vCPU, 1 GiB, no NIC on vmbr0, no default route)
    ens18 10.78.10.1/24 (vmbr2, dmz)     matched to its NIC by MAC
    ens19 10.78.20.1/24 (vmbr3, user)
    ens20 10.78.30.1/24 (vmbr4, server)
    - dnsmasq: DHCP + local DNS per segment, no upstream resolver
    - nftables: stateful; forward default-deny + allow-list; output drop (no egress)
    - ip_forward=1; configured entirely through the QEMU guest agent
```

A segment is a Proxmox bridge with **no bridge-ports (no uplink)**, no address,
and IPv6 disabled — identical in spirit to the existing `vmbr1`. Guests on a
segment reach each other at L2; anything off-segment goes through the router,
subject to its firewall.

### Containment design (defence in depth)

1. **Segments have no uplink** — a guest can physically reach only its own
   segment's L2 and the router.
2. **The router has no NIC on `vmbr0` and no default route** — it cannot reach
   the hypervisor, the range host, or the internet even if it tried. Its
   nftables `output` chain is default-drop (replies + its own DHCP/DNS/ICMP
   only), so router-originated egress is blocked three ways over.
3. **dnsmasq has no upstream resolver** (`no-resolv`) — guests resolve range
   names but not internet names.
4. **The node firewall** ([`../range-host/range-containment.nft`](../range-host/range-containment.nft))
   already accepts traffic to the node only on `lo`/`vmbr0` and drops it on every
   other bridge, including `vmbr2/3/4`, and never answers ARP there. No change
   was needed; verified in place.

## Files

| File | What |
|---|---|
| [`segments.json`](segments.json) | Source of truth: segments, bridges, CIDRs, DHCP ranges, domains. |
| [`provision.sh`](provision.sh) | Top-level, run on `vanilla`. Builds bridges + router, then configures it. Idempotent. |
| [`node_build.sh`](node_build.sh) | Node-side: bridges, offline image bake, router VM. Invoked by `provision.sh`. |
| [`configure_router.py`](configure_router.py) | Pushes IPs/DHCP/DNS/nftables into the router via the guest agent. Idempotent. |
| [`firewall-allow.rules`](firewall-allow.rules) | The inter-segment allow-list (default: empty = deny-all). |
| [`verify.py`](verify.py) | Stands up two throwaway guests, proves DHCP/DNS/policy/containment, tears them down. |

## (Re)provision

On `vanilla` (copy this directory there, e.g. to `~/cathedral/network/`, so it
sits next to the deployed `pve.py` and token):

```
bash provision.sh
```

What it does, all idempotent:

1. Generates the `vmbr2/3/4` stanzas from `segments.json` into
   `/etc/network/interfaces.d/range-segments` (sourced by
   `/etc/network/interfaces`) on the node and runs `ifreload -a`.
2. Downloads the Debian 13 genericcloud image (once) and **offline-bakes** two
   images with `virt-customize`, installing packages through the egress proxy at
   build time only: a **router** image (qemu-guest-agent, dnsmasq, nftables) and
   a **test-guest** image (qemu-guest-agent + DHCP client). Neither VM ever has
   egress at run time.
3. Creates router VM `9200` (1 vCPU / 1 GiB, `onboot=1`, one NIC per segment,
   none on `vmbr0`) if absent.
4. Runs `configure_router.py`, which writes `systemd-networkd` (static gateway IP
   per NIC, matched by MAC), `dnsmasq`, and `nftables` config into the router
   over the guest agent and reloads the services.

Reboot survival: bridges live in `interfaces.d` (sourced, persistent); the router
VM has `onboot=1`; router config is on its disk with services enabled; the node
firewall unit is already enabled. Verified by rebooting the node (see below).

## Add a segment

1. Append an entry to `segments.json` (pick the next free `vmbrN`, a fresh
   `10.78.N0.0/24`, gateway `.1`, DHCP `.100–.200`, and a domain).
2. Re-run `bash provision.sh`. The new bridge is created, the router gets a NIC
   on it (deterministic MAC derived from the gateway IP) and a gateway IP, and
   dnsmasq serves it. The Rust compiler picks up the new segment from the same
   file.

Note: `configure_router.py` writes the per-NIC config; a brand-new NIC also needs
to exist on the VM, which `node_build.sh` only does at VM-create time. To add a
NIC to the existing router, add the `--netN` via `qm set 9200 ...` (or destroy
and let `provision.sh` rebuild it), then re-run `provision.sh`.

## Open a firewall hole between segments

Edit [`firewall-allow.rules`](firewall-allow.rules) — one hole per line:

```
<src_segment>  <dst_segment>  <proto>  <dport>
# e.g.
user    server  tcp  443
user    server  icmp any
```

`src`/`dst` are segment names from `segments.json` (or `any`); `proto` is
`tcp|udp|icmp|any`. Rules are stateful (the reply direction is automatic). Then:

```
python3 configure_router.py segments.json firewall-allow.rules
```

The default file is empty, i.e. **deny-all between segments**.

## Verify

```
python3 verify.py          # add --keep to leave the guests up for inspection
```

It applies a temporary allow-list (`user->server icmp + tcp 8080`) through the
real `configure_router.py` path, boots guest `9250` on `user` and `9251` on
`server` from the baked test image, checks everything below, tears the guests
down, and restores the deny-all allow-list.

### Verification results (measured)

Run on `vanilla`, **after a full reboot of the Proxmox node** (proving
persistence). All checks `PASS`:

```
== DHCP + DNS ==
  [PASS] user guest got DHCP lease            -- 10.78.20.130
  [PASS] user guest default route via router  -- 10.78.20.1
  [PASS] user guest resolves router.user.range.lab via router DNS -- 10.78.20.1
  [PASS] server guest got DHCP lease          -- 10.78.30.135
  [PASS] server guest default route via router-- 10.78.30.1
  [PASS] server guest resolves router.srv.range.lab via router DNS -- 10.78.30.1
  [PASS] internet name does NOT resolve (no DNS egress) -- NXDOMAIN

== inter-segment policy (allow-list: user->server icmp + tcp 8080) ==
  [PASS] user CAN ping server (allowed icmp)
  [PASS] user CAN reach server:8080 (allowed)
  [PASS] user CANNOT reach server:8081 (not in allow-list)
  [PASS] server CANNOT ping user (reverse, default-deny)
  [PASS] server CANNOT reach user:8080 (reverse, default-deny)

== containment invariant 1 (no path to hypervisor/host/internet) ==
  [PASS] user CANNOT reach hypervisor API 10.77.0.10:8006
  [PASS] user CANNOT reach hypervisor SSH 10.77.0.10:22
  [PASS] user CANNOT reach range host proxy 10.77.0.1:3128
  [PASS] user CANNOT reach internet 1.1.1.1:443
  [PASS] user CANNOT ping hypervisor 10.77.0.10
  [PASS] user CANNOT ping internet 1.1.1.1

== containment invariant 3 (node firewall covers new bridges) ==
  [PASS] node range_containment present (accepts only lo/vmbr0, drops the rest)

RESULT: PASS
```

### Timings (nested KVM, empty 512 MB guests)

| Step | Time |
|---|---|
| `ifreload -a` (bridges) | < 1 s |
| Debian cloud image download (325 MiB, via proxy) | ~20 s (once) |
| offline bake per image (`virt-customize --install`) | ~40–50 s (once) |
| router VM create + disk import (3 GiB raw) | ~15 s (once) |
| router guest agent up after start | ~12 s |
| scratch guest create + start | ~2 s each |
| both scratch guest agents up | ~15–21 s |
| full `verify.py` (build + 23 checks + teardown) | ~68 s |

## Deviations from the contract / notes

- **Bridges via `interfaces.d`.** The contract says persist bridges via
  `/etc/network/interfaces`. They are written to
  `/etc/network/interfaces.d/range-segments`, which that file `source`s — this
  keeps the fabric's bridges in one managed, regenerable snippet instead of
  rewriting the hand-maintained main file. Equivalent persistence; applied with
  `ifreload -a`. No change to the contract's segment definitions.
- **Egress allow-list addition.** `cloud.debian.org` 302-redirects off the
  `debian.org` domain to a regional mirror, so `acc.umu.se` (the Academic
  Computer Club Umeå Debian mirror) was added to the **live** allow-list at
  `~/cathedral/egress-allowlist.txt` on `vanilla` (not the repo copy). Only the
  node reaches it, only at build time, through the logged proxy.
- **Test guests are fresh Debian cloud VMs, not linked clones.** The contract
  allows "a quick Debian cloud-image VM." They are created on the node with `qm
  ... --scsi0 import-from=<baked image>` because the non-root automation token
  may not reference arbitrary disk paths via the API (`import-from`); guest
  control still goes through the API's guest-agent exec, reusing
  [`../range-host/pve.py`](../range-host/pve.py).
- **Router disk is `raw`** on the `local` dir storage (how `import-from` lands a
  genericcloud image there); snapshots still work via qcow overlays if needed.

## Teardown

```
# scratch guests are already removed by verify.py; to remove the fabric:
export PATH=/snap/bin:$PATH
lxc exec cathedral-pve -- qm stop 9200 --skiplock 1
lxc exec cathedral-pve -- qm destroy 9200 --purge 1 --skiplock 1
lxc exec cathedral-pve -- rm -f /etc/network/interfaces.d/range-segments
lxc exec cathedral-pve -- ifreload -a
lxc exec cathedral-pve -- rm -rf /root/netbuild      # cached images
```
