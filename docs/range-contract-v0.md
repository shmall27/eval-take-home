# Range contract v0

Frozen so the network fabric and the Rust range compiler converge. Both the
`infra/network/` fabric and the Rust `range` crate depend on this. If something
here is wrong, change it here first and note it in the PR/notes.

## Segments

A segment is an isolated layer-2 network: one Proxmox bridge with **no uplink**
(like the existing `vmbr1`). Guests on a segment reach each other at layer 2.

The fabric publishes the source of truth as `infra/network/segments.json`:

```json
[
  {"name":"dmz",    "bridge":"vmbr2", "cidr":"10.78.10.0/24", "gateway_ip":"10.78.10.1",
   "dhcp_start":"10.78.10.100", "dhcp_end":"10.78.10.200", "domain":"dmz.range.lab"},
  {"name":"user",   "bridge":"vmbr3", "cidr":"10.78.20.0/24", "gateway_ip":"10.78.20.1",
   "dhcp_start":"10.78.20.100", "dhcp_end":"10.78.20.200", "domain":"user.range.lab"},
  {"name":"server", "bridge":"vmbr4", "cidr":"10.78.30.0/24", "gateway_ip":"10.78.30.1",
   "dhcp_start":"10.78.30.100", "dhcp_end":"10.78.30.200", "domain":"srv.range.lab"}
]
```

## Router / firewall

One small Linux VM is the gateway on every segment at `gateway_ip`. It does
inter-segment routing, a stateful firewall, and per-segment DNS + DHCP. It has
**no interface on `vmbr0`** and **no egress**; it is configured through the QEMU
guest agent, never over the network. Default firewall policy: deny between
segments unless explicitly allowed; deny to the hypervisor, the range host, and
the internet.

## Range definition (Rust crate consumes segments, emits Proxmox ops)

A range is TOML:

```toml
name = "example"
[[hosts]]
name     = "dc01"
template = 9000           # VMID of a Proxmox template to linked-clone
segment  = "server"       # references segments.json by name
ip       = "10.78.30.10"  # optional static; else DHCP from the router
cores    = 4
memory   = 4096
role     = "windows"      # "windows" | "linux"; selects guest-agent dialect
```

Compiler stages: `plan` (print the Proxmox operations, no side effects) →
`apply` (linked-clone each host, set its NIC to the segment's bridge, set the IP
via guest agent, snapshot each as `clean`) → `reset` (roll every host back to
`clean`) → `destroy` (stop + purge every host).

## VMID allocation

- Infra reserved: templates and smoke tests live at 9000–9999 (9000 template,
  9200 router, 9101/9102/9999 scratch). Do not use this band for ranges.
- Ranges use **10000–19999**. The Rust apply test should use 10000–10009 and
  tear them down.

## Reset model

Build a range once, snapshot every host (`clean`), reset by rolling all hosts
back. First boot of a fresh clone is minutes; rollback is seconds. After a live
rollback, lifecycle calls on that VM hit a ~30 s lock (reads and guest-agent
exec work immediately). Control guests through the guest agent, not the network.

## Containment invariants (must hold; verify, don't assume)

1. No range guest reaches the hypervisor management address (10.77.0.10), the
   range host (10.77.0.1 / vanilla), or the internet.
2. Segments reach each other only through the router, per its policy.
3. The node firewall (`infra/range-host/range-containment.nft`) already drops
   guest→node traffic on any bridge except `vmbr0`; new bridges are covered.

## Operating environment (how to reach everything)

- Proxmox VE 9.2 runs as LXD VM `cathedral-pve` (10.77.0.10) on host `vanilla`.
- From `vanilla`: `export PATH=/snap/bin:$PATH` then
  `lxc exec cathedral-pve -- <cmd> </dev/null`. The `</dev/null` is mandatory:
  `lxc` reads stdin and will otherwise eat the rest of a script.
- API: `https://10.77.0.10:8006/api2/json`, self-signed cert, node
  `cathedral-pve`. Token at `~/cathedral/pve-api-token.json` on vanilla. Python
  reference client: `infra/range-host/pve.py`.
- The API (10.77.0.10) is reachable **from vanilla directly**, and from the Mac
  only through a tunnel: `ssh -F /dev/null -N -L 8006:10.77.0.10:8006 vanilla`
  then hit `https://localhost:8006`. Plain `ssh vanilla` has forwards in
  `~/.ssh/config`; use `-F /dev/null` when adding your own `-L`.
- Secrets (token, passwords) stay on vanilla under `~/cathedral/`; never commit
  them.
