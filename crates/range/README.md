# `range` — cyber-range compiler

The reusable core of the cyber-eval harness. It compiles a **declarative range
definition** (TOML) into ordered **Proxmox operations** and can execute them.
This crate is range lifecycle only — model/provider concerns live elsewhere.

See `docs/range-contract-v0.md` (repo root) for the shared contract this
implements.

## Pipeline / modules

| Module        | Responsibility                                                                 |
|---------------|--------------------------------------------------------------------------------|
| `schema`      | Serde types for the range TOML (`Range`, `Host`, `Role`); parse from str/file. |
| `segments`    | Resolve segment names -> `{bridge, cidr, ...}` from `segments.json`, or fallback.|
| `planner`     | Validate + allocate VMIDs + compile a range into an ordered `Op` list. Pure.    |
| `proxmox`     | Blocking Proxmox API client (port of `infra/range-host/pve.py`).                |
| `executor`    | Runs the planner's `Op` list against a live node (task waits, lock retry).      |
| `guest`       | Builds guest-agent argv per role (Windows PowerShell / Linux shell).            |
| `error`       | `RangeError` for the pure, offline-testable failure modes.                      |

Clear boundaries: `planner` never touches the network; `proxmox` never knows
about ranges; `executor` bridges the two.

## Range schema

```toml
name = "example"      # range name
base_vmid = 10000     # optional; first VMID (default 10000). Band: 10000-19999

[[hosts]]
name     = "dc01"            # unique; also the clone's Proxmox name
template = 9000              # VMID of a Proxmox template to linked-clone
segment  = "server"          # references segments.json by name
ip       = "10.78.30.10"     # optional static IP (via guest agent); omit for DHCP
cores    = 4                 # default 2
memory   = 4096              # default 2048
role     = "windows"         # "windows" | "linux"; selects guest-agent dialect
vmid     = 10005             # optional explicit VMID; else base_vmid + host index
```

### VMID allocation
Each host gets `base_vmid + index` unless it sets `vmid` explicitly. All VMIDs
must fall in **10000-19999**; anything outside is a hard error. Duplicate host
names or VMIDs are rejected with a clear message.

### Segment resolution
Segments come from `infra/network/segments.json` (contract schema). If that file
is absent, the crate falls back to a single built-in segment named **`iso`**
mapped to bridge **`vmbr1`** (the existing isolated bridge), so the crate is
usable before the fabric exists. A sample segments file is in
`examples/segments.sample.json`.

## Lifecycle stages

- **plan** — print the ordered Proxmox operations, no side effects.
- **apply** — per host: linked-clone, point `net0` at the segment bridge, start,
  set the static IP via the guest agent (skipped for DHCP), snapshot `clean`
  (with RAM state).
- **reset** — roll every host back to `clean` (seconds vs. minutes to rebuild).
- **destroy** — stop + purge every host.

After a live rollback, state-changing calls on that VM hit a ~30 s file lock
(reads and guest-agent exec work immediately). The executor wraps post-rollback
`stop`/`delete` in a lock retry, mirroring `pve.py`'s `retry_locked`.

## Three-value endpoint config (the Proxmox client)

Base URL, node, and token are read from the environment — never hardcoded:

| Variable           | Default                                   | Meaning                         |
|--------------------|-------------------------------------------|---------------------------------|
| `PVE_BASE_URL`     | `https://localhost:8006/api2/json`        | API base (point at the tunnel)  |
| `PVE_NODE`         | `cathedral-pve`                           | Proxmox node name               |
| `PVE_TOKEN_ID`     | —                                         | e.g. `root@pam!automation`      |
| `PVE_TOKEN_SECRET` | —                                         | token secret value              |
| `PVE_TOKEN_FILE`   | —                                         | alt: JSON file `{full-tokenid,value}` |

Provide the token either as `PVE_TOKEN_ID` + `PVE_TOKEN_SECRET`, or as
`PVE_TOKEN_FILE` pointing at the JSON shape used on vanilla. The client accepts
the node's self-signed certificate.

## Usage

```sh
# Offline: inspect the compiled operations for every stage.
cargo run --bin range -- plan --file crates/range/examples/example-range.toml \
    --segments crates/range/examples/segments.sample.json

# Live (needs env + reachable API):
cargo run --bin range -- apply   --file my-range.toml
cargo run --bin range -- reset   --file my-range.toml
cargo run --bin range -- destroy --file my-range.toml
```

`--segments` defaults to `infra/network/segments.json`; when it is missing the
built-in `iso -> vmbr1` fallback is used (a note is printed to stderr).

## Tests

```sh
cargo test                 # offline: parsing, segment resolution, VMID alloc, plans
```

### Live end-to-end test (stretch, off by default)
Gated behind the `live` feature and additionally `#[ignore]`d, so `cargo test`
stays offline. It builds a 1-host range at VMID 10000 (linked-clone of template
9000 onto `vmbr1`), snapshots, resets, and destroys, exercising the lock retry.

```sh
# 1. tunnel the API from the Mac to the node
ssh -F /dev/null -N -L 8006:10.77.0.10:8006 vanilla &

# 2. fetch the token into a gitignored local file (never commit it)
ssh vanilla cat ~/cathedral/pve-api-token.json > .pve-token.json

# 3. run the single live test
PVE_BASE_URL=https://localhost:8006/api2/json \
PVE_TOKEN_FILE=$PWD/.pve-token.json \
    cargo test --features live -- --ignored live_apply_reset_destroy --nocapture
```
