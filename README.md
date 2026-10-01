# cathedral-take-home

AI cyber-capability evaluation harness (take-home project for Cathedral).

Status: scoping. No harness code yet.

- **Direction:** Rust-first harness that emulates a company network. Python only
  where a task's own tooling needs it.
- **Range infrastructure:** Proxmox VE 9.2 running as a nested VM on the
  Threadripper build machine. See [`infra/range-host/`](infra/range-host/README.md).
- **Windows:** a sysprepped Windows Server 2022 template is built and verified
  on the range host. See [`infra/windows/`](infra/windows/README.md). Whether
  the eval uses it is still open.
- **Reusable core (built, integration-verified):** a declarative range
  compiler in Rust ([`crates/range/`](crates/range/)) and an isolated
  network fabric with a router/firewall, DNS and DHCP
  ([`infra/network/`](infra/network/README.md)). The contract they share is
  [`docs/range-contract-v0.md`](docs/range-contract-v0.md). End to end, the Rust
  compiler stands up a host on a fabric segment that gets DHCP from the router
  and stays fully contained.
- **Original spec:** [`docs/spec-v0-base-layer.md`](docs/spec-v0-base-layer.md)
  is the Python/Inspect-oriented draft, kept for reference and due a rewrite.
