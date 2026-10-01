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
- **Original spec:** [`docs/spec-v0-base-layer.md`](docs/spec-v0-base-layer.md)
  is the Python/Inspect-oriented draft, kept for reference and due a rewrite.
