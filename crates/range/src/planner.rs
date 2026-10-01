//! Range compiler: resolve + validate a range, then emit ordered Proxmox
//! operations for each lifecycle stage. All of this is pure (no network), so it
//! powers both the side-effect-free `plan` and the executing stages, and is
//! fully unit-testable offline.

use std::collections::HashMap;

use serde::Serialize;

use crate::error::RangeError;
use crate::schema::{Host, Range, Role, VMID_MAX, VMID_MIN};
use crate::segments::{Segment, SegmentMap};

/// The snapshot name taken after a host is first built, and rolled back to on
/// reset (per the contract's reset model).
pub const CLEAN_SNAPSHOT: &str = "clean";

/// A lifecycle stage the compiler can emit operations for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Apply,
    Reset,
    Destroy,
}

/// A host whose segment has been resolved and whose VMID has been allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    pub name: String,
    pub vmid: u32,
    pub template: u32,
    pub bridge: String,
    pub segment: Segment,
    pub ip: Option<String>,
    pub cores: u32,
    pub memory: u32,
    pub role: Role,
}

/// A fully resolved and validated range, ready to compile into operations.
#[derive(Debug, Clone)]
pub struct CompiledRange {
    pub name: String,
    pub hosts: Vec<ResolvedHost>,
}

/// A single Proxmox operation. This is the intermediate representation the
/// planner emits and the executor consumes; `plan` renders it, the stages run
/// it. Kept provider-shaped but free of any live client state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Op {
    /// Linked-clone `template` into `vmid` named `name`, placed on `bridge`.
    Clone {
        template: u32,
        vmid: u32,
        name: String,
    },
    /// Point net0 at the segment bridge (virtio,bridge=<bridge>).
    SetNet { vmid: u32, bridge: String },
    /// Boot the VM (first boot of a fresh clone).
    Start { vmid: u32 },
    /// Configure a static IP inside the guest via the guest agent. Omitted for
    /// DHCP hosts. `role` selects the agent dialect (PowerShell vs. shell).
    SetIp { vmid: u32, ip: String, role: Role },
    /// Snapshot the host as `clean` (with vmstate so reset restores running RAM).
    Snapshot {
        vmid: u32,
        name: String,
        vmstate: bool,
    },
    /// Roll the host back to a snapshot (reset). Followed by the lock retry.
    Rollback { vmid: u32, name: String },
    /// Stop the VM.
    Stop { vmid: u32 },
    /// Delete + purge the VM.
    Delete { vmid: u32 },
}

impl Op {
    /// A one-line, human-readable rendering for `plan` output.
    pub fn describe(&self) -> String {
        match self {
            Op::Clone {
                template,
                vmid,
                name,
            } => format!("clone    template {template} -> VMID {vmid} ({name}), linked"),
            Op::SetNet { vmid, bridge } => {
                format!("set-net  VMID {vmid}: net0 = virtio,bridge={bridge}")
            }
            Op::Start { vmid } => format!("start    VMID {vmid}"),
            Op::SetIp { vmid, ip, role } => {
                format!("set-ip   VMID {vmid}: {ip} via guest-agent ({role:?})")
            }
            Op::Snapshot {
                vmid,
                name,
                vmstate,
            } => format!(
                "snapshot VMID {vmid}: {name} (vmstate={})",
                if *vmstate { "yes" } else { "no" }
            ),
            Op::Rollback { vmid, name } => {
                format!("rollback VMID {vmid} -> {name} (then lock-retry)")
            }
            Op::Stop { vmid } => format!("stop     VMID {vmid}"),
            Op::Delete { vmid } => format!("destroy  VMID {vmid} (purge)"),
        }
    }
}

/// Resolve segments + allocate VMIDs + validate. Pure; no network.
pub fn compile(range: &Range, segments: &SegmentMap) -> Result<CompiledRange, RangeError> {
    let base = range.base_vmid();

    // Duplicate host names.
    let mut seen_names: HashMap<&str, ()> = HashMap::new();
    for h in &range.hosts {
        if seen_names.insert(h.name.as_str(), ()).is_some() {
            return Err(RangeError::DuplicateHostName(h.name.clone()));
        }
    }

    let mut resolved = Vec::with_capacity(range.hosts.len());
    // Track VMID -> host name to detect duplicates with a clear message.
    let mut seen_vmids: HashMap<u32, String> = HashMap::new();

    for (index, h) in range.hosts.iter().enumerate() {
        let vmid = allocate_vmid(base, index, h);

        if !(VMID_MIN..=VMID_MAX).contains(&vmid) {
            return Err(RangeError::VmidOutOfRange {
                host: h.name.clone(),
                vmid,
                min: VMID_MIN,
                max: VMID_MAX,
            });
        }

        if let Some(prev) = seen_vmids.insert(vmid, h.name.clone()) {
            return Err(RangeError::DuplicateVmid {
                vmid,
                a: prev,
                b: h.name.clone(),
            });
        }

        let segment = segments.get(&h.segment).ok_or_else(|| RangeError::UnknownSegment {
            host: h.name.clone(),
            segment: h.segment.clone(),
            known: segments.known_names().join(", "),
        })?;

        resolved.push(ResolvedHost {
            name: h.name.clone(),
            vmid,
            template: h.template,
            bridge: segment.bridge.clone(),
            segment: segment.clone(),
            ip: h.ip.clone(),
            cores: h.cores,
            memory: h.memory,
            role: h.role,
        });
    }

    Ok(CompiledRange {
        name: range.name.clone(),
        hosts: resolved,
    })
}

/// VMID allocation per the contract: explicit `vmid` wins; otherwise `base + index`.
fn allocate_vmid(base: u32, index: usize, host: &Host) -> u32 {
    host.vmid.unwrap_or(base + index as u32)
}

impl CompiledRange {
    /// Emit the ordered operations for a stage.
    pub fn operations(&self, stage: Stage) -> Vec<Op> {
        match stage {
            Stage::Apply => self.apply_ops(),
            Stage::Reset => self.reset_ops(),
            Stage::Destroy => self.destroy_ops(),
        }
    }

    fn apply_ops(&self) -> Vec<Op> {
        let mut ops = Vec::new();
        for h in &self.hosts {
            ops.push(Op::Clone {
                template: h.template,
                vmid: h.vmid,
                name: h.name.clone(),
            });
            ops.push(Op::SetNet {
                vmid: h.vmid,
                bridge: h.bridge.clone(),
            });
            ops.push(Op::Start { vmid: h.vmid });
            if let Some(ip) = &h.ip {
                ops.push(Op::SetIp {
                    vmid: h.vmid,
                    ip: ip.clone(),
                    role: h.role,
                });
            }
            ops.push(Op::Snapshot {
                vmid: h.vmid,
                name: CLEAN_SNAPSHOT.to_string(),
                vmstate: true,
            });
        }
        ops
    }

    fn reset_ops(&self) -> Vec<Op> {
        self.hosts
            .iter()
            .map(|h| Op::Rollback {
                vmid: h.vmid,
                name: CLEAN_SNAPSHOT.to_string(),
            })
            .collect()
    }

    fn destroy_ops(&self) -> Vec<Op> {
        let mut ops = Vec::new();
        for h in &self.hosts {
            ops.push(Op::Stop { vmid: h.vmid });
            ops.push(Op::Delete { vmid: h.vmid });
        }
        ops
    }
}
