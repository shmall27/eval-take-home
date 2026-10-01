//! Executes the planner's operations against a live Proxmox node.
//!
//! The planner produces an ordered [`Op`] list; this module runs it, blocking on
//! Proxmox tasks and handling the realities the contract calls out: wait for the
//! guest agent before configuring a host, snapshot with RAM state, and wrap
//! state-changing calls that follow a rollback in the lock retry.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::planner::{CompiledRange, Op, Stage};
use crate::proxmox::Pve;

/// Timeouts used while executing. Generous to allow first boot + Windows agent.
const TASK_TIMEOUT: Duration = Duration::from_secs(600);
const AGENT_TIMEOUT: Duration = Duration::from_secs(1800);
const EXEC_TIMEOUT: Duration = Duration::from_secs(300);
/// Post-rollback lock is ~30 s; retry a bit beyond that.
const LOCK_ATTEMPTS: usize = 20;
const LOCK_DELAY: Duration = Duration::from_secs(3);

/// Run every operation for `stage` against the node.
pub fn execute(pve: &Pve, range: &CompiledRange, stage: Stage) -> Result<()> {
    let ops = range.operations(stage);
    for op in &ops {
        println!("-> {}", op.describe());
        run_op(pve, op).with_context(|| format!("executing: {}", op.describe()))?;
    }
    Ok(())
}

fn run_op(pve: &Pve, op: &Op) -> Result<()> {
    match op {
        Op::Clone {
            template,
            vmid,
            name,
        } => {
            let upid = pve.clone_linked(*template, *vmid, name)?;
            pve.wait(&upid, TASK_TIMEOUT)?;
        }
        Op::SetNet { vmid, bridge } => {
            pve.set_net0_bridge(*vmid, bridge)?;
        }
        Op::Start { vmid } => {
            let upid = pve.start(*vmid)?;
            pve.wait(&upid, TASK_TIMEOUT)?;
        }
        Op::SetIp { vmid, ip, role } => {
            // Control the guest through the agent, not the network. Wait for the
            // agent, then apply the IP in the role's dialect.
            pve.wait_agent(*vmid, AGENT_TIMEOUT)?;
            let argv = crate::guest::set_ip_argv(*role, ip);
            let argv_ref: Vec<&str> = argv.iter().map(String::as_str).collect();
            let res = pve.guest_exec(*vmid, &argv_ref, EXEC_TIMEOUT)?;
            if res.exitcode != 0 {
                anyhow::bail!(
                    "set-ip on VMID {vmid} exited {}: {}",
                    res.exitcode,
                    res.stderr
                );
            }
        }
        Op::Snapshot {
            vmid,
            name,
            vmstate,
        } => {
            let upid = pve.snapshot(*vmid, name, *vmstate)?;
            pve.wait(&upid, TASK_TIMEOUT)?;
        }
        Op::Rollback { vmid, name } => {
            let upid = pve.rollback(*vmid, name)?;
            pve.wait(&upid, TASK_TIMEOUT)?;
        }
        Op::Stop { vmid } => {
            // A stop may immediately follow a rollback (reset then destroy) and
            // hit the ~30 s file lock; retry until it clears. A no-op stop on an
            // already-stopped VM is tolerated by Proxmox.
            let vmid = *vmid;
            pve.retry_locked(LOCK_ATTEMPTS, LOCK_DELAY, || {
                let upid = pve.stop(vmid)?;
                pve.wait(&upid, TASK_TIMEOUT)?;
                Ok(())
            })?;
        }
        Op::Delete { vmid } => {
            let vmid = *vmid;
            pve.retry_locked(LOCK_ATTEMPTS, LOCK_DELAY, || {
                let upid = pve.delete_purge(vmid)?;
                pve.wait(&upid, TASK_TIMEOUT)?;
                Ok(())
            })?;
        }
    }
    Ok(())
}
