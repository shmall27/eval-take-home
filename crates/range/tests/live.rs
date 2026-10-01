//! Live end-to-end test against a real Proxmox node. OFF by default.
//!
//! Enable with `--features live`; it is additionally `#[ignore]` so even then it
//! only runs when named explicitly. It exercises a tiny 1-host range at VMID
//! 10000 (linked-clone of template 9000 onto bridge vmbr1), snapshots, resets
//! (rollback), and destroys, verifying the post-rollback lock retry.
//!
//! Prereqs (see the crate README):
//!   ssh -F /dev/null -N -L 8006:10.77.0.10:8006 vanilla &
//!   export PVE_BASE_URL=https://localhost:8006/api2/json
//!   export PVE_TOKEN_FILE=/path/to/pve-api-token.json   # fetched from vanilla
//!   cargo test --features live -- --ignored live_apply_reset_destroy --nocapture

#![cfg(feature = "live")]

use std::time::Duration;

use range::planner::{self, Stage};
use range::proxmox::{Config, Pve};
use range::schema::Range;
use range::segments::SegmentMap;

const LIVE_RANGE: &str = r#"
name = "live-smoke"
base_vmid = 10000
[[hosts]]
name = "live0"
template = 9000
segment = "iso"
role = "linux"
"#;

#[test]
#[ignore = "requires a live Proxmox node over the SSH tunnel; run explicitly"]
fn live_apply_reset_destroy() {
    let range = Range::from_toml_str(LIVE_RANGE).unwrap();
    // Force the built-in fallback (iso -> vmbr1) regardless of any fabric file.
    let segments = SegmentMap::fallback();
    let compiled = planner::compile(&range, &segments).unwrap();

    let cfg = Config::from_env().expect("PVE_* env for live test");
    let pve = Pve::new(cfg).unwrap();

    println!("proxmox version: {}", pve.version().unwrap());
    assert!(
        !pve.list_vms().unwrap().contains(&10000),
        "VMID 10000 already exists; clean up first"
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        range::executor::execute(&pve, &compiled, Stage::Apply).expect("apply");
        range::executor::execute(&pve, &compiled, Stage::Reset).expect("reset");
        // destroy exercises the post-rollback lock retry on stop/delete.
        range::executor::execute(&pve, &compiled, Stage::Destroy).expect("destroy");
    }));

    // Best-effort teardown no matter what happened above.
    if pve.list_vms().unwrap_or_default().contains(&10000) {
        let _ = pve.retry_locked(20, Duration::from_secs(3), || {
            let upid = pve.stop(10000)?;
            pve.wait(&upid, Duration::from_secs(120))?;
            Ok(())
        });
        if let Ok(upid) = pve.delete_purge(10000) {
            let _ = pve.wait(&upid, Duration::from_secs(120));
        }
    }

    assert!(
        !pve.list_vms().unwrap().contains(&10000),
        "VMID 10000 left behind after teardown"
    );
    result.expect("live lifecycle failed");
}
