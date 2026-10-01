//! Guest-agent command construction, per role dialect.
//!
//! Kept small and pure so it is unit-testable offline. The actual static-IP
//! configuration a guest needs is image-specific; these are reasonable,
//! idempotent defaults that the executor runs through the guest agent.

use crate::schema::Role;

/// Build the argv for setting a static IP inside the guest.
///
/// - `windows`: a PowerShell one-liner (netsh) run via the agent.
/// - `linux`: an `ip addr` invocation on the primary interface.
///
/// Both are expressed as a full argv so the caller passes them straight to
/// `qemu agent exec` with no shell on the Proxmox side.
pub fn set_ip_argv(role: Role, ip: &str) -> Vec<String> {
    match role {
        Role::Windows => {
            let script = format!(
                "netsh interface ip set address name=\"Ethernet\" static {ip} 255.255.255.0"
            );
            vec![
                "powershell.exe".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script,
            ]
        }
        Role::Linux => {
            // `ip addr add` is idempotent-enough; retries tolerate EEXIST.
            vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("ip addr add {ip}/24 dev eth0 || true"),
            ]
        }
    }
}
