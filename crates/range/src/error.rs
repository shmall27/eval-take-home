//! Error types for the range crate.

use thiserror::Error;

/// Errors produced while parsing, resolving, validating, or compiling a range.
///
/// Network/Proxmox-API errors are surfaced separately via `anyhow` in the
/// client; this enum covers the pure, offline-testable failure modes so callers
/// (and tests) can match on them precisely.
#[derive(Debug, Error)]
pub enum RangeError {
    #[error("io error: {0}")]
    Io(String),

    #[error("failed to parse range TOML: {0}")]
    Parse(String),

    #[error("failed to parse segments.json: {0}")]
    SegmentsParse(String),

    #[error("host {host:?} references unknown segment {segment:?} (known: {known})")]
    UnknownSegment {
        host: String,
        segment: String,
        known: String,
    },

    #[error("duplicate host name {0:?}")]
    DuplicateHostName(String),

    #[error("duplicate VMID {vmid} (hosts {a:?} and {b:?})")]
    DuplicateVmid { vmid: u32, a: String, b: String },

    #[error(
        "host {host:?} VMID {vmid} is outside the allowed range band {min}-{max}"
    )]
    VmidOutOfRange {
        host: String,
        vmid: u32,
        min: u32,
        max: u32,
    },
}
