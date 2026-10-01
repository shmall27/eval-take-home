//! Serde types for the range TOML schema (see `docs/range-contract-v0.md`).
//!
//! A range is a declarative document describing a set of hosts, each cloned
//! from a Proxmox template onto an isolated network segment referenced by name.
//! This module only parses and models the document; it performs no validation
//! that depends on external state (segments, VMID ranges) — that lives in the
//! planner so errors can be reported together with clear context.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::RangeError;

/// Default start of the range VMID band (contract: ranges use 10000-19999).
pub const DEFAULT_BASE_VMID: u32 = 10000;
/// Inclusive lower bound of the allowed range VMID band.
pub const VMID_MIN: u32 = 10000;
/// Inclusive upper bound of the allowed range VMID band.
pub const VMID_MAX: u32 = 19999;

fn default_cores() -> u32 {
    2
}
fn default_memory() -> u32 {
    2048
}

/// The guest-agent dialect used to configure a host. Selects how the planner
/// phrases the "set IP" step (PowerShell vs. a POSIX shell).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Windows,
    Linux,
}

/// A single host in a range.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// Human-readable name; also used as the clone's Proxmox name. Unique.
    pub name: String,
    /// VMID of the Proxmox template to linked-clone.
    pub template: u32,
    /// Segment name; resolved against `segments.json` (or the fallback).
    pub segment: String,
    /// Optional static IP set via the guest agent. If absent, DHCP is assumed.
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default = "default_cores")]
    pub cores: u32,
    #[serde(default = "default_memory")]
    pub memory: u32,
    /// Guest-agent dialect selector.
    pub role: Role,
    /// Optional explicit VMID. When omitted the planner allocates `base + index`.
    #[serde(default)]
    pub vmid: Option<u32>,
}

/// A whole range definition parsed from TOML.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub name: String,
    /// Optional override for the first VMID. Defaults to [`DEFAULT_BASE_VMID`].
    #[serde(default)]
    pub base_vmid: Option<u32>,
    #[serde(default)]
    pub hosts: Vec<Host>,
}

impl Range {
    /// Parse a range from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, RangeError> {
        toml::from_str(s).map_err(|e| RangeError::Parse(e.to_string()))
    }

    /// Parse a range from a TOML file on disk.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, RangeError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| RangeError::Io(format!("reading {}: {e}", path.display())))?;
        Self::from_toml_str(&text)
    }

    /// The effective base VMID, honoring the optional override.
    pub fn base_vmid(&self) -> u32 {
        self.base_vmid.unwrap_or(DEFAULT_BASE_VMID)
    }
}
