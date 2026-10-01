//! Segment resolution.
//!
//! The network fabric publishes the source of truth at
//! `infra/network/segments.json` (schema per the contract). This module loads
//! that file into a name -> [`Segment`] map. When the file is absent (the crate
//! is testable before the fabric exists), it falls back to a single built-in
//! segment named `iso` mapped to bridge `vmbr1`, which is the existing isolated
//! bridge used by the infra smoke tests.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::RangeError;

/// Default location of the fabric's segment definitions, relative to repo root.
pub const DEFAULT_SEGMENTS_PATH: &str = "infra/network/segments.json";

/// The fallback segment name used when no `segments.json` exists.
pub const FALLBACK_SEGMENT_NAME: &str = "iso";
/// The bridge the fallback segment maps to (the existing isolated bridge).
pub const FALLBACK_SEGMENT_BRIDGE: &str = "vmbr1";

/// One isolated layer-2 segment: a Proxmox bridge with no uplink.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Segment {
    pub name: String,
    pub bridge: String,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub gateway_ip: Option<String>,
    #[serde(default)]
    pub dhcp_start: Option<String>,
    #[serde(default)]
    pub dhcp_end: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
}

/// A resolved set of segments keyed by name.
#[derive(Debug, Clone, Default)]
pub struct SegmentMap {
    by_name: BTreeMap<String, Segment>,
    /// Whether this map came from the built-in fallback rather than a file.
    from_fallback: bool,
}

impl SegmentMap {
    /// Build a map from a list of segments (used by tests and the JSON loader).
    pub fn from_segments(segments: Vec<Segment>) -> Self {
        let by_name = segments.into_iter().map(|s| (s.name.clone(), s)).collect();
        Self {
            by_name,
            from_fallback: false,
        }
    }

    /// The built-in single-segment fallback: `iso` -> `vmbr1`.
    pub fn fallback() -> Self {
        let seg = Segment {
            name: FALLBACK_SEGMENT_NAME.to_string(),
            bridge: FALLBACK_SEGMENT_BRIDGE.to_string(),
            cidr: None,
            gateway_ip: None,
            dhcp_start: None,
            dhcp_end: None,
            domain: None,
        };
        let mut m = Self::from_segments(vec![seg]);
        m.from_fallback = true;
        m
    }

    /// Parse segments from a JSON string (same schema as the contract).
    pub fn from_json_str(s: &str) -> Result<Self, RangeError> {
        let segments: Vec<Segment> =
            serde_json::from_str(s).map_err(|e| RangeError::SegmentsParse(e.to_string()))?;
        Ok(Self::from_segments(segments))
    }

    /// Load segments from `path` if it exists, otherwise return the fallback.
    pub fn load_or_fallback(path: impl AsRef<Path>) -> Result<Self, RangeError> {
        let path = path.as_ref();
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| RangeError::Io(format!("reading {}: {e}", path.display())))?;
            Self::from_json_str(&text)
        } else {
            Ok(Self::fallback())
        }
    }

    /// Look up a segment by name.
    pub fn get(&self, name: &str) -> Option<&Segment> {
        self.by_name.get(name)
    }

    /// True if this map is the built-in fallback (no fabric file was found).
    pub fn is_fallback(&self) -> bool {
        self.from_fallback
    }

    /// Known segment names, sorted, for error messages.
    pub fn known_names(&self) -> Vec<String> {
        self.by_name.keys().cloned().collect()
    }
}
