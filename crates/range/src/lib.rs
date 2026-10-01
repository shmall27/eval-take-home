//! `range` — the reusable core of a cyber-eval harness.
//!
//! It compiles a declarative range definition (TOML) into ordered Proxmox
//! operations and, optionally, executes them. The pipeline is:
//!
//! 1. [`schema`] parses the range TOML into [`schema::Range`].
//! 2. [`segments`] resolves segment names against the fabric's
//!    `segments.json` (or a built-in fallback) into bridges.
//! 3. [`planner`] validates and compiles the range into an ordered [`planner::Op`]
//!    list for each lifecycle [`planner::Stage`] — pure, no network.
//! 4. [`executor`] runs those ops against a live node via the [`proxmox`] client.
//!
//! The model/provider concern is deliberately out of scope here — this crate is
//! range lifecycle only.

pub mod error;
pub mod executor;
pub mod guest;
pub mod planner;
pub mod proxmox;
pub mod schema;
pub mod segments;

pub use error::RangeError;
pub use planner::{compile, CompiledRange, Op, ResolvedHost, Stage};
pub use schema::{Host, Range, Role};
pub use segments::{Segment, SegmentMap};
