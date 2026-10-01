//! `range` CLI: compile a range definition and plan/apply/reset/destroy it.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use range::executor;
use range::planner::{self, Stage};
use range::proxmox::{Config, Pve};
use range::schema::Range;
use range::segments::{SegmentMap, DEFAULT_SEGMENTS_PATH};

#[derive(Parser)]
#[command(
    name = "range",
    about = "Compile a declarative cyber-range definition into Proxmox operations",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the ordered Proxmox operations with NO side effects.
    Plan(Common),
    /// Build the range: clone, wire NIC, boot, set IP, snapshot `clean`.
    Apply(Common),
    /// Roll every host back to its `clean` snapshot.
    Reset(Common),
    /// Stop and purge every host.
    Destroy(Common),
}

#[derive(Parser)]
struct Common {
    /// Path to the range TOML file.
    #[arg(short, long)]
    file: PathBuf,
    /// Path to the fabric's segments.json (falls back to a built-in `iso` segment).
    #[arg(long, default_value = DEFAULT_SEGMENTS_PATH)]
    segments: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let (common, stage, is_plan) = match &cli.command {
        Command::Plan(c) => (c, Stage::Apply, true),
        Command::Apply(c) => (c, Stage::Apply, false),
        Command::Reset(c) => (c, Stage::Reset, false),
        Command::Destroy(c) => (c, Stage::Destroy, false),
    };

    let range = Range::from_toml_file(&common.file)
        .with_context(|| format!("loading range {}", common.file.display()))?;
    let segments = SegmentMap::load_or_fallback(&common.segments)?;
    if segments.is_fallback() {
        eprintln!(
            "note: no segments.json at {}; using built-in fallback segment (iso -> vmbr1)",
            common.segments.display()
        );
    }
    let compiled = planner::compile(&range, &segments)?;

    if is_plan {
        print_plan(&compiled);
        return Ok(());
    }

    // Executing stages need a live client, configured from the environment.
    let cfg = Config::from_env().context("configuring Proxmox client")?;
    let pve = Pve::new(cfg)?;
    executor::execute(&pve, &compiled, stage)?;
    Ok(())
}

fn print_plan(compiled: &range::CompiledRange) {
    println!("range: {}", compiled.name);
    println!("hosts: {}", compiled.hosts.len());
    for h in &compiled.hosts {
        let ip = h.ip.as_deref().unwrap_or("dhcp");
        println!(
            "  - {} -> VMID {} (template {}, bridge {}, {}, {:?})",
            h.name, h.vmid, h.template, h.bridge, ip, h.role
        );
    }
    for (stage, label) in [
        (Stage::Apply, "apply"),
        (Stage::Reset, "reset"),
        (Stage::Destroy, "destroy"),
    ] {
        println!("\n== {label} plan ==");
        for (i, op) in compiled.operations(stage).iter().enumerate() {
            println!("  {:>2}. {}", i + 1, op.describe());
        }
    }
}
