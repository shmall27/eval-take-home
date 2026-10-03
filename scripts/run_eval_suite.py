#!/usr/bin/env python3
"""Run model trials from a frozen suite plan through Harbor.

The offline planner (boundary_eval.suite) freezes config/eval-suite.toml into
a hashed metadata plan; this executor is the other half. It validates the
frozen plan (internal consistency, then freshness: the registry bytes and
every task descriptor are re-hashed and compared with the sha256 values the
plan pinned), resolves each model trial into an attributed per-model package
rendered through the family's render module, and launches one Harbor job per
(model, entry) cell with the plan's replicates and the declared comparison
settings applied wherever the agent runtime supports them.

Discipline, mirroring the rest of the harness:

- The plan is the schedule of record: replicates are never adjusted, and
  trial ids come only from the plan.
- Declared settings the runtime cannot apply are an error unless
  --allow-unapplied-settings acknowledges them; acknowledged gaps are
  recorded in the execution record, never silently ignored.
- Families whose packages cannot be re-rendered attributed (hand-authored
  packages, e.g. crm) are an error unless --allow-unattributed-packages
  acknowledges them; they then run as-is, unattributed.
- Provider credentials are read from the local env files and passed through
  the Harbor process environment, never argv, never printed.
- One deterministic job name per cell; a cell whose job already has a
  result file is skipped (delete jobs/<name> to rerun it).
- Every cell appends one record to the run's execution record before and
  after execution; the record never contains credentials.

Cells run strictly serially by default — the plan order is the schedule of
record. --max-parallel-cells runs several at once, bounded per model by
--max-parallel-per-model so no single provider is hit beyond its share (each
cell already fans out to -n replicate requests inside one Harbor job), and
--retries adds backoff retry for a cell whose Harbor job exits nonzero. These
knobs change only how cells are scheduled, never the plan or the replicate set.

The shared budget's wall_clock_seconds applies per agent conversation (per
step for multi-step tasks), implemented as an --agent-timeout-multiplier
against each task descriptor's [agent] timeout_sec.

Example:
  python3 scripts/run_eval_suite.py --plan results/suites/open-weight-comparison-v1.plan.json --dry-run
  python3 scripts/run_eval_suite.py --plan results/suites/open-weight-comparison-v1.plan.json \\
      --model z-ai/glm-5.3 --family pivot-chain --condition baseline --max-cells 1

Standard library only.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from boundary_eval.suite import SuiteError, validate_plan  # noqa: E402
from provider_smoke import load_config  # noqa: E402

MAX_PLAN_BYTES = 64 * 1024 * 1024
PROBE_TIMEOUT_SEC = 45
PROBE_MAX_TOKENS = 2048

# Plan model_id -> how Harbor and the provider reach it. The harbor model
# string is f"{harbor_prefix}/{model_id}"; credentials come from the local
# env file (key read by name, exported under the name Harbor's provider
# reads) and never travel through argv.
MODEL_WIRING = {
    "z-ai/glm-5.3": {
        "job_key": "glm53",
        "env_file": ".env",
        "key_name": "OPENROUTER_API_KEY",
        "export_as": "OPENROUTER_API_KEY",
        "api_base": "https://openrouter.ai/api/v1",
        "harbor_prefix": "openrouter",
        "concurrency": 3,
    },
    "deepseek/deepseek-v4-pro-0813": {
        "job_key": "deepseek4pro",
        "env_file": ".env",
        "key_name": "OPENROUTER_API_KEY",
        "export_as": "OPENROUTER_API_KEY",
        "api_base": "https://openrouter.ai/api/v1",
        "harbor_prefix": "openrouter",
        "concurrency": 3,
    },
    "minimax/minimax-m3": {
        "job_key": "minimaxm3",
        "env_file": ".env",
        "key_name": "OPENROUTER_API_KEY",
        "export_as": "OPENROUTER_API_KEY",
        "api_base": "https://openrouter.ai/api/v1",
        "harbor_prefix": "openrouter",
        "concurrency": 3,
    },
    "qwen/qwen3.8-27b": {
        "job_key": "qwen3827b",
        "env_file": ".env",
        "key_name": "OPENROUTER_API_KEY",
        "export_as": "OPENROUTER_API_KEY",
        "api_base": "https://openrouter.ai/api/v1",
        "harbor_prefix": "openrouter",
        "concurrency": 3,
    },
}

SUPPORTED_AGENT = "terminus-2"

# kwargs harbor agent schema declares for the supported agent; a declared
# setting maps to a kwarg only when the agent actually accepts it.
SUPPORTED_AGENT_KWARGS = frozenset({
    "max_turns", "parser_name", "api_base", "temperature", "reasoning_effort",
    "collect_rollout_data", "session_id", "enable_summarize",
    "proactive_summarize_threshold", "max_thinking_tokens", "model_info",
    "tmux_pane_width", "tmux_pane_height", "store_all_messages",
})

# (section, key) -> how the executor applies a declared setting.
#   agent_kwarg: --ak <name>=<value> (only when SUPPORTED_AGENT_KWARGS has it)
#   agent_timeout: per-cell --agent-timeout-multiplier from the descriptor
SETTING_MAP = {
    ("generation_settings", "temperature"): ("agent_kwarg", "temperature"),
    ("budget", "max_tool_calls"): ("agent_kwarg", "max_turns"),
    ("budget", "wall_clock_seconds"): ("agent_timeout", None),
}

# Families rendered from a scenarios/ source whose render module takes
# --variant (both dial sources render the base, hard and expert positions
# of their difficulty dial).
VARIANT_RENDER_SOURCES = ("scenarios/northgate", "scenarios/pivot_chain")


class SuiteExecutionError(ValueError):
    """The suite cannot be executed as declared."""


def harbor_binary():
    """Locate the Harbor CLI; the declared agent version must be reachable."""
    found = shutil.which("harbor") or (Path.home() / ".local" / "bin" / "harbor")
    if not Path(found).exists():
        raise SuiteExecutionError("harbor binary not found on PATH or ~/.local/bin")
    return str(found)


def read_plan(path):
    """Load and validate a frozen suite plan; the plan is the schedule of record."""
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise SuiteExecutionError(f"cannot read plan {target}: {exc}") from None
    if len(raw) > MAX_PLAN_BYTES:
        raise SuiteExecutionError("plan exceeds the size guard")
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SuiteExecutionError(f"plan is not JSON: {exc}") from None
    try:
        validate_plan(plan)
    except (SuiteError, TypeError, ValueError) as exc:
        raise SuiteExecutionError(f"plan failed validation: {exc}") from None
    return plan


def _pinned_path(root, relative):
    """Resolve a plan-declared relative path and keep it inside the root."""
    if (Path(relative).is_absolute() or ".." in Path(relative).parts
            or Path(relative).parts and Path(relative).parts[0] in (".",)):
        raise SuiteExecutionError(f"plan path is not canonical and relative: {relative}")
    path = (root / relative).resolve()
    root = root.resolve()
    if path != root and root not in path.parents:
        raise SuiteExecutionError(f"plan path escapes the root: {relative}")
    return path


def fresh_catalog(root, plan):
    """Re-hash the registry and every descriptor the plan pinned.

    The frozen plan is only a schedule if it still describes the tree: a
    registry or descriptor byte that moved invalidates it. Returns the family
    source map and the descriptor bytes (already verified against their
    pinned sha256).
    """
    catalog_path = _pinned_path(root, plan["configuration"]["catalog"])
    registry_raw = catalog_path.read_bytes()
    if hashlib.sha256(registry_raw).hexdigest() != plan["catalog"]["catalog_sha256"]:
        raise SuiteExecutionError(
            "registry bytes changed since the plan was frozen; re-plan the suite")
    registry = json.loads(registry_raw)
    sources = {family["id"]: family.get("source")
               for family in registry["families"]}
    descriptors = {}
    for entry in plan["catalog"]["entries"]:
        descriptor_path = _pinned_path(root, entry["descriptor_path"])
        data = descriptor_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["descriptor_sha256"]:
            raise SuiteExecutionError(
                f"descriptor changed since the plan was frozen: {entry['descriptor_path']}")
        descriptors[entry["descriptor_path"]] = data
    return sources, descriptors


def agent_timeout_sec(descriptor_bytes, descriptor_path):
    """The [agent] timeout_sec the descriptor declares; fail closed without it."""
    try:
        parsed = tomllib.loads(descriptor_bytes.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise SuiteExecutionError(f"cannot parse descriptor {descriptor_path}: {exc}") from None
    try:
        timeout = parsed["agent"]["timeout_sec"]
    except (KeyError, TypeError):
        raise SuiteExecutionError(
            f"descriptor {descriptor_path} declares no [agent] timeout_sec") from None
    if type(timeout) not in (int, float) or not timeout > 0:
        raise SuiteExecutionError(
            f"descriptor {descriptor_path} has an invalid [agent] timeout_sec")
    return float(timeout)


def split_agent_version(shared):
    """'harbor-0.23.0/terminus-2' -> ('0.23.0', 'terminus-2')."""
    declared = shared["agent_version"]
    if "/" not in declared:
        raise SuiteExecutionError(
            f"agent_version must be '<harbor>/<agent>': {declared!r}")
    harbor_part, agent = declared.rsplit("/", 1)
    if not harbor_part.startswith("harbor-") or not agent:
        raise SuiteExecutionError(
            f"agent_version must be 'harbor-<version>/<agent>': {declared!r}")
    return harbor_part[len("harbor-"):], agent


def check_harbor_version(binary, expected, *, skip=False):
    """Fail closed unless the installed Harbor matches the declared version."""
    if skip:
        return None
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SuiteExecutionError(f"cannot run {binary} --version: {exc}") from None
    version = result.stdout.strip().split()[-1] if result.stdout.strip() else ""
    if result.returncode or version != expected:
        raise SuiteExecutionError(
            f"declared harbor {expected} but {version or '?'} is installed "
            f"(--skip-version-check to run anyway)")
    return version


def resolve_settings(shared, *, allow_unapplied):
    """Map declared comparison settings to runtime knobs; collect the gaps.

    Returns (agent_args, wall_clock_seconds, unapplied) where agent_args are
    '--ak name=value' pairs and wall_clock_seconds is applied per cell as an
    agent-timeout multiplier. Anything declared that the runtime cannot
    apply is an error unless explicitly acknowledged.
    """
    agent_args = []
    unapplied = []
    wall_clock = None
    for section in ("generation_settings", "budget"):
        for key, value in sorted(shared.get(section, {}).items()):
            mapping = SETTING_MAP.get((section, key))
            if mapping is None:
                unapplied.append(f"{section}.{key}")
            elif mapping[0] == "agent_kwarg":
                if mapping[1] not in SUPPORTED_AGENT_KWARGS:
                    unapplied.append(f"{section}.{key}")
                else:
                    agent_args.append(["--ak", f"{mapping[1]}={value}"])
            elif mapping[0] == "agent_timeout":
                wall_clock = float(value)
    if unapplied and not allow_unapplied:
        raise SuiteExecutionError(
            "declared settings the agent runtime cannot apply: "
            + ", ".join(unapplied)
            + " (terminus-2 supports: temperature, max_turns; wall_clock_seconds"
              " applies as an agent-timeout multiplier; pass"
              " --allow-unapplied-settings to acknowledge and record the gap)")
    return agent_args, wall_clock, unapplied


def select_cells(plan, *, models=None, families=None, conditions=None,
                 variants=None, max_cells=None):
    """Group the plan's shuffled model trials into (model, entry) cells.

    Cells keep the plan's shuffled order (first appearance); every cell
    carries the plan's full replicate set — the plan is the schedule of
    record, so no cell is ever partially executed.
    """
    entries = {entry["entry_id"]: entry for entry in plan["catalog"]["entries"]}
    cells = {}
    order = []
    for trial in plan["model_trials"]:
        entry = entries.get(trial["entry_id"])
        if entry is None:
            raise SuiteExecutionError(
                f"trial {trial['trial_id']} references unknown entry {trial['entry_id']}")
        if models and trial["model_id"] not in models:
            continue
        if families and entry["family_id"] not in families:
            continue
        if conditions and entry["condition"] not in conditions:
            continue
        if variants and entry["variant"] not in variants:
            continue
        if trial["model_id"] not in MODEL_WIRING:
            raise SuiteExecutionError(
                f"planned model has no Harbor wiring: {trial['model_id']}")
        key = (trial["model_id"], trial["entry_id"])
        if key not in cells:
            cells[key] = {"model_id": trial["model_id"], "entry": entry,
                          "trial_ids": [], "replicates": []}
            order.append(key)
        cells[key]["trial_ids"].append(trial["trial_id"])
        cells[key]["replicates"].append(trial["replicate"])
    wanted = [cells[key] for key in order]
    replicates = plan["configuration"]["replicates"]
    for cell in wanted:
        if sorted(cell["replicates"]) != list(range(1, replicates + 1)):
            raise SuiteExecutionError(
                f"cell {cell['entry']['entry_id']} / {cell['model_id']} is missing"
                " planned replicates; the plan is the schedule of record")
        cell["replicates"] = replicates
    if max_cells is not None:
        wanted = wanted[:max_cells]
    return wanted


def cell_slug(entry):
    """A unique, filesystem-safe job-name fragment for one entry."""
    part = entry["condition"] or entry["variant"] or entry["case"]
    if not part:
        raise SuiteExecutionError(f"entry {entry['entry_id']} has no condition,"
                                  " variant or case to name it by")
    return f"{entry['family_id']}-{part}"


def render_module(root, source):
    """The render module for a scenarios/ source, or None when unrenderable."""
    if not source or not source.startswith("scenarios/"):
        return None
    module = source.replace("/", ".") + ".render"
    if not (Path(root) / source / "render.py").exists():
        return None
    return module


def cell_commands(root, plan, cell, agent_args, wall_clock, descriptors,
                  *, allow_unattributed):
    """Resolve one cell to its render step (if any), package and Harbor argv."""
    entry = cell["entry"]
    wiring = MODEL_WIRING[cell["model_id"]]
    shared = plan["configuration"]["shared"]
    run_id = plan["configuration"]["run_id"]
    outputs = root / plan["configuration"]["outputs"]["directory"]
    source = cell.get("source")
    module = render_module(root, source)
    attributed = module is not None
    if module is None and not allow_unattributed:
        raise SuiteExecutionError(
            f"family {entry['family_id']} has no render module (source {source!r});"
            " its packages cannot be re-rendered attributed — pass"
            " --allow-unattributed-packages to run the registered package as-is")
    if module is None:
        package = root / entry["package_path"]
        render_argv = None
    else:
        package_dir = outputs / run_id / "packages" / wiring["job_key"] / entry["family_id"]
        package = package_dir / entry["condition"]
        render_argv = [sys.executable, "-m", module,
                       "--output", str(package_dir),
                       "--conditions", entry["condition"],
                       "--actor-kind", "model",
                       "--model-id", cell["model_id"],
                       "--plan-sha256", plan["plan_sha256"],
                       "--run-id", run_id]
        if source in VARIANT_RENDER_SOURCES:
            render_argv += ["--variant", entry["variant"] or "base"]
    job_name = f"{run_id}-{wiring['job_key']}-{cell_slug(entry)}"
    harbor_argv = [harbor_binary(), "run", "-p", str(package),
                   "-a", shared["agent_version"].rsplit("/", 1)[1],
                   "-m", f"{wiring['harbor_prefix']}/{cell['model_id']}",
                   "-k", str(cell["replicates"]),
                   "-n", str(wiring["concurrency"]),
                   "--yes", "--job-name", job_name]
    harbor_argv += [part for arg in agent_args for part in arg]
    if wall_clock is not None:
        timeout = agent_timeout_sec(descriptors[entry["descriptor_path"]],
                                    entry["descriptor_path"])
        multiplier = wall_clock / timeout
        if not 0 < multiplier <= 10:
            raise SuiteExecutionError(
                f"{job_name}: agent-timeout multiplier {multiplier:.3f} out of range"
                f" (wall_clock {wall_clock}s vs descriptor {timeout}s)")
        harbor_argv += ["--agent-timeout-multiplier", f"{multiplier:.4f}"]
    return {"job_name": job_name, "render_argv": render_argv,
            "package": str(package), "harbor_argv": harbor_argv,
            "attributed": attributed}


def credentials(model_id, *, root=ROOT):
    """Load one model's provider credentials; returns the child environment."""
    spec = MODEL_WIRING[model_id]
    config = load_config(Path(root) / spec["env_file"])
    key = config.get(spec["key_name"], "")
    if not key:
        raise SuiteExecutionError(
            f"{model_id}: missing {spec['key_name']} in {spec['env_file']}")
    environment = dict(os.environ)
    environment[spec["export_as"]] = key
    return environment


def probe_model(model_id, environment, *, root=ROOT, probe_fn=None):
    """One cheap completion against the provider; fail before cells burn."""
    spec = MODEL_WIRING[model_id]
    base = (os.environ.get("MODEL_BASE_URL")
            or load_config(Path(root) / spec["env_file"]).get("MODEL_BASE_URL")
            or spec["api_base"]).rstrip("/")
    body = json.dumps({"model": model_id, "max_tokens": PROBE_MAX_TOKENS,
                       "messages": [{"role": "user", "content": "Reply OK"}]}).encode()
    request = urllib.request.Request(
        f"{base}/chat/completions", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {environment[spec['export_as']]}"})
    if probe_fn is not None:
        return probe_fn(request, PROBE_TIMEOUT_SEC)
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT_SEC) as response:
            response.read()
        return response.status == 200
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
        return False


def job_finished(jobs_dir, job_name):
    """A cell is done when its job result reports a finish. Harbor writes
    result.json at job start with finished_at unset, so existence alone
    would mistake an interrupted job for a complete one."""
    result = jobs_dir / job_name / "result.json"
    if not result.exists():
        return False
    try:
        with result.open(encoding="utf-8") as stream:
            return bool(json.load(stream).get("finished_at"))
    except (OSError, ValueError):
        return False


def write_record(record_path, record):
    """Append one cell record; credentials never appear in it."""
    with record_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


RETRY_BACKOFF_CAP_SEC = 300.0


def make_base_record(cell, cell_cmd, agent_args, unapplied, wall_clock):
    """The per-cell execution record, minus the run outcome; credential-free."""
    return {
        "job_name": cell_cmd["job_name"], "trial_ids": cell["trial_ids"],
        "entry_id": cell["entry"]["entry_id"],
        "family_id": cell["entry"]["family_id"],
        "model_id": cell["model_id"],
        "condition": cell["entry"]["condition"],
        "variant": cell["entry"]["variant"], "case": cell["entry"]["case"],
        "package": cell_cmd["package"], "attributed": cell_cmd["attributed"],
        "settings_applied": [arg[1] for arg in agent_args],
        "settings_unapplied": unapplied,
        "wall_clock_seconds": wall_clock,
    }


def run_harbor(harbor_argv, *, cwd, env, retries, backoff):
    """Launch one Harbor job, retrying a nonzero exit up to `retries` times.

    Harbor's exit code cannot separate a transient provider failure (a 429, a
    dropped stream) from a deterministic one, and the common failure of a wide
    run is provider throttling — so any nonzero exit is retried with exponential
    backoff and jitter. retries=0 keeps the original single-attempt behavior.
    Returns (returncode, attempts)."""
    attempt = 0
    while True:
        attempt += 1
        code = subprocess.run(harbor_argv, cwd=cwd, env=env).returncode
        if code == 0 or attempt > retries:
            return code, attempt
        delay = min(RETRY_BACKOFF_CAP_SEC, backoff * (2 ** (attempt - 1)))
        time.sleep(delay + random.uniform(0, backoff))


def execute_cell(order, cell, cell_cmd, *, root, jobs_dir, record_path,
                 base_record, retries, backoff, render_lock, io_lock):
    """Run one (model, entry) cell: skip-if-done, render, then Harbor.

    Renders are serialized under render_lock — a cell renders into a per-model
    package dir, so only two cells of the same model and family could ever
    target the same tree, and the lock keeps that write exclusive. Stdout and
    the execution record are serialized under io_lock so concurrent cells never
    interleave a line or a record. Returns (status, returncode)."""
    job_name = cell_cmd["job_name"]
    if job_finished(jobs_dir, job_name):
        with io_lock:
            print(f"[{order}] SKIP {job_name} (result exists)")
            write_record(record_path, {**base_record, "status": "skipped"})
        return "skipped", 0
    started = time.time()
    with io_lock:
        print(f"[{order}] RUN {job_name} "
              f"({cell['replicates']} trials, "
              f"{'attributed' if cell_cmd['attributed'] else 'UNATTRIBUTED'})")
    status, code, attempts = "ran", 0, 0
    if cell_cmd["render_argv"]:
        with render_lock:
            code = subprocess.run(cell_cmd["render_argv"], cwd=root).returncode
        if code:
            status = "render-failed"
    if status == "ran":
        environment = credentials(cell["model_id"], root=root)
        code, attempts = run_harbor(cell_cmd["harbor_argv"], cwd=root,
                                    env=environment, retries=retries,
                                    backoff=backoff)
        if code:
            status = "harbor-failed"
    with io_lock:
        write_record(record_path, {**base_record, "status": status,
                                   "returncode": code, "attempts": attempts,
                                   "started_epoch": round(started, 3),
                                   "finished_epoch": round(time.time(), 3)})
        print(f"[{order}] {'FAILED' if code else 'done'} {job_name}"
              + (f" ({status}, exit {code})" if code else ""))
    return status, code


def _interleave(groups):
    """Round-robin items across per-model groups so the pool fills evenly
    across providers instead of draining one model first."""
    queues = [list(group) for group in groups]
    ordered = []
    while any(queues):
        for queue in queues:
            if queue:
                ordered.append(queue.pop(0))
    return ordered


def run_cells_concurrently(work, *, args, root, record_path, render_lock, io_lock):
    """Execute cells through a bounded thread pool.

    At most --max-parallel-cells cells run at once, and a per-model semaphore
    holds any single model to --max-parallel-per-model so one provider is never
    hit beyond its share. Cells are interleaved by model for an even fill.
    --stop-on-failure stops launching new cells; those already in flight drain,
    so the exact set that completes is not deterministic under concurrency.
    Returns the failed job names."""
    by_model = {}
    for item in work:
        by_model.setdefault(item[1]["model_id"], []).append(item)
    semaphores = {model: threading.Semaphore(args.max_parallel_per_model)
                  for model in by_model}
    stop = threading.Event()
    failed = []

    def worker(order, cell, cell_cmd, base_record):
        if stop.is_set():
            return
        with semaphores[cell["model_id"]]:
            if stop.is_set():
                return
            _status, code = execute_cell(
                order, cell, cell_cmd, root=root, jobs_dir=args.jobs_dir,
                record_path=record_path, base_record=base_record,
                retries=args.retries, backoff=args.retry_backoff,
                render_lock=render_lock, io_lock=io_lock)
        if code:
            with io_lock:
                failed.append(cell_cmd["job_name"])
            if args.stop_on_failure:
                stop.set()

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.max_parallel_cells) as pool:
        futures = [pool.submit(worker, *item)
                   for item in _interleave(by_model.values())]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    return failed


def main(argv=None, *, root=ROOT):
    root = Path(root)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", type=Path, required=True,
                        help="frozen suite plan (boundary_eval.suite output)")
    parser.add_argument("--jobs-dir", type=Path, default=root / "jobs")
    parser.add_argument("--model", action="append",
                        help="plan model_id to run; repeatable; default all planned")
    parser.add_argument("--family", action="append",
                        help="family_id to run; repeatable; default all planned")
    parser.add_argument("--condition", action="append",
                        help="condition to run; repeatable; default all planned")
    parser.add_argument("--variant", action="append",
                        help="variant to run; repeatable; default all planned")
    parser.add_argument("--max-cells", type=int,
                        help="stop after this many cells (smoke runs)")
    parser.add_argument("--dry-run", action="store_true",
                        help="resolve and print every command; run nothing")
    parser.add_argument("--allow-unapplied-settings", action="store_true",
                        help="acknowledge declared settings the runtime cannot apply")
    parser.add_argument("--allow-unattributed-packages", action="store_true",
                        help="run hand-authored packages as-is, unattributed")
    parser.add_argument("--skip-preflight", action="store_true",
                        help="do not probe each model's endpoint first")
    parser.add_argument("--skip-version-check", action="store_true",
                        help="run even if the installed Harbor version differs")
    parser.add_argument("--stop-on-failure", action="store_true",
                        help="abort the suite on the first failed cell")
    parser.add_argument("--max-parallel-cells", type=int, default=1,
                        help="run up to N cells concurrently (default 1,"
                             " strictly serial); each cell still fans out to -n"
                             " replicate requests inside one Harbor job")
    parser.add_argument("--max-parallel-per-model", type=int, default=2,
                        help="cap concurrent cells for any one model so a single"
                             " provider is not overloaded (default 2; only"
                             " engages when --max-parallel-cells > 1)")
    parser.add_argument("--retries", type=int, default=0,
                        help="retry a cell whose Harbor job exits nonzero, up to"
                             " N times, with exponential backoff (default 0)")
    parser.add_argument("--retry-backoff", type=float, default=15.0,
                        help="base seconds for retry backoff (default 15)")
    args = parser.parse_args(argv)
    if args.max_parallel_cells < 1:
        raise SuiteExecutionError("--max-parallel-cells must be >= 1")
    if args.max_parallel_per_model < 1:
        raise SuiteExecutionError("--max-parallel-per-model must be >= 1")
    if args.retries < 0:
        raise SuiteExecutionError("--retries must be >= 0")
    if args.retry_backoff < 0:
        raise SuiteExecutionError("--retry-backoff must be >= 0")

    plan = read_plan(args.plan)
    sources, descriptors = fresh_catalog(root, plan)
    shared = plan["configuration"]["shared"]
    harbor_part, agent = split_agent_version(shared)
    if agent != SUPPORTED_AGENT:
        raise SuiteExecutionError(
            f"this executor wires the {SUPPORTED_AGENT} agent only, not {agent!r}")
    check_harbor_version(harbor_binary(), harbor_part, skip=args.skip_version_check)
    agent_args, wall_clock, unapplied = resolve_settings(
        shared, allow_unapplied=args.allow_unapplied_settings)

    cells = select_cells(plan, models=set(args.model or []), families=set(args.family or []),
                         conditions=set(args.condition or []), variants=set(args.variant or []),
                         max_cells=args.max_cells)
    if not cells:
        raise SuiteExecutionError("no planned cells match the selection")

    resolved = []
    for cell in cells:
        cell["source"] = sources[cell["entry"]["family_id"]]
        resolved.append(cell_commands(root, plan, cell, agent_args, wall_clock,
                                       descriptors,
                                       allow_unattributed=args.allow_unattributed_packages))

    run_id = plan["configuration"]["run_id"]
    outputs = root / plan["configuration"]["outputs"]["directory"]
    record_path = outputs / run_id / "execution.jsonl"
    trials = sum(cell["replicates"] for cell in cells)
    print(f"plan {plan['plan_sha256'][:16]}… run {run_id}: "
          f"{len(cells)} cells / {trials} trials selected "
          f"of {len(plan['model_trials'])} planned")
    if unapplied:
        print(f"WARNING unapplied declared settings: {', '.join(unapplied)}")

    if args.dry_run:
        for order, (cell, cell_cmd) in enumerate(zip(cells, resolved), start=1):
            print(f"[{order}] {cell_cmd['job_name']} "
                  f"({cell['replicates']} trials, "
                  f"{'attributed' if cell_cmd['attributed'] else 'UNATTRIBUTED'})")
            print("    render:", cell_cmd["render_argv"]
                  and shlex.join(cell_cmd["render_argv"]) or "-")
            print("    harbor:", shlex.join(cell_cmd["harbor_argv"]))
        return 0

    if not args.skip_preflight:
        for model_id in {cell["model_id"] for cell in cells}:
            environment = credentials(model_id, root=root)
            if not probe_model(model_id, environment, root=root):
                raise SuiteExecutionError(
                    f"preflight probe failed for {model_id}; check the endpoint"
                    " and credentials before burning cells")
            print(f"preflight ok: {model_id}")

    if args.max_parallel_cells > 1:
        print(f"concurrency: up to {args.max_parallel_cells} cells in flight,"
              f" <= {args.max_parallel_per_model} per model,"
              f" retries={args.retries}")
    outputs.mkdir(parents=True, exist_ok=True)
    (outputs / run_id).mkdir(parents=True, exist_ok=True)
    work = [(order, cell, cell_cmd,
             make_base_record(cell, cell_cmd, agent_args, unapplied, wall_clock))
            for order, (cell, cell_cmd)
            in enumerate(zip(cells, resolved), start=1)]
    render_lock = threading.Lock()
    io_lock = threading.Lock()

    if args.max_parallel_cells == 1:
        # Serial: the plan order is the schedule of record, and --stop-on-failure
        # halts immediately on the first failure, exactly as it always has.
        failed = []
        for order, cell, cell_cmd, base_record in work:
            _status, code = execute_cell(
                order, cell, cell_cmd, root=root, jobs_dir=args.jobs_dir,
                record_path=record_path, base_record=base_record,
                retries=args.retries, backoff=args.retry_backoff,
                render_lock=render_lock, io_lock=io_lock)
            if code:
                failed.append(cell_cmd["job_name"])
                if args.stop_on_failure:
                    break
    else:
        failed = run_cells_concurrently(
            work, args=args, root=root, record_path=record_path,
            render_lock=render_lock, io_lock=io_lock)

    if failed:
        print(f"failed cells ({len(failed)}): {', '.join(failed)}")
        return 1
    print("suite selection complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SuiteExecutionError as exc:
        print(f"suite execution failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
