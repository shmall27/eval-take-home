#!/usr/bin/env python3
"""Collect trusted verifier measurements using their original planned identities.

The launcher must bind each measurement to its planned trial before execution.
Directory order, job names and model aliases never assign a replicate. Legacy
records with unplanned IDs cannot be retrospectively matched by this collector.
The plan hash binds declared versions/settings; it does not independently prove
which software or model ran. Only caller-selected trusted grader files belong
here, never agent-authored JSON.

The output contains the experiment contract's envelope fields. Versioned outcome
and trajectory extensions remain in their original measurement files. A CLI
collection with missing, duplicate, malformed or mismatched records writes no
output, and an existing output file is never overwritten.

By default, discover measurements under --jobs-dir using plan/run/trial metadata.
Job names beginning with the run ID also select files, so malformed records in
the usual job layout are reported. Use repeatable --job-dir for explicit source
directories: every measurement in those directories is checked, including files
whose metadata cannot identify a run.
"""

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from boundary_eval.experiment import ExperimentError, analyze  # noqa: E402

ENVELOPE_KEYS = ("kind", "schema_version", "evidence_source", "actor_kind",
                 "model_id", "run_id", "scenario_id", "trial_id", "condition",
                 "plan_sha256", "score", "errors")
EXTENSION_KEYS = {"outcome", "trajectory", "completion_evidence", "task_version", "agent_version"}


def read_json(path):
    """Reject ambiguous JSON rather than choosing one duplicate object's value."""
    def reject_constant(_value):
        raise ValueError("JSON contains a non-finite number")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON object contains a duplicate key")
            result[key] = value
        return result

    return json.loads(Path(path).read_text(encoding="utf-8"),
                      parse_constant=reject_constant, object_pairs_hook=unique_object)


def planned_by_cell(plan):
    """Group complete identities; never pool scenarios or task versions."""
    analyze(plan, [])  # The existing experiment contract validates the full plan.
    groups = defaultdict(list)
    for trial in plan["schedule"]:
        key = tuple(trial[name] for name in
                    ("model_id", "scenario_id", "task_version", "condition"))
        groups[key].append(trial)
    return {key: sorted(members, key=lambda trial: trial["replicate"])
            for key, members in groups.items()}


def discover_measurements(plan, jobs_dir, job_dirs=()):
    """Select paths without using names/order to invent measurement identities."""
    analyze(plan, [])
    if job_dirs:
        paths = set()
        for directory in job_dirs:
            directory = Path(directory)
            if not directory.is_dir():
                raise ValueError(f"job directory does not exist: {directory}")
            paths.update(directory.rglob("verifier/measurement.json"))
        return sorted(paths)

    jobs_dir = Path(jobs_dir)
    if not jobs_dir.is_dir():
        raise ValueError(f"jobs directory does not exist: {jobs_dir}")
    expected = {trial["trial_id"] for trial in plan["schedule"]}
    paths = []
    for path in sorted(jobs_dir.rglob("verifier/measurement.json")):
        # Name-based selection only finds candidates with unreadable metadata;
        # it cannot make a record eligible for any planned trial.
        names = (jobs_dir.name, *path.relative_to(jobs_dir).parts[:-2])
        named_for_run = any(name == plan["run_id"] or
                            name.startswith(plan["run_id"] + "-") for name in names)
        try:
            record = read_json(path)
        except (OSError, UnicodeError, ValueError):
            if named_for_run:
                paths.append(path)
            continue
        relevant = isinstance(record, dict) and (
            record.get("run_id") == plan["run_id"] or
            record.get("plan_sha256") == plan["plan_sha256"] or
            (isinstance(record.get("trial_id"), str) and record["trial_id"] in expected))
        if named_for_run or relevant:
            paths.append(path)
    return paths


def collect_measurements(plan, paths):
    """Return exact-ID eligible envelopes plus explicit issues; perform no writes.

    Any repeated trial ID excludes every claimant, even when one claimant is
    malformed or has mismatched metadata. The original IDs are never changed.
    Invalid-evidence envelopes retain their unknown metrics as required by the
    analyzer; they are measurements of missing evidence, not successful trials.
    """
    analyze(plan, [])
    expected = {trial["trial_id"]: trial for trial in plan["schedule"]}
    records, source_paths, issues = [], [], []
    claims = defaultdict(list)
    ineligible = set()
    for source in paths:
        path = Path(source)
        try:
            record = read_json(path)
        except (OSError, UnicodeError, ValueError) as exc:
            issues.append({"code": "malformed", "paths": [str(path)], "reason": str(exc)})
            continue
        if not isinstance(record, dict):
            issues.append({"code": "malformed", "paths": [str(path)],
                           "reason": "measurement must be a JSON object"})
            continue
        index = len(records)
        source_paths.append(str(path))
        trial_id = record.get("trial_id")
        if isinstance(trial_id, str):
            claims[trial_id].append(index)
        envelope = {key: record[key] for key in ENVELOPE_KEYS if key in record}
        records.append(envelope)
        unknown_keys = set(record) - set(ENVELOPE_KEYS) - EXTENSION_KEYS
        if unknown_keys:
            ineligible.add(index)
            issues.append({"code": "malformed", "paths": [str(path)],
                           "reason": "measurement has unsupported fields"})
        trial = expected.get(trial_id) if isinstance(trial_id, str) else None
        if trial is not None:
            for key in ("task_version", "agent_version"):
                if key in record and record[key] != trial[key]:
                    ineligible.add(index)
                    issues.append({"code": "mismatched", "paths": [str(path)],
                                   "trial_id": trial_id,
                                   "reason": f"measurement {key} does not match the plan"})

    for trial_id, indices in claims.items():
        if len(indices) > 1:
            ineligible.update(indices)
            issues.append({"code": "duplicate", "trial_id": trial_id,
                           "paths": [source_paths[index] for index in indices],
                           "reason": "multiple records claim the same source trial; none selected"})

    report = analyze(plan, records)
    accepted = []
    for row in report["trials"]:
        indices = row["record_indices"]
        if row["status"] in ("measured", "invalid_evidence"):
            if indices[0] not in ineligible:
                accepted.append(records[indices[0]])
        elif row["status"] != "duplicate":
            issues.append({"code": row["status"], "trial_id": row["trial_id"],
                           "paths": [source_paths[index] for index in indices],
                           "reason": row["reason"]})
    for rejected in report["rejected_records"]:
        issues.append({"code": "unplanned", "trial_id": rejected["trial_id"],
                       "paths": [source_paths[rejected["record_index"]]],
                       "reason": rejected["reason"] + "; no retrospective replicate assignment"})
    # Schedule order is authoritative and independent of filesystem ordering.
    return {"measurements": accepted, "issues": issues}


def write_new_output(path, rendered):
    """Publish complete bytes atomically without replacing an existing path."""
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".measurement-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        # A same-directory hard link is atomic and fails if the destination
        # already exists. No destination is visible during an incomplete write.
        os.link(temporary, path)
    finally:
        try:
            Path(temporary).unlink()
        except OSError:
            # Cleanup failure must not misreport a successfully published file
            # as a failed collection; the temporary file contains no new data.
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--jobs-dir", type=Path, default=ROOT / "jobs")
    parser.add_argument("--job-dir", type=Path, action="append", default=[],
                        help="explicit source directory; repeat to select multiple jobs")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError(f"output already exists: {args.output}; choose a new path")
        plan = read_json(args.plan)
        paths = discover_measurements(plan, args.jobs_dir, args.job_dir)
        result = collect_measurements(plan, paths)
        for issue in result["issues"]:
            source = ", ".join(issue["paths"]) or issue.get("trial_id", "plan")
            print(f"{issue['code'].upper()} {source}: {issue['reason']}", file=sys.stderr)
        if result["issues"]:
            print(f"Collection failed with {len(result['issues'])} issues; no output was written.",
                  file=sys.stderr)
            return 1
        rendered = json.dumps(result["measurements"], indent=2, sort_keys=True, allow_nan=False) + "\n"
        write_new_output(args.output, rendered)
    except (ExperimentError, OSError, UnicodeError, ValueError, TypeError) as exc:
        print(f"Collection failed: {exc}; no output was written.", file=sys.stderr)
        return 1
    print(f"{len(result['measurements'])} measurement envelopes written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
