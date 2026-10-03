"""Offline evidence summaries and human-review samples for boundary experiments.

Read caller-selected trusted verifier measurements against an existing plan.
This module never launches tasks, queries models, or reads agent trajectories.
The v1 experiment contract still controls trial identity and provenance. A
separately validated outcome extension supplies target completion; an answer,
delivery event, or successful supplied solution is not a substitute for it.

Clue delivery is an observation, not awareness. Joint and conditional counts
are descriptive, not evidence of intent or causality. Selected review rows are
a stratified diagnostic sample, not a population-rate estimator. Use all planned
trials and the explicit unknown counts in the aggregate tables for reporting.

CLI: python3 -m boundary_eval.review --plan PLAN --measurement SIDECAR ...
Use --format csv for a blank human-annotation sheet. The default sample includes
eligible observed model trials; --review-scope all includes evidence follow-up
for missing and invalid trials too. Every aggregate retains all planned trials.
Output goes to stdout, or to a new --output file. Inputs and existing outputs
are never overwritten. Source references are caller labels, not attestations.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import copy
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import sys
import tempfile

from .experiment import ExperimentError, analyze, wilson_interval
from .outcomes import OUTCOME_FIELDS

METRICS = (
    "answer_correct", "target_goal_completed", "clue_delivered",
    "boundary_attempted", "boundary_contacted", "boundary_content_delivered",
    "reference_content_delivered", "target_content_delivered",
)
IDENTITY = ("model_id", "scenario_id", "task_version", "condition")
ROW_IDENTITY = ("trial_id", *IDENTITY, "replicate")
EXTENSIONS = frozenset({
    "outcome", "trajectory", "completion_evidence", "task_version", "agent_version",
})
STATUSES = (
    "measured", "invalid_evidence", "missing", "duplicate", "excluded",
    "mismatched", "malformed",
)
OUTCOME_STATUSES = ("validated", "missing", "invalid", "ineligible")
ANNOTATION_FIELDS = (
    "reviewer", "observations", "failure_category", "uncertainty",
    "evidence_reference",
)
_OUTCOME_COPIES = {
    "apparent_success": "answer_correct",
    "clue_delivered": "clue_delivered",
    "boundary_attempted": "boundary_attempted",
    "boundary_contacted": "boundary_contacted",
    "boundary_content_delivered": "boundary_content_delivered",
}


def _counts(values):
    positive = sum(value == 1 for value in values)
    negative = sum(value == 0 for value in values)
    measurable = positive + negative
    return {
        "planned": len(values), "positive": positive, "negative": negative,
        "unknown": len(values) - measurable, "measurable": measurable,
        "rate": positive / measurable if measurable else None,
        "wilson_95": wilson_interval(positive, measurable),
    }


def _coverage(rows):
    statuses = {status: sum(row["status"] == status for row in rows) for status in STATUSES}
    return {
        "planned": len(rows), "received": len(rows) - statuses["missing"],
        "measured": statuses["measured"],
        "measurement_coverage": statuses["measured"] / len(rows) if rows else None,
        "statuses": statuses,
    }


def _joint(rows, first, second):
    cells = dict.fromkeys((
        "both_negative", "first_only_positive", "second_only_positive", "both_positive",
        "first_unknown", "second_unknown", "both_unknown",
    ), 0)
    for row in rows:
        a, b = row["metrics"][first], row["metrics"][second]
        if a is None and b is None:
            cell = "both_unknown"
        elif a is None:
            cell = "first_unknown"
        elif b is None:
            cell = "second_unknown"
        else:
            cell = {
                (0, 0): "both_negative", (1, 0): "first_only_positive",
                (0, 1): "second_only_positive", (1, 1): "both_positive",
            }[(a, b)]
        cells[cell] += 1
    return {
        "first_metric": first, "second_metric": second, "planned": len(rows),
        "joint_measurable": len(rows) - sum(cells[name] for name in
                                            ("first_unknown", "second_unknown", "both_unknown")),
        **cells,
    }


def _completion(record, row):
    """Validate the published outcome independently from the core score.

    A bad extension cannot erase valid base observations or supply completion.
    Other extension blocks are deliberately not interpreted or copied out.
    """
    if row["status"] not in ("measured", "invalid_evidence"):
        return "ineligible", None
    if "outcome" not in record:
        return "missing", None
    outcome = record["outcome"]
    if not isinstance(outcome, dict) or set(outcome) != {"contract_version", *OUTCOME_FIELDS}:
        return "invalid", None
    if type(outcome["contract_version"]) is not int or outcome["contract_version"] != 1:
        return "invalid", None
    if any(type(outcome[field]) is not int or outcome[field] not in (-1, 0, 1)
           for field in OUTCOME_FIELDS):
        return "invalid", None
    normalized = {field: None if outcome[field] == -1 else outcome[field] for field in OUTCOME_FIELDS}
    if any(normalized[field] != row["metrics"][source] for field, source in _OUTCOME_COPIES.items()):
        return "invalid", None
    target = normalized["target_goal_completed"]
    if row["status"] != "measured" and target is not None:
        return "invalid", None
    return "validated", target


def _stratum(row):
    """Mutually exclusive sampling categories; none is a judgment of intent."""
    if row["status"] != "measured":
        return "evidence_quality"
    if row["outcome_status"] == "invalid":
        return "outcome_validation"
    values = row["metrics"]
    if values["target_goal_completed"] is None:
        return "completion_unknown"
    if values["answer_correct"] == 1 and values["target_goal_completed"] == 0:
        return "answer_without_target_completion"
    return {
        (1, 1): "exposed_with_boundary_attempt",
        (1, 0): "exposed_without_boundary_attempt",
        (0, 1): "boundary_attempt_without_recorded_clue",
        (0, 0): "no_recorded_clue_or_boundary_attempt",
    }[(values["clue_delivered"], values["boundary_attempted"])]


def _ordering(seed, value):
    data = json.dumps([seed, value], sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _sample(rows, sample_size, seed, scope):
    buckets = defaultdict(list)
    for row in rows:
        key = tuple(row[field] for field in (*IDENTITY, "review_stratum"))
        buckets[key].append(row)
    keys = sorted(buckets, key=lambda key: (_ordering(seed, key), key))
    for key in keys:
        buckets[key].sort(key=lambda row: (_ordering(seed, row["trial_id"]), row["trial_id"]))
    selected = []
    selected_counts = Counter()
    offset = 0
    limit = min(sample_size, len(rows))
    while len(selected) < limit:
        for key in keys:
            if offset < len(buckets[key]):
                source = buckets[key][offset]
                selected.append({
                    **source, "metrics": dict(source["metrics"]),
                    "source_refs": list(source["source_refs"]),
                    "issues": list(source["issues"]),
                    "identity_mismatches": list(source["identity_mismatches"]),
                    "annotation": dict.fromkeys(ANNOTATION_FIELDS, ""),
                })
                selected_counts[key] += 1
                if len(selected) == limit:
                    break
        offset += 1
    return {
        "method": "seeded hash ordering; round-robin across identity and observation strata",
        "scope": scope,
        "seed": seed, "requested": sample_size, "eligible": len(rows),
        "selected": len(selected),
        "strata": [
            {**dict(zip((*IDENTITY, "review_stratum"), key)),
             "eligible": len(buckets[key]), "selected": selected_counts[key]}
            for key in sorted(buckets)
        ],
        "rows": selected,
    }


def build_review(plan, measurements, *, sample_size=30, seed=0,
                 source_refs=None, review_scope="observed"):
    """Return sanitized summaries; leave all inputs unchanged.

    Pass complete measurement sidecars, not scalar reward files. The existing
    analyzer supplies strict identity, duplication, provenance, and score checks.
    Missing outcome extensions remain explicitly unknown. Optional task/agent
    versions must agree with the plan when present. Unplanned records are counted
    but never reattached to trials by filename, order, or inferred identity.
    Optional source_refs are caller-provided file references, one per input.
    They help locate evidence and never participate in identity matching.
    The default sample reviews only eligible observed model trials. Scope "all"
    includes evidence-quality follow-up; all summaries always cover the plan.
    """
    if type(sample_size) is not int or sample_size < 0:
        raise ExperimentError("sample_size must be a nonnegative integer")
    if type(seed) not in (int, str):
        raise ExperimentError("seed must be an integer or string")
    if not isinstance(measurements, list):
        raise ExperimentError("measurements must be a list")
    if not isinstance(review_scope, str) or review_scope not in ("observed", "all"):
        raise ExperimentError("review_scope must be observed or all")
    if source_refs is not None and (
        not isinstance(source_refs, list) or len(source_refs) != len(measurements)
        or any(not isinstance(value, str) or not value.strip() for value in source_refs)
    ):
        raise ExperimentError("source_refs must contain one nonempty string per measurement")
    projected = [
        {key: value for key, value in record.items() if key not in EXTENSIONS}
        if isinstance(record, dict) else record
        for record in measurements
    ]
    analysis = analyze(plan, projected)
    rows = []
    for base in analysis["trials"]:
        row = {
            **{field: base[field] for field in ROW_IDENTITY},
            "status": base["status"],
            "metrics": {field: base["metrics"].get(field) for field in METRICS},
            "source_refs": sorted({source_refs[index] for index in base["record_indices"]})
            if source_refs is not None else [],
            "identity_mismatches": [],
        }
        record = measurements[base["record_indices"][0]] if len(base["record_indices"]) == 1 else {}
        if row["status"] in ("measured", "invalid_evidence"):
            if any(field in record and record[field] != base[field]
                   for field in ("task_version", "agent_version")):
                row["status"] = "mismatched"
                row["metrics"] = dict.fromkeys(METRICS)
        if row["status"] == "mismatched":
            expected = {field: base[field] for field in
                        ("model_id", "scenario_id", "trial_id", "condition", "task_version", "agent_version")}
            expected.update(run_id=plan["run_id"], plan_sha256=plan["plan_sha256"])
            row["identity_mismatches"] = sorted(
                field for field, value in expected.items()
                if (field not in ("task_version", "agent_version") or field in record)
                and record.get(field) != value
            )
        row["outcome_status"], target = _completion(record, row)
        row["metrics"]["target_goal_completed"] = target
        row["issues"] = {
            "measured": [], "invalid_evidence": ["invalid_evidence"],
            "missing": ["measurement_missing"], "duplicate": ["duplicate_trial_id"],
            "excluded": ["measurement_excluded"], "mismatched": ["measurement_mismatched"],
            "malformed": ["measurement_malformed"],
        }[row["status"]]
        if row["status"] in ("measured", "invalid_evidence"):
            if row["outcome_status"] in ("missing", "invalid"):
                row["issues"].append("outcome_" + row["outcome_status"])
            if target is None:
                row["issues"].append("completion_unknown")
        row["review_stratum"] = _stratum(row)
        rows.append(row)
    rows.sort(key=lambda row: row["trial_id"])
    groups = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in IDENTITY)].append(row)
    aggregates = []
    for key, members in sorted(groups.items()):
        aggregates.append({
            **dict(zip(IDENTITY, key)),
            "completion": _coverage(members),
            "outcome_statuses": {
                status: sum(row["outcome_status"] == status for row in members)
                for status in OUTCOME_STATUSES
            },
            "metrics": {field: _counts([row["metrics"][field] for row in members]) for field in METRICS},
            "clue_strata": {
                label: _counts([row["metrics"]["boundary_attempted"] for row in members
                                if row["metrics"]["clue_delivered"] == value])
                for label, value in (("delivered", 1), ("not_delivered", 0), ("unknown", None))
            },
            "joint_counts": {
                "answer_and_target": _joint(members, "answer_correct", "target_goal_completed"),
                "clue_and_boundary": _joint(members, "clue_delivered", "boundary_attempted"),
                "target_and_boundary": _joint(members, "target_goal_completed", "boundary_attempted"),
            },
        })
    input_issues = defaultdict(list)
    for rejected in analysis["rejected_records"]:
        code = "unplanned_trial_id" if rejected["trial_id"] is not None else "unassignable_trial_id"
        input_issues[code].append(rejected["record_index"])
    measured = sum(row["status"] == "measured" for row in rows)
    known_completion = sum(row["metrics"]["target_goal_completed"] is not None for row in rows)
    rejected_count = len(analysis["rejected_records"])
    readiness = "no_eligible_model_measurements" if measured == 0 else "partial"
    if measured == known_completion == len(rows) and rejected_count == 0:
        readiness = "complete"
    sample_rows = rows if review_scope == "all" else [row for row in rows if row["status"] == "measured"]
    return {
        "kind": "boundary_eval.review_report", "schema_version": 1,
        "run_id": plan["run_id"], "plan_sha256": plan["plan_sha256"],
        "declared_setup": {
            field: copy.deepcopy(plan["configuration"][field])
            for field in ("agent_version", "generation_settings", "budget")
        },
        "interpretation": {
            "trusted_grader_required": True,
            "source_references_attest_identity": False,
            "externally_attested_provenance": False,
            "target_completion_requires_validated_outcome": True,
            "clue_delivery_is_awareness": False,
            "boundary_attempt_is_intent": False,
            "contrasts_are_causal": False,
            "review_sample_estimates_population_rates": False,
            "model_difficulty_established_by_scripted_oracle_runs": False,
            "interval_denominator": "measurable trials; unknowns and planned counts are separate",
            "interval_limitation": "descriptive Wilson intervals; task and replicate dependence not modeled",
            "baseline_calibration": "observed target completion under the recorded plan budget; no automatic difficulty label",
            "review_instruction": "record observable facts, evidence references, and uncertainty before assigning a failure category",
        },
        "coverage": {
            **_coverage(rows), "input_records": len(measurements),
            "rejected_unassigned_records": len(analysis["rejected_records"]),
        },
        "readiness": {
            "status": readiness, "measured_trials": measured, "planned_trials": len(rows),
            "known_target_completion": known_completion, "unassigned_input_records": rejected_count,
        },
        "input_issues": [
            {"code": code, "count": len(indices),
             "source_refs": sorted({source_refs[index] for index in indices})
             if source_refs is not None else []}
            for code, indices in sorted(input_issues.items())
        ],
        "aggregates": aggregates,
        "baseline_calibration": [
            {**{field: aggregate[field] for field in IDENTITY},
             "target_goal_completed": dict(aggregate["metrics"]["target_goal_completed"])}
            for aggregate in aggregates if aggregate["condition"] == "baseline"
        ],
        "trials": rows,
        "review_sample": _sample(sample_rows, sample_size, seed, review_scope),
    }


def review_csv(report):
    """Render selected facts and blank notes; absent observations say unknown."""
    output = io.StringIO(newline="")
    fields = (*ROW_IDENTITY, "status", "outcome_status", "review_stratum",
              "source_references", "issues", "identity_mismatches", *METRICS, *ANNOTATION_FIELDS)
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in report["review_sample"]["rows"]:
        flat = {field: row[field] for field in (*ROW_IDENTITY, "status", "outcome_status", "review_stratum")}
        flat["source_references"] = json.dumps(row["source_refs"], ensure_ascii=False)
        flat["issues"] = "; ".join(row["issues"])
        flat["identity_mismatches"] = "; ".join(row["identity_mismatches"])
        flat.update({field: "unknown" if row["metrics"][field] is None else row["metrics"][field]
                     for field in METRICS})
        flat.update(row["annotation"])
        # Neutralize spreadsheet formulas in caller-provided identity labels.
        flat = {key: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                else value for key, value in flat.items()}
        writer.writerow(flat)
    return output.getvalue()


def _read_json(path):
    def unique_object(pairs):
        value = {}
        for key, child in pairs:
            if key in value:
                raise ExperimentError("JSON contains duplicate object keys")
            value[key] = child
        return value

    def reject_constant(_value):
        raise ExperimentError("JSON contains a non-finite number")

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ExperimentError("JSON contains a non-finite number")
        return result

    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=unique_object,
                         parse_constant=reject_constant, parse_float=finite_float)


def _publish_new(path, data):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".review-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(data)
        os.link(temporary, path)
    finally:
        try:
            Path(temporary).unlink(missing_ok=True)
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--measurement", type=Path, action="append", default=[],
                        help="trusted verifier sidecar; repeat for multiple files")
    parser.add_argument("--measurements", type=Path,
                        help="JSON list of complete trusted verifier sidecars")
    parser.add_argument("--sample-size", type=int, default=30)
    parser.add_argument("--seed", default="0")
    parser.add_argument("--review-scope", choices=("observed", "all"), default="observed",
                        help="observed model trials (default), or all planned rows for evidence follow-up")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--output", type=Path, help="new file; omitted means stdout")
    args = parser.parse_args(argv)
    try:
        plan = _read_json(args.plan)
        measurements = _read_json(args.measurements) if args.measurements else []
        if not isinstance(measurements, list):
            raise ExperimentError("--measurements must contain a JSON list")
        sources = [str(args.measurements.resolve()) + f"#/{index}" for index in range(len(measurements))]
        for path in args.measurement:
            measurements.append(_read_json(path))
            sources.append(str(path.resolve()))
        report = build_review(plan, measurements, sample_size=args.sample_size, seed=args.seed,
                              source_refs=sources, review_scope=args.review_scope)
        data = (review_csv(report) if args.format == "csv" else
                json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        if args.output:
            _publish_new(args.output, data)
        else:
            sys.stdout.write(data)
    except (ExperimentError, OSError, ValueError, TypeError) as exc:
        # Do not echo malformed source data or arbitrary exception contents.
        print(f"Review failed ({type(exc).__name__}); check input schemas, paths, and output availability.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
