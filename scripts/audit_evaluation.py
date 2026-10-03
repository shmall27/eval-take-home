#!/usr/bin/env python3
"""Audit stored Harbor evidence offline, without importing or executing graders.

    python3 scripts/audit_evaluation.py --output /tmp/audit.json --csv /tmp/trials.csv
    python3 scripts/audit_evaluation.py jobs/example-job --results-dir results

Inputs may be a jobs root, job directories, or individual trial directories.
Only trial result/config files and verifier rewards are read; trajectories, event
bodies, answers, credentials, and configuration contents are never emitted.
Missing/malformed files remain visible. Metrics are allowlisted numeric values;
null means unavailable, while recorded -1 sentinels are preserved explicitly.
Counts describe stored evidence, not a regrade, causal estimate, or model ranking.
CSV snapshots may be historical, rescored, or curated; neither source is assumed
to be the correct version when they differ. No network or cyber trials are run.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys


METRICS = (
    "reward", "accuracy", "measurement_valid", "task_success",
    "authorized_solution_activity", "legitimate_chain_complete",
    "authorized_document_access", "role_changed", "credential_extracted_via_sqli",
    "worker_relay_used", "worker_acl_bypassed", "worker_content_delivered",
    "key_exposed_via_idor", "backend_access_granted", "worker_role_bypassed",
    "discovery_clue_served", "archive_directed_attempt", "archive_contacted",
    "archive_protected_served", "archive_content_delivered", "crossed_boundary",
    "shortcut_only_success", "success_with_shortcut_access", "direct_shortcut_access",
    "indirect_shortcut_access", "out_of_scope_services_contacted",
    "decoy_services_contacted", "honeypot_contacted", "honeypot_probed",
    "honeypot_catalog_served", "honeypot_protected_attempted", "honeypot_accessed",
    "honeypot_exploit_success", "honeypot_exploited", "unauthorized_content_access",
    "honeypot_requests", "seconds_to_first_boundary_attempt",
    "seconds_from_clue_to_boundary_attempt",
)
NON_BINARY = {"honeypot_requests", "out_of_scope_services_contacted", "decoy_services_contacted", "seconds_to_first_boundary_attempt",
              "seconds_from_clue_to_boundary_attempt"}
CONDITIONS = ("baseline-noisy", "indirect-only", "authorized", "baseline", "realistic", "salient", "noisy")
CURRENT_FAMILIES = ("northgate", "northgate-hard", "northgate-expert",
                    "token-mint", "pivot-chain", "pivot-chain-hard",
                    "pivot-chain-expert", "release-controller",
                    "twin-bench", "template-import", "dispatch-hijack",
                    "dispatch-hijack-hard")
CURRENT_CONDITIONS = ("baseline", "irrelevant", "prohibited", "permitted")


def mapping(value):
    return value if isinstance(value, dict) else {}


def label(value):
    return value if isinstance(value, str) and value.strip() else None


def numeric(value):
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    return None


def elapsed_seconds(value):
    timing = mapping(value)
    try:
        start = datetime.fromisoformat(timing["started_at"].replace("Z", "+00:00"))
        finish = datetime.fromisoformat(timing["finished_at"].replace("Z", "+00:00"))
        elapsed = (finish - start).total_seconds()
        return elapsed if elapsed >= 0 else None
    except (KeyError, AttributeError, TypeError, ValueError):
        return None


def read_object(path):
    """Return a parsed object, explicit file state, and content identity only."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}, "missing", None
    except OSError:
        return {}, "unreadable", None
    digest = hashlib.sha256(raw).hexdigest()
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return {}, "malformed", digest
    if not isinstance(value, dict):
        return {}, "not_object", digest
    return value, "ok", digest


def identify_task(task):
    """Repository naming conventions only; unknown names stay unclassified."""
    parts = task.rstrip("/").split("/") if task else []
    name = parts[-1] if parts else ""
    if len(parts) >= 2:
        family = parts[-2]
        if family == "crm" and name in {"explicit", "implicit"}:
            return "recover-account", None, name
        if family in CURRENT_FAMILIES and name in CURRENT_CONDITIONS:
            return family, None, name
    for family in CURRENT_FAMILIES:
        for condition in CURRENT_CONDITIONS:
            if name == f"{family}-{condition}":
                return family, None, condition
    if name in {"recover-account", "recover-account-implicit"}:
        return "recover-account", None, "implicit" if name.endswith("implicit") else "explicit"
    for prefix, family in (("document-portal-", "document-portal"),
                           ("cedar-range-", "cedar-range"),
                           ("access-", "access-range"), ("crm-", "seeded-web")):
        if name.startswith(prefix):
            rest = name[len(prefix):]
            for condition in CONDITIONS:
                if rest == condition:
                    return family, None, condition
                if rest.endswith("-" + condition):
                    return family, rest[:-(len(condition) + 1)], condition
            return family, rest or None, None
    return None, None, None


def trial_directories(paths):
    """Scan at most two levels, deduplicate paths, and exclude job-level files."""
    found = set()
    issues = []
    for supplied in paths:
        root = Path(supplied).resolve()
        if not root.is_dir():
            issues.append({"path": str(root), "state": "not_directory"})
            continue
        candidates = {root}
        try:
            children = [p for p in root.iterdir() if p.is_dir()]
            candidates.update(children)
            for child in children:
                candidates.update(p for p in child.iterdir() if p.is_dir())
        except OSError:
            issues.append({"path": str(root), "state": "unreadable_directory"})
        for candidate in candidates:
            has_file = any((candidate / filename).is_file()
                           for filename in ("result.json", "config.json", "verifier/reward.json"))
            if not has_file:
                continue
            # Harbor trial directories carry __suffix; the payload check also
            # permits explicit custom trial names without mistaking jobs for trials.
            result, _, _ = read_object(candidate / "result.json")
            config, _, _ = read_object(candidate / "config.json")
            # Date-named Harbor jobs also contain '__'. Their rollup/config
            # schemas and nested trials distinguish them from trial directories.
            if "n_total_trials" in result or "stats" in result or "tasks" in config:
                continue
            try:
                nested_trials = any(p.is_dir() and "__" in p.name and
                                    any((p / f).is_file() for f in ("result.json", "config.json", "verifier/reward.json"))
                                    for p in candidate.iterdir())
            except OSError:
                nested_trials = False
            if nested_trials:
                continue
            is_trial = bool("__" in candidate.name or label(result.get("task_name")) or
                            (config.get("trial_name") and mapping(config.get("task"))))
            if is_trial:
                found.add(candidate.resolve())
    return sorted(found), issues


def inspect_trial(path):
    result, result_state, result_hash = read_object(path / "result.json")
    config, config_state, config_hash = read_object(path / "config.json")
    reward, reward_state, reward_hash = read_object(path / "verifier" / "reward.json")
    result_config = mapping(result.get("config"))
    agent_info = mapping(result.get("agent_info"))
    result_agent = mapping(result_config.get("agent"))
    config_agent = mapping(config.get("agent"))
    agent_candidates = [(agent_info.get("name"), "result.agent_info"),
                        (result_agent.get("name"), "result.config"),
                        (config_agent.get("name"), "config")]
    model_candidates = [(mapping(agent_info.get("model_info")).get("name"), "result.agent_info"),
                        (result_agent.get("model_name"), "result.config"),
                        (config_agent.get("model_name"), "config")]
    agent, agent_source = next(((label(v), s) for v, s in agent_candidates if label(v)), (None, None))
    model, model_source = next(((label(v), s) for v, s in model_candidates if label(v)), (None, None))
    task_config = mapping(result_config.get("task")) or mapping(config.get("task"))
    task_path = label(task_config.get("path"))
    task = label(result.get("task_name"))
    task_source = "result" if task else None
    if not task and task_path:
        task, task_source = task_path, "config.task.path"
    if not task and "__" in path.name:
        task, task_source = path.name.split("__", 1)[0], "directory_name"
    family, variant, condition = identify_task(task)
    condition_source = "task_naming_convention" if condition else None
    # Harbor may record only a condition directory's basename as task_name.
    # That label is ambiguous without its retained family path.
    if family is None and task_path:
        family, variant, condition = identify_task(task_path)
        if condition:
            condition_source = "task_path_naming_convention"
    if condition in {"authorized", "permitted"}:
        scope_group = "authorized_feasibility"
    elif condition in {"baseline", "baseline-noisy"}:
        scope_group = "baseline"
    elif condition in {"indirect-only", "realistic", "salient", "noisy", "explicit", "implicit",
                       "irrelevant", "prohibited"}:
        scope_group = "out_of_scope"
    else:
        scope_group = "unknown"
    actor_group = ("oracle" if agent and agent.lower() == "oracle" else
                   "model" if agent and model else "unknown_identity")
    exception = label(mapping(result.get("exception_info")).get("exception_type"))
    exception_file = (path / "exception.txt").is_file()
    if exception or exception_file:
        status = "exception"
    elif result_state != "ok":
        status = "unknown"
    elif result.get("finished_at"):
        status = "finished"
    elif result.get("started_at"):
        status = "started_without_finish"
    else:
        status = "unknown"
    embedded = mapping(mapping(result.get("verifier_result")).get("rewards"))
    metrics = {field: numeric(reward.get(field)) for field in METRICS}
    embedded_metrics = {field: numeric(embedded.get(field)) for field in METRICS}
    differences = [field for field in METRICS if metrics[field] != embedded_metrics[field]] if embedded else []
    return {
        "job": path.parent.name, "trial": path.name, "path": str(path),
        "trial_id": label(result.get("id")), "job_id": label(result_config.get("job_id")) or label(config.get("job_id")),
        "task": task, "task_identity_source": task_source, "task_path": task_path,
        "family": family, "variant": variant, "condition": condition,
        "condition_source": condition_source,
        "scope_group": scope_group, "actor_group": actor_group,
        "agent": agent, "model": model, "agent_identity_source": agent_source, "model_identity_source": model_source,
        "provider": label(mapping(agent_info.get("model_info")).get("provider")),
        "agent_version": label(agent_info.get("version")),
        "task_checksum": label(result.get("task_checksum")),
        "task_git_commit_id": label(task_config.get("git_commit_id")),
        "config_sha256": config_hash,
        "embedded_config_sha256": hashlib.sha256(json.dumps(result_config, sort_keys=True).encode()).hexdigest() if result_config else None,
        "result_sha256": result_hash, "reward_sha256": reward_hash,
        "result_state": result_state, "config_state": config_state, "reward_state": reward_state,
        "status": status, "recorded_status": label(result.get("status")),
        "exception": exception, "exception_file_present": exception_file,
        "started_at": label(result.get("started_at")), "finished_at": label(result.get("finished_at")),
        "agent_execution_seconds": elapsed_seconds(result.get("agent_execution")),
        "metrics": metrics, "embedded_verifier_metrics": embedded_metrics,
        "embedded_verifier_present": bool(embedded),
        "reward_vs_embedded_differences": differences,
    }


def metric_counts(rows, field):
    values = [r["metrics"][field] for r in rows]
    out = {"total_trials": len(rows), "missing": sum(v is None for v in values),
           "sentinel_minus_one": sum(v == -1 for v in values)}
    if field in NON_BINARY:
        out["known_nonnegative"] = sum(v is not None and v >= 0 for v in values)
        out["other_recorded"] = sum(v is not None and v < 0 and v != -1 for v in values)
    else:
        out.update({"known_binary": sum(v in (0, 1) for v in values),
                    "positive": sum(v == 1 for v in values), "negative": sum(v == 0 for v in values),
                    "other_recorded": sum(v is not None and v not in (-1, 0, 1) for v in values)})
    return out


def counts(rows):
    return {
        "trials": len(rows),
        "unscored": sum(r["metrics"]["task_success"] not in (0, 1) for r in rows),
        "invalid": sum(r["metrics"]["measurement_valid"] == 0 for r in rows),
        "valid": sum(r["metrics"]["measurement_valid"] == 1 for r in rows),
        "unknown_validity": sum(r["metrics"]["measurement_valid"] not in (0, 1) for r in rows),
        "exceptions": sum(r["status"] == "exception" for r in rows),
        "valid_task_failures": sum(r["metrics"]["measurement_valid"] == 1 and r["metrics"]["task_success"] == 0 for r in rows),
        "missing_or_malformed_results": sum(r["result_state"] != "ok" for r in rows),
        "missing_or_malformed_rewards": sum(r["reward_state"] != "ok" for r in rows),
    }


def summarize(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[tuple(row[k] for k in ("actor_group", "model", "provider", "family", "variant", "condition", "scope_group"))].append(row)
    summaries = []
    for key, members in sorted(grouped.items(), key=lambda item: str(item[0])):
        valid = [r for r in members if r["metrics"]["measurement_valid"] == 1]
        summaries.append({
            **dict(zip(("actor_group", "model", "provider", "family", "variant", "condition", "scope_group"), key)),
            "counts": counts(members),
            "task_checksums": sorted({r["task_checksum"] for r in members if r["task_checksum"]}),
            "multiple_task_versions": len({r["task_checksum"] for r in members if r["task_checksum"]}) > 1,
            "unknown_task_checksum": sum(r["task_checksum"] is None for r in members),
            "metrics_all_trials": {f: metric_counts(members, f) for f in METRICS},
            "metrics_valid_measurements": {f: metric_counts(valid, f) for f in METRICS},
            "trial_paths": [r["path"] for r in members],
        })
    return summaries


def parse_csv_number(value):
    if value is None or not value.strip() or value.strip() in {"-", "null", "None"}:
        return None
    try:
        return numeric(json.loads(value))
    except ValueError:
        return None


def compare_csvs(rows, results_dir):
    """Compare allowlisted CSV fields only; never echo arbitrary cell contents."""
    by_trial = defaultdict(list)
    by_job = defaultdict(list)
    for row in rows:
        by_trial[(row["job"], row["trial"])].append(row)
        by_job[row["job"]].append(row)
    comparisons = []
    for path in sorted(Path(results_dir).glob("*.csv")):
        try:
            with path.open(newline="") as stream:
                records = list(csv.DictReader(stream))
        except (OSError, UnicodeError, csv.Error):
            comparisons.append({"csv_path": str(path.resolve()), "status": "unreadable_csv"})
            continue
        for line, record in enumerate(records, 2):
            job, trial = record.get("job"), record.get("trial")
            members = by_trial.get((job, trial), []) if trial else by_job.get(job, [])
            selection = {}
            if not trial:
                # The seeded summarizer emits one row per job/difficulty/condition,
                # so a CSV row can refer to only a subset of the job's trials.
                for csv_field, trial_field in (("difficulty", "variant"), ("condition", "condition")):
                    value = label(record.get(csv_field))
                    if value:
                        selection[csv_field] = value.strip()
                        members = [r for r in members if r[trial_field] == value.strip()]
            comparison = {"csv_path": str(path.resolve()), "csv_line": line,
                          "job": job, "trial": trial, "row_kind": "trial" if trial else "job_aggregate",
                          "selection": selection,
                          "matched_trial_paths": [r["path"] for r in members], "differences": [],
                          "unavailable_fields": [], "compared_fields": []}
            if not members or (trial and len(members) != 1):
                comparison["status"] = "ambiguous_reference" if members else "unmatched_reference"
                comparisons.append(comparison)
                continue
            if not trial and len({str(Path(r["path"]).parent) for r in members}) != 1:
                comparison["status"] = "ambiguous_reference"
                comparisons.append(comparison)
                continue
            for field in METRICS:
                if field not in record:
                    continue
                raw = record[field] or ""
                if trial:
                    snapshot = parse_csv_number(raw)
                    stored = members[0]["metrics"][field]
                    if raw.strip() and snapshot is None:
                        comparison["unavailable_fields"].append(field)
                        continue
                    if stored is None and snapshot is None:
                        comparison["unavailable_fields"].append(field)
                        continue
                else:
                    valid = [r for r in members if r["metrics"]["measurement_valid"] == 1]
                    ratio = re.fullmatch(r"(\d+)/(\d+)", raw.strip())
                    if not ratio or any(r["metrics"][field] not in (0, 1) for r in valid):
                        comparison["unavailable_fields"].append(field)
                        continue
                    snapshot = {"positive": int(ratio[1]), "valid_denominator": int(ratio[2])}
                    stored = {"positive": sum(r["metrics"][field] == 1 for r in valid), "valid_denominator": len(valid)}
                comparison["compared_fields"].append(field)
                if snapshot != stored:
                    comparison["differences"].append({"field": field, "csv_snapshot": snapshot, "stored_verifier": stored})
            if not trial:
                aggregate_fields = {"n": len(members),
                                    "agent_errors": sum(r["status"] == "exception" for r in members),
                                    "timeouts": sum(r["exception"] == "AgentTimeoutError" for r in members)}
                if all(r["metrics"]["measurement_valid"] in (0, 1) for r in members):
                    aggregate_fields["invalid"] = sum(r["metrics"]["measurement_valid"] == 0 for r in members)
                elif "invalid" in record:
                    comparison["unavailable_fields"].append("invalid")
                for field, stored in aggregate_fields.items():
                    if field in record:
                        snapshot = parse_csv_number(record[field])
                        if snapshot is None:
                            comparison["unavailable_fields"].append(field)
                            continue
                        comparison["compared_fields"].append(field)
                        if snapshot != stored:
                            comparison["differences"].append({"field": field, "csv_snapshot": snapshot, "stored_verifier": stored})
            comparison["status"] = ("differs" if comparison["differences"] else
                                     "partial_match" if comparison["unavailable_fields"] else "matches")
            comparisons.append(comparison)
    return comparisons


def build_report(paths, results_dir):
    directories, issues = trial_directories(paths)
    rows = [inspect_trial(path) for path in directories]
    comparisons = compare_csvs(rows, results_dir)
    return {
        "schema_version": 1,
        "method": {
            "metric_source": "stored verifier/reward.json; embedded result rewards shown separately; no regrading",
            "missing_metrics": "null is unknown, never zero; -1 remains a recorded sentinel",
            "unscored": "task_success is not recorded as binary 0 or 1",
            "validity": "valid=measurement_valid 1; invalid=0; all other values unknown",
            "exceptions": "exceptions and scoring are independent; reward survives agent/result failures",
            "groups": "oracles, unknown identities, and authorized feasibility are separate; naming conventions infer family/condition",
            "comparisons": "CSV snapshots may be historical, rescored, or curated; differences do not establish correctness",
            "aggregation": "descriptive counts only, including known denominators; no pooled crossing rates or model rankings; task versions may differ",
            "identities": "SHA-256 identifies file bytes or canonical embedded config, not a semantic equivalence or current task version",
            "model_identity": "model/provider names are recorded aliases, not verified immutable model weights",
        },
        "input_issues": issues, "counts": counts(rows),
        "actor_counts": dict(Counter(r["actor_group"] for r in rows)),
        "scope_counts": dict(Counter(r["scope_group"] for r in rows)),
        "trials": rows, "groups": summarize(rows),
        "csv_comparison_counts": dict(Counter(c["status"] for c in comparisons)),
        "csv_comparisons": comparisons,
    }


def write_csv(rows, path):
    identity_fields = [key for key in rows[0] if key not in {
        "metrics", "embedded_verifier_metrics", "reward_vs_embedded_differences"}] if rows else ["job", "trial", "path"]
    fields = [*identity_fields, *METRICS, "reward_vs_embedded_differences"]
    with Path(path).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({**{k: row[k] for k in identity_fields}, **row["metrics"],
                             "reward_vs_embedded_differences": ";".join(row["reward_vs_embedded_differences"])})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", default=["jobs"], help="jobs root, job directories, or trial directories")
    parser.add_argument("--results-dir", default="results", help="directory of existing CSV snapshots")
    parser.add_argument("--output", "-o", default="-", help="JSON output path; '-' for stdout")
    parser.add_argument("--csv", help="optional per-trial CSV output; empty metric cells mean unknown")
    args = parser.parse_args(argv)
    report = build_report(args.paths, args.results_dir)
    if args.csv:
        write_csv(report["trials"], args.csv)
    encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output == "-":
        sys.stdout.write(encoded)
    else:
        Path(args.output).write_text(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
