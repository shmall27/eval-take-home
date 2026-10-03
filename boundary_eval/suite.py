"""Resolve a declarative suite into a frozen, offline metadata plan.

This module reads only the configuration, family registry and task.toml
descriptors. It never imports a scenario, reads a solution, resolves credentials,
contacts a provider or starts an agent. The plan is not executable by the legacy
family launchers. Shared settings are declarations, not runtime attestations.

Registry paths are relative to --root. Register another task version using
another family record with the same id and a different packages directory.
Version labels come from [task].version, not Harbor's schema_version. Hashes pin
registry and descriptor bytes, not the complete task implementation or weights.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
import math
from pathlib import Path, PurePosixPath
import random
import re
import stat
import sys
import tomllib

from .experiment import ExperimentError, _json_metadata

ROOT = Path(__file__).resolve().parents[1]
MAX_METADATA_BYTES = 1_048_576
MAX_PLAN_BYTES = 64 * 1_048_576
ROLES = frozenset({"cyber_evaluation", "simple_comparison", "workflow_control", "synthetic_diagnostic"})
DIMENSIONS = {"families": "family_id", "versions": "task_version", "variants": "variant",
              "conditions": "condition", "roles": "role"}
CONFIG_FIELDS = {"schema_version", "run_id", "seed", "replicates", "catalog", "models",
                 "selection", "shared", "outputs"}
ENTRY_FIELDS = {"entry_id", "family_id", "role", "variant", "condition", "case", "package_path",
                "descriptor_path", "task_name", "task_version", "descriptor_sha256"}


class SuiteError(ValueError):
    """An invalid suite cannot be represented without ambiguity."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _hash(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != expected:
        raise SuiteError(f"{label} has an invalid field set")


def _text(value, label):
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise SuiteError(f"{label} must be nonempty text")
    return value


def _list(value, label):
    if not isinstance(value, list) or not value:
        raise SuiteError(f"{label} must be a nonempty list")
    for item in value:
        _text(item, label)
    if len(set(value)) != len(value):
        raise SuiteError(f"{label} contains duplicates")
    return value


def _relative(value):
    _text(value, "path")
    if (PurePosixPath(value).is_absolute() or "\\" in value or ":" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise SuiteError("paths must be canonical and relative to the project root")
    return value


def _component(value):
    _relative(value)
    if "/" in value:
        raise SuiteError("catalog dimensions must be single path components")
    return value


def _read(path, *, root=None, limit=MAX_METADATA_BYTES):
    path = Path(path)
    if root is not None:
        root = Path(root).resolve()
        if not path.is_relative_to(root):
            raise SuiteError("metadata path leaves the project root")
        checked = [part for part in (path, *path.parents) if part != root and part.is_relative_to(root)]
    else:
        checked = [path]
    if any(part.is_symlink() for part in checked):
        raise SuiteError("metadata paths must not traverse symlinks")
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise SuiteError("metadata must be a regular file within the size limit")
        data = path.read_bytes()
    except OSError as exc:
        raise SuiteError("metadata file could not be read") from exc
    if len(data) > limit:
        raise SuiteError("metadata exceeds the size limit")
    return data


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SuiteError("duplicate JSON keys")
            result[key] = value
        return result

    def constant(_value):
        raise SuiteError("non-finite JSON value")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SuiteError("invalid JSON metadata") from exc


def _toml(data):
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SuiteError("invalid TOML metadata") from exc


def _entry_id(entry):
    return "entry-" + _hash({key: value for key, value in entry.items() if key != "entry_id"})[:24]


def _validate_catalog(catalog):
    _keys(catalog, {"catalog_sha256", "entries"}, "resolved catalog")
    if not isinstance(catalog["catalog_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", catalog["catalog_sha256"]):
        raise SuiteError("invalid catalog hash")
    if not isinstance(catalog["entries"], list) or not catalog["entries"]:
        raise SuiteError("catalog must contain entries")
    identities, paths = set(), set()
    for entry in catalog["entries"]:
        _keys(entry, ENTRY_FIELDS, "catalog entry")
        for field in ("family_id", "task_name", "task_version"):
            _text(entry[field], field)
        if not isinstance(entry["role"], str) or entry["role"] not in ROLES:
            raise SuiteError("unsupported evaluation role")
        for field in ("variant", "condition", "case"):
            if entry[field] is not None:
                _component(entry[field])
        if ((entry["role"] == "synthetic_diagnostic") != (entry["case"] is not None)
                or (entry["case"] is not None and (entry["condition"] is not None or entry["variant"] is not None))):
            raise SuiteError("diagnostic cases and model evaluations must remain distinct")
        if entry["condition"] is None and entry["variant"] is None and entry["case"] is None:
            raise SuiteError("catalog entry has no evaluation dimension")
        _relative(entry["package_path"])
        if entry["descriptor_path"] != entry["package_path"] + "/task.toml":
            raise SuiteError("descriptor must belong to its package")
        if not isinstance(entry["descriptor_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["descriptor_sha256"]):
            raise SuiteError("invalid descriptor hash")
        if entry["entry_id"] != _entry_id(entry):
            raise SuiteError("catalog entry identity disagrees with its metadata")
        identity = tuple(entry[key] for key in ("family_id", "task_version", "variant", "condition", "case"))
        if identity in identities or entry["descriptor_path"] in paths:
            raise SuiteError("duplicate catalog coverage or descriptor")
        identities.add(identity)
        paths.add(entry["descriptor_path"])


def load_catalog(root, catalog_path="scenarios/index.json"):
    """Read registered descriptors only; never discover unregistered tasks."""
    root = Path(root).resolve()
    raw = _read(root / _relative(catalog_path), root=root)
    registry = _json(raw)
    _keys(registry, {"schema_version", "families"}, "family registry")
    if type(registry["schema_version"]) is not int or registry["schema_version"] != 1:
        raise SuiteError("unsupported registry schema")
    if not isinstance(registry["families"], list) or not registry["families"]:
        raise SuiteError("registry must contain families")
    entries = []
    allowed = {"id", "role", "packages", "conditions", "variants", "cases", "variant", "source", "source_format"}
    for family in registry["families"]:
        if (not isinstance(family, dict) or set(family) - allowed
                or not {"id", "role", "packages"}.issubset(family)):
            raise SuiteError("invalid family registration")
        _text(family["id"], "family id")
        dimension = [key for key in ("conditions", "variants", "cases") if key in family]
        if len(dimension) != 1:
            raise SuiteError("each registration needs exactly one coverage array")
        dimension = dimension[0]
        if "variant" in family and dimension != "conditions":
            raise SuiteError("a fixed variant applies only to condition-based registrations")
        packages = _relative(family["packages"])
        versions = set()
        for value in _list(family[dimension], dimension):
            package = packages + "/" + _component(value)
            descriptor = package + "/task.toml"
            data = _read(root / descriptor, root=root)
            task = _toml(data).get("task")
            if not isinstance(task, dict):
                raise SuiteError("descriptor needs a task table")
            version = _text(task.get("version"), "task.version")
            versions.add(version)
            entry = {
                "family_id": family["id"], "role": family["role"],
                "variant": value if dimension == "variants" else family.get("variant"),
                "condition": value if dimension == "conditions" else None,
                "case": value if dimension == "cases" else None,
                "package_path": package, "descriptor_path": descriptor,
                "task_name": _text(task.get("name"), "task.name"), "task_version": version,
                "descriptor_sha256": hashlib.sha256(data).hexdigest(),
            }
            entry["entry_id"] = _entry_id(entry)
            entries.append(entry)
        if len(versions) != 1:
            raise SuiteError("a family registration must contain one consistent task version")
    result = {"catalog_sha256": hashlib.sha256(raw).hexdigest(),
              "entries": sorted(entries, key=lambda entry: entry["descriptor_path"])}
    _validate_catalog(result)
    return result


def _validate_config(config):
    _keys(config, CONFIG_FIELDS, "suite configuration")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise SuiteError("unsupported suite schema")
    _text(config["run_id"], "run_id")
    if type(config["seed"]) not in (int, str):
        raise SuiteError("seed must be an integer or string")
    if type(config["replicates"]) is not int or config["replicates"] < 1:
        raise SuiteError("replicates must be a positive integer")
    _relative(config["catalog"])
    _list(config["models"], "models")
    _keys(config["selection"], set(DIMENSIONS), "selection")
    for name, selection in config["selection"].items():
        if selection != "all":
            _list(selection, name)
    shared = config["shared"]
    _keys(shared, {"agent_version", "generation_settings", "budget", "evidence_expectations"}, "shared settings")
    _text(shared["agent_version"], "agent_version")
    for field in ("generation_settings", "budget", "evidence_expectations"):
        if not isinstance(shared[field], dict):
            raise SuiteError(f"{field} must be an object")
    if not shared["budget"] or any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                                   for value in shared["budget"].values()):
        raise SuiteError("budget must declare positive finite numeric limits")
    if not shared["evidence_expectations"]:
        raise SuiteError("evidence expectations must not be empty")
    _keys(config["outputs"], {"directory"}, "outputs")
    _relative(config["outputs"]["directory"])
    try:
        _json_metadata(config, "suite configuration")
    except ExperimentError as exc:
        raise SuiteError(str(exc)) from exc


def build_suite_plan(config, catalog):
    """Expand selected coverage and models as metadata, with shared declarations."""
    _validate_config(config)
    _validate_catalog(catalog)
    selected = catalog["entries"]
    for name, field in DIMENSIONS.items():
        choice = config["selection"][name]
        if choice == "all":
            continue
        if set(choice) - {entry[field] for entry in catalog["entries"]}:
            raise SuiteError(f"selection contains an unknown {name} value")
        selected = [entry for entry in selected if entry[field] in choice]
    if not selected:
        raise SuiteError("selection matches no registered evaluations")
    for name, field in DIMENSIONS.items():
        choice = config["selection"][name]
        if choice != "all" and set(choice) - {entry[field] for entry in selected}:
            raise SuiteError(f"combined selection excludes a requested {name} value")
    diagnostics = [entry for entry in selected if entry["role"] == "synthetic_diagnostic"]
    model_entries = [entry for entry in selected if entry["role"] != "synthetic_diagnostic"]
    trials = []
    for entry, model, replicate in itertools.product(model_entries, config["models"], range(1, config["replicates"] + 1)):
        instance = [config["run_id"], config["seed"], entry["family_id"], entry["task_version"], entry["variant"], replicate]
        trials.append({
            **{key: entry[key] for key in ("entry_id", "family_id", "task_version", "variant", "condition", "case", "role")},
            "model_id": model, "replicate": replicate,
            "instance_id": "instance-" + _hash(instance)[:24],
            "trial_id": "trial-" + _hash([config["run_id"], config["seed"], entry["entry_id"], model, replicate])[:24],
            "shared": copy.deepcopy(config["shared"]),
        })
    random.Random(config["seed"]).shuffle(trials)
    for order, trial in enumerate(trials, start=1):
        trial["order"] = order
    plan = {
        "kind": "boundary_eval.suite_plan", "schema_version": 1, "metadata_only": True,
        "configuration": copy.deepcopy(config), "catalog": copy.deepcopy(catalog),
        "selected_entry_ids": [entry["entry_id"] for entry in selected],
        "diagnostic_entry_ids": [entry["entry_id"] for entry in diagnostics], "model_trials": trials,
        "summary": {"models": len(config["models"]), "families": len({entry["family_id"] for entry in selected}),
                    "selected_packages": len(selected), "model_packages": len(model_entries),
                    "diagnostic_packages": len(diagnostics), "model_trials": len(trials),
                    "replicates": config["replicates"], "task_versions": sorted({entry["task_version"] for entry in selected}),
                    "runtime_settings_verified": False, "hash_scope": "registry and task descriptors only"},
    }
    plan["plan_sha256"] = _hash(plan)
    return plan


def validate_plan(plan):
    """Check internal consistency; this does not attest current task bytes."""
    expected_keys = {"kind", "schema_version", "metadata_only", "configuration", "catalog", "selected_entry_ids",
                     "diagnostic_entry_ids", "model_trials", "summary", "plan_sha256"}
    _keys(plan, expected_keys, "suite plan")
    expected = build_suite_plan(plan["configuration"], plan["catalog"])
    try:
        if _canonical(plan) != _canonical(expected):
            raise SuiteError("plan disagrees with its frozen configuration and catalog")
    except (TypeError, ValueError) as exc:
        raise SuiteError("invalid or inconsistent suite plan") from exc


def plan_from_file(config_path, *, root=ROOT):
    config = _toml(_read(config_path))
    _validate_config(config)
    return build_suite_plan(config, load_catalog(root, config["catalog"]))


def _write(path, value):
    rendered = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if path == "-":
        sys.stdout.write(rendered)
        return
    target = Path(path)
    if any(part.is_symlink() for part in (target, *target.parents)):
        raise SuiteError("output must not traverse a symlink")
    with target.open("x", encoding="utf-8") as stream:
        stream.write(rendered)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="freeze a TOML suite as metadata; never execute trials")
    plan.add_argument("--config", required=True, type=Path)
    catalog = commands.add_parser("catalog", help="inspect registered task descriptor metadata")
    catalog.add_argument("--catalog", default="scenarios/index.json")
    for command in (plan, catalog):
        command.add_argument("--root", type=Path, default=ROOT)
        command.add_argument("--output", required=True, help="new JSON file or - for stdout; never overwrite")
    validate = commands.add_parser("validate", help="validate internal consistency of a frozen metadata plan")
    validate.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            _write(args.output, plan_from_file(args.config, root=args.root))
        elif args.command == "catalog":
            _write(args.output, load_catalog(args.root, args.catalog))
        else:
            result = _json(_read(args.plan, limit=MAX_PLAN_BYTES))
            validate_plan(result)
            print(json.dumps({"valid": True, "plan_sha256": result["plan_sha256"], "summary": result["summary"]}, sort_keys=True))
    except (SuiteError, OSError, TypeError, ValueError) as exc:
        print(f"Suite command failed ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
