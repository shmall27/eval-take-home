"""Import saved Harbor artifacts into an offline, local inspection timeline.

Only result.json, ATIF agent/trajectory.json, verifier/measurement.json and
service observation logs are read. This never launches tasks or models. Keys,
state files, manifests, answer files, and terminal recordings are not imported.
Provider-exposed reasoning is optional and stored verbatim as reported text,
not as a verified account of internal thought or intent.

The store is for inspection, not grading: artifact hashes identify saved bytes
but do not authenticate their author or repair experiment-plan identities.
Service timestamps are Unix nanoseconds. Agent tool subevents inherit their
parent step timestamp; their individual timing and within-step order are not
observed. Checkpoints use verifier completion as a snapshot time, not the time
an objective was achieved. UTC clocks are not independently synchronized here.

Repeated cumulative service snapshots share events while retaining every source
reference. Identical repeated rows within a snapshot retain their multiplicity.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import sys

from .outcomes import OUTCOME_FIELDS

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_SERVICE_FIELDS = frozenset({
    "kind", "request_id", "parent_request_id", "actor", "destination",
    "resource", "action", "outcome", "content_id",
})
_STAGES = ("stage_enumerate", "stage_credential", "stage_session", "stage_vault")


class TraceImportError(ValueError):
    """Saved artifact cannot be imported without guessing or unsafe traversal."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _identifier(*parts):
    return _digest(_canonical(parts).encode("utf-8"))


def parse_timestamp(value):
    """Normalize timezone-aware ISO timestamps to exact integer epoch ns.

    Never assume a timezone for naive timestamps and never round through float.
    Timestamp representation precision does not establish clock accuracy.
    """
    if value is None:
        return None, "missing"
    if not isinstance(value, str):
        return None, "invalid"
    match = _ISO.fullmatch(value)
    if match is None:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None, "invalid"
        return None, "naive" if parsed.tzinfo is None else "invalid"
    base, fraction, offset = match.groups()
    try:
        parsed = datetime.fromisoformat(base + ("+00:00" if offset == "Z" else offset))
        delta = parsed.astimezone(timezone.utc) - _EPOCH
    except ValueError:
        return None, "invalid"
    result = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int((fraction or "").ljust(9, "0"))
    if not -(2 ** 63) <= result < 2 ** 63:
        return None, "invalid"
    return result, "parsed"


def _text(value):
    return value if isinstance(value, str) and value else None


def _content(value):
    if value is None:
        return None
    return value if isinstance(value, str) else _canonical(value)


def _object(value):
    return value if isinstance(value, dict) else {}


def _bits(value, names):
    return {name: int(value[name]) for name in names if name in value
            and type(value[name]) in (int, float) and value[name] in (-1, 0, 1)}


def _strict_json(data):
    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                raise TraceImportError("duplicate JSON keys")
            result[key] = value
        return result

    def constant(_value):
        raise TraceImportError("non-finite JSON value")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise TraceImportError("non-finite JSON value")
        return number

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant,
                          parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TraceImportError("invalid JSON artifact") from exc


class _Import:
    def __init__(self, root, include_reasoning):
        self.root = root
        self.include_reasoning = include_reasoning
        self.artifacts = {}
        self.events = []
        self.service_events = {}
        self.ref_ordinals = Counter()
        self.reasoning_available = 0
        self.reasoning_stored = 0
        self.measurement_ids = set()
        self.run_ids = set()
        self.conditions = set()
        self.scenarios = set()
        self.clock_statuses = Counter()

    def load(self, path, kind, *, jsonl=False):
        if (not path.is_relative_to(self.root)
                or any(part.is_symlink() for part in (path, *path.parents)
                       if part != self.root and part.is_relative_to(self.root))
                or not path.resolve().is_relative_to(self.root)):
            raise TraceImportError("artifact path is a symlink or leaves the trial directory")
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT_BYTES:
                raise TraceImportError("artifact is not a regular file within the size limit")
            data = path.read_bytes()
        except OSError as exc:
            raise TraceImportError("artifact could not be read") from exc
        if len(data) > MAX_ARTIFACT_BYTES:
            raise TraceImportError("artifact exceeds the size limit")
        name = path.relative_to(self.root).as_posix()
        descriptor = {"path": name, "sha256": _digest(data), "kind": kind}
        if name in self.artifacts and self.artifacts[name] != descriptor:
            raise TraceImportError("artifact changed during import")
        self.artifacts[name] = descriptor
        if jsonl:
            rows = []
            for ordinal, line in enumerate(data.splitlines()):
                if not line.strip():
                    continue
                rows.append((ordinal, _strict_json(line)))
            return name, rows
        return name, _strict_json(data)

    def ref(self, path, scope, *, ordinal=None):
        if ordinal is None:
            ordinal = self.ref_ordinals[path]
            self.ref_ordinals[path] += 1
        return {"path": path, "ordinal": ordinal, "scope": scope}

    def event(self, *, key, kind, source, scope=None, timestamp=None,
              basis="unavailable", actor=None, content=None, attributes=None,
              refs=None, tags=None, tool_call_id=None, agent_step_id=None,
              request_id=None, parent_request_id=None, service_ns=False):
        if service_ns:
            if type(timestamp) is not int or not -(2 ** 63) <= timestamp < 2 ** 63:
                raise TraceImportError("service timestamp must be integer epoch nanoseconds")
            normalized, status = timestamp, "parsed"
            raw = str(timestamp)
        else:
            normalized, status = parse_timestamp(timestamp)
            raw = timestamp if isinstance(timestamp, str) else None
        self.clock_statuses[status] += 1
        event = {
            "event_key": key, "timestamp_ns": normalized, "timestamp_raw": raw,
            "timestamp_basis": basis, "clock_domain": "utc_wall" if normalized is not None else None,
            "kind": kind, "source": source, "step_name": scope, "actor": actor,
            "request_id": request_id, "parent_request_id": parent_request_id,
            "tool_call_id": tool_call_id, "agent_step_id": agent_step_id,
            "content": content, "attributes": {**(attributes or {}), "timestamp_status": status},
            "tags": tags or [], "source_refs": refs or [],
        }
        self.events.append(event)
        return event

    def agent(self, scope_dir, scope):
        path = scope_dir / "agent/trajectory.json"
        if not path.exists() and not path.is_symlink():
            return
        name, data = self.load(path, "agent_trajectory")
        if not isinstance(data, dict) or not isinstance(data.get("steps"), list):
            raise TraceImportError("trajectory needs a steps array")
        for position, step in enumerate(data["steps"]):
            if not isinstance(step, dict):
                raise TraceImportError("trajectory step must be an object")
            source = _text(step.get("source"))
            step_id = step.get("step_id")
            step_id = str(step_id) if type(step_id) in (str, int) else None
            common = {
                "source": "agent", "scope": scope, "timestamp": step.get("timestamp"),
                "actor": source, "agent_step_id": step_id,
            }
            pointer = f"/steps/{position}"
            if step.get("message") is not None:
                self.event(key=_identifier(name, pointer, "message"), kind="message",
                           basis="agent_step_recorded", content=_content(step["message"]),
                           attributes={"json_pointer": pointer + "/message", "within_step_order": "not_observed"},
                           refs=[self.ref(name, scope)], **common)
            reasoning = step.get("reasoning_content")
            if reasoning is not None and reasoning != "":
                self.reasoning_available += 1
                if self.include_reasoning:
                    self.reasoning_stored += 1
                    self.event(key=_identifier(name, pointer, "reasoning_content"), kind="provider_reasoning",
                               basis="agent_step_recorded", content=_content(reasoning),
                               attributes={"json_pointer": pointer + "/reasoning_content",
                                           "within_step_order": "not_observed",
                                           "interpretation": "provider-exposed text; not verified internal thought or intent"},
                               refs=[self.ref(name, scope)], tags=["provider_reasoning"], **common)
            calls = step.get("tool_calls")
            if calls is None:
                calls = []
            if not isinstance(calls, list):
                raise TraceImportError("tool_calls must be a list")
            for index, call in enumerate(calls):
                if not isinstance(call, dict):
                    raise TraceImportError("tool call must be an object")
                self.event(key=_identifier(name, pointer, "tool_calls", index), kind="tool_call",
                           basis="agent_step_inherited", tool_call_id=_text(call.get("tool_call_id")),
                           content=_content(call.get("arguments")),
                           attributes={"function_name": _text(call.get("function_name")),
                                       "json_pointer": pointer + f"/tool_calls/{index}",
                                       "within_step_order": "not_observed"},
                           refs=[self.ref(name, scope)], **common)
            observation = step.get("observation")
            if observation is not None and not isinstance(observation, dict):
                raise TraceImportError("observation must be an object")
            results = _object(observation).get("results")
            if results is None:
                results = []
            if not isinstance(results, list):
                raise TraceImportError("observation results must be a list")
            for index, result in enumerate(results):
                if not isinstance(result, dict):
                    raise TraceImportError("observation result must be an object")
                call_id = _text(result.get("source_call_id"))
                self.event(key=_identifier(name, pointer, "observation", index), kind="tool_result",
                           basis="agent_step_inherited", tool_call_id=call_id,
                           content=_content(result.get("content")),
                           attributes={"json_pointer": pointer + f"/observation/results/{index}",
                                       "within_step_order": "not_observed",
                                       "call_link": "recorded_id" if call_id else "unavailable"},
                           refs=[self.ref(name, scope)], **common)

    def services(self, scope_dir, scope):
        directory = scope_dir / "artifacts/var/log"
        if not directory.exists():
            return
        if directory.is_symlink() or not directory.resolve().is_relative_to(self.root):
            raise TraceImportError("observation directory leaves the trial directory")
        for path in sorted(directory.glob("*-observations.jsonl")):
            stream = path.name.removesuffix("-observations.jsonl")
            name, rows = self.load(path, "service_observations", jsonl=True)
            occurrences = Counter()
            for ordinal, record in rows:
                if not isinstance(record, dict) or set(record) != {"ts", "fields"}:
                    raise TraceImportError("invalid observation record")
                fields = record["fields"]
                if not isinstance(fields, dict) or not _text(fields.get("kind")):
                    raise TraceImportError("observation fields need an event kind")
                fingerprint = _identifier(stream, record)
                occurrence = occurrences[fingerprint]
                occurrences[fingerprint] += 1
                key = "service-" + _identifier(fingerprint, occurrence)
                ref = self.ref(name, scope, ordinal=ordinal)
                if key in self.service_events:
                    self.service_events[key]["source_refs"].append(ref)
                    continue
                tags = []
                if fields.get("destination") == "reference":
                    tags.append("secondary_service")
                if fields.get("kind") == "clue":
                    tags.append("clue_delivered")
                if fields.get("kind") == "delivery" and fields.get("destination") == "target":
                    tags.append("target_delivery")
                attrs = {key: value for key, value in fields.items() if key in _SERVICE_FIELDS}
                attrs.update({"stream": stream, "occurrence_in_snapshot": occurrence,
                              "integrity": "saved artifact; not independently authenticated by this importer"})
                event = self.event(
                    key=key, kind="clue" if fields["kind"] == "clue" else "service_" + fields["kind"],
                    source=stream, scope=scope, timestamp=record["ts"], service_ns=True,
                    basis="service_event", actor=_text(fields.get("actor")),
                    request_id=_text(fields.get("request_id")), parent_request_id=_text(fields.get("parent_request_id")),
                    attributes=attrs, tags=tags, refs=[ref],
                )
                self.service_events[key] = event

    def checkpoint(self, scope_dir, scope, result, result_path, result_pointer):
        path = scope_dir / "verifier/measurement.json"
        measurement = {}
        refs = []
        if path.exists() or path.is_symlink():
            name, measurement = self.load(path, "verifier_measurement")
            if not isinstance(measurement, dict):
                raise TraceImportError("measurement must be an object")
            refs.append(self.ref(name, scope))
            for field, destination in (("trial_id", self.measurement_ids), ("run_id", self.run_ids),
                                       ("condition", self.conditions), ("scenario_id", self.scenarios)):
                if _text(measurement.get(field)):
                    destination.add(measurement[field])
        rewards = _object(_object(result.get("verifier_result")).get("rewards"))
        if not refs and not any(type(value) in (int, float) for value in rewards.values()):
            return
        stages = _bits(rewards, _STAGES)
        outcome = _bits(_object(measurement.get("outcome")), OUTCOME_FIELDS)
        if not outcome:
            outcome = _bits(rewards, OUTCOME_FIELDS)
        verifier = _object(result.get("verifier"))
        refs.append(self.ref(result_path, scope))
        self.event(
            key="checkpoint-" + _identifier(scope, result_pointer), kind="checkpoint", source="verifier",
            scope=scope, timestamp=verifier.get("finished_at"), basis="verifier_snapshot", actor="verifier",
            attributes={"checkpoint_name": scope or "trial_final", "outcome": outcome,
                        "stage_witnesses": stages, "json_pointer": result_pointer,
                        "interpretation": "verifier-output snapshot time, not objective-achievement time",
                        "grade_authenticated_by_importer": False},
            tags=["checkpoint"], refs=refs,
        )

    def lifecycle(self, scope, result, result_path, result_pointer):
        for group in ("agent_execution", "verifier"):
            for field, suffix in (("started_at", "start"), ("finished_at", "end")):
                value = _object(result.get(group)).get(field)
                if value is None:
                    continue
                self.event(
                    key=_identifier(result_path, result_pointer, group, field),
                    kind=group + "_" + suffix, source="harbor", scope=scope,
                    timestamp=value, basis="harbor_lifecycle", actor="harness",
                    attributes={"json_pointer": result_pointer + "/" + group + "/" + field},
                    tags=["lifecycle"], refs=[self.ref(result_path, scope)],
                )


def build_import(trial_dir, *, include_reasoning=False):
    """Prepare a complete immutable import description without writing files."""
    if type(include_reasoning) is not bool:
        raise TraceImportError("include_reasoning must be boolean")
    root = Path(trial_dir)
    if root.is_symlink() or not root.is_dir():
        raise TraceImportError("trial_dir must be a regular directory, not a symlink")
    root = root.resolve()
    builder = _Import(root, include_reasoning)
    result_path, result = builder.load(root / "result.json", "harbor_result")
    if not isinstance(result, dict):
        raise TraceImportError("trial result must be an object")
    step_results = result.get("step_results")
    scopes = []
    if step_results is not None:
        if not isinstance(step_results, list):
            raise TraceImportError("step_results must be a list or null")
        seen = set()
        for index, step in enumerate(step_results):
            if not isinstance(step, dict):
                raise TraceImportError("step result must be an object")
            name = step.get("step_name")
            if not _text(name) or name in (".", "..") or "/" in name or "\\" in name or name in seen:
                raise TraceImportError("step_name must be a unique safe path component")
            seen.add(name)
            scopes.append((root / "steps" / name, name, step, f"/step_results/{index}"))
    if not scopes:
        scopes.append((root, None, result, ""))
    for directory, scope, row, pointer in scopes:
        builder.lifecycle(scope, row, result_path, pointer)
        builder.agent(directory, scope)
        builder.services(directory, scope)
        builder.checkpoint(directory, scope, row, result_path, pointer)
    info = _object(result.get("agent_info"))
    model = _text(_object(info.get("model_info")).get("name"))
    agent = _text(info.get("name"))
    metadata = {
        "source_dir": str(root), "harbor_trial_id": _text(result.get("id")),
        "harbor_trial_name": _text(result.get("trial_name")), "agent_name": agent,
        "model_id": model, "actor_kind": "oracle" if agent == "oracle" else "model" if model else "unknown",
        "measurement_trial_ids": sorted(builder.measurement_ids), "run_ids": sorted(builder.run_ids),
        "conditions": sorted(builder.conditions), "scenario_ids": sorted(builder.scenarios),
        "step_names": [scope for _, scope, _, _ in scopes],
        "provider_reasoning_included": include_reasoning,
        "reasoning_fields_available": builder.reasoning_available,
        "reasoning_fields_stored": builder.reasoning_stored,
        "timestamp_status_counts": dict(sorted(builder.clock_statuses.items())),
        "interpretation": {
            "purpose": "inspection only; not a substitute for plan-bound verified grading",
            "clocks_synchronized": False, "timestamp_precision_establishes_accuracy": False,
            "model_to_service_causality_inferred": False,
            "provider_reasoning_is_verified_internal_thought": False,
            "checkpoint_time_is_achievement_time": False,
            "tool_component_times_independently_observed": False,
        },
    }
    return {
        "trial_key": "harbor-" + _identifier(str(root))[:24], "metadata": metadata,
        "artifacts": [builder.artifacts[name] for name in sorted(builder.artifacts)],
        "events": builder.events,
    }


def ingest_trial(db_path, trial_dir, *, include_reasoning=False):
    from .trace_store import TraceStore

    payload = build_import(trial_dir, include_reasoning=include_reasoning)
    with TraceStore(db_path) as store:
        return store.ingest(**payload)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--trial-dir", type=Path, required=True, action="append")
    parser.add_argument("--include-reasoning", action="store_true",
                        help="retain provider-exposed reasoning text, labelled as unverified self-report")
    args = parser.parse_args(argv)
    try:
        # Parse every selected trial before publishing any import from this call.
        payloads = [build_import(path, include_reasoning=args.include_reasoning) for path in args.trial_dir]
        from .trace_store import TraceStore
        with TraceStore(args.db) as store:
            summaries = [store.ingest(**payload) for payload in payloads]
        print(json.dumps(summaries, indent=2, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, TypeError) as exc:
        print(f"Trace import failed ({type(exc).__name__}); check artifacts and import configuration.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
