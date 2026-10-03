"""Durable, authenticated evidence plumbing for trusted service adapters.

This module starts no service, executes no agent, and exposes no ingestion API.
Adapters call one recorder directly; its lock orders threads in that process,
not independent processes. They must explicitly record service start and final
collection. A failed emit poisons the recorder; incomplete logs cannot be sealed.

The instrumentation, recorder, signing key, and all parent directories must be
outside agent control. HMAC authenticates the recorder's exact output; it cannot
prove the instrumentation was truthful or complete. ``plan_sha256`` is a trusted
launcher's assertion about the planned run, not proof of actual runtime settings.
Use a fresh trial identity per run and verify it against trusted scheduling state.

Files are private, bounded, exclusive, and opened without following symlinks.
Only fixed filenames in a pinned directory are read. These protections assume
trusted parents; they are not containment for a compromised recorder process.
No signing key or submitted answer is copied into grading output. Synthetic
evidence stays labelled synthetic and must not be counted as model behaviour.

    python -m boundary_eval.collection grade --help
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
import threading
from typing import Any
import uuid

from .contract import COMMON_EVENT_KEYS, EVENT_KEYS, validate_events, validate_manifest
from .harbor import encode_rewards, read_submission
from .score import BEHAVIOR_FIELDS, OUTCOME_FIELDS, score

MAX_MANIFEST_BYTES = 256 * 1024
MAX_PROVENANCE_BYTES = 16 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_EVENTS_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 100_000
MAX_COMPLETION_BYTES = 16 * 1024
MAX_KEY_BYTES = 4096
_FILES = ("manifest.json", "events.jsonl", "provenance.json")
_LIMITS = (MAX_MANIFEST_BYTES, MAX_EVENTS_BYTES, MAX_PROVENANCE_BYTES)
_ENVELOPE = frozenset(COMMON_EVENT_KEYS) - {"kind", "actor"}
_PROVENANCE = frozenset({"evidence_source", "actor_kind", "model_id", "run_id", "plan_sha256"})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN = b"boundary_eval.authenticated_bundle.v1\x00"


class CollectionError(ValueError):
    """Safe, content-free description of a collection or filesystem failure."""


@dataclass(frozen=True)
class Bundle:
    """Validated authenticated artifacts, or only errors and null artifacts."""

    manifest: dict[str, Any] | None
    events: list[dict[str, Any]] | None
    provenance: dict[str, Any] | None
    errors: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.errors and self.manifest is not None


def _key(value: bytes) -> bytes:
    if type(value) is not bytes or not 32 <= len(value) <= MAX_KEY_BYTES:
        raise CollectionError("key: expected 32 to 4096 raw bytes")
    return value


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _check_provenance(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != _PROVENANCE:
        raise CollectionError("provenance: incorrect fields")
    if value["evidence_source"] not in ("live_service", "synthetic_fixture"):
        raise CollectionError("provenance: invalid evidence_source")
    if value["actor_kind"] not in ("model", "oracle", "scripted", "unknown"):
        raise CollectionError("provenance: invalid actor_kind")
    if not _text(value["run_id"]):
        raise CollectionError("provenance: invalid run_id")
    if value["actor_kind"] == "model":
        if not _text(value["model_id"]):
            raise CollectionError("provenance: model actor requires model_id")
        if not isinstance(value["plan_sha256"], str) or not _HEX.fullmatch(value["plan_sha256"]):
            raise CollectionError("provenance: model actor requires plan_sha256")
    elif value["model_id"] is not None or value["plan_sha256"] is not None:
        raise CollectionError("provenance: non-model actor requires null model_id and plan_sha256")


def _dump(value: Any, *, limit: int) -> bytes:
    try:
        data = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise CollectionError("serialization: expected finite JSON data") from None
    if len(data) > limit:
        raise CollectionError("serialization: size limit exceeded")
    return data


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate key")
        result[name] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("non-finite number")


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite number")
    return result


def _parse(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                          parse_constant=_constant, parse_float=_float)
    except (ValueError, RecursionError):
        raise CollectionError(f"{label}: malformed JSON") from None


def _events(data: bytes) -> list[dict[str, Any]]:
    if not data or not data.endswith(b"\n"):
        raise CollectionError("events: missing or truncated log")
    lines = data[:-1].split(b"\n")
    if len(lines) > MAX_EVENTS:
        raise CollectionError("events: count limit exceeded")
    result = []
    for line in lines:
        if len(line) + 1 > MAX_EVENT_BYTES:
            raise CollectionError("events: event size limit exceeded")
        event = _parse(line, "events")
        if not isinstance(event, dict):
            raise CollectionError("events: expected JSON objects")
        result.append(event)
    return result


def _dir(path: Path | str, *, create: bool = False) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise CollectionError("filesystem: no-follow directory opens unavailable")
    try:
        if create:
            os.mkdir(path, 0o700)
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise CollectionError("directory: must be a safe " + ("new directory" if create else "existing directory")) from None


def _regular(fd: int, *, limit: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CollectionError("file: expected a regular file with one link")
    if info.st_size > limit:
        raise CollectionError("file: size limit exceeded")
    return info


def _read(dirfd: int, name: str, limit: int) -> bytes:
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
        before = _regular(fd, limit=limit)
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = _regular(fd, limit=limit)
        data = b"".join(chunks)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(data) > limit or len(data) != before.st_size
                or any(getattr(before, field) != getattr(after, field) for field in stable)):
            raise CollectionError("file: changed during read or size limit exceeded")
        return data
    except OSError:
        raise CollectionError("file: missing, unreadable, or unsafe") from None
    finally:
        if fd is not None:
            os.close(fd)


def _write(dirfd: int, name: str, data: bytes, *, append: bool = False) -> None:
    fd = None
    try:
        mode = os.O_APPEND if append else os.O_CREAT | os.O_EXCL
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | mode,
                     0o600, dir_fd=dirfd)
        _regular(fd, limit=MAX_EVENTS_BYTES)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise CollectionError("file: incomplete write")
            offset += written
        os.fsync(fd)
        if not append:
            os.fsync(dirfd)
    except (OSError, CollectionError):
        # A partially written completion marker must never look final. Removing
        # other newly created partial files also leaves the bundle ungradeable.
        if fd is not None and not append:
            try:
                os.unlink(name, dir_fd=dirfd)
            except OSError:
                pass
        raise CollectionError("file: durable exclusive write failed") from None
    finally:
        if fd is not None:
            os.close(fd)


def _file_records(raw: dict[str, bytes]) -> dict[str, dict[str, Any]]:
    return {name: {"bytes": len(raw[name]), "sha256": hashlib.sha256(raw[name]).hexdigest()}
            for name in _FILES}


def _mac(key: bytes, trial_id: str, raw: dict[str, bytes]) -> str:
    result = hmac.new(key, _DOMAIN, hashlib.sha256)
    chunks = [trial_id.encode("utf-8")]
    for name in _FILES:
        chunks.extend((name.encode("ascii"), raw[name]))
    for chunk in chunks:
        result.update(struct.pack(">Q", len(chunk)))
        result.update(chunk)
    return result.hexdigest()


class EvidenceRecorder:
    """One thread-safe recorder per new trial; callers supply lifecycle events.

    ``emit(service, fields)`` returns its assigned event. Callers may supply only
    kind/actor and kind-specific fields, never envelope fields. All rejected emits
    and write failures prevent sealing. ``close()`` releases resources without
    inventing collection markers or sealing. The context manager only closes.
    """

    def __init__(self, directory: Path | str, manifest: dict, *, key: bytes, provenance: dict):
        self._key = _key(key)
        _check_provenance(provenance)
        if validate_manifest(manifest):
            raise CollectionError("manifest: violates boundary contract")
        manifest_data = _dump(manifest, limit=MAX_MANIFEST_BYTES)
        provenance_data = _dump(provenance, limit=MAX_PROVENANCE_BYTES)
        self.directory = Path(directory)
        self._manifest = _parse(manifest_data, "manifest")
        self._raw = {"manifest.json": manifest_data, "provenance.json": provenance_data}
        self._lock = threading.Lock()
        self._count = self._bytes = 0
        self._digest = hashlib.sha256()
        self._failed = self._sealed = False
        self._dirfd = _dir(self.directory, create=True)
        try:
            _write(self._dirfd, "manifest.json", manifest_data)
            _write(self._dirfd, "provenance.json", provenance_data)
            _write(self._dirfd, "events.jsonl", b"")
        except CollectionError:
            self.close()
            raise

    def _open(self) -> None:
        if self._dirfd is None or self._sealed or self._failed:
            raise CollectionError("recorder: closed, sealed, or failed")

    def emit(self, service: str, event_fields: dict) -> dict:
        with self._lock:
            self._open()
            try:
                if service not in self._manifest["required_services"]:
                    raise CollectionError("event: unlisted service")
                if not isinstance(event_fields, dict) or _ENVELOPE.intersection(event_fields):
                    raise CollectionError("event: envelope fields cannot be supplied")
                if set(event_fields) - set(EVENT_KEYS) or not {"kind", "actor"} <= set(event_fields):
                    raise CollectionError("event: incorrect fields")
                event = dict(event_fields, schema_version=1, trial_id=self._manifest["trial_id"],
                             event_id=str(uuid.uuid4()), seq=self._count + 1, service=service)
                data = _dump(event, limit=MAX_EVENT_BYTES)
                if self._count >= MAX_EVENTS or self._bytes + len(data) > MAX_EVENTS_BYTES:
                    raise CollectionError("events: count or size limit exceeded")
                _write(self._dirfd, "events.jsonl", data, append=True)
                self._digest.update(data)
                self._count += 1
                self._bytes += len(data)
                return _parse(data, "event")
            except (CollectionError, TypeError, ValueError):
                self._failed = True
                raise CollectionError("event: rejected or not durably recorded; recorder invalid") from None

    def seal(self) -> Path:
        """Validate all recorded evidence, then write the completion MAC last."""
        with self._lock:
            self._open()
            try:
                raw = {name: _read(self._dirfd, name, limit) for name, limit in zip(_FILES, _LIMITS)}
                if any(raw[name] != data for name, data in self._raw.items()):
                    raise CollectionError("recorder: private metadata changed")
                if len(raw["events.jsonl"]) != self._bytes or hashlib.sha256(raw["events.jsonl"]).digest() != self._digest.digest():
                    raise CollectionError("recorder: event log changed")
                events = _events(raw["events.jsonl"])
                if len(events) != self._count or validate_events(self._manifest, events):
                    raise CollectionError("events: incomplete or violates boundary contract")
                trial_id = self._manifest["trial_id"]
                completion = {"schema_version": 1, "trial_id": trial_id, "files": _file_records(raw),
                              "hmac_sha256": _mac(self._key, trial_id, raw)}
                _write(self._dirfd, "completion.json", _dump(completion, limit=MAX_COMPLETION_BYTES))
                self._sealed = True
                self._key = b""
                return self.directory
            except CollectionError:
                self._failed = True
                raise

    def close(self) -> None:
        with self._lock:
            if self._dirfd is not None:
                os.close(self._dirfd)
                self._dirfd = None
            self._key = b""

    def __enter__(self) -> EvidenceRecorder:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def load_bundle(directory: Path | str, *, key: bytes, expected_trial_id: str) -> Bundle:
    """Return artifacts only if their MAC, identity, provenance and contract pass.

    Invalid evidence never exposes an untrusted answer or identity to grading.
    The key and expected trial id must come from trusted scheduling state.
    """
    dirfd = None
    try:
        _key(key)
        if not _text(expected_trial_id):
            raise CollectionError("identity: trusted expected trial id is required")
        dirfd = _dir(directory)
        raw = {name: _read(dirfd, name, limit) for name, limit in zip(_FILES, _LIMITS)}
        completion = _parse(_read(dirfd, "completion.json", MAX_COMPLETION_BYTES), "completion")
        if not isinstance(completion, dict) or set(completion) != {"schema_version", "trial_id", "files", "hmac_sha256"}:
            raise CollectionError("completion: incorrect fields")
        if type(completion["schema_version"]) is not int or completion["schema_version"] != 1:
            raise CollectionError("completion: invalid version")
        if completion["trial_id"] != expected_trial_id:
            raise CollectionError("identity: trial does not match trusted expectation")
        supplied = completion["hmac_sha256"]
        if not isinstance(supplied, str) or not _HEX.fullmatch(supplied):
            raise CollectionError("authentication: invalid completion MAC")
        if not hmac.compare_digest(supplied, _mac(key, expected_trial_id, raw)):
            raise CollectionError("authentication: bundle MAC mismatch")
        records = completion["files"]
        if (not isinstance(records, dict) or set(records) != set(_FILES)
                or any(not isinstance(record, dict) or set(record) != {"bytes", "sha256"}
                       or type(record["bytes"]) is not int
                       or not isinstance(record["sha256"], str)
                       or not _HEX.fullmatch(record["sha256"])
                       for record in records.values())
                or records != _file_records(raw)):
            raise CollectionError("completion: file records do not match evidence")
        manifest = _parse(raw["manifest.json"], "manifest")
        provenance = _parse(raw["provenance.json"], "provenance")
        _check_provenance(provenance)
        if validate_manifest(manifest):
            raise CollectionError("manifest: violates boundary contract")
        if manifest["trial_id"] != expected_trial_id:
            raise CollectionError("identity: manifest trial does not match trusted expectation")
        events = _events(raw["events.jsonl"])
        if validate_events(manifest, events):
            raise CollectionError("events: incomplete or violates boundary contract")
        return Bundle(manifest, events, provenance)
    except CollectionError as exc:
        return Bundle(None, None, None, (str(exc),))
    except (OSError, TypeError, ValueError, RecursionError):
        return Bundle(None, None, None, ("bundle: could not validate evidence",))
    finally:
        if dirfd is not None:
            os.close(dirfd)


def _unknown(errors: list[str]) -> dict[str, Any]:
    return {"schema_version": 1, "measurement_valid": 0, "errors": errors,
            **dict.fromkeys(("answer_correct",) + BEHAVIOR_FIELDS + OUTCOME_FIELDS)}


def _evaluate_bundle(directory: Path | str, *, key: bytes, expected_trial_id: str,
                     submission_path: Path | str) -> tuple[dict, dict]:
    bundle = load_bundle(directory, key=key, expected_trial_id=expected_trial_id)
    errors = list(bundle.errors)
    if bundle.valid:
        submission = read_submission(submission_path)
        if submission.status in ("rejected", "error"):
            errors.append("submission: unreadable or unsafe artifact")
        result = _unknown(errors) if errors else score(bundle.manifest, bundle.events, submission.text)
        # Validated inputs should produce no scorer errors; do not copy values
        # from unexpected diagnostics into output that travels beyond the bundle.
        if result["errors"] and not errors:
            errors.append("scoring: measurement could not be validated")
            result = _unknown(errors)
    else:
        result = _unknown(errors)
    provenance = bundle.provenance or {}
    manifest = bundle.manifest or {}
    measurement = {"kind": "boundary_eval.measurement", "schema_version": 1,
                   **{field: provenance.get(field) for field in sorted(_PROVENANCE)},
                   **{field: manifest.get(field) for field in ("scenario_id", "trial_id", "condition")},
                   "score": result, "errors": errors}
    prefix = {"synthetic_fixture": "synthetic_", "live_service": "live_"}.get(
        provenance.get("evidence_source"), "unknown_")
    rewards, anomalies = encode_rewards(result, prefix=prefix)
    if anomalies:
        raise CollectionError("scoring: numeric reward encoding failed")
    return measurement, rewards


def grade_bundle(directory: Path | str, *, key: bytes, expected_trial_id: str,
                 submission_path: Path | str, output_dir: Path | str) -> dict[str, Any]:
    """Write a lossless measurement and numeric rewards to a fresh directory.

    Invalid evidence has null identities, source and metrics. Rejected submissions
    retain authenticated identities but invalidate all metrics. No submission is
    a normal incorrect answer. Reward keys use synthetic_/live_/unknown_ prefixes;
    no scalar reward is invented. Aggregate nulls explicitly, never as zero.
    """
    measurement, rewards = _evaluate_bundle(directory, key=key, expected_trial_id=expected_trial_id,
                                            submission_path=submission_path)
    dirfd = _dir(output_dir, create=True)
    try:
        _write(dirfd, "measurement.json", _dump(measurement, limit=MAX_MANIFEST_BYTES))
        _write(dirfd, "reward.json", _dump(rewards, limit=MAX_COMPLETION_BYTES))
    finally:
        os.close(dirfd)
    return measurement


def _clear_verifier_outputs(dirfd: int) -> None:
    errors = False
    for name in ("reward.json", "reward.txt", "measurement.json"):
        try:
            info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                errors = True
                continue
            # Removing a symlink removes the link, never its referent. Still
            # reject it, while continuing to clear every other stale reward.
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                errors = True
            os.unlink(name, dir_fd=dirfd)
        except FileNotFoundError:
            continue
        except OSError:
            errors = True
    try:
        os.fsync(dirfd)
    except OSError:
        errors = True
    if errors:
        raise CollectionError("verifier output: unsafe or uncleared previous artifacts")


def _publish(dirfd: int, name: str, data: bytes) -> None:
    temporary = f".boundary-{uuid.uuid4().hex}.tmp"
    published = False
    try:
        _write(dirfd, temporary, data)
        os.replace(temporary, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        published = True
        os.fsync(dirfd)
    except (OSError, CollectionError):
        for candidate in (temporary, name) if published else (temporary,):
            try:
                os.unlink(candidate, dir_fd=dirfd)
            except OSError:
                pass
        raise CollectionError("verifier output: durable publication failed") from None


def harbor_grade_bundle(directory: Path | str, *, key: bytes, expected_trial_id: str,
                        submission_path: Path | str, output_dir: Path | str) -> dict[str, Any]:
    """Publish into an existing trusted verifier log directory, clearing stale rewards.

    The bundle and key must be protected verifier inputs, separate from the agent
    submission and log handoff. Only three fixed output names are removed; unusual
    files fail closed after the other stale rewards have been removed. The numeric
    reward is published last. This adapter configures no Harbor task or container.
    """
    dirfd = _dir(output_dir)
    try:
        _clear_verifier_outputs(dirfd)
        measurement, rewards = _evaluate_bundle(directory, key=key, expected_trial_id=expected_trial_id,
                                                submission_path=submission_path)
        _publish(dirfd, "measurement.json", _dump(measurement, limit=MAX_MANIFEST_BYTES))
        _publish(dirfd, "reward.json", _dump(rewards, limit=MAX_COMPLETION_BYTES))
        return measurement
    finally:
        os.close(dirfd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade authenticated boundary evidence; never runs a target or agent.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("grade", "Write to a new directory"),
                            ("harbor-grade", "Replace stale rewards in an existing trusted verifier directory")):
        grade = commands.add_parser(name, help=help_text)
        grade.add_argument("--bundle", required=True, type=Path)
        grade.add_argument("--key-file", required=True, type=Path, help="Protected regular file with 32–4096 raw key bytes")
        grade.add_argument("--trial-id", required=True, help="Expected identity from trusted scheduling state")
        grade.add_argument("--submission", required=True, type=Path)
        grade.add_argument("--output", required=True, type=Path, help="Trusted output directory (new for grade, existing for harbor-grade)")
    args = parser.parse_args(argv)
    dirfd = None
    try:
        # A key read failure still creates an invalid measurement; it is never
        # converted into a wrong answer or a compliant behaviour record.
        key = b""
        try:
            dirfd = _dir(args.key_file.parent)
            key = _read(dirfd, args.key_file.name, MAX_KEY_BYTES)
        except CollectionError:
            pass
        finally:
            if dirfd is not None:
                os.close(dirfd)
                dirfd = None
        grade_fn = harbor_grade_bundle if args.command == "harbor-grade" else grade_bundle
        result = grade_fn(args.bundle, key=key, expected_trial_id=args.trial_id,
                         submission_path=args.submission, output_dir=args.output)
    except CollectionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("measurement valid" if result["score"]["measurement_valid"] else "measurement invalid; metrics unknown")
    return 0 if result["score"]["measurement_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
