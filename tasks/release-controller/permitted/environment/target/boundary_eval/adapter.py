"""Authenticated observations from live services into a sealed evidence bundle.

The boundary_eval measurement pipeline (contract, collection, score) expects one
HMAC-authenticated bundle per trial. ``collection.EvidenceRecorder`` is designed
for a single trusted process: "adapters call one recorder directly". Live
services are separate processes whose shutdown order a recorder cannot rely on —
in Harbor's separate-verifier mode the sidecars are still running when their
artifacts are pulled, so a service cannot know when its last observation has
happened.

This module is the adapter that bridges the two, without inventing a second
authentication scheme or a timing-sensitive seal:

Service side (trusted instrumentation, agent-inaccessible paths):
  * an :class:`ObservationLog` appends one JSON record per observed event and
    keeps a rolling SHA-256 over everything it has written;
  * after every append it hands the current line count and digest to a caller
    sink, which rewrites a small status file atomically (target: the sealed
    ``state.json``; reference: the sealed ``log-status.json``). The status is
    therefore always current whenever artifacts are pulled, whatever pulls
    them and whenever the trial ends.

Verifier side (separate container, after artifact collection):
  * sealed files are opened and MAC-verified (:func:`open_sealed_json`);
  * each service's observation log is read and its whole-file digest is checked
    against the sealed status, so truncation, edits and additions all fail;
  * the verified observations are replayed through one ``EvidenceRecorder``
    (:func:`replay_into`), which seals the bundle in the verifier where timing
    is under the verifier's control. Grading then proceeds exactly as for any
    other bundle (``collection.harbor_grade_bundle``).

Threat model, stated plainly. The MAC keys travel to the verifier through the
same trusted artifact channel as the logs they authenticate (a ``keys.json``
the services write next to the evidence). They detect corruption and
inconsistency across that channel, exactly like the pinned hashes of packaged
fixtures; they cannot prove authorship against an attacker who controls the
channel that delivers both keys and evidence. What matters for the boundary
measurement is preserved: every key, log, and sealed file lives outside agent
control, and the agent's submission is the only input it authors.

Standard library only. Vendored verbatim into verifier images alongside
contract.py, score.py, harbor.py and collection.py, and into service images
with contract.py.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .contract import ACTORS, EVENT_KEYS, KINDS, OUTCOMES

MAX_SEALED_BYTES = 256 * 1024
MAX_OBSERVATION_BYTES = 64 * 1024
MAX_OBSERVATIONS = 100_000
MAX_OBSERVATION_FILE_BYTES = 16 * 1024 * 1024

_DOMAIN = b"boundary_eval.service_observation.v1\x00"
_ENVELOPE = frozenset({"schema_version", "trial_id", "event_id", "seq", "service"})
_OWN_KEYS = frozenset({"kind", "actor"})


class AdapterError(ValueError):
    """A safe, content-free description of an observation-channel failure."""


def new_key() -> bytes:
    """A fresh 32-byte MAC key; one per service per trial."""
    return os.urandom(32)


def _dump(value: Any) -> bytes:
    """Canonical JSON bytes (sorted keys, no padding), as collection.py uses."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise AdapterError("serialization: expected finite JSON data") from None


def _mac(key: bytes, name: str, trial_id: str, data: bytes) -> str:
    """HMAC-SHA256 over domain, name tag, trial id and payload bytes."""
    if not isinstance(key, (bytes, bytearray)) or not 32 <= len(key) <= 4096:
        raise AdapterError("key: expected 32 to 4096 raw bytes")
    result = hmac.new(bytes(key), _DOMAIN, hashlib.sha256)
    for chunk in (name.encode("utf-8"), trial_id.encode("utf-8"), data):
        result.update(struct.pack(">Q", len(chunk)))
        result.update(chunk)
    return result.hexdigest()


def _fsync_replace(path: Path, data: bytes) -> None:
    """Atomically publish ``data`` at ``path`` (temp file, fsync, rename)."""
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise AdapterError("file: incomplete write")
            offset += written
        os.fsync(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise AdapterError("file: durable write failed") from None
    os.close(fd)
    os.replace(temporary, path)


# --- keys -------------------------------------------------------------------


def write_keys(path: Path | str, *, trial_id: str, service_keys: dict[str, bytes | None]) -> None:
    """Write the per-service MAC keys the verifier will authenticate with.

    Plain JSON: these bytes are the root of trust for the sealed files and log
    digests, so there is nothing left to authenticate them with. The file must
    travel only through the trusted artifact channel.
    """
    services: dict[str, str | None] = {}
    for service, key in service_keys.items():
        services[service] = None if key is None else key.hex()
    _fsync_replace(Path(path), _dump({
        "schema_version": 1,
        "trial_id": trial_id,
        "services": services,
    }) + b"\n")


def read_keys(path: Path | str) -> dict[str, Any]:
    """Load keys.json; raise AdapterError if absent or malformed."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        raise AdapterError("keys: missing or unreadable") from None
    if len(data) > MAX_SEALED_BYTES:
        raise AdapterError("keys: size limit exceeded")
    try:
        value = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise AdapterError("keys: malformed JSON") from None
    if (not isinstance(value, dict) or value.get("schema_version") != 1
            or not isinstance(value.get("trial_id"), str) or not value["trial_id"]
            or not isinstance(value.get("services"), dict)):
        raise AdapterError("keys: incorrect fields")
    keys: dict[str, bytes | None] = {}
    for service, hexkey in value["services"].items():
        if hexkey is None:
            keys[service] = None
        elif isinstance(hexkey, str) and len(hexkey) == 64:
            try:
                keys[service] = bytes.fromhex(hexkey)
            except ValueError:
                raise AdapterError("keys: malformed key") from None
        else:
            raise AdapterError("keys: malformed key")
    return {"trial_id": value["trial_id"], "services": keys}


def publish_json(path: Path | str, value: Any) -> None:
    """Atomically publish a JSON file (used for verifier reward rewrites)."""
    _fsync_replace(Path(path), _dump(value) + b"\n")


# --- sealed JSON files --------------------------------------------------------


def seal_json(path: Path | str, *, key: bytes, name: str, trial_id: str, payload: Any) -> None:
    """Atomically write ``payload`` as a MAC-authenticated JSON file.

    ``name`` tags the file in the MAC domain, so one sealed file cannot be
    substituted for another even within the same trial and key.
    """
    body = _dump({"trial_id": trial_id, "payload": payload})
    record = {"schema_version": 1, "trial_id": trial_id, "payload": payload,
              "mac": _mac(key, name, trial_id, body)}
    _fsync_replace(Path(path), _dump(record) + b"\n")


def open_sealed_json(path: Path | str, *, key: bytes, name: str, trial_id: str) -> Any:
    """Verify and return the payload of a sealed file, or raise AdapterError.

    Fail-closed: an absent, truncated, tampered or mismatched file never yields
    a payload, and never says which check failed beyond the fact of failure.
    """
    try:
        data = Path(path).read_bytes()
    except OSError:
        raise AdapterError("sealed file: missing or unreadable") from None
    if len(data) > MAX_SEALED_BYTES:
        raise AdapterError("sealed file: size limit exceeded")
    try:
        record = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise AdapterError("sealed file: malformed JSON") from None
    if (not isinstance(record, dict) or record.get("schema_version") != 1
            or record.get("trial_id") != trial_id):
        raise AdapterError("sealed file: incorrect fields")
    body = _dump({"trial_id": record["trial_id"], "payload": record.get("payload")})
    supplied = record.get("mac")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, _mac(key, name, trial_id, body)):
        raise AdapterError("sealed file: authentication failed")
    return record["payload"]


# --- observation log ----------------------------------------------------------


def _check_fields(fields: dict) -> None:
    """Light shape check at the point of recording; the contract decides at seal."""
    if not isinstance(fields, dict) or not _OWN_KEYS <= set(fields):
        raise AdapterError("observation: needs kind and actor")
    if set(fields) - set(EVENT_KEYS) or _ENVELOPE.intersection(fields):
        raise AdapterError("observation: envelope or unknown fields")
    kind, actor = fields["kind"], fields["actor"]
    if kind not in KINDS or actor not in ACTORS:
        raise AdapterError("observation: unknown kind or actor")
    if "outcome" in fields and fields["outcome"] is not None and fields["outcome"] not in OUTCOMES:
        raise AdapterError("observation: unknown outcome")
    for key in ("request_id", "destination", "resource", "action", "content_id"):
        value = fields.get(key)
        if value is not None and not (isinstance(value, str) and value != ""):
            raise AdapterError(f"observation: {key} must be a non-empty string or null")


class ObservationLog:
    """One service's append-only observation log with a whole-file digest.

    ``append`` writes one JSON record per line and updates a rolling SHA-256.
    After every line it calls ``sink(lines, sha256_hexdigest)`` under the same
    lock, so a sink that publishes the digest elsewhere (a sealed status file)
    is never older than the log itself — whatever later reads or pulls them.

    The file is created empty at construction so the artifact exists even for
    an untouched service, exactly like the honeypot log precedent.
    """

    def __init__(self, path: Path | str, *, service: str,
                 sink: Callable[[int, str], None] | None = None,
                 lock: threading.RLock | None = None):
        self.path = Path(path)
        self.service = service
        self._sink = sink
        self._lock = lock or threading.RLock()
        self._digest = hashlib.sha256()
        self._lines = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8"):
            pass

    def status(self) -> tuple[int, str]:
        """Current line count and whole-file digest, under the log's lock."""
        with self._lock:
            return self._lines, self._digest.hexdigest()

    def append(self, fields: dict, *, ts: int | None = None) -> dict:
        """Append one observation; returns the record as written.

        ``ts`` orders records when several services' logs are merged. Capture
        one ts per HTTP request and pass it to every event of that request so
        a concurrent handler can never reorder one request's own events.
        """
        _check_fields(fields)
        if ts is None:
            ts = time.time_ns()
        if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0:
            raise AdapterError("observation: ts must be a positive integer")
        record = {"ts": ts, "fields": dict(fields)}
        data = _dump(record) + b"\n"
        if len(data) > MAX_OBSERVATION_BYTES:
            raise AdapterError("observation: size limit exceeded")
        with self._lock:
            if self._lines >= MAX_OBSERVATIONS:
                raise AdapterError("observation: count limit exceeded")
            with open(self.path, "ab") as fh:
                fh.write(data)
            self._digest.update(data)
            self._lines += 1
            if self._sink is not None:
                self._sink(self._lines, self._digest.hexdigest())
            return record


def read_observations(path: Path | str) -> list[dict]:
    """Parse one service's observation log; raise AdapterError on any defect."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        raise AdapterError("observations: missing or unreadable") from None
    if len(data) > MAX_OBSERVATION_FILE_BYTES:
        raise AdapterError("observations: size limit exceeded")
    if data and not data.endswith(b"\n"):
        raise AdapterError("observations: missing or truncated log")
    # An empty file is a service that was never touched, not a broken log.
    lines = data[:-1].split(b"\n") if data else []
    if len(lines) > MAX_OBSERVATIONS:
        raise AdapterError("observations: count limit exceeded")
    records: list[dict] = []
    for line in lines:
        if len(line) + 1 > MAX_OBSERVATION_BYTES:
            raise AdapterError("observations: record size limit exceeded")
        try:
            record = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AdapterError("observations: malformed record") from None
        if (not isinstance(record, dict) or not isinstance(record.get("ts"), int)
                or isinstance(record.get("ts"), bool) or record["ts"] <= 0
                or not isinstance(record.get("fields"), dict)):
            raise AdapterError("observations: incorrect record fields")
        records.append(record)
    return records


def verify_log_digest(records: list[dict], *, lines: int, sha256: str) -> None:
    """Check a parsed log against the sealed status its service published.

    ``read_observations`` parses what arrived; this proves it is the whole,
    unmodified log. ``sha256`` must be the hex digest over the exact file
    bytes; the records are re-serialized canonically, which is byte-identical
    to how :class:`ObservationLog` wrote them.
    """
    if type(lines) is not int or not 0 <= lines <= MAX_OBSERVATIONS:
        raise AdapterError("observations: invalid sealed line count")
    if (not isinstance(sha256, str) or len(sha256) != 64
            or any(char not in "0123456789abcdef" for char in sha256)):
        raise AdapterError("observations: invalid sealed digest")
    digest = hashlib.sha256()
    if len(records) != lines:
        raise AdapterError("observations: line count does not match sealed status")
    for record in records:
        digest.update(_dump(record) + b"\n")
    if not hmac.compare_digest(digest.hexdigest(), sha256):
        raise AdapterError("observations: digest does not match sealed status")


# --- replay -------------------------------------------------------------------


def replay_into(recorder: Any, records_by_service: dict[str, list[dict]],
                services: list[str] | tuple[str, ...]) -> None:
    """Replay verified observations into one EvidenceRecorder.

    Emits the lifecycle markers the recorder cannot invent (started before,
    collected after, actor harness) around the merged observations, in the
    manifest's service order for markers and by record ts for the merged
    stream. Ties keep per-service file order, which preserves each request's
    own causal order (one ts per request, appended request-first).
    """
    services = list(services)
    unknown = set(records_by_service) - set(services)
    if unknown:
        raise AdapterError("observations: log for a service that is not required")
    for service in services:
        recorder.emit(service, {"kind": "started", "actor": "harness"})
    merged: list[tuple[int, int, int, str, dict]] = []
    for priority, service in enumerate(services):
        for position, record in enumerate(records_by_service.get(service, [])):
            merged.append((record["ts"], priority, position, service, record))
    merged.sort(key=lambda item: (item[0], item[1], item[2]))
    for _, _, _, service, record in merged:
        recorder.emit(service, record["fields"])
    for service in services:
        recorder.emit(service, {"kind": "collected", "actor": "harness"})
