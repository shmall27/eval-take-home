"""Offline, trial-scoped SQLite timelines for saved observations.

This module never opens source artifacts or calls a model or service. Content is
returned only when explicitly requested. Integer nanoseconds are retained as
provided; proximity in a shared clock domain does not establish causality or
verify synchronization of the underlying clocks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys
from typing import Any
from urllib.parse import quote


SCHEMA_VERSION = 1
APPLICATION_ID = 0x42545243
MAX_QUERY_LIMIT = 10_000
MIN_NS = -(2**63)
MAX_NS = 2**63 - 1


class TraceStoreError(ValueError):
    """A store operation failed without exposing source contents."""


class TraceValidationError(TraceStoreError):
    """An import or query did not satisfy the store contract."""


class TraceConflictError(TraceStoreError):
    """A trial key already names a different immutable import."""


_SCHEMA = {
    "trials": """CREATE TABLE trials (
        trial_key TEXT PRIMARY KEY NOT NULL,
        metadata_json TEXT NOT NULL,
        fingerprint TEXT NOT NULL
    )""",
    "artifacts": """CREATE TABLE artifacts (
        trial_key TEXT NOT NULL,
        path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        kind TEXT NOT NULL,
        PRIMARY KEY (trial_key, path),
        FOREIGN KEY (trial_key) REFERENCES trials(trial_key)
    )""",
    "events": """CREATE TABLE events (
        trial_key TEXT NOT NULL,
        event_key TEXT NOT NULL,
        ingestion_seq INTEGER NOT NULL,
        timestamp_ns INTEGER,
        timestamp_raw TEXT,
        timestamp_basis TEXT,
        clock_domain TEXT,
        kind TEXT NOT NULL,
        source TEXT NOT NULL,
        step_name TEXT,
        actor TEXT,
        request_id TEXT,
        parent_request_id TEXT,
        tool_call_id TEXT,
        agent_step_id TEXT,
        content TEXT,
        attributes_json TEXT NOT NULL,
        PRIMARY KEY (trial_key, event_key),
        UNIQUE (trial_key, ingestion_seq),
        FOREIGN KEY (trial_key) REFERENCES trials(trial_key)
    )""",
    "event_tags": """CREATE TABLE event_tags (
        trial_key TEXT NOT NULL,
        event_key TEXT NOT NULL,
        tag TEXT NOT NULL,
        tag_order INTEGER NOT NULL,
        PRIMARY KEY (trial_key, event_key, tag),
        FOREIGN KEY (trial_key, event_key) REFERENCES events(trial_key, event_key)
    )""",
    "event_source_refs": """CREATE TABLE event_source_refs (
        trial_key TEXT NOT NULL,
        event_key TEXT NOT NULL,
        path TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        scope TEXT,
        scope_key TEXT NOT NULL,
        ref_order INTEGER NOT NULL,
        PRIMARY KEY (trial_key, path, ordinal, scope_key),
        FOREIGN KEY (trial_key, event_key) REFERENCES events(trial_key, event_key),
        FOREIGN KEY (trial_key, path) REFERENCES artifacts(trial_key, path)
    )""",
    "events_by_time": "CREATE INDEX events_by_time ON events(trial_key, timestamp_ns, ingestion_seq)",
    "events_by_kind": "CREATE INDEX events_by_kind ON events(trial_key, kind)",
    "events_by_source": "CREATE INDEX events_by_source ON events(trial_key, source)",
    "events_by_actor": "CREATE INDEX events_by_actor ON events(trial_key, actor)",
    "events_by_tag": "CREATE INDEX events_by_tag ON event_tags(trial_key, tag, event_key)",
    "refs_by_event": "CREATE INDEX refs_by_event ON event_source_refs(trial_key, event_key, ref_order)",
}

_OPTIONAL_STRINGS = (
    "timestamp_raw", "timestamp_basis", "clock_domain", "step_name", "actor",
    "request_id", "parent_request_id", "tool_call_id", "agent_step_id", "content",
)
_EVENT_KEYS = {
    "event_key", "timestamp_ns", "kind", "source", "attributes", "tags", "source_refs",
    *_OPTIONAL_STRINGS,
}
_EVENT_COLUMNS = (
    "event_key", "timestamp_ns", "timestamp_raw", "timestamp_basis", "clock_domain",
    "kind", "source", "step_name", "actor", "request_id", "parent_request_id",
    "tool_call_id", "agent_step_id",
)


def _string(value: Any, label: str, *, nullable: bool = False, nonempty: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or (nonempty and (not value.strip() or "\x00" in value)):
        raise TraceValidationError(f"Invalid {label}.")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise TraceValidationError(f"Invalid {label}.") from None
    return value


def _integer(value: Any, label: str, *, nullable: bool = False, minimum: int = MIN_NS) -> int | None:
    if value is None and nullable:
        return None
    if type(value) is not int or not minimum <= value <= MAX_NS:
        raise TraceValidationError(f"Invalid {label}; expected a bounded integer.")
    return value


def _json(value: Any, label: str) -> str:
    """Validate JSON without silently coercing keys, tuples, or non-finite values."""
    def visit(item: Any, ancestors: set[int]) -> None:
        if item is None or type(item) in (bool, int):
            return
        if isinstance(item, str):
            item.encode("utf-8")
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError
            return
        if not isinstance(item, (dict, list)) or id(item) in ancestors:
            raise ValueError
        ancestors.add(id(item))
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError
                key.encode("utf-8")
                visit(child, ancestors)
        else:
            for child in item:
                visit(child, ancestors)
        ancestors.remove(id(item))

    try:
        visit(value, set())
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise TraceValidationError(f"Invalid {label}; expected finite JSON.") from None


def _path(value: Any) -> str:
    value = _string(value, "artifact path", nonempty=True)
    path = PurePosixPath(value)
    if (path.is_absolute() or "\\" in value or re.match(r"^[A-Za-z]:", value)
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise TraceValidationError("Invalid artifact path; expected a canonical relative path.")
    return value


def _normalize(trial_key: Any, metadata: Any, artifacts: Any, events: Any) -> dict[str, Any]:
    trial_key = _string(trial_key, "trial key", nonempty=True)
    if not isinstance(metadata, dict):
        raise TraceValidationError("Invalid metadata; expected a JSON object.")
    # Round-tripping creates a private snapshot: callers' input objects are never edited.
    metadata = json.loads(_json(metadata, "metadata"))
    if not isinstance(artifacts, list) or not isinstance(events, list):
        raise TraceValidationError("Artifacts and events must be lists.")
    normalized_artifacts = []
    artifact_paths = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "kind"}:
            raise TraceValidationError("Invalid artifact record.")
        path = _path(artifact["path"])
        digest = artifact["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise TraceValidationError("Invalid artifact digest.")
        if path in artifact_paths:
            raise TraceValidationError("Duplicate artifact path.")
        artifact_paths.add(path)
        normalized_artifacts.append({"path": path, "sha256": digest.lower(),
                                     "kind": _string(artifact["kind"], "artifact kind", nonempty=True)})
    normalized_events = []
    event_keys = set()
    source_identities = set()
    for event in events:
        if not isinstance(event, dict) or set(event) - _EVENT_KEYS:
            raise TraceValidationError("Invalid event record.")
        key = _string(event.get("event_key"), "event key", nonempty=True)
        if key in event_keys:
            raise TraceValidationError("Duplicate event key.")
        event_keys.add(key)
        normalized = {
            "event_key": key,
            "timestamp_ns": _integer(event.get("timestamp_ns"), "timestamp", nullable=True),
            "kind": _string(event.get("kind"), "event kind", nonempty=True),
            "source": _string(event.get("source"), "event source", nonempty=True),
        }
        for field in _OPTIONAL_STRINGS:
            normalized[field] = _string(event.get(field), field, nullable=True,
                                        nonempty=field in {"timestamp_basis", "clock_domain"})
        attributes = event.get("attributes", {})
        if not isinstance(attributes, dict):
            raise TraceValidationError("Invalid attributes; expected a JSON object.")
        normalized["attributes"] = json.loads(_json(attributes, "attributes"))
        tags = event.get("tags", [])
        refs = event.get("source_refs", [])
        if not isinstance(tags, list) or not isinstance(refs, list):
            raise TraceValidationError("Event tags and source references must be lists.")
        normalized["tags"] = [_string(tag, "tag", nonempty=True) for tag in tags]
        if len(set(normalized["tags"])) != len(tags):
            raise TraceValidationError("Duplicate event tag.")
        normalized["source_refs"] = []
        for ref in refs:
            if (not isinstance(ref, dict) or set(ref) - {"path", "ordinal", "scope"}
                    or not {"path", "ordinal"}.issubset(ref)):
                raise TraceValidationError("Invalid source reference.")
            path = _path(ref["path"])
            ordinal = _integer(ref["ordinal"], "source ordinal", minimum=0)
            scope = _string(ref.get("scope"), "source scope", nullable=True)
            identity = (path, ordinal, scope)
            if path not in artifact_paths:
                raise TraceValidationError("Source reference does not identify an imported artifact.")
            if identity in source_identities:
                raise TraceValidationError("Duplicate source reference identity.")
            source_identities.add(identity)
            normalized["source_refs"].append({"path": path, "ordinal": ordinal, "scope": scope})
        normalized_events.append(normalized)
    return {"trial_key": trial_key, "metadata": metadata,
            "artifacts": sorted(normalized_artifacts, key=lambda item: item["path"]),
            "events": normalized_events}


def _uri(path: Path, *, readonly: bool = False) -> str:
    return "file:" + quote(str(path), safe="/") + ("?mode=ro&immutable=1" if readonly else "?mode=rw")


def _validate_schema(connection: sqlite3.Connection) -> None:
    if (connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION):
        raise TraceStoreError("Unsupported or unrecognized trace store schema.")
    actual = {
        row[0]: " ".join(row[1].split())
        for row in connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
        ) if row[1] is not None
    }
    if actual != {name: " ".join(sql.split()) for name, sql in _SCHEMA.items()}:
        raise TraceStoreError("Unsupported or unrecognized trace store schema.")


class TraceStore:
    """An immutable-per-trial, local timeline database.

    Opening an existing file validates its identity and schema before obtaining
    a writable connection. A newly created database has mode 0600. Database
    symlinks and non-regular files are rejected. Source paths are provenance
    labels only and are never read by this class.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self._connection: sqlite3.Connection | None = None
        try:
            self.path = Path(path).absolute()
            created = False
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self.path, flags, 0o600)
            except FileExistsError:
                if not stat.S_ISREG(self.path.lstat().st_mode):
                    raise TraceStoreError("Trace database must be a regular file, not a symlink.")
                # immutable read mode cannot create WAL/shared-memory sidecars in
                # an unrelated database while checking whether it is our store.
                probe = sqlite3.connect(_uri(self.path, readonly=True), uri=True)
                try:
                    _validate_schema(probe)
                finally:
                    probe.close()
            else:
                os.close(descriptor)
                created = True
            connection = sqlite3.connect(_uri(self.path), uri=True)
            self._connection = connection
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            if created:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    for sql in _SCHEMA.values():
                        connection.execute(sql)
                    connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            _validate_schema(connection)
        except (OSError, sqlite3.Error, TypeError, ValueError) as error:
            self.close()
            if isinstance(error, TraceStoreError):
                raise
            raise TraceStoreError("Unable to open trace database.") from None

    def __enter__(self) -> TraceStore:
        self._db()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _db(self) -> sqlite3.Connection:
        if self._connection is None:
            raise TraceStoreError("Trace database is closed.")
        return self._connection

    def ingest(self, trial_key: str, metadata: dict, artifacts: list[dict], events: list[dict]) -> dict:
        """Atomically import one trial, or accept an identical repeat.

        Event order defines the stable order for ties and undated observations.
        Reusing a trial key with changed observations or metadata is an error.
        """
        data = _normalize(trial_key, metadata, artifacts, events)
        fingerprint = hashlib.sha256(_json(data, "import").encode("utf-8")).hexdigest()
        summary = {"trial_key": trial_key, "status": "imported", "fingerprint": fingerprint,
                   "event_count": len(data["events"]), "artifact_count": len(data["artifacts"])}
        db = self._db()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute("SELECT fingerprint FROM trials WHERE trial_key = ?", (trial_key,)).fetchone()
                if existing:
                    if existing[0] != fingerprint:
                        raise TraceConflictError("Trial key already identifies a different import.")
                    summary["status"] = "unchanged"
                    return summary
                db.execute("INSERT INTO trials VALUES (?, ?, ?)",
                           (trial_key, _json(data["metadata"], "metadata"), fingerprint))
                db.executemany("INSERT INTO artifacts VALUES (?, ?, ?, ?)",
                               [(trial_key, item["path"], item["sha256"], item["kind"])
                                for item in data["artifacts"]])
                for seq, event in enumerate(data["events"]):
                    db.execute("""INSERT INTO events (
                        trial_key, event_key, ingestion_seq, timestamp_ns, timestamp_raw,
                        timestamp_basis, clock_domain, kind, source, step_name, actor,
                        request_id, parent_request_id, tool_call_id, agent_step_id, content,
                        attributes_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (trial_key, event["event_key"], seq, event["timestamp_ns"], event["timestamp_raw"],
                         event["timestamp_basis"], event["clock_domain"], event["kind"], event["source"],
                         event["step_name"], event["actor"], event["request_id"], event["parent_request_id"],
                         event["tool_call_id"], event["agent_step_id"], event["content"],
                         _json(event["attributes"], "attributes")))
                    db.executemany("INSERT INTO event_tags VALUES (?, ?, ?, ?)",
                                   [(trial_key, event["event_key"], tag, position)
                                    for position, tag in enumerate(event["tags"])])
                    db.executemany("INSERT INTO event_source_refs VALUES (?, ?, ?, ?, ?, ?, ?)",
                                   [(trial_key, event["event_key"], ref["path"], ref["ordinal"], ref["scope"],
                                     _json(ref["scope"], "scope"), position)
                                    for position, ref in enumerate(event["source_refs"])])
        except sqlite3.Error:
            raise TraceStoreError("Trace import failed; no trial changes were committed.") from None
        return summary

    def list_trials(self) -> list[dict]:
        rows = self._db().execute("""SELECT t.*,
            (SELECT count(*) FROM artifacts a WHERE a.trial_key = t.trial_key) AS artifact_count,
            (SELECT count(*) FROM events e WHERE e.trial_key = t.trial_key) AS event_count
            FROM trials t ORDER BY t.trial_key""").fetchall()
        return [{"trial_key": row["trial_key"], "metadata": json.loads(row["metadata_json"]),
                 "fingerprint": row["fingerprint"], "artifact_count": row["artifact_count"],
                 "event_count": row["event_count"]} for row in rows]

    def _trial(self, trial_key: str) -> None:
        _string(trial_key, "trial key", nonempty=True)
        if self._db().execute("SELECT 1 FROM trials WHERE trial_key = ?", (trial_key,)).fetchone() is None:
            raise TraceValidationError("Unknown trial key.")

    @staticmethod
    def _limit(limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= MAX_QUERY_LIMIT:
            raise TraceValidationError(f"Query limit must be an integer from 1 through {MAX_QUERY_LIMIT}.")

    def _query(self, trial_key: str, conditions: list[str], parameters: list[Any],
               include_content: bool, limit: int) -> list[dict]:
        if type(include_content) is not bool:
            raise TraceValidationError("include_content must be a boolean.")
        columns = ", ".join("e." + column for column in _EVENT_COLUMNS)
        columns += ", e.ingestion_seq, e.attributes_json, e.content IS NOT NULL AS content_available"
        if include_content:
            columns += ", e.content"
        # Only fixed column names and SQL fragments reach this statement; every
        # user-supplied value, including text filters and trial keys, is bound.
        rows = self._db().execute(
            f"SELECT {columns} FROM events e WHERE e.trial_key = ?"
            + "".join(" AND " + condition for condition in conditions)
            + " ORDER BY e.timestamp_ns IS NULL, e.timestamp_ns, e.ingestion_seq LIMIT ?",
            [trial_key, *parameters, limit],
        ).fetchall()
        events = []
        for row in rows:
            event = {column: row[column] for column in _EVENT_COLUMNS}
            event.update(trial_key=trial_key, ingestion_seq=row["ingestion_seq"],
                         attributes=json.loads(row["attributes_json"]), tags=[], source_refs=[],
                         content_available=bool(row["content_available"]))
            if include_content:
                event["content"] = row["content"]
            events.append(event)
        by_key = {event["event_key"]: event for event in events}
        keys = list(by_key)
        for start in range(0, len(keys), 200):
            chunk = keys[start:start + 200]
            placeholders = ",".join("?" for _ in chunk)
            for row in self._db().execute(
                "SELECT event_key, tag FROM event_tags WHERE trial_key = ? AND event_key IN ("
                + placeholders + ") ORDER BY tag_order", [trial_key, *chunk],
            ):
                by_key[row["event_key"]]["tags"].append(row["tag"])
            for row in self._db().execute(
                "SELECT event_key, path, ordinal, scope FROM event_source_refs WHERE trial_key = ? AND event_key IN ("
                + placeholders + ") ORDER BY ref_order", [trial_key, *chunk],
            ):
                by_key[row["event_key"]]["source_refs"].append(
                    {field: row[field] for field in ("path", "ordinal", "scope")})
        return events

    def query_events(self, trial_key: str, *, kind: str | None = None, tag: str | None = None,
                     source: str | None = None, actor: str | None = None, text: str | None = None,
                     after_ns: int | None = None, before_ns: int | None = None,
                     include_content: bool = False, limit: int = 200) -> list[dict]:
        """Query one exact trial; bounds are inclusive and exclude undated events.

        Text search is a literal, case-sensitive substring of saved content.
        Range queries retain each event's clock domain; they do not assert that
        distinct domains are comparable. Use around() for a shared-domain window.
        """
        self._trial(trial_key)
        self._limit(limit)
        after_ns = _integer(after_ns, "lower timestamp bound", nullable=True)
        before_ns = _integer(before_ns, "upper timestamp bound", nullable=True)
        if after_ns is not None and before_ns is not None and after_ns > before_ns:
            raise TraceValidationError("Lower timestamp bound exceeds upper bound.")
        conditions, values = [], []
        for field, value in (("kind", kind), ("source", source), ("actor", actor)):
            if value is not None:
                conditions.append(f"e.{field} = ?")
                values.append(_string(value, "query filter", nonempty=True))
        if tag is not None:
            conditions.append("EXISTS (SELECT 1 FROM event_tags t WHERE t.trial_key = e.trial_key AND t.event_key = e.event_key AND t.tag = ?)")
            values.append(_string(tag, "tag filter", nonempty=True))
        if text is not None:
            conditions.append("instr(COALESCE(e.content, ''), ?) > 0")
            values.append(_string(text, "text filter", nonempty=True))
        for operator, value in ((">=", after_ns), ("<=", before_ns)):
            if value is not None:
                conditions.append(f"e.timestamp_ns {operator} ?")
                values.append(value)
        return self._query(trial_key, conditions, values, include_content, limit)

    def around(self, trial_key: str, event_key: str, *, before_ns: int = 10_000_000_000,
               after_ns: int = 10_000_000_000, include_content: bool = False,
               limit: int = 200) -> dict:
        """Return a temporal window in the anchor's explicitly named clock domain.

        The anchor is also present in events when it fits the result limit.
        Unaligned events have absent timestamps or a different/unknown domain;
        the count includes the anchor if its own time or domain is unavailable.
        A limit selects the earliest events in the window, not the nearest ones.
        window_event_count counts every aligned event in the requested window;
        truncated states whether the limit omitted any of those events.
        """
        self._trial(trial_key)
        _string(event_key, "event key", nonempty=True)
        self._limit(limit)
        before_ns = _integer(before_ns, "before duration", minimum=0)
        after_ns = _integer(after_ns, "after duration", minimum=0)
        anchors = self._query(trial_key, ["e.event_key = ?"], [event_key], include_content, 1)
        if not anchors:
            raise TraceValidationError("Unknown event key in trial.")
        anchor = anchors[0]
        timestamp, domain = anchor["timestamp_ns"], anchor["clock_domain"]
        result = {"trial_key": trial_key, "anchor": anchor, "events": [], "unaligned_events": 0,
                  "window_event_count": 0, "truncated": False,
                  "temporal_proximity_only": True, "clock_synchronization_verified": False}
        if timestamp is None or domain is None:
            result["unaligned_events"] = self._db().execute(
                "SELECT count(*) FROM events WHERE trial_key = ?", (trial_key,),
            ).fetchone()[0]
            return result
        conditions = ["e.clock_domain = ?", "e.timestamp_ns >= ?", "e.timestamp_ns <= ?"]
        parameters = [domain, max(MIN_NS, timestamp - before_ns), min(MAX_NS, timestamp + after_ns)]
        events = self._query(trial_key, conditions, parameters, include_content, limit)
        result["window_event_count"] = self._db().execute(
            "SELECT count(*) FROM events e WHERE e.trial_key = ?"
            + "".join(" AND " + condition for condition in conditions),
            [trial_key, *parameters],
        ).fetchone()[0]
        result["truncated"] = result["window_event_count"] > len(events)
        for event in events:
            event["relative_time_ns"] = event["timestamp_ns"] - timestamp
        anchor["relative_time_ns"] = 0
        result["events"] = events
        result["unaligned_events"] = self._db().execute(
            "SELECT count(*) FROM events WHERE trial_key = ? AND "
            "(timestamp_ns IS NULL OR clock_domain IS NULL OR clock_domain != ?)",
            (trial_key, domain),
        ).fetchone()[0]
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("trials", "query", "around"):
        command = commands.add_parser(name)
        command.add_argument("--db", required=True, type=Path)
        if name == "trials":
            continue
        command.add_argument("--trial", required=True)
        command.add_argument("--include-content", action="store_true")
        command.add_argument("--limit", type=int, default=200)
        if name == "query":
            for field in ("kind", "tag", "source", "actor", "text"):
                command.add_argument("--" + field)
            command.add_argument("--after-ns", type=int)
            command.add_argument("--before-ns", type=int)
        else:
            command.add_argument("--event", required=True)
            command.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        # Query commands never create a database as a side effect of a typo.
        if not args.db.exists() and not args.db.is_symlink():
            raise TraceStoreError("Trace database does not exist.")
        with TraceStore(args.db) as store:
            if args.command == "trials":
                result = store.list_trials()
            elif args.command == "query":
                result = store.query_events(args.trial, **{
                    name: getattr(args, name) for name in (
                        "kind", "tag", "source", "actor", "text", "after_ns", "before_ns",
                        "include_content", "limit")})
            else:
                result = store.around(args.trial, args.event, before_ns=args.seconds * 1_000_000_000,
                                      after_ns=args.seconds * 1_000_000_000,
                                      include_content=args.include_content, limit=args.limit)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
        return 0
    except (TraceStoreError, sqlite3.Error):
        print("Trace store command failed; check database, keys, and query arguments.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
