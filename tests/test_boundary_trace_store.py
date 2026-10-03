"""Synthetic offline timeline checks; no real artifacts, models, or services."""

import contextlib
import copy
import io
import json
import math
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from boundary_eval.trace_store import (
    APPLICATION_ID,
    MAX_NS,
    MIN_NS,
    TraceConflictError,
    TraceStore,
    TraceStoreError,
    TraceValidationError,
    main,
)


ARTIFACTS = [
    {"path": "agent/trace.json", "sha256": "a" * 64, "kind": "agent_trace"},
    {"path": "verifier/events.jsonl", "sha256": "b" * 64, "kind": "service_events"},
]
BASE_NS = 1_800_000_000_000_000_000


def event(key, timestamp=BASE_NS, **overrides):
    value = {
        "event_key": key,
        "timestamp_ns": timestamp,
        "timestamp_raw": None if timestamp is None else str(timestamp),
        "timestamp_basis": "agent_step",
        "clock_domain": "utc_wall" if timestamp is not None else None,
        "kind": "assistant_message",
        "source": "agent_trace",
        "step_name": "inspect",
        "actor": "assistant",
        "request_id": None,
        "parent_request_id": None,
        "tool_call_id": None,
        "agent_step_id": key,
        "content": "Synthetic saved output.",
        "attributes": {"fabricated": True},
        "tags": ["analysis"],
        "source_refs": [],
    }
    value.update(overrides)
    return value


class TraceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "traces.sqlite"
        self.store = TraceStore(self.path)
        self.addCleanup(self.store.close)

    def ingest(self, events=None, *, trial="trial-a", metadata=None, artifacts=None):
        return self.store.ingest(
            trial, {"synthetic": True} if metadata is None else metadata,
            copy.deepcopy(ARTIFACTS) if artifacts is None else artifacts,
            [event("one")] if events is None else events,
        )

    def test_ns_precision_stable_ties_and_unknown_times_last(self):
        self.ingest([
            event("unknown-first", None),
            event("later", BASE_NS + 1),
            event("same-first", BASE_NS),
            event("same-second", BASE_NS),
            event("earlier", BASE_NS - 1),
            event("unknown-last", None),
        ])
        rows = self.store.query_events("trial-a")
        self.assertEqual([row["event_key"] for row in rows],
                         ["earlier", "same-first", "same-second", "later", "unknown-first", "unknown-last"])
        self.assertEqual([row["timestamp_ns"] for row in rows[:4]],
                         [BASE_NS - 1, BASE_NS, BASE_NS, BASE_NS + 1])
        self.assertIs(type(rows[0]["timestamp_ns"]), int)
        bounded = self.store.query_events("trial-a", after_ns=BASE_NS, before_ns=BASE_NS)
        self.assertEqual([row["event_key"] for row in bounded], ["same-first", "same-second"])
        self.assertEqual(len(self.store.query_events("trial-a", before_ns=MAX_NS)), 4)

    def test_cross_trial_isolation_for_all_filters_and_anchor(self):
        self.ingest([event("one", tags=["shared"], content="trial a token")])
        self.ingest([event("one", tags=["shared"], content="trial b token"),
                     event("b-only")], trial="trial-b")
        rows = self.store.query_events("trial-a", kind="assistant_message", source="agent_trace",
                                       actor="assistant", tag="shared", text="token", include_content=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["content"], "trial a token")
        self.assertEqual(self.store.query_events("trial-a", text="trial b"), [])
        self.assertEqual(len(self.store.around("trial-a", "one")["events"]), 1)
        with self.assertRaises(TraceValidationError):
            self.store.around("trial-a", "b-only")
        with self.assertRaises(TraceValidationError):
            self.store.query_events("trial-%")
        self.assertEqual([row["trial_key"] for row in self.store.list_trials()], ["trial-a", "trial-b"])

    def test_text_and_content_opt_in_are_independent(self):
        self.ingest([event("private", content="synthetic %_ ' ? token\x00", tags=["analysis", "checkpoint"]),
                     event("absent", content=None), event("empty", content="")])
        rows = self.store.query_events("trial-a", text="%_ ' ?")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["content_available"])
        self.assertNotIn("content", rows[0])
        self.assertEqual(self.store.query_events("trial-a", text="SYNTHETIC"), [])
        full = self.store.query_events("trial-a", include_content=True)
        self.assertEqual(full[0]["content"], "synthetic %_ ' ? token\x00")
        self.assertEqual([row["content_available"] for row in full], [True, False, True])
        self.assertEqual(full[1]["content"], None)
        self.assertEqual(full[2]["content"], "")
        self.assertEqual(len(self.store.query_events("trial-a", tag="checkpoint")), 1)
        self.assertEqual(self.store.query_events("trial-a", tag="check"), [])
        self.assertNotIn("content", self.store.around("trial-a", "private")["anchor"])

    def test_explicit_ids_attributes_and_source_references_are_exact(self):
        refs = [
            {"path": "agent/trace.json", "ordinal": 0, "scope": None},
            {"path": "agent/trace.json", "ordinal": 0, "scope": "null"},
            {"path": "verifier/events.jsonl", "ordinal": 4, "scope": "first"},
        ]
        self.ingest([event("tool", kind="tool_result", actor="tool", source="service_event",
                           request_id="r", parent_request_id="parent", tool_call_id="tc", agent_step_id="s",
                           timestamp_basis="service_event", timestamp_raw="2027-01-15T08:00:00.000000000Z",
                           source_refs=refs, attributes={"json_pointer": "/steps/0", "nested": [1, None, True]})])
        row = self.store.query_events("trial-a")[0]
        self.assertEqual(row["source_refs"], refs)
        self.assertEqual((row["request_id"], row["parent_request_id"], row["tool_call_id"], row["agent_step_id"]),
                         ("r", "parent", "tc", "s"))
        self.assertEqual(row["attributes"], {"json_pointer": "/steps/0", "nested": [1, None, True]})
        self.assertEqual(row["timestamp_basis"], "service_event")
        self.assertEqual(row["timestamp_raw"], "2027-01-15T08:00:00.000000000Z")
        self.assertEqual(row["clock_domain"], "utc_wall")

    def test_around_uses_exact_offsets_and_same_clock_domain(self):
        self.ingest([
            event("earlier", BASE_NS - 10), event("anchor"), event("later", BASE_NS + 10),
            event("outside", BASE_NS + 11), event("unknown", None),
            event("other-clock", BASE_NS, clock_domain="monotonic_service"),
            event("no-domain", BASE_NS, clock_domain=None),
        ])
        result = self.store.around("trial-a", "anchor", before_ns=10, after_ns=10)
        self.assertEqual([row["event_key"] for row in result["events"]], ["earlier", "anchor", "later"])
        self.assertEqual([row["relative_time_ns"] for row in result["events"]], [-10, 0, 10])
        self.assertEqual(result["anchor"]["relative_time_ns"], 0)
        self.assertEqual(result["unaligned_events"], 3)
        self.assertEqual(result["window_event_count"], 3)
        self.assertFalse(result["truncated"])
        self.assertTrue(result["temporal_proximity_only"])
        self.assertFalse(result["clock_synchronization_verified"])
        unknown = self.store.around("trial-a", "unknown")
        self.assertEqual(unknown["events"], [])
        self.assertEqual(unknown["unaligned_events"], 7)
        self.assertEqual(unknown["window_event_count"], 0)
        self.assertFalse(unknown["truncated"])
        self.assertNotIn("relative_time_ns", unknown["anchor"])
        self.assertEqual(len(self.store.around("trial-a", "anchor", limit=2)["events"]), 2)

    def test_around_reports_dense_window_truncation_even_when_anchor_is_omitted(self):
        self.ingest([
            event("boundary-before", BASE_NS - 3), event("early-one", BASE_NS - 2),
            event("early-two", BASE_NS - 1), event("anchor"), event("boundary-after", BASE_NS + 3),
            event("outside-before", BASE_NS - 4), event("outside-after", BASE_NS + 4),
            event("different-clock", BASE_NS, clock_domain="other"), event("undated", None),
        ])
        self.ingest([event("anchor"), event("unrelated")], trial="trial-b")
        result = self.store.around("trial-a", "anchor", before_ns=3, after_ns=3, limit=2)
        self.assertEqual([row["event_key"] for row in result["events"]], ["boundary-before", "early-one"])
        self.assertEqual(result["anchor"]["event_key"], "anchor")
        self.assertEqual(result["window_event_count"], 5)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["unaligned_events"], 2)
        complete = self.store.around("trial-a", "anchor", before_ns=3, after_ns=3, limit=5)
        self.assertEqual(complete["window_event_count"], len(complete["events"]))
        self.assertEqual(complete["window_event_count"], 5)
        self.assertFalse(complete["truncated"])

    def test_signed_integer_endpoints_and_saturated_windows(self):
        self.ingest([event("minimum", MIN_NS), event("maximum", MAX_NS)])
        self.assertEqual(self.store.around("trial-a", "minimum")["events"][0]["timestamp_ns"], MIN_NS)
        self.assertEqual(self.store.around("trial-a", "maximum")["events"][0]["timestamp_ns"], MAX_NS)

    def test_idempotence_conflict_and_input_immutability(self):
        metadata = {"config": {"synthetic": True}, "settings": ["one"]}
        events = [event("one", source_refs=[{"path": "agent/trace.json", "ordinal": 0, "scope": None}])]
        artifacts = copy.deepcopy(ARTIFACTS)
        original = copy.deepcopy((metadata, artifacts, events))
        first = self.store.ingest("trial-a", metadata, artifacts, events)
        second = self.store.ingest("trial-a", metadata, artifacts, events)
        self.assertEqual(first["status"], "imported")
        self.assertEqual(second["status"], "unchanged")
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual((metadata, artifacts, events), original)
        metadata["settings"].append("changed-config-marker")
        with self.assertRaises(TraceConflictError) as raised:
            self.store.ingest("trial-a", metadata, artifacts, events)
        self.assertNotIn("changed-config-marker", str(raised.exception))
        with self.assertRaises(TraceConflictError):
            self.store.ingest("trial-a", original[0], artifacts, [event("one", content="changed")])
        self.assertEqual(len(self.store.query_events("trial-a")), 1)
        self.assertEqual(self.store.list_trials()[0]["metadata"], original[0])
        self.store.close()
        with TraceStore(self.path) as reopened:
            self.assertEqual(reopened.ingest("trial-a", *original)["status"], "unchanged")

    def test_duplicate_event_keys_reject_entire_new_import(self):
        self.ingest()
        with self.assertRaises(TraceValidationError):
            self.ingest([event("same"), event("same")], trial="invalid")
        self.assertEqual([row["trial_key"] for row in self.store.list_trials()], ["trial-a"])

    def test_sql_failure_rolls_back_trial_artifacts_events_and_tags(self):
        # A synthetic SQLite limit failure occurs after the trial/artifact inserts
        # and first event insert, exercising rollback rather than prevalidation.
        self.store._db().setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8_000)
        with self.assertRaises(TraceStoreError):
            self.ingest([event("first"), event("too-big", content="x" * 20_000)])
        self.assertEqual(self.store.list_trials(), [])
        for table in ("trials", "artifacts", "events", "event_tags", "event_source_refs"):
            self.assertEqual(self.store._db().execute("SELECT count(*) FROM " + table).fetchone()[0], 0)

    def test_malformed_refs_and_duplicate_identity_are_rejected(self):
        invalid = [
            [{"path": "missing.json", "ordinal": 0}],
            [{"path": "agent/trace.json", "ordinal": -1}],
            [{"path": "agent/trace.json", "ordinal": True}],
            [{"path": "agent/trace.json", "ordinal": 2**63}],
            [{"path": "agent/trace.json", "ordinal": 0, "unexpected": "private-marker"}],
            [{"path": "agent/trace.json", "ordinal": 0}, {"path": "agent/trace.json", "ordinal": 0, "scope": None}],
        ]
        for refs in invalid:
            with self.subTest(refs=refs), self.assertRaises(TraceValidationError) as raised:
                self.ingest([event("one", source_refs=refs)])
            self.assertNotIn("private-marker", str(raised.exception))
        same_ref = [{"path": "agent/trace.json", "ordinal": 0}]
        with self.assertRaises(TraceValidationError):
            self.ingest([event("one", source_refs=same_ref), event("two", source_refs=same_ref)])
        self.assertEqual(self.store.list_trials(), [])

    def test_validation_of_json_keys_timestamps_and_limits(self):
        for timestamp in (True, 1.2, "1", MIN_NS - 1, MAX_NS + 1):
            with self.subTest(timestamp=timestamp), self.assertRaises(TraceValidationError):
                self.ingest([event("one", timestamp)])
        for value in (math.nan, math.inf, -math.inf, (1, 2), {1: "coerced-key"}):
            with self.subTest(value=value), self.assertRaises(TraceValidationError):
                self.ingest(metadata={"private-marker": value})
            with self.subTest(value=value), self.assertRaises(TraceValidationError):
                self.ingest([event("one", attributes={"private-marker": value})])
        recursive = {}
        recursive["self"] = recursive
        with self.assertRaises(TraceValidationError):
            self.ingest(metadata=recursive)
        for key in ("", " ", None):
            with self.subTest(key=key), self.assertRaises(TraceValidationError):
                self.ingest(trial=key)
            with self.subTest(key=key), self.assertRaises(TraceValidationError):
                self.ingest([event(key)])
        self.ingest()
        for limit in (0, -1, 10_001, True, 1.2):
            with self.subTest(limit=limit), self.assertRaises(TraceValidationError):
                self.store.query_events("trial-a", limit=limit)
            with self.subTest(limit=limit), self.assertRaises(TraceValidationError):
                self.store.around("trial-a", "one", limit=limit)
        with self.assertRaises(TraceValidationError):
            self.store.query_events("trial-a", after_ns=1, before_ns=0)
        with self.assertRaises(TraceValidationError):
            self.store.query_events("trial-a", include_content="yes")
        with self.assertRaises(TraceValidationError):
            self.store.around("trial-a", "one", before_ns=-1)

    def test_reject_invalid_artifacts_without_reading_provenance_paths(self):
        for path in ("../outside", "/absolute", "./trace", "a//trace", "a/../trace", "a\\trace", "C:/trace", "trace/"):
            with self.subTest(path=path), self.assertRaises(TraceValidationError):
                self.ingest(artifacts=[dict(ARTIFACTS[0], path=path)])
        with self.assertRaises(TraceValidationError):
            self.ingest(artifacts=[dict(ARTIFACTS[0], sha256="secret-marker")])
        with self.assertRaises(TraceValidationError):
            self.ingest(artifacts=[ARTIFACTS[0], ARTIFACTS[0]])
        with patch.object(Path, "read_bytes", side_effect=AssertionError("must not open artifacts")), \
                patch.object(Path, "read_text", side_effect=AssertionError("must not open artifacts")):
            self.ingest([event("one", source_refs=[{"path": "agent/trace.json", "ordinal": 0}])])
            self.store.query_events("trial-a")
        self.assertFalse((self.path.parent / "agent").exists())

    def test_db_permissions_foreign_keys_context_and_reopen(self):
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(self.store._db().execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(self.store._db().execute("PRAGMA application_id").fetchone()[0], APPLICATION_ID)
        self.ingest()
        with TraceStore(self.path) as reopened:
            self.assertEqual(len(reopened.query_events("trial-a")), 1)
        with self.assertRaises(TraceStoreError):
            reopened.list_trials()
        reopened.close()

    def test_database_symlinks_and_arbitrary_databases_are_not_modified(self):
        link = self.path.parent / "link.sqlite"
        link.symlink_to(self.path)
        before = self.path.read_bytes()
        with self.assertRaises(TraceStoreError):
            TraceStore(link)
        self.assertEqual(before, self.path.read_bytes())
        missing_link = self.path.parent / "broken.sqlite"
        missing_link.symlink_to(self.path.parent / "absent.sqlite")
        with self.assertRaises(TraceStoreError):
            TraceStore(missing_link)
        self.assertFalse((self.path.parent / "absent.sqlite").exists())
        arbitrary = self.path.parent / "arbitrary.sqlite"
        with contextlib.closing(sqlite3.connect(arbitrary)) as foreign, foreign:
            foreign.execute("CREATE TABLE unrelated (secret TEXT)")
            foreign.execute("INSERT INTO unrelated VALUES ('private-marker')")
        before = arbitrary.read_bytes()
        inventory = sorted(path.name for path in self.path.parent.iterdir())
        with self.assertRaises(TraceStoreError) as raised:
            TraceStore(arbitrary)
        self.assertNotIn("private-marker", str(raised.exception))
        self.assertEqual(arbitrary.read_bytes(), before)
        self.assertEqual(sorted(path.name for path in self.path.parent.iterdir()), inventory)

    def test_existing_unsupported_or_altered_schema_is_not_migrated(self):
        self.store.close()
        with contextlib.closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("PRAGMA user_version = 999")
        before = self.path.read_bytes()
        with self.assertRaises(TraceStoreError):
            TraceStore(self.path)
        self.assertEqual(before, self.path.read_bytes())
        with contextlib.closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("PRAGMA user_version = 1")
            connection.execute("CREATE TABLE unexpected (x TEXT)")
        before = self.path.read_bytes()
        with self.assertRaises(TraceStoreError):
            TraceStore(self.path)
        self.assertEqual(before, self.path.read_bytes())

    def invoke(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main(list(args))
        return code, output.getvalue(), error.getvalue()

    def test_cli_queries_default_to_no_content_and_preserve_ns(self):
        self.ingest([event("one", BASE_NS + 1)])
        code, output, error = self.invoke("query", "--db", str(self.path), "--trial", "trial-a", "--text", "saved")
        self.assertEqual((code, error), (0, ""))
        row = json.loads(output)[0]
        self.assertEqual(row["timestamp_ns"], BASE_NS + 1)
        self.assertNotIn("content", row)
        code, output, error = self.invoke("around", "--db", str(self.path), "--trial", "trial-a", "--event", "one",
                                          "--seconds", "0", "--include-content")
        self.assertEqual((code, error), (0, ""))
        result = json.loads(output)
        self.assertEqual(result["anchor"]["content"], "Synthetic saved output.")
        self.assertEqual(len(result["events"]), 1)
        code, output, error = self.invoke("trials", "--db", str(self.path))
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)[0]["event_count"], 1)

    def test_cli_invalid_inputs_do_not_create_database_or_leak_values(self):
        missing = self.path.parent / "missing.sqlite"
        code, output, error = self.invoke("trials", "--db", str(missing))
        self.assertEqual((code, output), (1, ""))
        self.assertFalse(missing.exists())
        self.ingest()
        code, output, error = self.invoke("query", "--db", str(self.path), "--trial", "private-marker")
        self.assertEqual((code, output), (1, ""))
        self.assertNotIn("private-marker", error)
        code, output, _ = self.invoke("around", "--db", str(self.path), "--trial", "trial-a", "--event", "one",
                                       "--seconds", "-1")
        self.assertEqual((code, output), (1, ""))


if __name__ == "__main__":
    unittest.main()
