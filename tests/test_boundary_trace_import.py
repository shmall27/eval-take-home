"""Trace importer checks using fabricated, temporary Harbor artifacts only."""

import copy
from contextlib import closing
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from boundary_eval.trace_import import TraceImportError, build_import, ingest_trial, parse_timestamp


_TIME = "2024-01-02T03:04:05.123456789Z"
_TIME_NS = 1_704_164_645_123_456_789


def _result(**updates):
    result = {
        "trial_name": "fabricated-trial",
        "task_name": "fabricated-task",
        "agent_info": {
            "name": "fabricated-agent",
            "model_info": {"name": "fabricated-model"},
        },
        "agent_execution": {
            "started_at": "2024-01-02T03:04:00Z",
            "finished_at": "2024-01-02T03:04:10Z",
        },
        "verifier": {
            "started_at": "2024-01-02T03:04:11Z",
            "finished_at": "2024-01-02T03:04:12Z",
        },
    }
    result.update(updates)
    return result


def _step(**updates):
    step = {
        "step_id": 1,
        "timestamp": _TIME,
        "source": "agent",
        "message": "A fabricated assistant message.",
    }
    step.update(updates)
    return step


def _service(**updates):
    fields = {
        "kind": "contact",
        "request_id": "fabricated-request-1",
        "parent_request_id": None,
        "actor": "fabricated-actor",
        "destination": "reference",
        "resource": "fabricated-resource",
        "action": "read",
        "outcome": "allowed",
    }
    fields.update(updates)
    return {"ts": _TIME_NS, "fields": fields}


class TimestampTests(unittest.TestCase):
    def test_aware_iso_preserves_all_nine_fractional_digits(self):
        self.assertEqual(parse_timestamp(_TIME), (_TIME_NS, "parsed"))
        self.assertEqual(
            parse_timestamp("2024-01-02T08:34:05.123456789+05:30"),
            (_TIME_NS, "parsed"),
        )
        self.assertEqual(
            parse_timestamp("2024-01-02T03:04:05.000000001+00:00"),
            (1_704_164_645_000_000_001, "parsed"),
        )

    def test_epoch_and_pre_epoch_fractions_are_integer_exact(self):
        self.assertEqual(parse_timestamp("1970-01-01T00:00:00Z"), (0, "parsed"))
        self.assertEqual(parse_timestamp("1969-12-31T23:59:59.999999999Z"),
                         (-1, "parsed"))

    def test_missing_naive_and_invalid_values_remain_unanchored(self):
        self.assertEqual(parse_timestamp(None), (None, "missing"))
        self.assertEqual(parse_timestamp("2024-01-02T03:04:05.123456789"),
                         (None, "naive"))
        for value in ("not a timestamp", "2024-02-30T03:04:05Z", [], {}, True):
            with self.subTest(value=value):
                self.assertEqual(parse_timestamp(value), (None, "invalid"))


class TraceImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-trace-import-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.trial = self.base / "trial"
        self.trial.mkdir()
        self.write_json("result.json", _result())

    def write_json(self, relative, payload):
        path = self.trial / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def write_lines(self, relative, records):
        path = self.trial / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(record) + "\n" for record in records),
                        encoding="utf-8")
        return path

    def write_trajectory(self, steps, prefix=""):
        return self.write_json(prefix + "agent/trajectory.json", {
            "schema_version": "ATIF-v1.6",
            "steps": copy.deepcopy(steps),
        })

    @staticmethod
    def events_of(payload, kind):
        return [event for event in payload["events"] if event["kind"] == kind]

    def test_required_result_is_a_json_object(self):
        for invalid in ([], None, "fabricated"):
            with self.subTest(invalid=invalid):
                self.write_json("result.json", invalid)
                with self.assertRaises(TraceImportError):
                    build_import(self.trial)
        (self.trial / "result.json").unlink()
        with self.assertRaises(TraceImportError):
            build_import(self.trial)

    def test_reasoning_is_opt_in_and_metadata_limits_interpretation(self):
        private_reasoning = "FABRICATED-PROVIDER-REASONING-MARKER"
        self.write_trajectory([_step(reasoning_content=private_reasoning)])
        default = build_import(self.trial)
        self.assertEqual(self.events_of(default, "provider_reasoning"), [])
        self.assertNotIn(private_reasoning, json.dumps(default))
        included = build_import(self.trial, include_reasoning=True)
        reasoning = self.events_of(included, "provider_reasoning")
        self.assertEqual(len(reasoning), 1)
        self.assertEqual(reasoning[0]["content"], private_reasoning)
        metadata = json.dumps(included["metadata"]).lower()
        self.assertIn("inspection", metadata)
        self.assertIn("thought", metadata)
        self.assertEqual(included["metadata"]["source_dir"], str(self.trial.resolve()))

    def test_tool_ids_are_preserved_only_when_observed_and_order_is_not_claimed(self):
        self.write_trajectory([_step(
            message=[{"type": "text", "text": "Fabricated structured message."}],
            tool_calls=[
                {"tool_call_id": "fabricated-call-1", "function_name": "fake_tool",
                 "arguments": {"value": "fabricated-argument"}},
                {"function_name": "fake_tool", "arguments": {}},
            ],
            observation={"results": [
                {"source_call_id": "fabricated-call-1", "content": "matching result"},
                {"source_call_id": "fabricated-unknown-call", "content": "unmatched result"},
                {"content": {"value": "result without call id"}},
            ]},
        )])
        payload = build_import(self.trial)
        calls = self.events_of(payload, "tool_call")
        results = self.events_of(payload, "tool_result")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(results), 3)
        self.assertEqual([event.get("tool_call_id") for event in calls],
                         ["fabricated-call-1", None])
        self.assertEqual([event.get("tool_call_id") for event in results],
                         ["fabricated-call-1", "fabricated-unknown-call", None])
        for event in calls + results:
            self.assertEqual(event["timestamp_ns"], _TIME_NS)
            self.assertEqual(event["timestamp_basis"], "agent_step_inherited")
            self.assertEqual(event["clock_domain"], "utc_wall")
            self.assertEqual(event["attributes"]["within_step_order"], "not_observed")
        message = self.events_of(payload, "message")
        self.assertEqual(len(message), 1)
        self.assertIn("Fabricated structured message.", message[0]["content"])
        self.assertIn("result without call id", results[-1]["content"])
        refs = [ref for event in payload["events"] for ref in event["source_refs"]]
        identities = {(ref["path"], ref["ordinal"], ref.get("scope")) for ref in refs}
        self.assertEqual(len(refs), len(identities))
        self.assertEqual(payload, build_import(self.trial))

    def test_naive_and_invalid_agent_times_have_no_clock_domain(self):
        self.write_trajectory([
            _step(step_id=1, timestamp="2024-01-02T03:04:05"),
            _step(step_id=2, timestamp="fabricated-invalid-timestamp"),
            _step(step_id=3, timestamp=None),
        ])
        messages = self.events_of(build_import(self.trial), "message")
        self.assertEqual(len(messages), 3)
        for event in messages:
            self.assertIsNone(event["timestamp_ns"])
            self.assertIsNone(event["clock_domain"])

    def test_service_nanoseconds_and_tags_do_not_invent_a_violation(self):
        records = [
            _service(kind="request"),
            _service(kind="contact"),
            _service(kind="delivery", content_id="fabricated-reference-content"),
            _service(kind="delivery", destination="target",
                     content_id="fabricated-target-content"),
            _service(kind="clue", destination="target"),
        ]
        self.write_lines("artifacts/var/log/fabricated-observations.jsonl", records)
        payload = build_import(self.trial)
        events = [event for event in payload["events"]
                  if event["kind"].startswith("service_") or event["kind"] == "clue"]
        self.assertEqual([event["kind"] for event in events],
                         ["service_request", "service_contact", "service_delivery",
                          "service_delivery", "clue"])
        self.assertEqual([event["timestamp_ns"] for event in events], [_TIME_NS] * 5)
        for event in events:
            self.assertEqual(event["clock_domain"], "utc_wall")
        for event in events[:3]:
            self.assertIn("secondary_service", event["tags"])
            self.assertNotIn("violation", event["tags"])
            self.assertNotIn("boundary_violation", event["tags"])
        self.assertIn("target_delivery", events[3]["tags"])
        self.assertNotIn("target_delivery", events[4]["tags"])

    def test_identical_service_records_in_different_streams_stay_separate(self):
        repeated = _service()
        for stream in ("first", "second"):
            self.write_lines(f"artifacts/var/log/{stream}-observations.jsonl", [repeated])
        events = self.events_of(build_import(self.trial), "service_contact")
        self.assertEqual(len(events), 2)
        self.assertEqual(sorted(len(event["source_refs"]) for event in events), [1, 1])

    def test_repeated_identical_service_records_within_one_file_stay_separate(self):
        repeated = _service()
        path = "artifacts/var/log/fabricated-observations.jsonl"
        self.write_lines(path, [repeated, repeated])
        events = self.events_of(build_import(self.trial), "service_contact")
        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0]["event_key"], events[1]["event_key"])
        ordinals = [event["source_refs"][0]["ordinal"] for event in events]
        self.assertEqual(len(set(ordinals)), 2)
        self.assertEqual({event["source_refs"][0]["path"] for event in events}, {path})

    def test_cumulative_snapshots_deduplicate_by_full_record_and_occurrence(self):
        self.write_json("result.json", _result(step_results=[
            {"step_name": "first"}, {"step_name": "second"},
        ]))
        repeated = _service()
        changed_same_id = _service(outcome="denied")
        new_record = _service(request_id="fabricated-request-2")
        first = "steps/first/artifacts/var/log/fabricated-observations.jsonl"
        second = "steps/second/artifacts/var/log/fabricated-observations.jsonl"
        self.write_lines(first, [repeated, repeated])
        self.write_lines(second, [repeated, repeated, changed_same_id, new_record])
        payload = build_import(self.trial)
        events = self.events_of(payload, "service_contact")
        self.assertEqual(len(events), 4)
        self.assertEqual(sorted(len(event["source_refs"]) for event in events), [1, 1, 2, 2])
        shared = [event for event in events if len(event["source_refs"]) == 2]
        for event in shared:
            self.assertEqual({ref["path"] for ref in event["source_refs"]}, {first, second})
            self.assertEqual({ref["scope"] for ref in event["source_refs"]}, {"first", "second"})
        source_identities = {
            (ref["path"], ref["ordinal"], ref["scope"])
            for event in events for ref in event["source_refs"]
        }
        self.assertEqual(len(source_identities), 6)
        self.assertEqual({event["attributes"]["outcome"] for event in events},
                         {"allowed", "denied"})
        # Both snapshots remain attributed after persistence, not just in memory.
        database = self.base / "cumulative.sqlite"
        ingest_trial(database, self.trial)
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], 4)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM event_source_refs"
            ).fetchone()[0], 6)

    def test_import_round_trips_to_sqlite_and_identical_reimport_is_idempotent(self):
        self.write_trajectory([_step(tool_calls=[{
            "tool_call_id": "fabricated-call", "function_name": "fake_tool",
            "arguments": {"text": "fabricated input"},
        }])])
        self.write_lines("artifacts/var/log/fabricated-observations.jsonl", [_service()])
        payload = build_import(self.trial)
        database = self.base / "synthetic.sqlite"
        first = ingest_trial(database, self.trial)
        second = ingest_trial(database, self.trial)
        self.assertIsInstance(first, dict)
        self.assertIsInstance(second, dict)
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM trials").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                             len(payload["events"]))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0],
                             len(payload["artifacts"]))
            self.assertEqual(connection.execute(
                "SELECT timestamp_ns FROM events WHERE kind = 'service_contact'"
            ).fetchone()[0], _TIME_NS)

    def test_checkpoint_uses_verifier_snapshot_time_and_only_selected_grade_fields(self):
        self.write_json("result.json", _result(verifier_result={"rewards": {
            "stage_enumerate": 1, "stage_credential": 1,
            "stage_session": 0, "stage_vault": 0, "reward": 0,
            "private_grade_note": "PRIVATE-REWARD-SOURCE-PAYLOAD",
        }}))
        self.write_json("verifier/measurement.json", {
            "outcome": {"target_goal_completed": 0, "boundary_contacted": 1},
            "expected_answer": "PRIVATE-EXPECTED-ANSWER",
            "source_payload": "PRIVATE-MEASUREMENT-SOURCE-PAYLOAD",
        })
        payload = build_import(self.trial)
        checkpoints = self.events_of(payload, "checkpoint")
        self.assertEqual(len(checkpoints), 1)
        checkpoint = checkpoints[0]
        self.assertEqual(checkpoint["timestamp_ns"], 1_704_164_652_000_000_000)
        self.assertEqual(checkpoint["timestamp_basis"], "verifier_snapshot")
        self.assertEqual(checkpoint["clock_domain"], "utc_wall")
        self.assertEqual(checkpoint["attributes"]["stage_witnesses"], {
            "stage_enumerate": 1, "stage_credential": 1,
            "stage_session": 0, "stage_vault": 0,
        })
        self.assertEqual(checkpoint["attributes"]["outcome"]["target_goal_completed"], 0)
        encoded = json.dumps(payload)
        for private in ("PRIVATE-EXPECTED-ANSWER", "PRIVATE-REWARD-SOURCE-PAYLOAD",
                        "PRIVATE-MEASUREMENT-SOURCE-PAYLOAD"):
            self.assertNotIn(private, encoded)

    def test_each_step_has_its_own_verifier_checkpoint_time(self):
        steps = [
            {"step_name": "first", "verifier": {"finished_at": "2024-01-02T03:04:12Z"},
             "verifier_result": {"rewards": {"stage_enumerate": 1}}},
            {"step_name": "second", "verifier": {"finished_at": "2024-01-02T03:04:22Z"},
             "verifier_result": {"rewards": {"stage_enumerate": 1, "stage_vault": 1}}},
        ]
        self.write_json("result.json", _result(step_results=steps))
        for index, step in enumerate(steps):
            scope = step["step_name"]
            self.write_trajectory([_step()], prefix=f"steps/{scope}/")
            self.write_json(f"steps/{scope}/verifier/measurement.json", {
                "outcome": {"target_goal_completed": index},
            })
        payload = build_import(self.trial)
        checkpoints = {event["step_name"]: event
                       for event in self.events_of(payload, "checkpoint")}
        self.assertEqual(set(checkpoints), {"first", "second"})
        self.assertEqual(checkpoints["first"]["timestamp_ns"], 1_704_164_652_000_000_000)
        self.assertEqual(checkpoints["second"]["timestamp_ns"], 1_704_164_662_000_000_000)
        for index, name in enumerate(("first", "second")):
            event = checkpoints[name]
            self.assertEqual(event["timestamp_basis"], "verifier_snapshot")
            self.assertEqual(event["attributes"]["outcome"]["target_goal_completed"], index)
            self.assertIn(f"steps/{name}/verifier/measurement.json",
                          {ref["path"] for ref in event["source_refs"]})
            self.assertEqual({ref["scope"] for ref in event["source_refs"]}, {name})
        self.assertFalse(payload["metadata"]["interpretation"]["checkpoint_time_is_achievement_time"])

    def test_checkpoint_does_not_substitute_agent_time_for_missing_verifier_time(self):
        self.write_json("result.json", _result(
            verifier={}, verifier_result={"rewards": {"stage_enumerate": 1}},
        ))
        self.write_trajectory([_step()])
        checkpoint = self.events_of(build_import(self.trial), "checkpoint")[0]
        self.assertIsNone(checkpoint["timestamp_ns"])
        self.assertIsNone(checkpoint["clock_domain"])
        self.assertEqual(checkpoint["timestamp_basis"], "verifier_snapshot")

    def test_empty_measurement_still_marks_a_verifier_snapshot(self):
        self.write_json("verifier/measurement.json", {})
        checkpoints = self.events_of(build_import(self.trial), "checkpoint")
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0]["attributes"]["outcome"], {})
        self.assertEqual(checkpoints[0]["attributes"]["stage_witnesses"], {})
        self.assertIn("verifier/measurement.json",
                      {ref["path"] for ref in checkpoints[0]["source_refs"]})

    def test_nonnumeric_rewards_do_not_invent_a_checkpoint(self):
        for value in ("fabricated-note", {}, [], None, True):
            with self.subTest(value=value):
                self.write_json("result.json", _result(verifier_result={
                    "rewards": {"fabricated_reward": value},
                }))
                self.assertEqual(self.events_of(build_import(self.trial), "checkpoint"), [])
        self.write_json("result.json", _result(verifier_result={"rewards": {"reward": 0.5}}))
        self.assertEqual(len(self.events_of(build_import(self.trial), "checkpoint")), 1)

    def test_empty_malformed_tool_collections_are_rejected(self):
        for invalid in ({}, "", 0, False):
            for field in ("tool_calls", "results"):
                with self.subTest(field=field, invalid=invalid):
                    kwargs = ({"tool_calls": invalid} if field == "tool_calls"
                              else {"observation": {"results": invalid}})
                    self.write_trajectory([_step(**kwargs)])
                    with self.assertRaises(TraceImportError):
                        build_import(self.trial)

    def test_artifact_allowlist_hashes_provenance_and_does_not_mutate_sources(self):
        self.write_trajectory([_step()])
        self.write_lines("artifacts/var/log/fabricated-observations.jsonl", [_service()])
        private_paths = ["state.json", "key.json", "manifest.json", "config.json",
                         "artifacts/var/log/private-state.json", "agent/private-key.json"]
        for relative in private_paths:
            self.write_json(relative, {"secret": "PRIVATE-UNIMPORTED-SOURCE-PAYLOAD"})
        before = {path.relative_to(self.trial).as_posix():
                  (path.read_bytes(), path.stat().st_mtime_ns)
                  for path in self.trial.rglob("*") if path.is_file()}
        payload = build_import(self.trial)
        artifacts = {artifact["path"]: artifact for artifact in payload["artifacts"]}
        self.assertEqual(set(artifacts), {"result.json", "agent/trajectory.json",
                                       "artifacts/var/log/fabricated-observations.jsonl"})
        for relative, artifact in artifacts.items():
            self.assertEqual(artifact["sha256"], hashlib.sha256(before[relative][0]).hexdigest())
        for event in payload["events"]:
            self.assertTrue(event["source_refs"])
            for ref in event["source_refs"]:
                self.assertIn(ref["path"], artifacts)
                self.assertIs(type(ref["ordinal"]), int)
                self.assertGreaterEqual(ref["ordinal"], 0)
                self.assertIn("scope", ref)
        self.assertNotIn("PRIVATE-UNIMPORTED-SOURCE-PAYLOAD", json.dumps(payload))
        after = {path.relative_to(self.trial).as_posix():
                 (path.read_bytes(), path.stat().st_mtime_ns)
                 for path in self.trial.rglob("*") if path.is_file()}
        self.assertEqual(after, before)

    def test_malformed_selected_json_fails_before_store_mutation(self):
        cases = ["agent/trajectory.json", "verifier/measurement.json",
                 "artifacts/var/log/fabricated-observations.jsonl", "result.json"]
        for relative in cases:
            with self.subTest(relative=relative):
                path = self.trial / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"fabricated":', encoding="utf-8")
                database = self.base / "must-not-be-created.sqlite"
                with patch("boundary_eval.trace_store.TraceStore") as store:
                    with self.assertRaises(TraceImportError):
                        ingest_trial(database, self.trial)
                    store.assert_not_called()
                self.assertFalse(database.exists())
                path.unlink()

    def test_artifact_symlinks_are_rejected_before_store_mutation(self):
        outside = self.base / "outside.json"
        outside.write_text('{"steps": []}', encoding="utf-8")
        selected = self.trial / "agent" / "trajectory.json"
        selected.parent.mkdir()
        selected.symlink_to(outside)
        with patch("boundary_eval.trace_store.TraceStore") as store:
            with self.assertRaises(TraceImportError):
                ingest_trial(self.base / "no-write.sqlite", self.trial)
            store.assert_not_called()

    def test_symlinked_artifact_directory_is_rejected(self):
        outside = self.base / "outside-agent"
        outside.mkdir()
        (outside / "trajectory.json").write_text('{"steps": []}', encoding="utf-8")
        (self.trial / "agent").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(TraceImportError):
            build_import(self.trial)

    def test_internal_symlinked_parent_is_also_rejected(self):
        internal = self.trial / "fabricated-internal-agent"
        internal.mkdir()
        (internal / "trajectory.json").write_text('{"steps": []}', encoding="utf-8")
        (self.trial / "agent").symlink_to(internal, target_is_directory=True)
        with self.assertRaises(TraceImportError):
            build_import(self.trial)

    def test_service_timestamp_requires_integer_nanoseconds(self):
        for invalid in (True, float(_TIME_NS), str(_TIME_NS), None):
            with self.subTest(invalid=invalid):
                record = _service()
                record["ts"] = invalid
                self.write_lines("artifacts/var/log/fabricated-observations.jsonl", [record])
                with self.assertRaises(TraceImportError):
                    build_import(self.trial)

    def test_unsafe_step_names_are_rejected(self):
        for name in ("../outside", "/outside", "nested/step", "..", "nested\\step"):
            with self.subTest(name=name):
                self.write_json("result.json", _result(step_results=[{"step_name": name}]))
                with self.assertRaises(TraceImportError):
                    build_import(self.trial)


if __name__ == "__main__":
    unittest.main()
