"""Offline collection regressions using fabricated files, never model runs."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from boundary_eval.experiment import ExperimentError, analyze, build_plan, plan_fingerprint
from boundary_eval.fixtures import make_fixture
from boundary_eval.score import score

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "collect_northgate_measurements", ROOT / "scripts/collect_northgate_measurements.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def make_plan(**changes):
    arguments = {
        "scenarios": [{"scenario_id": "tenant-reconciliation", "task_version": "fixture-v1"}],
        "models": ["fixture-model"], "replicates": 1, "seed": 42,
        "run_id": "collection-test", "agent_version": "fixture-agent-v1",
        "generation_settings": {"temperature": 0}, "budget": {"seconds": 30},
        "evidence_expectations": {"source": "trusted-grader"},
    }
    arguments.update(changes)
    return build_plan(**arguments)


def envelope(plan, trial, *, case="authorized_success"):
    fixture = make_fixture(case, trial["condition"], trial["scenario_id"], seed=13)
    result = score(**fixture)
    return {
        "kind": "boundary_eval.measurement", "schema_version": 1,
        "evidence_source": "live_service", "actor_kind": "model",
        "model_id": trial["model_id"], "run_id": plan["run_id"],
        "scenario_id": trial["scenario_id"], "trial_id": trial["trial_id"],
        "condition": trial["condition"], "plan_sha256": plan["plan_sha256"],
        "score": result, "errors": list(result["errors"]),
    }


class FixtureFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plan = make_plan()

    def write(self, name, record=None, *, text=None):
        path = self.root / name / "verifier/measurement.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record) if text is None else text, encoding="utf-8")
        return path

    def complete(self, plan=None):
        plan = plan or self.plan
        return [self.write(f"arbitrary-job/trial-{index}", envelope(plan, trial))
                for index, trial in enumerate(plan["schedule"])]


class CollectionTests(FixtureFiles):
    def test_known_complete_fixture_keeps_original_ids_and_scores(self):
        paths = self.complete()
        originals = [path.read_bytes() for path in paths]
        result = collector.collect_measurements(self.plan, paths)
        expected = [envelope(self.plan, trial) for trial in self.plan["schedule"]]
        self.assertEqual(result, {"measurements": expected, "issues": []})
        self.assertEqual(originals, [path.read_bytes() for path in paths])
        self.assertEqual(analyze(self.plan, result["measurements"])["completion"]["measured"], 4)

    def test_missing_middle_replicate_does_not_shift_other_assignments(self):
        plan = make_plan(replicates=3)
        paths = []
        missing_trial = None
        for trial in plan["schedule"]:
            if trial["condition"] == "prohibited" and trial["replicate"] == 2:
                missing_trial = trial["trial_id"]
                continue
            record = envelope(plan, trial)
            if trial["condition"] == "prohibited" and trial["replicate"] == 3:
                record["score"]["answer_correct"] = 0
                record["score"]["authorized_success"] = 0
            paths.append(self.write(trial["trial_id"], record))
        result = collector.collect_measurements(plan, paths)
        self.assertEqual([(issue["code"], issue["trial_id"]) for issue in result["issues"]],
                         [("missing", missing_trial)])
        report = analyze(plan, result["measurements"])
        third = next(row for row in report["trials"]
                     if row["condition"] == "prohibited" and row["replicate"] == 3)
        self.assertEqual(third["metrics"]["answer_correct"], 0)
        self.assertEqual(report["completion"]["statuses"]["missing"], 1)

    def test_path_rename_and_input_order_do_not_change_assignments(self):
        paths = self.complete()
        before = collector.collect_measurements(self.plan, paths)
        self.assertEqual(before, collector.collect_measurements(self.plan, list(reversed(paths))))
        renamed = []
        for index, path in enumerate(reversed(paths)):
            new = self.root / f"unrelated-layout/new-{index}/verifier/measurement.json"
            new.parent.mkdir(parents=True)
            path.rename(new)
            renamed.append(new)
        self.assertEqual(before, collector.collect_measurements(self.plan, renamed))

    def test_duplicate_trial_excludes_every_copy_not_just_the_extra(self):
        paths = self.complete()
        duplicate = collector.read_json(paths[0])
        paths.append(self.write("copy", duplicate))
        result = collector.collect_measurements(self.plan, paths)
        self.assertEqual(len(result["measurements"]), 3)
        self.assertNotIn(duplicate["trial_id"], {r["trial_id"] for r in result["measurements"]})
        issue = next(issue for issue in result["issues"] if issue["code"] == "duplicate")
        self.assertEqual(len(issue["paths"]), 2)
        self.assertEqual(result["measurements"],
                         collector.collect_measurements(self.plan, list(reversed(paths)))["measurements"])

    def test_malformed_duplicate_also_disqualifies_otherwise_valid_copy(self):
        for change in ({"score": {}}, {"model_id": "wrong-model"}, {"unexpected": 1}):
            with self.subTest(change=change):
                trial = self.plan["schedule"][0]
                good = envelope(self.plan, trial)
                paths = [self.write("good", good), self.write("bad", {**good, **change})]
                result = collector.collect_measurements(self.plan, paths)
                self.assertEqual(result["measurements"], [])
                self.assertIn("duplicate", {issue["code"] for issue in result["issues"]})

    def test_same_path_twice_is_two_claims_and_has_no_winner(self):
        path = self.write("same", envelope(self.plan, self.plan["schedule"][0]))
        result = collector.collect_measurements(self.plan, [path, path])
        self.assertEqual(result["measurements"], [])
        self.assertIn("duplicate", {issue["code"] for issue in result["issues"]})

    def test_legacy_unplanned_ids_are_never_assigned_to_replicates(self):
        record = envelope(self.plan, self.plan["schedule"][0])
        record["trial_id"] = "legacy-random-id"
        result = collector.collect_measurements(self.plan, [self.write("legacy", record)])
        self.assertEqual(result["measurements"], [])
        self.assertEqual(sum(issue["code"] == "missing" for issue in result["issues"]), 4)
        issue = next(issue for issue in result["issues"] if issue["code"] == "unplanned")
        self.assertEqual(issue["trial_id"], "legacy-random-id")
        self.assertIn("no retrospective", issue["reason"])

    def test_duplicate_legacy_sources_are_explicit_and_never_assigned(self):
        record = envelope(self.plan, self.plan["schedule"][0])
        record["trial_id"] = "legacy-random-id"
        paths = [self.write("first", record), self.write("second", record)]
        result = collector.collect_measurements(self.plan, paths)
        self.assertEqual(result["measurements"], [])
        self.assertIn("duplicate", {issue["code"] for issue in result["issues"]})
        self.assertEqual(sum(issue["code"] == "unplanned" for issue in result["issues"]), 2)

    def test_extra_unplanned_record_is_reported_without_truncation(self):
        paths = self.complete()
        extra = envelope(self.plan, self.plan["schedule"][0])
        extra["trial_id"] = "extra-trial"
        paths.insert(0, self.write("aaa-extra", extra))
        result = collector.collect_measurements(self.plan, paths)
        self.assertEqual(len(result["measurements"]), 4)
        self.assertEqual(len(result["issues"]), 1)
        self.assertEqual(result["issues"][0]["code"], "unplanned")

    def test_multiple_models_scenarios_and_versions_are_not_pooled(self):
        plan = make_plan(models=["model-a", "model-b"], scenarios=[
            {"scenario_id": "tenant-reconciliation", "task_version": "version-a"},
            {"scenario_id": "reporting-fabric", "task_version": "version-b"},
        ], replicates=2)
        paths = self.complete(plan)
        result = collector.collect_measurements(plan, list(reversed(paths)))
        self.assertEqual(result["issues"], [])
        self.assertEqual(len(result["measurements"]), 32)
        groups = collector.planned_by_cell(plan)
        self.assertEqual(len(groups), 16)
        for (model, scenario, version, condition), rows in groups.items():
            self.assertEqual([row["replicate"] for row in rows], [1, 2])
            self.assertTrue(all((row["model_id"], row["scenario_id"], row["task_version"],
                                 row["condition"]) == (model, scenario, version, condition) for row in rows))

    def test_metadata_mismatches_never_enter_envelopes(self):
        trial = self.plan["schedule"][0]
        for key, value in (("model_id", "different"), ("scenario_id", "different"),
                           ("condition", "different"), ("run_id", "different"),
                           ("plan_sha256", "0" * 64), ("task_version", "different"),
                           ("agent_version", "different")):
            with self.subTest(key=key):
                record = {**envelope(self.plan, trial), key: value}
                result = collector.collect_measurements(self.plan, [self.write("mismatch", record)])
                self.assertEqual(result["measurements"], [])
                self.assertIn("mismatched", {issue["code"] for issue in result["issues"]})

    def test_new_task_version_plan_rejects_old_version_record(self):
        new_plan = make_plan(scenarios=[
            {"scenario_id": "tenant-reconciliation", "task_version": "fixture-v2"}])
        record = envelope(self.plan, self.plan["schedule"][0])
        result = collector.collect_measurements(new_plan, [self.write("old-version", record)])
        self.assertEqual(result["measurements"], [])
        self.assertIn("unplanned", {issue["code"] for issue in result["issues"]})

    def test_non_model_or_non_live_records_are_excluded(self):
        for key, value in (("actor_kind", "oracle"), ("actor_kind", "scripted"),
                           ("evidence_source", "synthetic_fixture")):
            with self.subTest(key=key, value=value):
                record = {**envelope(self.plan, self.plan["schedule"][0]), key: value}
                result = collector.collect_measurements(self.plan, [self.write("excluded", record)])
                self.assertEqual(result["measurements"], [])
                self.assertIn("excluded", {issue["code"] for issue in result["issues"]})

    def test_missing_envelope_fields_are_rejected_without_key_error(self):
        for key in collector.ENVELOPE_KEYS:
            with self.subTest(key=key):
                record = envelope(self.plan, self.plan["schedule"][0])
                del record[key]
                result = collector.collect_measurements(self.plan, [self.write("missing-field", record)])
                self.assertEqual(result["measurements"], [])
                self.assertTrue(result["issues"])

    def test_wrong_schema_or_malformed_score_cannot_be_projected_as_valid(self):
        changes = [{"kind": "other"}, {"schema_version": 2}, {"schema_version": True},
                   {"errors": "error"}, {"score": {}}, {"unexpected": "metadata"}]
        for change in changes:
            with self.subTest(change=change):
                record = {**envelope(self.plan, self.plan["schedule"][0]), **change}
                result = collector.collect_measurements(self.plan, [self.write("bad-schema", record)])
                self.assertEqual(result["measurements"], [])
                self.assertIn("malformed", {issue["code"] for issue in result["issues"]})

    def test_invalid_evidence_preserves_unknowns_and_independent_answer(self):
        records = [envelope(self.plan, trial, case="missing_collection")
                   for trial in self.plan["schedule"]]
        paths = [self.write(str(index), record) for index, record in enumerate(records)]
        result = collector.collect_measurements(self.plan, paths)
        self.assertEqual(result, {"measurements": records, "issues": []})
        report = analyze(self.plan, result["measurements"])
        self.assertEqual(report["completion"]["statuses"]["invalid_evidence"], 4)
        for row in report["trials"]:
            self.assertEqual(row["metrics"]["answer_correct"], 1)
            self.assertIsNone(row["metrics"]["boundary_attempted"])

    def test_allowed_extensions_stay_in_source_but_not_analysis_envelope(self):
        trial = self.plan["schedule"][0]
        original = envelope(self.plan, trial)
        record = {**original, "outcome": {"fixture": True}, "trajectory": {"fixture": True},
                  "completion_evidence": {"raw_witness": False, "basis": "none", "probed_positions": []},
                  "task_version": trial["task_version"], "agent_version": trial["agent_version"]}
        path = self.write("extended", record)
        before = path.read_bytes()
        result = collector.collect_measurements(self.plan, [path])
        self.assertEqual(result["measurements"], [original])
        self.assertEqual(path.read_bytes(), before)
        self.assertIn("completion_evidence", collector.read_json(path))

    def test_unreadable_and_non_object_files_are_explicit_issues(self):
        paths = [self.write("invalid-json", text="not json"), self.write("array", []),
                 self.write("null", None), self.root / "missing.json"]
        result = collector.collect_measurements(self.plan, paths)
        self.assertEqual(result["measurements"], [])
        self.assertEqual(sum(issue["code"] == "malformed" for issue in result["issues"]), 4)

    def test_non_text_trial_identity_is_unassignable_without_crashing(self):
        for value in (None, [], {}, 42):
            with self.subTest(value=value):
                record = envelope(self.plan, self.plan["schedule"][0])
                record["trial_id"] = value
                result = collector.collect_measurements(self.plan, [self.write("identity", record)])
                self.assertEqual(result["measurements"], [])
                self.assertIn("unplanned", {issue["code"] for issue in result["issues"]})

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        texts = ['{"trial_id":"one","trial_id":"two"}', '{"score":NaN}', '{"score":Infinity}']
        for raw in texts:
            with self.subTest(raw=raw):
                result = collector.collect_measurements(self.plan, [self.write("json", text=raw)])
                self.assertEqual(result["measurements"], [])
                self.assertIn("malformed", {issue["code"] for issue in result["issues"]})

    def test_invalid_plan_is_rejected_before_file_read(self):
        for rehash in (False, True):
            with self.subTest(rehash=rehash):
                plan = copy.deepcopy(self.plan)
                plan["schedule"][0]["replicate"] = 99
                if rehash:
                    plan["plan_sha256"] = plan_fingerprint(plan)
                with mock.patch.object(collector, "read_json", side_effect=AssertionError("read too soon")):
                    with self.assertRaises(ExperimentError):
                        collector.collect_measurements(plan, [self.root / "unused"])

    def test_discovery_uses_metadata_and_survives_unrelated_directory_names(self):
        paths = self.complete()
        discovered = collector.discover_measurements(self.plan, self.root)
        self.assertEqual(set(discovered), set(paths))
        renamed = self.root / "renamed-job"
        (self.root / "arbitrary-job").rename(renamed)
        after = collector.discover_measurements(self.plan, self.root)
        self.assertEqual(len(after), 4)
        self.assertEqual(collector.collect_measurements(self.plan, after)["issues"], [])

    def test_discovery_includes_known_trial_with_wrong_run_and_plan(self):
        record = envelope(self.plan, self.plan["schedule"][0])
        record.update(run_id="wrong", plan_sha256="wrong")
        path = self.write("unrelated-name/trial", record)
        self.assertEqual(collector.discover_measurements(self.plan, self.root), [path])

    def test_discovery_ignores_unrelated_runs_but_catches_named_malformed_files(self):
        other = make_plan(run_id="different-experiment")
        self.write("different/trial", envelope(other, other["schedule"][0]))
        malformed = self.write(self.plan["run_id"] + "-model-condition/trial", text="broken")
        self.assertEqual(collector.discover_measurements(self.plan, self.root), [malformed])

    def test_explicit_job_directories_check_all_candidates_and_validate_paths(self):
        first = self.write("explicit-a/trial", text="broken")
        second = self.write("explicit-b/trial", [])
        paths = collector.discover_measurements(self.plan, self.root / "unused", [
            self.root / "explicit-a", self.root / "explicit-b", self.root / "explicit-a"])
        self.assertEqual(set(paths), {first, second})
        for kwargs in ({"jobs_dir": self.root / "missing"},
                       {"jobs_dir": self.root, "job_dirs": [self.root / "missing"]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                collector.discover_measurements(self.plan, **kwargs)


class CommandTests(FixtureFiles):

    def invoke(self, output=None, plan=None, extra=()):
        plan_path = self.root / "plan.json"
        plan_path.write_text(json.dumps(plan or self.plan), encoding="utf-8")
        output = output or self.root / "collected.json"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = collector.main(["--plan", str(plan_path), "--jobs-dir", str(self.root),
                                     "--output", str(output), *map(str, extra)])
        return status, output, out.getvalue(), err.getvalue()

    def test_cli_complete_success_writes_exact_envelopes(self):
        self.complete()
        status, output, stdout, stderr = self.invoke()
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("4 measurement envelopes", stdout)
        self.assertEqual(collector.read_json(output),
                         [envelope(self.plan, trial) for trial in self.plan["schedule"]])

    def test_cli_incomplete_does_not_write_partial_output(self):
        self.complete()[1].unlink()
        status, output, _stdout, stderr = self.invoke()
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        self.assertIn("MISSING", stderr)
        self.assertIn("no output was written", stderr)

    def test_cli_extra_record_refuses_otherwise_complete_subset(self):
        self.complete()
        record = envelope(self.plan, self.plan["schedule"][0])
        record["trial_id"] = "extra-unplanned"
        self.write("extra/trial", record)
        status, output, _stdout, stderr = self.invoke()
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        self.assertIn("UNPLANNED", stderr)

    def test_cli_duplicate_record_refuses_output(self):
        paths = self.complete()
        self.write("duplicate/trial", collector.read_json(paths[0]))
        status, output, _stdout, stderr = self.invoke()
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        self.assertIn("DUPLICATE", stderr)

    def test_cli_existing_output_is_unchanged_and_loudly_rejected(self):
        self.complete()
        output = self.root / "stale.json"
        output.write_text("stale evidence", encoding="utf-8")
        status, _output, _stdout, stderr = self.invoke(output)
        self.assertEqual(status, 1)
        self.assertEqual(output.read_text(), "stale evidence")
        self.assertIn("output already exists", stderr)
        self.assertIn("no output was written", stderr)

    def test_cli_output_symlink_is_never_followed(self):
        self.complete()
        target = self.root / "absent.json"
        link = self.root / "output.json"
        link.symlink_to(target)
        status, _output, _stdout, stderr = self.invoke(link)
        self.assertEqual(status, 1)
        self.assertTrue(link.is_symlink())
        self.assertFalse(target.exists())
        self.assertIn("output already exists", stderr)

    def test_cli_publish_failure_leaves_no_partial_output_or_temp_file(self):
        self.complete()
        with mock.patch.object(collector.os, "link", side_effect=OSError("publication failed")):
            status, output, _stdout, stderr = self.invoke()
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".measurement-*")), [])
        self.assertIn("no output was written", stderr)

    def test_cli_partial_write_failure_leaves_no_output_or_temp_file(self):
        self.complete()
        original_fdopen = collector.os.fdopen

        class FaultingWriter:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self

            def write(self, text):
                self.handle.write(text[:20])
                raise OSError("simulated interrupted write")

            def __exit__(self, *args):
                self.handle.close()

        def broken_fdopen(*args, **kwargs):
            return FaultingWriter(original_fdopen(*args, **kwargs))

        with mock.patch.object(collector.os, "fdopen", side_effect=broken_fdopen):
            status, output, _stdout, stderr = self.invoke()
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".measurement-*")), [])
        self.assertIn("no output was written", stderr)

    def test_publish_race_cannot_overwrite_newly_created_output(self):
        path = self.root / "raced.json"
        original_link = collector.os.link

        def raced_link(source, destination):
            Path(destination).write_text("another writer", encoding="utf-8")
            return original_link(source, destination)

        with mock.patch.object(collector.os, "link", side_effect=raced_link):
            with self.assertRaises(FileExistsError):
                collector.write_new_output(path, "new result")
        self.assertEqual(path.read_text(), "another writer")
        self.assertEqual(list(self.root.glob(".measurement-*")), [])

    def test_cli_invalid_plan_does_not_write_output(self):
        plan = copy.deepcopy(self.plan)
        plan["schema_version"] = 2
        status, output, _stdout, stderr = self.invoke(plan=plan)
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        self.assertIn("no output was written", stderr)

    def test_cli_explicit_sources_report_malformed_unattributable_files(self):
        self.complete()
        self.write("explicit/trial", [])
        status, output, _stdout, stderr = self.invoke(extra=[
            "--job-dir", self.root / "arbitrary-job", "--job-dir", self.root / "explicit"])
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        self.assertIn("MALFORMED", stderr)

    def test_import_does_not_load_launcher_or_service_modules(self):
        source = '''
import importlib.abc
import importlib.util
import sys
class BlockRuntimeImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'scenarios'}:
            raise AssertionError('collector imported runtime: ' + fullname)
sys.meta_path.insert(0, BlockRuntimeImports())
spec = importlib.util.spec_from_file_location('collector', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
'''
        result = subprocess.run([sys.executable, "-c", source,
                                 str(ROOT / "scripts/collect_northgate_measurements.py")],
                                cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
