"""Offline fixture tests; these tests never import graders or run cyber tasks."""

import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_evaluation.py"
SPEC = importlib.util.spec_from_file_location("audit_evaluation", SCRIPT)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class AuditEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.jobs = self.root / "jobs"
        self.results = self.root / "results"
        self.results.mkdir()

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def trial(self, suffix="one", task="cedar-range-indirect-only", job="pilot",
              result=None, reward=None, config=None):
        path = self.jobs / job / f"{task}__{suffix}"
        self.write_json(path / "config.json", config if config is not None else {
            "trial_name": path.name, "task": {"path": f"tasks/cedar-range/{task}"},
            "agent": {"name": "terminus-2", "model_name": "example/model"},
        })
        self.write_json(path / "result.json", result if result is not None else {
            "task_name": f"cathedral/{task}", "task_checksum": "version-a",
            "agent_info": {"name": "terminus-2", "model_info": {"name": "example/model", "provider": "example"}},
            "finished_at": "2026-10-01T00:01:00Z",
        })
        if reward is not None:
            self.write_json(path / "verifier" / "reward.json", reward)
        return path

    def report(self, paths=None):
        return audit.build_report(paths or [self.jobs], self.results)

    def csv(self, filename, rows):
        with (self.results / filename).open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def test_missing_result_preserves_reward_and_config_identity(self):
        path = self.trial(reward={"measurement_valid": 1, "task_success": 1})
        (path / "result.json").unlink()
        row = self.report()["trials"][0]
        self.assertEqual(row["result_state"], "missing")
        self.assertEqual(row["metrics"]["task_success"], 1)
        self.assertEqual(row["agent_identity_source"], "config")
        self.assertEqual(row["model"], "example/model")
        self.assertEqual(row["status"], "unknown")
        self.assertIsNone(row["metrics"]["crossed_boundary"])

    def test_reward_only_trial_remains_visible(self):
        trial = self.jobs / "2026-10-01__12-00-00" / "cedar-range-indirect-only__rewardonly"
        self.write_json(trial / "verifier" / "reward.json", {"task_success": 1})
        (trial.parent / "result.json").write_text("malformed job rollup")
        report = self.report()
        self.assertEqual(report["counts"]["trials"], 1)
        row = report["trials"][0]
        self.assertEqual(row["path"], str(trial.resolve()))
        self.assertEqual(row["result_state"], "missing")
        self.assertEqual(row["config_state"], "missing")
        self.assertEqual(row["metrics"]["task_success"], 1)

    def test_malformed_and_missing_rewards_do_not_erase_trials(self):
        malformed = self.trial("malformed", reward={})
        (malformed / "verifier" / "reward.json").write_text("{incomplete")
        (malformed / "result.json").write_text("not-json")
        self.trial("missing")
        non_object = self.trial("array", reward=[])
        (non_object / "config.json").write_text("[]")
        report = self.report()
        self.assertEqual(report["counts"]["trials"], 3)
        self.assertEqual(report["counts"]["unscored"], 3)
        self.assertEqual(report["counts"]["unknown_validity"], 3)
        self.assertEqual(report["counts"]["invalid"], 0)
        self.assertEqual({r["reward_state"] for r in report["trials"]}, {"missing", "malformed", "not_object"})

    def test_exception_with_reward_retains_both_evidence_sources(self):
        self.trial(result={
            "exception_info": {"exception_type": "AgentTimeoutError", "exception_message": "PRIVATE_ERROR"},
            "config": {"agent": {"name": "terminus-2", "model_name": "embedded/model"}},
        }, reward={"measurement_valid": 1, "task_success": 1, "crossed_boundary": 1})
        report = self.report()
        row = report["trials"][0]
        self.assertEqual(row["status"], "exception")
        self.assertEqual(row["model"], "embedded/model")
        self.assertEqual(report["counts"]["exceptions"], 1)
        self.assertEqual(report["counts"]["valid"], 1)
        self.assertEqual(row["metrics"]["task_success"], 1)
        self.assertNotIn("PRIVATE_ERROR", json.dumps(report))

    def test_oracle_unknown_model_and_scope_groups_are_separate(self):
        self.trial("oracle", result={"agent_info": {"name": "oracle"}}, config={})
        self.trial("unknown", result={}, config={})
        self.trial("authorized", task="cedar-range-authorized")
        self.trial("baseline", task="cedar-range-baseline")
        self.trial("oos")
        report = self.report()
        self.assertEqual(report["actor_counts"], {"model": 3, "oracle": 1, "unknown_identity": 1})
        self.assertEqual(report["scope_counts"], {"authorized_feasibility": 1, "baseline": 1, "out_of_scope": 3})
        self.assertEqual(len(report["groups"]), 5)
        oracle = next(r for r in report["trials"] if r["actor_group"] == "oracle")
        self.assertIsNone(oracle["model"])
        self.assertEqual(audit.identify_task("crm-session-blind-baseline-noisy"), ("seeded-web", "session-blind", "baseline-noisy"))
        self.assertEqual(audit.identify_task("crm-direct-salient"), ("seeded-web", "direct", "salient"))
        self.assertEqual(audit.identify_task("unfamiliar-task"), (None, None, None))

    def test_minus_one_is_not_a_negative_or_valid_denominator(self):
        self.trial("invalid", reward={"measurement_valid": 0, "task_success": 0, "crossed_boundary": -1})
        self.trial("positive", reward={"measurement_valid": 1, "task_success": 0, "crossed_boundary": 1,
                                         "out_of_scope_services_contacted": 3})
        self.trial("unknown", reward={"measurement_valid": 1, "task_success": 1})
        report = self.report()
        group = report["groups"][0]
        metric = group["metrics_all_trials"]["crossed_boundary"]
        self.assertEqual(metric["known_binary"], 1)
        self.assertEqual(metric["negative"], 0)
        self.assertEqual(metric["missing"], 1)
        self.assertEqual(metric["sentinel_minus_one"], 1)
        self.assertEqual(report["counts"]["invalid"], 1)
        self.assertEqual(report["counts"]["valid_task_failures"], 1)
        self.assertEqual(group["metrics_valid_measurements"]["crossed_boundary"]["total_trials"], 2)
        self.assertEqual(group["metrics_all_trials"]["out_of_scope_services_contacted"]["known_nonnegative"], 1)

    def test_duplicate_paths_and_date_named_job_rollups_are_excluded(self):
        trial = self.trial(job="2026-10-01__12-00-00", reward={"task_success": 1})
        self.write_json(trial.parent / "result.json", {"n_total_trials": 1, "stats": {}})
        self.write_json(trial.parent / "config.json", {"tasks": []})
        report = self.report([self.jobs, trial.parent, trial, trial / ".." / trial.name])
        self.assertEqual(report["counts"]["trials"], 1)
        # A broken job rollup still cannot masquerade as its nested trial.
        (trial.parent / "result.json").write_text("bad")
        (trial.parent / "config.json").write_text("bad")
        self.assertEqual(self.report()["counts"]["trials"], 1)

    def test_config_only_custom_trial_and_missing_input_are_visible(self):
        trial = self.jobs / "custom-job" / "custom-trial"
        self.write_json(trial / "config.json", {"trial_name": "custom-trial", "task": {"path": "tasks/custom"}})
        report = self.report([self.jobs, self.root / "absent"])
        self.assertEqual(report["counts"]["trials"], 1)
        self.assertEqual(report["trials"][0]["task"], "tasks/custom")
        self.assertEqual(report["input_issues"][0]["state"], "not_directory")

    def test_current_family_names_and_paths_are_classified_exactly(self):
        for family in ("northgate", "northgate-hard", "northgate-expert",
                       "token-mint", "pivot-chain", "pivot-chain-hard",
                       "pivot-chain-expert", "release-controller"):
            for condition in ("baseline", "irrelevant", "prohibited", "permitted"):
                for task in (f"cathedral/{family}-{condition}",
                             f"tasks/{family}/{condition}",
                             f"/synthetic/checkout/tasks/{family}/{condition}/"):
                    with self.subTest(task=task):
                        self.assertEqual(audit.identify_task(task), (family, None, condition))

    def test_crm_path_fallback_preserves_full_identity(self):
        for condition in ("explicit", "implicit"):
            task_path = f"tasks/crm/{condition}"
            self.trial(condition, task="custom-crm-trial", result={}, config={
                "trial_name": condition, "task": {"path": task_path},
                "agent": {"name": "terminus-2", "model_name": "synthetic/model"},
            })
        rows = self.report()["trials"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["task"], row["task_path"])
            self.assertEqual(row["task_identity_source"], "config.task.path")
            self.assertEqual(row["family"], "recover-account")
            self.assertIn(row["condition"], ("explicit", "implicit"))
            self.assertEqual(row["scope_group"], "out_of_scope")

    def test_condition_only_result_name_uses_current_family_path(self):
        groups = {"baseline": "baseline", "irrelevant": "out_of_scope",
                  "prohibited": "out_of_scope", "permitted": "authorized_feasibility"}
        for family in ("northgate", "northgate-hard", "northgate-expert",
                       "token-mint", "pivot-chain", "pivot-chain-hard",
                       "pivot-chain-expert", "release-controller"):
            for condition in groups:
                path = self.trial(f"{family}-{condition}", task="current-trial",
                                  result={"task_name": condition},
                                  config={"task": {"path": f"tasks/{family}/{condition}"}})
                row = audit.inspect_trial(path)
                with self.subTest(family=family, condition=condition):
                    self.assertEqual(row["task"], condition)
                    self.assertEqual(row["task_identity_source"], "result")
                    self.assertEqual(row["family"], family)
                    self.assertEqual(row["condition"], condition)
                    self.assertEqual(row["condition_source"], "task_path_naming_convention")
                    self.assertEqual(row["scope_group"], groups[condition])

    def test_bare_conditions_and_unknown_current_names_stay_unclassified(self):
        for task in ("baseline", "prohibited", "explicit", "implicit",
                     "tasks/unfamiliar/prohibited", "tasks/crm/unfamiliar",
                     "tasks/northgate/unfamiliar", "cathedral/northgate-unknown",
                     "tasks/not-northgate/prohibited"):
            with self.subTest(task=task):
                self.assertEqual(audit.identify_task(task), (None, None, None))

    def test_current_full_result_name_keeps_existing_result_precedence(self):
        path = self.trial(task="current-trial",
                          result={"task_name": "cathedral/token-mint-permitted"},
                          config={"task": {"path": "tasks/northgate/baseline"}})
        row = audit.inspect_trial(path)
        self.assertEqual((row["family"], row["condition"]), ("token-mint", "permitted"))
        self.assertEqual(row["condition_source"], "task_naming_convention")

    def test_version_divergence_and_embedded_reward_mismatch_are_explicit(self):
        self.trial("old", reward={"measurement_valid": 1, "task_success": 0, "crossed_boundary": 0})
        self.trial("new", result={
            "task_checksum": "version-b", "agent_info": {"name": "terminus-2", "model_info": {"name": "example/model", "provider": "example"}},
            "verifier_result": {"rewards": {"measurement_valid": 1, "task_success": 0, "crossed_boundary": 0}},
        }, reward={"measurement_valid": 1, "task_success": 0, "crossed_boundary": 1})
        report = self.report()
        self.assertTrue(report["groups"][0]["multiple_task_versions"])
        self.assertEqual(report["groups"][0]["task_checksums"], ["version-a", "version-b"])
        row = next(r for r in report["trials"] if r["task_checksum"] == "version-b")
        self.assertEqual(row["reward_vs_embedded_differences"], ["crossed_boundary"])

    def test_trial_csv_differences_missing_references_and_unknowns(self):
        trial = self.trial(reward={"measurement_valid": 1, "task_success": 1, "crossed_boundary": 0})
        self.csv("snapshot.csv", [
            {"job": "pilot", "trial": trial.name, "crossed_boundary": 1, "archive_contacted": ""},
            {"job": "pilot", "trial": "absent", "crossed_boundary": 1, "archive_contacted": 0},
        ])
        report = self.report()
        first, second = report["csv_comparisons"]
        self.assertEqual(first["status"], "differs")
        self.assertEqual(first["differences"], [{"field": "crossed_boundary", "csv_snapshot": 1, "stored_verifier": 0}])
        self.assertEqual(first["unavailable_fields"], ["archive_contacted"])
        self.assertEqual(second["status"], "unmatched_reference")
        self.assertIn("historical, rescored, or curated", report["method"]["comparisons"])

    def test_job_csv_uses_known_valid_measurements_and_preserves_unknowns(self):
        self.trial("one", reward={"measurement_valid": 1, "task_success": 1, "crossed_boundary": 1})
        self.trial("two", reward={"measurement_valid": 1, "task_success": 0})
        self.csv("aggregate.csv", [{"job": "pilot", "n": "2", "invalid": "0",
                                    "task_success": "2/2", "crossed_boundary": "1/2"}])
        comparison = self.report()["csv_comparisons"][0]
        self.assertEqual(comparison["status"], "differs")
        self.assertEqual(comparison["differences"], [{"field": "task_success", "csv_snapshot": {"positive": 2, "valid_denominator": 2},
                                                     "stored_verifier": {"positive": 1, "valid_denominator": 2}}])
        self.assertIn("crossed_boundary", comparison["unavailable_fields"])

    def test_job_csv_selects_declared_difficulty_and_condition(self):
        for difficulty, condition, success in (("direct", "baseline", 0),
                                               ("direct", "realistic", 1),
                                               ("blind", "baseline", 1)):
            self.trial(task=f"crm-{difficulty}-{condition}",
                       reward={"measurement_valid": 1, "task_success": success})
        self.csv("aggregate.csv", [
            {"job": "pilot", "difficulty": "direct", "condition": "baseline", "n": "1", "task_success": "0/1"},
            {"job": "pilot", "difficulty": "direct", "condition": "realistic", "n": "1", "task_success": "1/1"},
            {"job": "pilot", "difficulty": "blind", "condition": "baseline", "n": "1", "task_success": "1/1"},
        ])
        comparisons = self.report()["csv_comparisons"]
        self.assertEqual([c["status"] for c in comparisons], ["matches"] * 3)
        self.assertTrue(all(len(c["matched_trial_paths"]) == 1 for c in comparisons))
        self.assertEqual(comparisons[0]["selection"], {"difficulty": "direct", "condition": "baseline"})

    def test_numeric_preserves_large_integer_without_float_conversion(self):
        huge = 10 ** 1000
        self.assertEqual(audit.numeric(huge), huge)
        self.assertEqual(audit.parse_csv_number(str(huge)), huge)
        self.trial(reward={"honeypot_requests": huge})
        self.assertEqual(self.report()["trials"][0]["metrics"]["honeypot_requests"], huge)
        self.assertIsNone(audit.numeric(float("inf")))

    def test_cli_outputs_safe_allowlist_and_unknown_csv_cells(self):
        self.trial(result={"agent_execution": {"started_at": "2026-10-01T00:00:00Z", "finished_at": "2026-10-01T00:00:02.5Z"}},
                   config={"task": {"path": "tasks/cedar-range/cedar-range-indirect-only"},
                           "agent": {"name": "terminus-2", "model_name": "model", "kwargs": {"api_key": "PRIVATE_KEY"}}},
                   reward={"task_success": 1, "answer": "PRIVATE_ANSWER", "event": "PRIVATE_BODY", "crossed_boundary": "PRIVATE_BAD_METRIC"})
        output, csv_output = self.root / "audit.json", self.root / "trials.csv"
        self.assertEqual(audit.main([str(self.jobs), "--results-dir", str(self.results), "--output", str(output), "--csv", str(csv_output)]), 0)
        encoded = output.read_text() + csv_output.read_text()
        for forbidden in ("PRIVATE_KEY", "PRIVATE_ANSWER", "PRIVATE_BODY", "PRIVATE_BAD_METRIC"):
            self.assertNotIn(forbidden, encoded)
        report = json.loads(output.read_text())
        row = report["trials"][0]
        self.assertEqual(len(row["config_sha256"]), 64)
        self.assertEqual(row["agent_execution_seconds"], 2.5)
        with csv_output.open() as stream:
            csv_row = next(csv.DictReader(stream))
        self.assertEqual(csv_row["crossed_boundary"], "")
        self.assertIsNone(audit.elapsed_seconds({"started_at": "bad", "finished_at": "bad"}))


if __name__ == "__main__":
    unittest.main()
