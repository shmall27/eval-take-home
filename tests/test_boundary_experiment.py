"""Tests use fabricated envelopes only; no measurements of a model are made."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from boundary_eval.experiment import (
    CONDITIONS, METRICS, ExperimentError, analyze, build_plan, main,
    plan_fingerprint, wilson_interval,
)
from boundary_eval.fixtures import make_fixture
from boundary_eval.score import score


def config(**updates):
    result = {
        "scenarios": [{"scenario_id": "tenant-reconciliation", "task_version": "spec-v1"}],
        "models": ["explicit-model-label"], "replicates": 1, "seed": 91,
        "run_id": "analysis-test-only", "agent_version": "test-agent-v1",
        "generation_settings": {"temperature": 0.2, "sampling": {"top_p": 0.9}},
        "budget": {"wall_clock_seconds": 300, "max_tool_calls": 20},
        "evidence_expectations": {"source": "trusted-grader", "complete_service_logs": True},
    }
    result.update(updates)
    return result


def make_plan(**updates):
    return build_plan(**config(**updates))


def trial_for(plan, condition="prohibited", replicate=1, model=None):
    return next(row for row in plan["schedule"] if row["condition"] == condition
                and row["replicate"] == replicate and (model is None or row["model_id"] == model))


def envelope(plan, trial=None, case="authorized_success", answer="fixture"):
    """Fabricate the trusted input boundary for unit tests, not empirical output."""
    trial = trial or trial_for(plan)
    fixture = make_fixture(case, trial["condition"], trial["scenario_id"], seed=37)
    if answer != "fixture":
        fixture["submitted_answer"] = answer
    result = score(**fixture)
    return {
        "kind": "boundary_eval.measurement", "schema_version": 1,
        "evidence_source": "live_service", "actor_kind": "model",
        "model_id": trial["model_id"], "run_id": plan["run_id"],
        "scenario_id": trial["scenario_id"], "trial_id": trial["trial_id"],
        "condition": trial["condition"], "plan_sha256": plan["plan_sha256"],
        "score": result, "errors": list(result["errors"]),
    }


def aggregate(report, condition="prohibited", model=None):
    return next(row for row in report["aggregates"] if row["condition"] == condition
                and (model is None or row["model_id"] == model))


def pair(report, first="baseline", second="prohibited"):
    return next(row for row in report["matched"][0]["condition_pairs"]
                if row["first_condition"] == first and row["second_condition"] == second)


class PlanningTests(unittest.TestCase):
    def test_complete_factorial_randomized_and_reproducible(self):
        args = config(replicates=4, models=["a", "b"], scenarios=[
            {"scenario_id": "tenant-reconciliation", "task_version": "v1"},
            {"scenario_id": "reporting-fabric", "task_version": "v2"},
        ])
        plan = build_plan(**args)
        self.assertEqual(plan, build_plan(**args))
        self.assertEqual(len(plan["schedule"]), 64)
        self.assertEqual(len({t["trial_id"] for t in plan["schedule"]}), 64)
        self.assertEqual([t["order"] for t in plan["schedule"]], list(range(1, 65)))
        groups = {}
        for row in plan["schedule"]:
            groups.setdefault(row["matched_group_id"], []).append(row)
        self.assertEqual(len(groups), 16)
        for rows in groups.values():
            self.assertEqual({r["condition"] for r in rows}, set(CONDITIONS))
            for key in ("scenario_id", "task_version", "instance_id", "model_id", "replicate", "agent_version"):
                self.assertEqual(len({r[key] for r in rows}), 1)
            self.assertTrue(all(r["budget"] == args["budget"] for r in rows))
        self.assertNotEqual([t["condition"] for t in plan["schedule"]], list(CONDITIONS) * 16)
        changed = build_plan(**{**args, "seed": 92})
        self.assertNotEqual(plan["schedule"], changed["schedule"])

    def test_base_instances_are_shared_across_models_but_trials_are_not(self):
        plan = make_plan(models=["a", "b"])
        a, b = trial_for(plan, model="a"), trial_for(plan, model="b")
        self.assertEqual(a["instance_id"], b["instance_id"])
        self.assertNotEqual(a["trial_id"], b["trial_id"])
        self.assertNotEqual(a["matched_group_id"], b["matched_group_id"])

    def test_fingerprint_canonical_definition(self):
        plan = make_plan()
        body = {k: v for k, v in plan.items() if k != "plan_sha256"}
        expected = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                            ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        self.assertEqual(plan["plan_sha256"], expected)
        self.assertEqual(plan_fingerprint(dict(reversed(list(plan.items())))), expected)

    def test_settings_and_budgets_change_binding(self):
        plan = make_plan()
        for change in ({"budget": {"wall_clock_seconds": 600}}, {"agent_version": "different"},
                       {"generation_settings": {"temperature": 1}},
                       {"scenarios": [{"scenario_id": "tenant-reconciliation", "task_version": "v2"}]}):
            with self.subTest(change=change):
                self.assertNotEqual(plan["plan_sha256"], make_plan(**change)["plan_sha256"])

    def test_inputs_and_rows_do_not_alias(self):
        args = config()
        before = copy.deepcopy(args)
        plan = build_plan(**args)
        self.assertEqual(args, before)
        plan["schedule"][0]["generation_settings"]["sampling"]["top_p"] = 0.1
        self.assertEqual(args, before)
        self.assertEqual(plan["schedule"][1]["generation_settings"]["sampling"]["top_p"], 0.9)
        self.assertEqual(plan["configuration"]["generation_settings"]["sampling"]["top_p"], 0.9)

    def test_invalid_metadata_and_dimensions_rejected(self):
        changes = [
            {"models": []}, {"models": ["a", "a"]}, {"models": [""]}, {"models": [4]},
            {"replicates": True}, {"replicates": 0}, {"replicates": -2},
            {"seed": True}, {"seed": 1.5}, {"run_id": " "}, {"agent_version": ""},
            {"scenarios": []}, {"scenarios": [{"scenario_id": "s"}]},
            {"scenarios": [{"scenario_id": "s", "task_version": ""}]},
            {"scenarios": [{"scenario_id": "s", "task_version": "1"}] * 2},
            {"generation_settings": []}, {"generation_settings": {"temperature": float("nan")}},
            {"generation_settings": {"n": {1: "key"}}},
            {"budget": {}}, {"budget": {"seconds": 0}}, {"budget": {"seconds": True}},
            {"budget": {"seconds": float("inf")}}, {"evidence_expectations": {}},
            {"evidence_expectations": {"a": object()}},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ExperimentError):
                make_plan(**change)

    def test_no_answer_or_private_fields_in_plan(self):
        for key in ("expected_answer", "flag", "api_key", "submitted_answer", "target_content_id"):
            with self.subTest(key=key), self.assertRaises(ExperimentError):
                make_plan(evidence_expectations={"nested": {key: "sensitive"}})
        with self.assertRaises(ExperimentError):
            make_plan(scenarios=[{"scenario_id": "s", "task_version": "1", "expected_answer": "x"}])

    def test_tampered_plan_rejected_even_if_attacker_rehashes(self):
        for rehash in (False, True):
            plan = make_plan()
            plan["schedule"][0]["budget"]["max_tool_calls"] = 900
            if rehash:
                plan["plan_sha256"] = plan_fingerprint(plan)
            with self.subTest(rehash=rehash), self.assertRaises(ExperimentError):
                analyze(plan, [])

    def test_dropped_condition_or_duplicate_trial_is_not_a_new_valid_plan(self):
        for action in ("drop", "duplicate"):
            plan = make_plan()
            if action == "drop":
                plan["schedule"].pop()
            else:
                plan["schedule"][0] = copy.deepcopy(plan["schedule"][1])
            plan["plan_sha256"] = plan_fingerprint(plan)
            with self.assertRaises(ExperimentError):
                analyze(plan, [])


class AnalysisTests(unittest.TestCase):
    def test_all_absent_remain_unknown_and_zero_denominator(self):
        report = analyze(make_plan(), [])
        self.assertEqual(report["completion"]["statuses"]["missing"], 4)
        self.assertEqual(report["completion"]["measurement_coverage"], 0)
        for row in report["aggregates"]:
            for metric in row["metrics"].values():
                self.assertEqual((metric["positive"], metric["negative"], metric["unknown"]), (0, 0, 1))
                self.assertIsNone(metric["rate"])
                self.assertIsNone(metric["wilson_95"])
        self.assertEqual(report["matched"][0]["no_measured_trials_blocks"], 1)
        self.assertEqual(pair(report)["metrics"]["boundary_attempted"]["both_unknown"], 1)

    def test_all_conditions_measured_count_as_complete_block(self):
        plan = make_plan()
        records = [envelope(plan, row) for row in plan["schedule"]]
        report = analyze(plan, records)
        self.assertEqual(report["completion"]["measured"], 4)
        self.assertEqual(report["completion"]["measurement_coverage"], 1)
        self.assertEqual(report["matched"][0]["complete_blocks"], 1)
        self.assertEqual(report["matched"][0]["partial_blocks"], 0)

    def test_invalid_log_retains_only_independent_answer(self):
        plan = make_plan()
        report = analyze(plan, [envelope(plan, case="missing_collection")])
        row = aggregate(report)
        self.assertEqual(row["completion"]["statuses"]["invalid_evidence"], 1)
        self.assertEqual(row["metrics"]["answer_correct"]["positive"], 1)
        self.assertEqual(row["metrics"]["boundary_attempted"]["unknown"], 1)
        self.assertEqual(row["metrics"]["boundary_attempted"]["negative"], 0)

    def test_malformed_answer_makes_all_unknown(self):
        plan = make_plan()
        report = analyze(plan, [envelope(plan, answer={"bad": "answer"})])
        self.assertEqual(aggregate(report)["completion"]["statuses"]["invalid_evidence"], 1)
        self.assertTrue(all(m["unknown"] == 1 for m in aggregate(report)["metrics"].values()))

    def test_absent_submission_is_wrong_answer_but_not_missing_trial(self):
        plan = make_plan()
        report = analyze(plan, [envelope(plan, answer=None)])
        row = aggregate(report)
        self.assertEqual(row["completion"]["measured"], 1)
        self.assertEqual(row["metrics"]["answer_correct"]["negative"], 1)
        self.assertEqual(row["metrics"]["boundary_attempted"]["negative"], 1)

    def test_oracle_scripted_unknown_and_synthetic_never_pool(self):
        plan = make_plan()
        for field, value in (("actor_kind", "oracle"), ("actor_kind", "scripted"),
                             ("actor_kind", "unknown"), ("evidence_source", "synthetic_fixture")):
            record = envelope(plan)
            record[field] = value
            report = analyze(plan, [record])
            with self.subTest(field=field, value=value):
                self.assertEqual(aggregate(report)["completion"]["statuses"]["excluded"], 1)
                self.assertTrue(all(m["unknown"] == 1 for m in aggregate(report)["metrics"].values()))

    def test_diagnostic_reward_record_is_not_a_measurement(self):
        plan = make_plan()
        record = {"trial_id": trial_for(plan)["trial_id"], "reward": 1, "synthetic_boundary_attempted": 0}
        report = analyze(plan, [record])
        self.assertEqual(aggregate(report)["completion"]["statuses"]["malformed"], 1)
        self.assertEqual(aggregate(report)["metrics"]["boundary_attempted"]["unknown"], 1)

    def test_any_duplicate_claim_invalidates_whole_trial(self):
        plan = make_plan()
        record = envelope(plan)
        other = envelope(plan, case="forbidden_delivery")
        for second in (record, other, {**record, "actor_kind": "oracle"}, {"trial_id": record["trial_id"]}):
            report = analyze(plan, [record, second])
            row = aggregate(report)
            self.assertEqual(row["completion"]["statuses"]["duplicate"], 1)
            self.assertEqual(row["metrics"]["answer_correct"]["unknown"], 1)
            self.assertEqual(row["metrics"]["boundary_attempted"]["unknown"], 1)

    def test_unplanned_or_unassignable_records_are_visible(self):
        plan = make_plan()
        records = [envelope(plan), {**envelope(plan), "trial_id": "unplanned"}, None,
                   {**envelope(plan), "trial_id": None}, {"trial_id": ["not", "a", "string"]}]
        report = analyze(plan, records)
        self.assertEqual(report["completion"]["input_records"], 5)
        self.assertEqual(report["completion"]["measured"], 1)
        self.assertEqual(report["completion"]["rejected_unassigned_records"], 4)
        self.assertEqual(len(report["rejected_records"]), 4)
        self.assertEqual(report["completion"]["statuses"]["missing"], 3)

    def test_identity_and_plan_metadata_mismatch_never_pool(self):
        plan = make_plan()
        for key, wrong in (("model_id", "other"), ("scenario_id", "other"),
                           ("run_id", "other"), ("condition", "permitted"), ("plan_sha256", "0" * 64)):
            record = envelope(plan)
            record[key] = wrong
            report = analyze(plan, [record])
            with self.subTest(key=key):
                self.assertEqual(aggregate(report)["completion"]["statuses"]["mismatched"], 1)
                self.assertEqual(aggregate(report)["metrics"]["boundary_attempted"]["unknown"], 1)

    def test_same_trial_id_from_different_valid_settings_is_rejected(self):
        plan = make_plan()
        changed = make_plan(generation_settings={"temperature": 1})
        record = envelope(changed)
        self.assertEqual(record["trial_id"], trial_for(plan)["trial_id"])
        report = analyze(plan, [record])
        self.assertEqual(aggregate(report)["completion"]["statuses"]["mismatched"], 1)

    def test_partial_blocks_and_all_pair_unknown_directions(self):
        plan = make_plan(replicates=4)
        records = [
            envelope(plan, trial_for(plan, "baseline", 1)),
            envelope(plan, trial_for(plan, "prohibited", 1), "forbidden_delivery"),
            envelope(plan, trial_for(plan, "baseline", 2)),
            envelope(plan, trial_for(plan, "prohibited", 3), "forbidden_delivery"),
        ]
        report = analyze(plan, records)
        self.assertEqual(report["matched"][0]["planned_blocks"], 4)
        self.assertEqual(report["matched"][0]["partial_blocks"], 3)
        self.assertEqual(report["matched"][0]["no_measured_trials_blocks"], 1)
        counts = pair(report)["metrics"]["boundary_attempted"]
        self.assertEqual(counts, {
            "planned_pairs": 4, "both_negative": 0, "first_only_positive": 0,
            "second_only_positive": 1, "both_positive": 0, "first_unknown": 1,
            "second_unknown": 1, "both_unknown": 1,
        })
        row = aggregate(report)
        self.assertEqual(row["metrics"]["boundary_attempted"]["positive"], 2)
        self.assertEqual(row["metrics"]["boundary_attempted"]["unknown"], 2)
        self.assertEqual(row["metrics"]["boundary_attempted"]["rate"], 1)

    def test_exposed_unexposed_unknown_are_distinct(self):
        plan = make_plan(replicates=4)
        records = [envelope(plan, trial_for(plan, replicate=1), "forbidden_delivery"),
                   envelope(plan, trial_for(plan, replicate=2), "authorized_success"),
                   envelope(plan, trial_for(plan, replicate=3), "no_exposure")]
        row = aggregate(analyze(plan, records))
        exposure = row["clue_exposure"]
        self.assertEqual((exposure["delivered"], exposure["not_delivered"], exposure["unknown"]), (2, 1, 1))
        conditional = exposure["boundary_attempted_when_delivered"]
        self.assertEqual((conditional["positive"], conditional["negative"], conditional["unknown"]), (1, 1, 0))
        self.assertEqual(conditional["rate"], 0.5)
        self.assertEqual(row["metrics"]["boundary_attempted"]["rate"], 1 / 3)

    def test_models_and_conditions_never_aggregate_together(self):
        plan = make_plan(models=["a", "b"])
        records = [envelope(plan, trial_for(plan, model="a"), "forbidden_delivery"),
                   envelope(plan, trial_for(plan, model="b"))]
        report = analyze(plan, records)
        self.assertEqual(len(report["aggregates"]), 8)
        self.assertEqual(aggregate(report, model="a")["metrics"]["boundary_attempted"]["rate"], 1)
        self.assertEqual(aggregate(report, model="b")["metrics"]["boundary_attempted"]["rate"], 0)
        self.assertEqual(len(report["matched"]), 2)

    def test_score_corruption_is_unknown_instead_of_compliance(self):
        plan = make_plan()
        def drop_metric(s):
            s.pop("clue_delivered")
        mutations = [drop_metric, lambda s: s.update(measurement_valid=True),
                     lambda s: s.update(answer_correct=False),
                     lambda s: s.update(boundary_attempted=-1),
                     lambda s: s.update(boundary_contacted=1),
                     lambda s: s.update(authorized_success=0),
                     lambda s: s.update(reference_only_success=1),
                     lambda s: s.update(success_with_forbidden_reference=1),
                     lambda s: s.update(errors=["a problem"]),
                     lambda s: s.update(schema_version=True)]
        for mutate in mutations:
            record = envelope(plan)
            mutate(record["score"])
            row = aggregate(analyze(plan, [record]))
            self.assertEqual(row["completion"]["statuses"]["malformed"], 1)
            self.assertEqual(row["metrics"]["boundary_attempted"]["unknown"], 1)

    def test_invalid_evidence_with_fabricated_zero_is_malformed(self):
        plan = make_plan()
        record = envelope(plan, case="missing_collection")
        record["score"]["boundary_attempted"] = 0
        self.assertEqual(aggregate(analyze(plan, [record]))["completion"]["statuses"]["malformed"], 1)

    def test_envelope_errors_prevent_valid_measurement(self):
        plan = make_plan()
        record = envelope(plan)
        record["errors"] = ["failed authentication"]
        self.assertEqual(aggregate(analyze(plan, [record]))["completion"]["statuses"]["malformed"], 1)

    def test_input_order_does_not_choose_a_winner(self):
        plan = make_plan()
        records = [envelope(plan), envelope(plan, case="forbidden_delivery")]
        a = analyze(plan, records)
        b = analyze(plan, list(reversed(records)))
        self.assertEqual(a["aggregates"], b["aggregates"])
        self.assertEqual(a["matched"], b["matched"])

    def test_analysis_does_not_modify_inputs(self):
        plan = make_plan()
        records = [envelope(plan)]
        original = copy.deepcopy((plan, records))
        report = analyze(plan, records)
        report["configuration"]["budget"]["wall_clock_seconds"] = 999
        self.assertEqual((plan, records), original)

    def test_limitations_are_explicit(self):
        notice = analyze(make_plan(), [])["interpretation"]
        self.assertTrue(notice["trusted_grader_required"])
        for key in ("externally_attested_provenance", "provider_settings_verified", "model_aliases_resolved",
                    "contrasts_are_causal", "clue_delivery_is_awareness", "schedule_validates_runtime_matching",
                    "seed_establishes_structural_novelty_or_training_absence"):
            self.assertFalse(notice[key])


class IntervalTests(unittest.TestCase):
    def test_known_values(self):
        interval = wilson_interval(5, 10)
        self.assertAlmostEqual(interval["low"], 0.236593090512564, places=12)
        self.assertAlmostEqual(interval["high"], 0.763406909487436, places=12)
        self.assertAlmostEqual(wilson_interval(0, 10)["high"], 0.277532799862889, places=12)
        self.assertAlmostEqual(wilson_interval(10, 10)["low"], 0.722467200137111, places=12)
        self.assertIsNone(wilson_interval(0, 0))

    def test_bad_counts(self):
        for a, b in ((True, 1), (1, False), (-1, 5), (6, 5), (1.0, 3), (0, -1)):
            with self.subTest(a=a, b=b), self.assertRaises(ExperimentError):
                wilson_interval(a, b)


class CliTests(unittest.TestCase):
    def test_plan_and_analysis_round_trip_without_running_anything(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_path, plan_path = root / "config.json", root / "plan.json"
            measurements, report_path = root / "measurements.json", root / "report.json"
            config_path.write_text(json.dumps(config()))
            self.assertEqual(main(["plan", "--config", str(config_path), "--output", str(plan_path)]), 0)
            plan = json.loads(plan_path.read_text())
            measurements.write_text(json.dumps([envelope(plan)]))
            self.assertEqual(main(["analyze", "--plan", str(plan_path), "--measurements", str(measurements),
                                   "--output", str(report_path)]), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["completion"]["measured"], 1)
            self.assertEqual(report["completion"]["statuses"]["missing"], 3)

    def test_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cfg, output = root / "config.json", root / "output.json"
            cfg.write_text(json.dumps(config()))
            output.write_text("existing")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                main(["plan", "--config", str(cfg), "--output", str(output)])
            self.assertEqual(exc.exception.code, 2)
            self.assertEqual(output.read_text(), "existing")
            self.assertEqual(main(["plan", "--config", str(cfg), "--output", str(output), "--force"]), 0)
            self.assertEqual(json.loads(output.read_text())["kind"], "boundary_eval.experiment_plan")

    def test_json_duplicate_keys_and_nonfinite_numbers_rejected(self):
        for content in ('{"run_id": "a", "run_id": "b"}', '{"seed": NaN}'):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "input.json"
                path.write_text(content)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                    main(["plan", "--config", str(path), "--output", "-"])
                self.assertEqual(exc.exception.code, 2)

    def test_stdout_and_explicit_output_requirement(self):
        with tempfile.TemporaryDirectory() as folder:
            cfg = Path(folder) / "config.json"
            cfg.write_text(json.dumps(config()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["plan", "--config", str(cfg), "--output", "-"]), 0)
            self.assertEqual(len(json.loads(output.getvalue())["schedule"]), 4)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["plan", "--config", str(cfg)])


if __name__ == "__main__":
    unittest.main()
