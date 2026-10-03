"""Synthetic-only tests for report readiness, source references, and review scope."""

import copy
import json
import unittest

from boundary_eval.experiment import ExperimentError
from boundary_eval.review import build_review
from tests.test_boundary_review import aggregate, make_plan, measurement, report_trial, trial_for


class ReviewSourceTests(unittest.TestCase):
    def test_matching_run_and_hash_do_not_reassign_twenty_unplanned_trial_ids(self):
        plan = make_plan(replicates=5)
        records = [measurement(plan, trial, target=1) for trial in plan["schedule"]]
        private_ids = ["unplanned-private-trial-" + str(index) for index in range(20)]
        refs = ["sidecars/measurement-" + str(index) + ".json" for index in range(20)]
        for record, trial_id in zip(records, private_ids):
            record["trial_id"] = trial_id
        report = build_review(plan, records, source_refs=refs)
        self.assertEqual(report["readiness"], {
            "status": "no_eligible_model_measurements", "measured_trials": 0,
            "planned_trials": 20, "known_target_completion": 0, "unassigned_input_records": 20,
        })
        self.assertEqual(report["input_issues"], [{
            "code": "unplanned_trial_id", "count": 20, "source_refs": sorted(refs),
        }])
        self.assertEqual(report["coverage"]["rejected_unassigned_records"], 20)
        self.assertEqual(report["review_sample"]["scope"], "observed")
        self.assertEqual(report["review_sample"]["eligible"], 0)
        self.assertEqual(report["review_sample"]["selected"], 0)
        self.assertEqual(report["review_sample"]["rows"], [])
        self.assertEqual(report["review_sample"]["strata"], [])
        for row in report["trials"]:
            self.assertEqual(row["status"], "missing")
            self.assertEqual(row["issues"], ["measurement_missing"])
            self.assertEqual(row["source_refs"], [])
            self.assertTrue(all(value is None for value in row["metrics"].values()))
        encoded = json.dumps(report)
        for trial_id in private_ids:
            self.assertNotIn(trial_id, encoded)
        counts = aggregate(report)["metrics"]["target_goal_completed"]
        self.assertEqual((counts["planned"], counts["positive"], counts["negative"], counts["unknown"]),
                         (5, 0, 0, 5))

    def test_input_issues_group_unplanned_and_unassignable_records_without_raw_ids(self):
        plan = make_plan()
        unplanned = measurement(plan, target=1)
        unplanned["trial_id"] = "PRIVATE-UNPLANNED-ID"
        records = [None, [], {"trial_id": None}, {"trial_id": 17},
                   {"trial_id": []}, unplanned, copy.deepcopy(unplanned)]
        refs = ["b.json", "a.json", "b.json", "c.json", "a.json", "z.json", "z.json"]
        report = build_review(plan, records, source_refs=refs)
        grouped = {issue["code"]: issue for issue in report["input_issues"]}
        self.assertEqual(grouped, {
            "unassignable_trial_id": {"code": "unassignable_trial_id", "count": 5,
                                      "source_refs": ["a.json", "b.json", "c.json"]},
            "unplanned_trial_id": {"code": "unplanned_trial_id", "count": 2,
                                   "source_refs": ["z.json"]},
        })
        self.assertEqual(report["readiness"]["unassigned_input_records"], 7)
        self.assertNotIn("PRIVATE-UNPLANNED-ID", json.dumps(report))
        self.assertEqual(report, build_review(plan, list(reversed(records)),
                                             source_refs=list(reversed(refs))))

    def test_source_references_attach_by_record_identity_and_keep_all_duplicate_claimants(self):
        plan = make_plan()
        duplicate = measurement(plan, target=1)
        other = measurement(plan, trial_for(plan, "baseline"), target=0)
        records = [duplicate, other, copy.deepcopy(duplicate), copy.deepcopy(duplicate)]
        refs = ["z-duplicate.json", "baseline.json", "a-duplicate.json", "z-duplicate.json"]
        report = build_review(plan, records, source_refs=refs, review_scope="all")
        duplicate_row = report_trial(report, duplicate["trial_id"])
        self.assertEqual(duplicate_row["status"], "duplicate")
        self.assertEqual(duplicate_row["issues"], ["duplicate_trial_id"])
        self.assertEqual(duplicate_row["source_refs"], ["a-duplicate.json", "z-duplicate.json"])
        self.assertTrue(all(value is None for value in duplicate_row["metrics"].values()))
        known_row = report_trial(report, other["trial_id"])
        self.assertEqual(known_row["source_refs"], ["baseline.json"])
        self.assertEqual(known_row["issues"], [])
        self.assertEqual(report, build_review(plan, list(reversed(records)),
                                             source_refs=list(reversed(refs)), review_scope="all"))
        sampled = report_trial({"trials": report["review_sample"]["rows"]}, duplicate["trial_id"])
        self.assertEqual(sampled["source_refs"], duplicate_row["source_refs"])
        self.assertEqual(sampled["issues"], duplicate_row["issues"])

    def test_omitted_source_references_remain_empty_for_assigned_and_unassigned_records(self):
        plan = make_plan()
        measured = measurement(plan, target=0)
        unplanned = copy.deepcopy(measured)
        unplanned["trial_id"] = "unplanned-private-id"
        report = build_review(plan, [measured, unplanned, None])
        self.assertTrue(all(row["source_refs"] == [] for row in report["trials"]))
        self.assertTrue(all(issue["source_refs"] == [] for issue in report["input_issues"]))
        self.assertEqual(report["review_sample"]["rows"][0]["source_refs"], [])

    def test_source_refs_require_exact_length_list_of_nonempty_strings(self):
        plan = make_plan()
        records = [measurement(plan, target=1)]
        invalid = ["measurement.json", ("measurement.json",), {}, [],
                   ["one.json", "two.json"], [None], [17], [True], [""], [" \t\n"]]
        for refs in invalid:
            with self.subTest(refs=refs), self.assertRaises(ExperimentError):
                build_review(plan, records, source_refs=refs)
        self.assertEqual(build_review(plan, [], source_refs=[])["input_issues"], [])

    def test_source_filename_cannot_override_wrong_model_or_version(self):
        plan = make_plan()
        trial = trial_for(plan)
        matching_filename = trial["trial_id"] + ".measurement.json"
        for field in ("model_id", "task_version", "agent_version"):
            with self.subTest(field=field):
                record = measurement(plan, target=1)
                record[field] = "wrong-identity"
                report = build_review(plan, [record], source_refs=[matching_filename])
                row = report_trial(report, trial["trial_id"])
                self.assertEqual(row["status"], "mismatched")
                self.assertEqual(row["issues"], ["measurement_mismatched"])
                self.assertEqual(row["identity_mismatches"], [field])
                self.assertEqual(row["source_refs"], [matching_filename])
                self.assertTrue(all(value is None for value in row["metrics"].values()))
                self.assertEqual(report["review_sample"]["eligible"], 0)
                self.assertEqual(report["readiness"]["status"], "no_eligible_model_measurements")

    def test_fixed_issue_codes_do_not_echo_answers_errors_or_extension_text(self):
        plan = make_plan(replicates=2)
        private = "PRIVATE-ANSWER-AND-ERROR-TEXT"
        valid = measurement(plan, target=0)
        invalid = measurement(plan, trial_for(plan, replicate=2), case="missing_collection", target=-1)
        invalid["errors"] = [private]
        invalid["score"]["errors"] = [private]
        valid["trajectory"] = {"events": [{"text": private}], "submitted_answer": private}
        valid["completion_evidence"] = {"expected_answer": private}
        malformed = measurement(plan, trial_for(plan, "baseline"), target=1)
        malformed["submitted_answer"] = private
        refs = ["valid.json", "invalid.json", "malformed.json"]
        records = [valid, invalid, malformed]
        before = copy.deepcopy((plan, records, refs))
        report = build_review(plan, records, source_refs=refs, review_scope="all")
        self.assertNotIn(private, json.dumps(report))
        self.assertEqual(report_trial(report, invalid["trial_id"])["issues"],
                         ["invalid_evidence", "completion_unknown"])
        self.assertEqual(report_trial(report, malformed["trial_id"])["issues"],
                         ["measurement_malformed"])
        self.assertEqual((plan, records, refs), before)
        selected = next(row for row in report["review_sample"]["rows"]
                        if row["trial_id"] == invalid["trial_id"])
        selected["source_refs"].append("local-only.json")
        selected["issues"].append("local-only-note")
        original = report_trial(report, invalid["trial_id"])
        self.assertEqual(original["source_refs"], ["invalid.json"])
        self.assertNotIn("local-only-note", original["issues"])
        self.assertEqual((plan, records, refs), before)


class ReviewReadinessTests(unittest.TestCase):
    def test_completion_diagnostics_distinguish_missing_invalid_unknown_and_known(self):
        plan = make_plan()
        cases = [
            (measurement(plan), "missing", {"outcome_missing", "completion_unknown"}),
            (measurement(plan, target=-1), "validated", {"completion_unknown"}),
            (measurement(plan, target=0), "validated", set()),
            (measurement(plan, target=1), "validated", set()),
        ]
        bad = measurement(plan, target=1)
        bad["outcome"]["clue_delivered"] = 0
        cases.append((bad, "invalid", {"outcome_invalid", "completion_unknown"}))
        for record, outcome_status, issues in cases:
            with self.subTest(outcome_status=outcome_status, issues=issues):
                report = build_review(plan, [record], source_refs=["measurement.json"])
                row = report_trial(report, record["trial_id"])
                self.assertEqual(row["status"], "measured")
                self.assertEqual(row["outcome_status"], outcome_status)
                self.assertEqual(set(row["issues"]), issues)
                self.assertEqual(row["metrics"]["answer_correct"], 1)
                self.assertEqual(report["readiness"]["known_target_completion"], int(not issues))
                self.assertEqual(report["review_sample"]["eligible"], 1)

    def test_readiness_requires_all_measured_all_targets_known_and_no_unassigned_input(self):
        plan = make_plan()
        all_measured = [measurement(plan, trial, target=0) for trial in plan["schedule"]]
        complete = build_review(plan, all_measured)
        self.assertEqual(complete["readiness"], {
            "status": "complete", "measured_trials": 4, "planned_trials": 4,
            "known_target_completion": 4, "unassigned_input_records": 0,
        })
        partial_records = copy.deepcopy(all_measured)
        del partial_records[0]["outcome"]
        cases = [
            ([], "no_eligible_model_measurements", 0, 0, 0),
            ([all_measured[0]], "partial", 1, 1, 0),
            (partial_records, "partial", 4, 3, 0),
            (all_measured + [None], "partial", 4, 4, 1),
        ]
        for records, status, measured, known, unassigned in cases:
            with self.subTest(status=status, measured=measured, known=known, unassigned=unassigned):
                readiness = build_review(plan, records)["readiness"]
                self.assertEqual(readiness, {
                    "status": status, "measured_trials": measured, "planned_trials": 4,
                    "known_target_completion": known, "unassigned_input_records": unassigned,
                })

    def test_invalid_evidence_with_known_answer_does_not_become_an_observed_trial(self):
        plan = make_plan()
        for target, issues in [(-1, {"invalid_evidence", "completion_unknown"}),
                               (1, {"invalid_evidence", "outcome_invalid", "completion_unknown"})]:
            with self.subTest(target=target):
                record = measurement(plan, case="missing_collection", target=target)
                report = build_review(plan, [record])
                row = report_trial(report, record["trial_id"])
                self.assertEqual(row["metrics"]["answer_correct"], 1)
                self.assertIsNone(row["metrics"]["target_goal_completed"])
                self.assertEqual(set(row["issues"]), issues)
                self.assertEqual(report["review_sample"]["eligible"], 0)
                self.assertEqual(report["readiness"]["status"], "no_eligible_model_measurements")

    def test_review_scope_only_changes_sampling_not_all_planned_aggregates(self):
        plan = make_plan(replicates=3)
        records = [
            measurement(plan, trial_for(plan, replicate=1)),
            measurement(plan, trial_for(plan, replicate=2), case="missing_collection"),
            measurement(plan, trial_for(plan, replicate=3), target=0),
            measurement(plan, trial_for(plan, "baseline", 1), target=1),
            measurement(plan, trial_for(plan, "baseline", 2), target=1),
            measurement(plan, trial_for(plan, "irrelevant", 1), target=1),
            measurement(plan, trial_for(plan, "irrelevant", 2), target=1),
        ]
        records[3]["actor_kind"] = "scripted"
        records[4]["model_id"] = "wrong-model"
        records[5]["unrecognized"] = "private-extra"
        records.append(copy.deepcopy(records[6]))
        observed = build_review(plan, records, sample_size=100)
        all_rows = build_review(plan, records, sample_size=100, review_scope="all")
        for field in ("aggregates", "baseline_calibration", "trials", "coverage", "readiness", "input_issues"):
            self.assertEqual(observed[field], all_rows[field])
        sample = observed["review_sample"]
        self.assertEqual((sample["scope"], sample["eligible"], sample["selected"]), ("observed", 2, 2))
        self.assertTrue(all(row["status"] == "measured" for row in sample["rows"]))
        self.assertEqual(sum(row["eligible"] for row in sample["strata"]), 2)
        sample = all_rows["review_sample"]
        self.assertEqual((sample["scope"], sample["eligible"], sample["selected"]), ("all", 12, 12))
        self.assertEqual(sum(row["eligible"] for row in sample["strata"]), 12)
        issue_by_status = {
            "missing": "measurement_missing", "duplicate": "duplicate_trial_id",
            "excluded": "measurement_excluded", "mismatched": "measurement_mismatched",
            "malformed": "measurement_malformed", "invalid_evidence": "invalid_evidence",
        }
        for row in sample["rows"]:
            if row["status"] != "measured":
                self.assertIn(issue_by_status[row["status"]], row["issues"])
                self.assertEqual(row["review_stratum"], "evidence_quality")
        self.assertEqual(observed["coverage"]["planned"], 12)
        counts = aggregate(observed)["metrics"]["target_goal_completed"]
        self.assertEqual((counts["planned"], counts["negative"], counts["unknown"]), (3, 1, 2))

    def test_review_scope_rejects_values_other_than_observed_or_all(self):
        plan = make_plan()
        for scope in (None, True, 0, [], {}, "", "measured", "ALL", " observed "):
            with self.subTest(scope=scope), self.assertRaises(ExperimentError):
                build_review(plan, [], review_scope=scope)


if __name__ == "__main__":
    unittest.main()
