"""Filesystem/CLI checks on fabricated measurements; no services or models."""

import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

from boundary_eval.outcomes import outcome_record
from boundary_eval.review import build_review, main, review_csv
from tests.test_boundary_experiment import envelope, make_plan, trial_for


class ReviewCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = make_plan()
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_text(json.dumps(self.plan))
        self.record = envelope(self.plan)
        self.record["outcome"] = outcome_record(self.record["score"], 1)
        self.measurement = self.root / "measurement.json"
        self.measurement.write_text(json.dumps(self.record))

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--plan", str(self.plan_path), *map(str, args)])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_full_sidecar_cli_preserves_completion_and_inputs(self):
        originals = [path.read_bytes() for path in (self.plan_path, self.measurement)]
        code, output, errors = self.invoke("--measurement", self.measurement)
        self.assertEqual((code, errors), (0, ""))
        report = json.loads(output)
        row = next(row for row in report["trials"] if row["trial_id"] == self.record["trial_id"])
        self.assertEqual(row["metrics"]["target_goal_completed"], 1)
        self.assertEqual(report["declared_setup"]["budget"], self.plan["configuration"]["budget"])
        self.assertEqual(originals, [path.read_bytes() for path in (self.plan_path, self.measurement)])

    def test_csv_blanks_annotations_but_names_unknown_observations(self):
        code, output, errors = self.invoke("--format", "csv", "--sample-size", 4,
                                          "--review-scope", "all")
        self.assertEqual((code, errors), (0, ""))
        rows = list(csv.DictReader(io.StringIO(output)))
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["status"], "missing")
            self.assertEqual(row["target_goal_completed"], "unknown")
            self.assertEqual(row["boundary_attempted"], "unknown")
            self.assertEqual(row["observations"], "")
            self.assertEqual(row["failure_category"], "")

    def test_default_review_does_not_invent_observed_trials_from_missing_records(self):
        code, output, errors = self.invoke()
        self.assertEqual((code, errors), (0, ""))
        report = json.loads(output)
        self.assertEqual(report["coverage"]["planned"], 4)
        self.assertEqual(report["readiness"]["status"], "no_eligible_model_measurements")
        self.assertEqual(report["review_sample"]["scope"], "observed")
        self.assertEqual(report["review_sample"]["rows"], [])

    def test_sidecar_reference_is_available_in_csv_without_filling_human_notes(self):
        code, output, errors = self.invoke("--measurement", self.measurement, "--format", "csv")
        self.assertEqual((code, errors), (0, ""))
        rows = list(csv.DictReader(io.StringIO(output)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]["source_references"]), [str(self.measurement.resolve())])
        self.assertEqual(rows[0]["evidence_reference"], "")
        self.assertEqual(rows[0]["observations"], "")

    def test_list_references_keep_original_indices_for_unplanned_inputs(self):
        stray = dict(self.record, trial_id="UNPLANNED-PRIVATE-ID")
        listing = self.root / "measurements.json"
        listing.write_text(json.dumps([stray, self.record]))
        code, output, errors = self.invoke("--measurements", listing)
        self.assertEqual((code, errors), (0, ""))
        report = json.loads(output)
        self.assertNotIn("UNPLANNED-PRIVATE-ID", output)
        self.assertEqual(report["input_issues"], [{
            "code": "unplanned_trial_id", "count": 1,
            "source_refs": [str(listing.resolve()) + "#/0"],
        }])
        row = report["review_sample"]["rows"][0]
        self.assertEqual(row["source_refs"], [str(listing.resolve()) + "#/1"])

    def test_list_and_sidecar_duplicates_do_not_become_two_trials(self):
        listing = self.root / "measurements.json"
        listing.write_text(json.dumps([self.record]))
        code, output, _ = self.invoke("--measurements", listing, "--measurement", self.measurement)
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report["coverage"]["statuses"]["duplicate"], 1)
        row = next(row for row in report["trials"] if row["status"] == "duplicate")
        self.assertTrue(all(value is None for value in row["metrics"].values()))

    def test_publish_creates_new_file_and_never_overwrites(self):
        output = self.root / "review.json"
        code, stdout, stderr = self.invoke("--measurement", self.measurement, "--output", output)
        self.assertEqual((code, stdout, stderr), (0, "", ""))
        before = output.read_bytes()
        self.assertEqual(json.loads(before)["kind"], "boundary_eval.review_report")
        code, stdout, stderr = self.invoke("--sample-size", 0, "--output", output)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("FileExistsError", stderr)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".review-*")), [])

    def test_output_symlink_does_not_overwrite_referent(self):
        link = self.root / "output.json"
        link.symlink_to(self.measurement)
        before = self.measurement.read_bytes()
        code, _, _ = self.invoke("--output", link)
        self.assertEqual(code, 1)
        self.assertEqual(self.measurement.read_bytes(), before)
        self.assertTrue(link.is_symlink())

    def test_invalid_json_fails_without_echoing_source_or_writing_output(self):
        output = self.root / "report.json"
        for value in ('{"private-marker": 0, "private-marker": 1}',
                      '{"private-marker": NaN}', '{"private-marker": 1e999}',
                      'private-marker malformed json'):
            with self.subTest(value=value):
                self.measurement.write_text(value)
                code, stdout, stderr = self.invoke("--measurement", self.measurement, "--output", output)
                self.assertEqual(code, 1)
                self.assertNotIn("private-marker", stdout + stderr)
                self.assertFalse(output.exists())

    def test_measurement_list_must_be_a_list(self):
        code, stdout, _ = self.invoke("--measurements", self.measurement)
        self.assertEqual((code, stdout), (1, ""))

    def test_csv_neutralizes_formula_labels(self):
        plan = make_plan(models=["  =formula()"])
        record = envelope(plan, trial_for(plan))
        output = review_csv(build_review(plan, [record], sample_size=4))
        rows = list(csv.DictReader(io.StringIO(output)))
        self.assertTrue(all(row["model_id"] == "'  =formula()" for row in rows))


if __name__ == "__main__":
    unittest.main()
