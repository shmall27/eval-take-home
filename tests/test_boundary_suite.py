"""Offline suite planning over invented metadata; no models or services run."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from boundary_eval.suite import (
    SuiteError, build_suite_plan, load_catalog, main, plan_from_file, validate_plan,
)


def configuration(**updates):
    value = {
        "schema_version": 1,
        "run_id": "synthetic-suite-check",
        "seed": 71,
        "replicates": 2,
        "catalog": "scenarios/index.json",
        "models": ["provider/model-a", "provider/model-b"],
        "selection": {
            "families": "all", "versions": "all", "variants": "all",
            "conditions": "all", "roles": "all",
        },
        "shared": {
            "agent_version": "fixed-harness-v1",
            "generation_settings": {"temperature": 0.2, "sampling": {"top_p": 0.9}},
            "budget": {"wall_clock_seconds": 120, "max_tool_calls": 17},
            "evidence_expectations": {"service_logs": True, "source": "verifier"},
        },
        "outputs": {"directory": "results/synthetic-suite"},
    }
    value.update(updates)
    return value


class SyntheticRegistry(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.registry = {
            "schema_version": 1,
            "families": [
                {"id": "alpha", "role": "cyber_evaluation", "packages": "tasks/alpha/v1",
                 "variant": "standard", "conditions": ["baseline", "prohibited", "permitted"]},
                {"id": "alpha", "role": "cyber_evaluation", "packages": "tasks/alpha/v2",
                 "variant": "standard", "conditions": ["baseline", "prohibited", "permitted"]},
                {"id": "alpha", "role": "cyber_evaluation", "packages": "tasks/alpha/hard-v2",
                 "variant": "hard", "conditions": ["baseline", "prohibited", "permitted"]},
                {"id": "beta", "role": "simple_comparison", "packages": "tasks/beta",
                 "variants": ["explicit", "implicit"]},
                {"id": "control", "role": "workflow_control", "packages": "tasks/control",
                 "conditions": ["baseline"]},
                {"id": "diagnostics", "role": "synthetic_diagnostic", "packages": "tasks/diagnostics",
                 "cases": ["allowed", "denied"]},
            ],
        }
        for family in self.registry["families"]:
            dimension = next(key for key in ("conditions", "variants", "cases") if key in family)
            version = "2.0.0" if family["packages"].endswith("v2") else "1.2.0"
            for member in family[dimension]:
                descriptor = self.root / family["packages"] / member / "task.toml"
                descriptor.parent.mkdir(parents=True)
                descriptor.write_text(
                    'schema_version = "2099.0"\n\n[task]\n'
                    f'name = "{family["id"]}-{member}"\nversion = "{version}"\n',
                    encoding="utf-8",
                )
        self.registry_path = self.root / "scenarios/index.json"
        self.write_registry()

    def write_registry(self):
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(json.dumps(self.registry), encoding="utf-8")

    def catalog(self):
        return load_catalog(self.root)

    def plan(self, **updates):
        return build_suite_plan(configuration(**updates), self.catalog())

    def config_file(self, value=None):
        def toml_value(item):
            if isinstance(item, dict):
                return "{ " + ", ".join(json.dumps(key) + " = " + toml_value(child)
                                        for key, child in item.items()) + " }"
            return json.dumps(item)

        path = self.root / "suite.toml"
        value = configuration() if value is None else value
        path.write_text("\n".join(json.dumps(key) + " = " + toml_value(item)
                                  for key, item in value.items()) + "\n", encoding="utf-8")
        return path


class CatalogTests(SyntheticRegistry):
    def test_all_versions_variants_conditions_and_cases_have_explicit_metadata(self):
        catalog = self.catalog()
        self.assertRegex(catalog["catalog_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(catalog["entries"]), 14)
        self.assertEqual(len({entry["entry_id"] for entry in catalog["entries"]}), 14)
        required = {"entry_id", "family_id", "role", "variant", "condition", "case",
                    "package_path", "descriptor_path", "task_name", "task_version", "descriptor_sha256"}
        for entry in catalog["entries"]:
            self.assertEqual(set(entry), required)
            self.assertRegex(entry["descriptor_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(entry["descriptor_path"], entry["package_path"] + "/task.toml")
            self.assertFalse(Path(entry["package_path"]).is_absolute())
        alpha = [entry for entry in catalog["entries"] if entry["family_id"] == "alpha"]
        self.assertEqual({entry["task_version"] for entry in alpha}, {"1.2.0", "2.0.0"})
        self.assertEqual({entry["variant"] for entry in alpha}, {"standard", "hard"})
        self.assertEqual({entry["condition"] for entry in alpha}, {"baseline", "prohibited", "permitted"})
        self.assertTrue(all(entry["case"] is None for entry in alpha))
        beta = [entry for entry in catalog["entries"] if entry["family_id"] == "beta"]
        self.assertTrue(all(entry["condition"] is None and entry["case"] is None for entry in beta))
        diagnostics = [entry for entry in catalog["entries"] if entry["role"] == "synthetic_diagnostic"]
        self.assertTrue(all(entry["variant"] is None and entry["condition"] is None for entry in diagnostics))
        self.assertEqual({entry["case"] for entry in diagnostics}, {"allowed", "denied"})

    def test_harbor_schema_is_not_the_task_version(self):
        self.assertNotIn("2099.0", {entry["task_version"] for entry in self.catalog()["entries"]})

    def test_descriptor_byte_change_changes_catalog_binding(self):
        before = self.catalog()
        descriptor = self.root / before["entries"][0]["descriptor_path"]
        descriptor.write_text(descriptor.read_text() + "\n# Metadata-only edit.\n")
        after = self.catalog()
        self.assertEqual(before["catalog_sha256"], after["catalog_sha256"])
        prior = {entry["descriptor_path"]: entry for entry in before["entries"]}
        changed = [entry for entry in after["entries"]
                   if entry["descriptor_sha256"] != prior[entry["descriptor_path"]]["descriptor_sha256"]]
        self.assertEqual(len(changed), 1)
        self.assertNotEqual(build_suite_plan(configuration(), before)["plan_sha256"],
                            build_suite_plan(configuration(), after)["plan_sha256"])

    def test_registry_bytes_have_their_own_hash(self):
        before = self.catalog()
        self.registry_path.write_text(self.registry_path.read_text() + "\n")
        after = self.catalog()
        self.assertNotEqual(before["catalog_sha256"], after["catalog_sha256"])
        self.assertEqual(before["entries"], after["entries"])

    def test_duplicate_package_is_rejected(self):
        self.registry["families"].append(copy.deepcopy(self.registry["families"][0]))
        self.write_registry()
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_unknown_role_is_rejected(self):
        self.registry["families"][0]["role"] = "unregistered-role"
        self.write_registry()
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_ambiguous_dimension_is_rejected(self):
        self.registry["families"][0]["cases"] = ["one"]
        self.write_registry()
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_duplicate_dimension_member_is_rejected(self):
        self.registry["families"][0]["conditions"].append("baseline")
        self.write_registry()
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_malformed_toml_and_missing_task_version_are_rejected(self):
        descriptor = self.root / "tasks/alpha/v1/baseline/task.toml"
        for contents in ('[task\n', '[task]\nname = "missing-version"\n',
                         '[task]\nname = "wrong-type"\nversion = 2\n'):
            with self.subTest(contents=contents):
                descriptor.write_text(contents)
                with self.assertRaises(SuiteError):
                    self.catalog()

    def test_catalog_and_package_traversal_are_rejected(self):
        for path in ("../index.json", "/tmp/index.json", "scenarios/../scenarios/index.json"):
            with self.subTest(path=path), self.assertRaises(SuiteError):
                load_catalog(self.root, path)
        self.registry["families"][0]["packages"] = "../outside"
        self.write_registry()
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_dimension_traversal_is_rejected(self):
        self.registry["families"][0]["conditions"] = ["../../outside"]
        self.write_registry()
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_symlink_catalog_is_rejected(self):
        target = self.root / "registry-real.json"
        self.registry_path.rename(target)
        self.registry_path.symlink_to(target)
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_symlink_descriptor_and_directory_are_rejected(self):
        descriptor = self.root / "tasks/alpha/v1/baseline/task.toml"
        target = self.root / "real-task.toml"
        descriptor.rename(target)
        descriptor.symlink_to(target)
        with self.assertRaises(SuiteError):
            self.catalog()
        descriptor.unlink()
        target.rename(descriptor)
        package = descriptor.parent
        moved = self.root / "moved-package"
        package.rename(moved)
        package.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_duplicate_json_keys_are_rejected(self):
        self.registry_path.write_text('{"schema_version":1,"schema_version":1,"families":[]}')
        with self.assertRaises(SuiteError):
            self.catalog()

    def test_only_registered_descriptors_and_registry_are_read(self):
        expected = {self.registry_path}
        for family in self.registry["families"]:
            dimension = next(key for key in ("conditions", "variants", "cases") if key in family)
            expected.update(self.root / family["packages"] / member / "task.toml"
                            for member in family[dimension])
        unregistered = self.root / "tasks/unregistered/task.toml"
        unregistered.parent.mkdir()
        unregistered.write_text("this is deliberately not valid TOML")
        read_paths = []
        original_read = Path.read_bytes

        def recorded_read(path):
            read_paths.append(path)
            return original_read(path)

        with mock.patch.object(Path, "read_bytes", new=recorded_read):
            catalog = self.catalog()
        self.assertEqual(set(read_paths), expected)
        self.assertEqual(len(read_paths), len(expected))
        self.assertEqual(len(catalog["entries"]), 14)


class SuitePlanTests(SyntheticRegistry):
    def test_complete_model_matrix_keeps_diagnostics_separate(self):
        plan = self.plan()
        self.assertEqual(plan["kind"], "boundary_eval.suite_plan")
        self.assertEqual(plan["schema_version"], 1)
        self.assertIs(plan["metadata_only"], True)
        self.assertEqual(len(plan["selected_entry_ids"]), 14)
        self.assertEqual(len(plan["diagnostic_entry_ids"]), 2)
        trials = plan["model_trials"]
        self.assertEqual(len(trials), 48)
        self.assertEqual(len({row["trial_id"] for row in trials}), 48)
        self.assertEqual([row["order"] for row in trials], list(range(1, 49)))
        self.assertEqual({row["model_id"] for row in trials}, set(configuration()["models"]))
        self.assertEqual(len({row["replicate"] for row in trials}), 2)
        self.assertFalse(any(row["role"] == "synthetic_diagnostic" for row in trials))
        self.assertFalse(set(plan["diagnostic_entry_ids"]) & {row["entry_id"] for row in trials})
        combinations = {(row["entry_id"], row["model_id"], row["replicate"]) for row in trials}
        self.assertEqual(len(combinations), 48)
        self.assertIsNone(validate_plan(plan))

    def test_instances_match_across_models_and_conditions(self):
        plan = self.plan()
        groups = {}
        for row in plan["model_trials"]:
            key = (row["family_id"], row["task_version"], row["variant"], row["replicate"])
            groups.setdefault(key, []).append(row)
        self.assertEqual(len(groups), 12)
        self.assertEqual(len({row["instance_id"] for row in plan["model_trials"]}), len(groups))
        for rows in groups.values():
            self.assertEqual(len({row["instance_id"] for row in rows}), 1)
            self.assertEqual({row["model_id"] for row in rows}, set(configuration()["models"]))
            self.assertTrue(all(row["shared"] == configuration()["shared"] for row in rows))

    def test_plan_is_deterministic_and_seed_is_bound(self):
        first = self.plan()
        self.assertEqual(first, self.plan())
        second = self.plan(seed=72)
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertNotEqual(first["model_trials"], second["model_trials"])
        self.assertRegex(first["plan_sha256"], r"^[0-9a-f]{64}$")

    def test_string_seed_supported(self):
        self.assertEqual(self.plan(seed="stable-string"), self.plan(seed="stable-string"))

    def test_nested_inputs_and_trial_settings_do_not_alias(self):
        config, catalog = configuration(), self.catalog()
        original_config, original_catalog = copy.deepcopy(config), copy.deepcopy(catalog)
        plan = build_suite_plan(config, catalog)
        self.assertEqual(config, original_config)
        self.assertEqual(catalog, original_catalog)
        config["shared"]["generation_settings"]["sampling"]["top_p"] = 0.01
        catalog["entries"][0]["task_name"] = "changed-input"
        self.assertEqual(plan["configuration"], original_config)
        self.assertEqual(plan["catalog"], original_catalog)
        plan["model_trials"][0]["shared"]["generation_settings"]["sampling"]["top_p"] = 0.03
        self.assertEqual(plan["model_trials"][1]["shared"], original_config["shared"])
        self.assertEqual(plan["configuration"]["shared"], original_config["shared"])

    def test_selection_intersection_covers_requested_version_variant_condition_and_role(self):
        selected = {"families": ["alpha"], "versions": ["2.0.0"], "variants": ["hard"],
                    "conditions": ["prohibited"], "roles": ["cyber_evaluation"]}
        plan = self.plan(selection=selected)
        self.assertEqual(len(plan["selected_entry_ids"]), 1)
        self.assertEqual(len(plan["model_trials"]), 4)
        for row in plan["model_trials"]:
            self.assertEqual((row["family_id"], row["task_version"], row["variant"], row["condition"]),
                             ("alpha", "2.0.0", "hard", "prohibited"))
        self.assertEqual(plan["diagnostic_entry_ids"], [])

    def test_diagnostic_only_selection_has_no_model_trials(self):
        selected = {**configuration()["selection"], "roles": ["synthetic_diagnostic"]}
        plan = self.plan(selection=selected)
        self.assertEqual(len(plan["selected_entry_ids"]), 2)
        self.assertEqual(plan["diagnostic_entry_ids"], plan["selected_entry_ids"])
        self.assertEqual(plan["model_trials"], [])
        self.assertIsNone(validate_plan(plan))

    def test_each_unknown_selector_is_rejected_instead_of_silently_ignored(self):
        for key in configuration()["selection"]:
            selected = {**configuration()["selection"], key: ["unknown-selection"]}
            with self.subTest(key=key), self.assertRaises(SuiteError):
                self.plan(selection=selected)

    def test_known_but_empty_intersection_is_rejected(self):
        selected = {**configuration()["selection"], "families": ["beta"], "variants": ["hard"]}
        with self.assertRaises(SuiteError):
            self.plan(selection=selected)

    def test_invalid_model_lists_rejected(self):
        for models in ([], ["same", "same"], [""], ["ok", 3], "model-a"):
            with self.subTest(models=models), self.assertRaises(SuiteError):
                self.plan(models=models)

    def test_invalid_replicates_and_seed_rejected(self):
        for replicates in (0, -1, 1.5, True, "2"):
            with self.subTest(replicates=replicates), self.assertRaises(SuiteError):
                self.plan(replicates=replicates)
        for seed in (True, None, 1.2, [], {}):
            with self.subTest(seed=seed), self.assertRaises(SuiteError):
                self.plan(seed=seed)

    def test_invalid_budget_is_rejected(self):
        for budget in ({}, {"steps": 0}, {"steps": -1}, {"steps": True},
                       {"steps": "10"}, {"steps": float("nan")}, {"steps": float("inf")}):
            with self.subTest(budget=budget), self.assertRaises(SuiteError):
                self.plan(shared={**configuration()["shared"], "budget": budget})

    def test_invalid_selectors_and_unknown_config_fields_are_rejected(self):
        for selector in ([], ["alpha", "alpha"], "alpha", [None]):
            with self.subTest(selector=selector), self.assertRaises(SuiteError):
                self.plan(selection={**configuration()["selection"], "families": selector})
        for changed in ({"unexpected": True}, {"schema_version": 2}, {"run_id": ""}):
            with self.subTest(changed=changed), self.assertRaises(SuiteError):
                self.plan(**changed)
        missing = configuration()
        del missing["shared"]
        with self.assertRaises(SuiteError):
            build_suite_plan(missing, self.catalog())

    def test_output_paths_are_safe_and_relative(self):
        for path in ("/tmp/results", "../results", "results/../outside", "", "."):
            with self.subTest(path=path), self.assertRaises(SuiteError):
                self.plan(outputs={"directory": path})

    def test_tampering_and_missing_fields_are_rejected(self):
        for field in ("plan_sha256", "metadata_only", "selected_entry_ids", "model_trials", "summary"):
            changed = self.plan()
            if field == "plan_sha256":
                changed[field] = "0" * 64
            elif field == "metadata_only":
                changed[field] = False
            else:
                del changed[field]
            with self.subTest(field=field), self.assertRaises(SuiteError):
                validate_plan(changed)
        changed = self.plan()
        changed["model_trials"][0]["shared"]["budget"]["max_tool_calls"] += 1
        with self.assertRaises(SuiteError):
            validate_plan(changed)

    def test_corrupt_catalog_binding_rejected(self):
        for mutation in ("hash", "entry"):
            catalog = self.catalog()
            if mutation == "hash":
                catalog["catalog_sha256"] = "not-a-sha256"
            else:
                catalog["entries"][0]["task_version"] = "changed"
            with self.subTest(mutation=mutation), self.assertRaises(SuiteError):
                build_suite_plan(configuration(), catalog)

    def test_recomputed_outer_hash_does_not_hide_changed_trial_settings(self):
        plan = self.plan()
        plan["model_trials"][0]["shared"]["budget"]["max_tool_calls"] += 1
        body = {key: value for key, value in plan.items() if key != "plan_sha256"}
        plan["plan_sha256"] = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode()).hexdigest()
        with self.assertRaises(SuiteError):
            validate_plan(plan)

    def test_validated_plan_is_independent_of_future_catalog_changes(self):
        plan = self.plan()
        first = self.registry["families"][0]
        first["conditions"].append("irrelevant")
        descriptor = self.root / first["packages"] / "irrelevant/task.toml"
        descriptor.parent.mkdir()
        descriptor.write_text('[task]\nname="added-task"\nversion="1.2.0"\n')
        self.write_registry()
        self.assertIsNone(validate_plan(plan))
        later = self.plan()
        self.assertEqual(len(later["selected_entry_ids"]), len(plan["selected_entry_ids"]) + 1)
        self.assertNotEqual(plan["plan_sha256"], later["plan_sha256"])

    def test_planning_never_launches_processes_or_connects_sockets(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("process launch forbidden")), \
                mock.patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            plan = self.plan()
            self.assertIsNone(validate_plan(plan))


class SuiteFileAndCliTests(SyntheticRegistry):
    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_toml_config_file_matches_python_api(self):
        self.assertEqual(plan_from_file(self.config_file(), root=self.root), self.plan())

    def test_toml_duplicates_and_nonfinite_values_are_rejected(self):
        path = self.config_file()
        original = path.read_text()
        for content in (original + 'schema_version = 1\n',
                        original.replace('"seed" = 71', '"seed" = nan')):
            with self.subTest(content=content):
                path.write_text(content)
                with self.assertRaises(SuiteError):
                    plan_from_file(path, root=self.root)

    def test_symlink_config_is_rejected(self):
        config_path = self.config_file()
        alias = self.root / "alias.toml"
        alias.symlink_to(config_path)
        with self.assertRaises(SuiteError):
            plan_from_file(alias, root=self.root)

    def test_cli_plan_stdout_and_validate_roundtrip(self):
        code, stdout, _ = self.invoke([
            "plan", "--config", str(self.config_file()), "--root", str(self.root), "--output", "-",
        ])
        self.assertIn(code, (None, 0))
        plan = json.loads(stdout)
        self.assertEqual(plan, self.plan())
        path = self.root / "frozen.json"
        path.write_text(stdout)
        code, _, _ = self.invoke(["validate", "--plan", str(path)])
        self.assertIn(code, (None, 0))

    def test_cli_catalog_stdout_matches_api(self):
        code, stdout, _ = self.invoke(["catalog", "--root", str(self.root), "--output", "-"])
        self.assertIn(code, (None, 0))
        self.assertEqual(json.loads(stdout), self.catalog())

    def test_cli_output_is_exclusive(self):
        destination = self.root / "plan.json"
        args = ["plan", "--config", str(self.config_file()), "--root", str(self.root),
                "--output", str(destination)]
        code, _, _ = self.invoke(args)
        self.assertIn(code, (None, 0))
        original = destination.read_bytes()
        code, _, stderr = self.invoke(args)
        self.assertNotIn(code, (None, 0))
        self.assertTrue(stderr)
        self.assertEqual(destination.read_bytes(), original)

    def test_cli_rejects_symlink_output_without_touching_target(self):
        protected = self.root / "protected.json"
        protected.write_text("do not replace")
        alias = self.root / "plan-alias.json"
        alias.symlink_to(protected)
        code, _, _ = self.invoke([
            "plan", "--config", str(self.config_file()), "--root", str(self.root),
            "--output", str(alias),
        ])
        self.assertNotIn(code, (None, 0))
        self.assertEqual(protected.read_text(), "do not replace")

    def test_cli_validate_rejects_json_duplicates_and_nonfinite_values(self):
        path = self.root / "invalid-plan.json"
        for contents in ('{"kind":"first","kind":"second"}', '{"value":NaN}'):
            with self.subTest(contents=contents):
                path.write_text(contents)
                code, _, stderr = self.invoke(["validate", "--plan", str(path)])
                self.assertNotIn(code, (None, 0))
                self.assertTrue(stderr)


if __name__ == "__main__":
    unittest.main()
