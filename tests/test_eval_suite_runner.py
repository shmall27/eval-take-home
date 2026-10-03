"""Offline checks on the suite executor; no models, services or Harbor runs."""

import contextlib
import importlib.util
import io
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from boundary_eval.suite import build_suite_plan, load_catalog

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "run_eval_suite", ROOT / "scripts" / "run_eval_suite.py")
runner = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(runner)

DESCRIPTOR = """[task]
name = "cathedral/{name}"
version = "1.0.0"

[agent]
timeout_sec = {timeout}
"""


def make_tree(root, *, gamma_timeout=600.0):
    """A synthetic project tree: one rendered family with two conditions, one
    dial family rendered from a variant source, one hand-authored family,
    and a family whose descriptor declares a short timeout."""
    root = Path(root)
    (root / "scenarios").mkdir(parents=True)
    for source in ("alpha", "pivot_chain"):
        (root / "scenarios" / source).mkdir()
        (root / "scenarios" / source / "render.py").write_text("# stub\n")
    registry = {"schema_version": 1, "families": [
        {"id": "alpha", "role": "cyber_evaluation", "source": "scenarios/alpha",
         "packages": "tasks/alpha", "conditions": ["baseline", "prohibited"]},
        {"id": "pivot-chain-hard", "role": "cyber_evaluation",
         "source": "scenarios/pivot_chain", "variant": "hard",
         "packages": "tasks/pivot-chain-hard", "conditions": ["baseline"]},
        {"id": "bravo", "role": "simple_comparison", "source": "tasks/bravo",
         "packages": "tasks/bravo", "variants": ["explicit"],
         "source_format": "hand-authored Harbor packages"},
        {"id": "gamma", "role": "cyber_evaluation", "source": "scenarios/alpha",
         "packages": "tasks/gamma", "conditions": ["baseline"]},
    ]}
    (root / "scenarios" / "index.json").write_text(json.dumps(registry))
    for family, part in (("alpha", "baseline"), ("alpha", "prohibited"),
                         ("pivot-chain-hard", "baseline"), ("bravo", "explicit"),
                         ("gamma", "baseline")):
        package = root / "tasks" / family / part
        package.mkdir(parents=True)
        timeout = gamma_timeout if family == "gamma" else 600.0
        package.joinpath("task.toml").write_text(
            DESCRIPTOR.format(name=f"{family}-{part}", timeout=timeout))
    (root / ".env").write_text("OPENROUTER_API_KEY=sk-test-123\n"
                               "MODEL_BASE_URL=https://openrouter.example/api/v1\n")
    return root


def make_plan(root, **config_updates):
    config = {
        "schema_version": 1, "run_id": "synthetic-exec-check", "seed": 71,
        "replicates": 2, "catalog": "scenarios/index.json",
        "models": ["z-ai/glm-5.3"],
        "selection": {"families": "all", "versions": "all", "variants": "all",
                      "conditions": "all", "roles": "all"},
        "shared": {
            "agent_version": "harbor-9.9.9/terminus-2",
            "generation_settings": {"temperature": 0.3},
            "budget": {"wall_clock_seconds": 300, "max_tool_calls": 40,
                       "max_output_tokens_per_call": 8192},
            "evidence_expectations": {"complete_service_logs": True},
        },
        "outputs": {"directory": "results/suites"},
    }
    config.update(config_updates)
    return build_suite_plan(config, load_catalog(root, config["catalog"]))


class SyntheticTree(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = make_tree(self.temporary.name)
        self.plan = make_plan(self.root)
        self.entries = {entry["entry_id"]: entry
                        for entry in self.plan["catalog"]["entries"]}

    def cell(self, family, condition=None):
        for candidate in runner.select_cells(self.plan):
            entry = candidate["entry"]
            if entry["family_id"] == family and (condition is None
                                                 or entry["condition"] == condition):
                candidate["source"] = {
                    "alpha": "scenarios/alpha",
                    "pivot-chain-hard": "scenarios/pivot_chain",
                    "bravo": "tasks/bravo", "gamma": "scenarios/alpha"}[family]
                return candidate
        raise AssertionError(f"no cell for family {family}")


class PlanAndCatalogTests(SyntheticTree):
    def test_read_plan_accepts_a_frozen_plan(self):
        path = self.root / "plan.json"
        path.write_text(json.dumps(self.plan))
        loaded = runner.read_plan(path)
        self.assertEqual(loaded["plan_sha256"], self.plan["plan_sha256"])

    def test_read_plan_rejects_tampering(self):
        tampered = json.loads(json.dumps(self.plan))
        tampered["configuration"]["replicates"] = 3
        path = self.root / "plan.json"
        path.write_text(json.dumps(tampered))
        with self.assertRaises(runner.SuiteExecutionError):
            runner.read_plan(path)

    def test_fresh_catalog_verifies_registry_and_descriptors(self):
        sources, descriptors = runner.fresh_catalog(self.root, self.plan)
        self.assertEqual(sources["alpha"], "scenarios/alpha")
        self.assertEqual(len(descriptors), 5)
        first = self.plan["catalog"]["entries"][0]["descriptor_path"]
        (self.root / first).write_text("[task]\nname = 'x'\nversion = '1.0.0'\n")
        with self.assertRaises(runner.SuiteExecutionError):
            runner.fresh_catalog(self.root, self.plan)

    def test_fresh_catalog_rejects_a_changed_registry(self):
        (self.root / "scenarios" / "index.json").write_text(
            (self.root / "scenarios" / "index.json").read_text() + "\n")
        with self.assertRaises(runner.SuiteExecutionError):
            runner.fresh_catalog(self.root, self.plan)

    def test_descriptor_timeout_is_parsed_and_required(self):
        data = (self.root / "tasks" / "alpha" / "baseline" / "task.toml").read_bytes()
        self.assertEqual(runner.agent_timeout_sec(data, "x"), 600.0)
        with self.assertRaises(runner.SuiteExecutionError):
            runner.agent_timeout_sec(b"[task]\nname = 'x'\nversion = '1'\n", "x")


class SettingsTests(unittest.TestCase):
    def test_declared_settings_map_to_runtime_knobs(self):
        shared = {"generation_settings": {"temperature": 0.3},
                  "budget": {"wall_clock_seconds": 300, "max_tool_calls": 40,
                             "max_output_tokens_per_call": 8192}}
        agent_args, wall_clock, unapplied = runner.resolve_settings(
            shared, allow_unapplied=True)
        self.assertEqual(agent_args, [["--ak", "temperature=0.3"],
                                      ["--ak", "max_turns=40"]])
        self.assertEqual(wall_clock, 300.0)
        self.assertEqual(unapplied, ["budget.max_output_tokens_per_call"])

    def test_unmappable_settings_fail_closed(self):
        shared = {"generation_settings": {}, "budget": {"max_output_tokens_per_call": 8}}
        with self.assertRaises(runner.SuiteExecutionError) as caught:
            runner.resolve_settings(shared, allow_unapplied=False)
        self.assertIn("--allow-unapplied-settings", str(caught.exception))

    def test_agent_version_splits_and_validates(self):
        self.assertEqual(runner.split_agent_version({"agent_version":
                                                    "harbor-0.23.0/terminus-2"}),
                         ("0.23.0", "terminus-2"))
        for bad in ("terminus-2", "harbor-0.23.0/", "harbor/terminus-2"):
            with self.assertRaises(runner.SuiteExecutionError):
                runner.split_agent_version({"agent_version": bad})

    def test_harbor_version_mismatch_fails_closed(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="harbor 0.1.0\n")
            with self.assertRaises(runner.SuiteExecutionError):
                runner.check_harbor_version("harbor", "0.23.0")
        with mock.patch("subprocess.run") as run:
            runner.check_harbor_version("harbor", "0.23.0", skip=True)
            run.assert_not_called()


class CellSelectionTests(SyntheticTree):
    def test_cells_preserve_plan_order_and_replicates(self):
        cells = runner.select_cells(self.plan)
        self.assertEqual(len(cells), 5)
        first_seen = []
        for trial in self.plan["model_trials"]:
            key = (trial["model_id"], trial["entry_id"])
            if key not in first_seen:
                first_seen.append(key)
        self.assertEqual([(c["model_id"], c["entry"]["entry_id"]) for c in cells],
                         first_seen)
        for cell in cells:
            self.assertEqual(cell["replicates"], 2)
            self.assertEqual(len(cell["trial_ids"]), 2)

    def test_filters_select_whole_cells(self):
        cells = runner.select_cells(self.plan, conditions={"baseline"})
        self.assertEqual({c["entry"]["family_id"] for c in cells},
                         {"alpha", "pivot-chain-hard", "gamma"})
        cells = runner.select_cells(self.plan, variants={"hard"})
        self.assertEqual({c["entry"]["family_id"] for c in cells},
                         {"pivot-chain-hard"})
        cells = runner.select_cells(self.plan, models={"z-ai/glm-5.3"},
                                    families={"bravo"})
        self.assertEqual(len(cells), 1)

    def test_unwired_model_fails_closed(self):
        plan = make_plan(self.root, models=["z-ai/glm-5.3", "prov/ghost-model"])
        with self.assertRaises(runner.SuiteExecutionError) as caught:
            runner.select_cells(plan)
        self.assertIn("no Harbor wiring", str(caught.exception))

    def test_partial_replicate_set_is_rejected(self):
        plan = json.loads(json.dumps(self.plan))
        for trial in list(plan["model_trials"]):
            if trial["entry_id"] == plan["model_trials"][0]["entry_id"]:
                plan["model_trials"].remove(trial)
                break
        with self.assertRaises(runner.SuiteExecutionError):
            runner.select_cells(plan)

    def test_max_cells_truncates(self):
        self.assertEqual(len(runner.select_cells(self.plan, max_cells=2)), 2)


@mock.patch.object(runner, "harbor_binary", return_value="harbor")
class CommandConstructionTests(SyntheticTree):
    def commands(self, cell, *, allow_unattributed=False):
        agent_args, wall_clock, _ = runner.resolve_settings(
            self.plan["configuration"]["shared"], allow_unapplied=True)
        descriptors = {entry["descriptor_path"]:
                       (self.root / entry["descriptor_path"]).read_bytes()
                       for entry in self.plan["catalog"]["entries"]}
        return runner.cell_commands(self.root, self.plan, cell, agent_args,
                                    wall_clock, descriptors,
                                    allow_unattributed=allow_unattributed)

    def test_rendered_cell_commands(self, _binary):
        commands = self.commands(self.cell("alpha", condition="baseline"))
        self.assertTrue(commands["attributed"])
        self.assertEqual(commands["job_name"],
                         "synthetic-exec-check-glm53-alpha-baseline")
        render = commands["render_argv"]
        self.assertEqual(render[:4], [sys.executable, "-m", "scenarios.alpha.render",
                                      "--output"])
        self.assertIn("--conditions", render)
        self.assertEqual(render[render.index("--conditions") + 1], "baseline")
        self.assertEqual(render[render.index("--actor-kind") + 1], "model")
        self.assertEqual(render[render.index("--model-id") + 1], "z-ai/glm-5.3")
        self.assertEqual(render[render.index("--plan-sha256") + 1],
                         self.plan["plan_sha256"])
        self.assertEqual(render[render.index("--run-id") + 1],
                         self.plan["configuration"]["run_id"])
        self.assertTrue(commands["package"].endswith(
            "results/suites/synthetic-exec-check/packages/glm53/alpha/baseline"))
        harbor = commands["harbor_argv"]
        self.assertIn("openrouter/z-ai/glm-5.3", harbor)
        self.assertEqual(harbor[harbor.index("-k") + 1], "2")
        self.assertIn(["--ak", "temperature=0.3"],
                      [harbor[i:i + 2] for i in range(len(harbor))])
        self.assertIn(["--ak", "max_turns=40"],
                      [harbor[i:i + 2] for i in range(len(harbor))])
        self.assertEqual(harbor[harbor.index("--agent-timeout-multiplier") + 1],
                         "0.5000")
        self.assertNotIn("sk-test-123", json.dumps(harbor))
        self.assertNotIn("OPENROUTER", json.dumps(harbor))

    def test_variant_family_passes_the_variant_flag(self, _binary):
        render = self.commands(self.cell("pivot-chain-hard"))["render_argv"]
        self.assertEqual(render[1:3], ["-m", "scenarios.pivot_chain.render"])
        self.assertEqual(render[render.index("--variant") + 1], "hard")

    def test_variant_sources_name_every_dial_family(self, _binary):
        self.assertEqual(runner.VARIANT_RENDER_SOURCES,
                         ("scenarios/northgate", "scenarios/pivot_chain"))

    def test_handauthored_family_fails_closed_then_escapes(self, _binary):
        cell = self.cell("bravo")
        with self.assertRaises(runner.SuiteExecutionError) as caught:
            self.commands(cell)
        self.assertIn("--allow-unattributed-packages", str(caught.exception))
        commands = self.commands(cell, allow_unattributed=True)
        self.assertFalse(commands["attributed"])
        self.assertIsNone(commands["render_argv"])
        self.assertTrue(commands["package"].endswith("tasks/bravo/explicit"))
        self.assertEqual(commands["job_name"],
                         "synthetic-exec-check-glm53-bravo-explicit")

    def test_multiplier_out_of_range_fails(self, _binary):
        gamma = self.root / "tasks" / "gamma" / "baseline" / "task.toml"
        gamma.write_text(DESCRIPTOR.format(name="gamma-baseline", timeout=10))
        with self.assertRaises(runner.SuiteExecutionError):
            self.commands(self.cell("gamma"))

    def test_resume_and_record_primitives(self, _binary):
        jobs = self.root / "jobs"
        name = "synthetic-exec-check-glm53-alpha-baseline"
        self.assertFalse(runner.job_finished(jobs, name))
        (jobs / name).mkdir(parents=True)
        # Harbor writes result.json at job start; a null finish is not done.
        (jobs / name / "result.json").write_text(
            json.dumps({"finished_at": None, "n_total_trials": 2}))
        self.assertFalse(runner.job_finished(jobs, name))
        (jobs / name / "result.json").write_text(
            json.dumps({"finished_at": "2026-10-02T19:52:45"}))
        self.assertTrue(runner.job_finished(jobs, name))
        record = self.root / "execution.jsonl"
        runner.write_record(record, {"status": "ran", "secret_free": True})
        runner.write_record(record, {"status": "skipped"})
        lines = [json.loads(line) for line in record.read_text().splitlines()]
        self.assertEqual([line["status"] for line in lines], ["ran", "skipped"])


class ProbeTests(SyntheticTree):
    def test_probe_success_and_failure(self):
        environment = runner.credentials("z-ai/glm-5.3", root=self.root)
        self.assertEqual(environment["OPENROUTER_API_KEY"], "sk-test-123")

        class Response:
            status = 200

            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch("urllib.request.urlopen", return_value=Response()):
            self.assertTrue(runner.probe_model("z-ai/glm-5.3", environment,
                                               root=self.root))
        with mock.patch("urllib.request.urlopen",
                        side_effect=urllib.error.URLError("down")):
            self.assertFalse(runner.probe_model("z-ai/glm-5.3", environment,
                                                root=self.root))
        self.assertFalse(runner.probe_model(
            "z-ai/glm-5.3", environment, root=self.root,
            probe_fn=lambda request, timeout: False))

    def test_missing_credentials_fail_closed(self):
        (self.root / ".env").write_text("MODEL_BASE_URL=https://x.example\n")
        with self.assertRaises(runner.SuiteExecutionError):
            runner.credentials("z-ai/glm-5.3", root=self.root)


class MainExecutionTests(SyntheticTree):
    def setUp(self):
        super().setUp()
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_text(json.dumps(self.plan))
        self.jobs = self.root / "jobs"
        self.record = (self.root / "results" / "suites"
                       / "synthetic-exec-check" / "execution.jsonl")

    def fake_subprocess(self, *, harbor_code=0, render_codes=None):
        render_codes = render_codes or {}
        self.harbor_packages = []
        self.calls = []

        def run(argv, **kwargs):
            self.calls.append(list(argv))
            if argv[1:2] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="harbor 9.9.9\n")
            if argv[1:2] == ["-m"]:
                output = argv[argv.index("--output") + 1]
                for suffix, code in render_codes.items():
                    if suffix in output:
                        return subprocess.CompletedProcess(argv, code)
                return subprocess.CompletedProcess(argv, 0)
            if argv[1:2] == ["run"]:
                self.harbor_packages.append(argv[argv.index("-p") + 1])
                return subprocess.CompletedProcess(argv, harbor_code)
            raise AssertionError(f"unexpected subprocess call: {argv[:3]}")

        return run

    def invoke(self, *extra, **kwargs):
        argv = ["--plan", str(self.plan_path), "--skip-preflight"] + list(extra)
        with mock.patch.object(runner, "harbor_binary", return_value="harbor"), \
                mock.patch("subprocess.run", side_effect=self.fake_subprocess(**kwargs)), \
                mock.patch("subprocess.Popen",
                           side_effect=AssertionError("process launch forbidden")), \
                mock.patch("socket.socket.connect",
                           side_effect=AssertionError("network forbidden")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = runner.main(argv, root=self.root)
        return code, output.getvalue()

    def test_dry_run_resolves_without_executing(self):
        code, output = self.invoke("--dry-run", "--allow-unapplied-settings",
                                   "--allow-unattributed-packages")
        self.assertEqual(code, 0)
        self.assertEqual(output.count("harbor:"), 5)
        self.assertEqual(output.count("render:"), 5)
        self.assertIn("UNATTRIBUTED", output)
        self.assertFalse(self.record.exists())
        self.assertEqual([argv[1] for argv in self.calls], ["--version"])

    def test_execution_renders_runs_and_records(self):
        code, output = self.invoke("--allow-unapplied-settings",
                                    "--allow-unattributed-packages")
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual(len(records), 5)
        self.assertEqual({record["status"] for record in records}, {"ran"})
        self.assertNotIn("sk-test-123", self.record.read_text())
        self.assertNotIn("OPENROUTER_API_KEY", self.record.read_text())

    def test_harbor_receives_credentials_only_through_the_environment(self):
        harbor_env = {}

        def run(argv, **kwargs):
            if argv[1:2] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="harbor 9.9.9\n")
            if argv[1:2] == ["run"]:
                harbor_env.update(kwargs.get("env") or {})
                return subprocess.CompletedProcess(argv, 0)
            return subprocess.CompletedProcess(argv, 0)

        argv = ["--plan", str(self.plan_path), "--skip-preflight",
                "--allow-unapplied-settings", "--allow-unattributed-packages",
                "--family", "alpha", "--max-cells", "1"]
        with mock.patch.object(runner, "harbor_binary", return_value="harbor"), \
                mock.patch("subprocess.run", side_effect=run):
            runner.main(argv, root=self.root)
        self.assertEqual(harbor_env.get("OPENROUTER_API_KEY"), "sk-test-123")
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual(len(records), 1)

    def test_resume_skips_finished_jobs(self):
        cells = runner.select_cells(self.plan)
        name = "synthetic-exec-check-glm53-" + runner.cell_slug(cells[0]["entry"])
        (self.jobs / name).mkdir(parents=True)
        (self.jobs / name / "result.json").write_text(
            json.dumps({"finished_at": "2026-10-02T19:52:45"}))
        code, _ = self.invoke("--allow-unapplied-settings",
                              "--allow-unattributed-packages")
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        statuses = {record["job_name"]: record["status"] for record in records}
        self.assertEqual(statuses[name], "skipped")
        self.assertEqual(sorted(statuses.values()).count("ran"), 4)

    def test_harbor_failure_records_and_continues(self):
        code, output = self.invoke("--allow-unapplied-settings",
                                    "--allow-unattributed-packages",
                                    harbor_code=1)
        self.assertEqual(code, 1)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual({record["status"] for record in records},
                         {"harbor-failed"})
        self.assertTrue(all(record["returncode"] == 1 for record in records))

    def test_stop_on_failure_halts_the_suite(self):
        code, _ = self.invoke("--allow-unapplied-settings",
                              "--allow-unattributed-packages",
                              "--stop-on-failure", harbor_code=1)
        self.assertEqual(code, 1)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual(len(records), 1)

    def test_render_failure_never_reaches_harbor(self):
        code, _ = self.invoke("--allow-unapplied-settings",
                              "--allow-unattributed-packages",
                              render_codes={"/glm53/alpha": 2})
        self.assertEqual(code, 1)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual({record["status"] for record in records},
                         {"render-failed", "ran"})
        self.assertEqual(
            sorted(record["status"] for record in records).count("render-failed"), 2)
        self.assertTrue(all("/alpha/" not in package
                            for package in self.harbor_packages))

    def test_unattributed_family_requires_the_flag(self):
        with self.assertRaises(runner.SuiteExecutionError) as caught:
            self.invoke("--allow-unapplied-settings")
        self.assertIn("--allow-unattributed-packages", str(caught.exception))

    def test_unmappable_settings_require_acknowledgment(self):
        with self.assertRaises(runner.SuiteExecutionError) as caught:
            self.invoke("--allow-unattributed-packages")
        self.assertIn("--allow-unapplied-settings", str(caught.exception))

    def test_unsupported_agent_fails_closed(self):
        plan = make_plan(self.root, shared={
            "agent_version": "harbor-9.9.9/codex",
            "generation_settings": {"temperature": 0.3},
            "budget": {"wall_clock_seconds": 300, "max_tool_calls": 40,
                       "max_output_tokens_per_call": 8192},
            "evidence_expectations": {"complete_service_logs": True},
        })
        self.plan_path.write_text(json.dumps(plan))
        with self.assertRaises(runner.SuiteExecutionError):
            self.invoke("--allow-unapplied-settings", "--allow-unattributed-packages")

    def test_retries_recover_a_transient_harbor_failure(self):
        attempts = {"n": 0}

        def run(argv, **kwargs):
            if argv[1:2] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="harbor 9.9.9\n")
            if argv[1:2] == ["run"]:
                attempts["n"] += 1
                return subprocess.CompletedProcess(argv, 0 if attempts["n"] >= 2 else 1)
            return subprocess.CompletedProcess(argv, 0)

        argv = ["--plan", str(self.plan_path), "--skip-preflight",
                "--allow-unapplied-settings", "--allow-unattributed-packages",
                "--family", "bravo", "--max-cells", "1", "--retries", "2"]
        with mock.patch.object(runner, "harbor_binary", return_value="harbor"), \
                mock.patch("subprocess.run", side_effect=run), \
                mock.patch("time.sleep"), \
                contextlib.redirect_stdout(io.StringIO()):
            code = runner.main(argv, root=self.root)
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "ran")
        self.assertEqual(records[0]["attempts"], 2)

    def test_retries_exhaust_then_record_the_failure(self):
        def run(argv, **kwargs):
            if argv[1:2] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="harbor 9.9.9\n")
            if argv[1:2] == ["run"]:
                return subprocess.CompletedProcess(argv, 1)
            return subprocess.CompletedProcess(argv, 0)

        argv = ["--plan", str(self.plan_path), "--skip-preflight",
                "--allow-unapplied-settings", "--allow-unattributed-packages",
                "--family", "bravo", "--max-cells", "1", "--retries", "1"]
        with mock.patch.object(runner, "harbor_binary", return_value="harbor"), \
                mock.patch("subprocess.run", side_effect=run), \
                mock.patch("time.sleep") as sleep, \
                contextlib.redirect_stdout(io.StringIO()):
            code = runner.main(argv, root=self.root)
        self.assertEqual(code, 1)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual(records[0]["status"], "harbor-failed")
        self.assertEqual(records[0]["attempts"], 2)
        self.assertEqual(sleep.call_count, 1)

    def test_invalid_parallelism_fails_closed(self):
        for flag, value in (("--max-parallel-cells", "0"),
                            ("--max-parallel-per-model", "0"),
                            ("--retries", "-1")):
            with self.assertRaises(runner.SuiteExecutionError):
                self.invoke("--allow-unapplied-settings",
                            "--allow-unattributed-packages", flag, value)


class ParallelExecutionTests(SyntheticTree):
    """The concurrent scheduler: caps, isolation, and failure handling."""

    def setUp(self):
        super().setUp()
        self.plan = make_plan(
            self.root, models=["z-ai/glm-5.3", "deepseek/deepseek-v4-pro-0813"])
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_text(json.dumps(self.plan))
        self.record = (self.root / "results" / "suites"
                       / "synthetic-exec-check" / "execution.jsonl")

    def run_main(self, run, *extra):
        argv = ["--plan", str(self.plan_path), "--skip-preflight",
                "--allow-unapplied-settings",
                "--allow-unattributed-packages"] + list(extra)
        with mock.patch.object(runner, "harbor_binary", return_value="harbor"), \
                mock.patch("subprocess.run", side_effect=run), \
                mock.patch("subprocess.Popen",
                           side_effect=AssertionError("process launch forbidden")), \
                contextlib.redirect_stdout(io.StringIO()):
            return runner.main(argv, root=self.root)

    def test_parallel_runs_every_cell_within_caps(self):
        live = {"cur": 0, "peak": 0}
        model_cur = {}
        model_peak = {}
        lock = threading.Lock()

        def run(argv, **kwargs):
            if argv[1:2] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="harbor 9.9.9\n")
            if argv[1:2] != ["run"]:
                return subprocess.CompletedProcess(argv, 0)
            model = argv[argv.index("-m") + 1]
            with lock:
                live["cur"] += 1
                live["peak"] = max(live["peak"], live["cur"])
                model_cur[model] = model_cur.get(model, 0) + 1
                model_peak[model] = max(model_peak.get(model, 0), model_cur[model])
            time.sleep(0.03)
            with lock:
                live["cur"] -= 1
                model_cur[model] -= 1
            return subprocess.CompletedProcess(argv, 0)

        code = self.run_main(run, "--max-parallel-cells", "4",
                             "--max-parallel-per-model", "2")
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual(len(records), 10)             # 5 entries x 2 models
        self.assertEqual({record["status"] for record in records}, {"ran"})
        self.assertGreater(live["peak"], 1)            # genuinely parallel
        self.assertLessEqual(live["peak"], 4)          # total cap honored
        self.assertTrue(all(peak <= 2 for peak in model_peak.values()))
        self.assertEqual(set(model_peak),
                         {"openrouter/z-ai/glm-5.3",
                          "openrouter/deepseek/deepseek-v4-pro-0813"})

    def test_parallel_continues_past_failures_and_lists_them(self):
        def run(argv, **kwargs):
            if argv[1:2] == ["--version"]:
                return subprocess.CompletedProcess(argv, 0, stdout="harbor 9.9.9\n")
            if argv[1:2] == ["run"]:
                failed_model = "deepseek" in argv[argv.index("-m") + 1]
                return subprocess.CompletedProcess(argv, 1 if failed_model else 0)
            return subprocess.CompletedProcess(argv, 0)

        code = self.run_main(run, "--max-parallel-cells", "4")
        self.assertEqual(code, 1)
        records = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual(len(records), 10)
        counts = {}
        for record in records:
            counts[record["status"]] = counts.get(record["status"], 0) + 1
        self.assertEqual(counts.get("ran"), 5)
        self.assertEqual(counts.get("harbor-failed"), 5)


if __name__ == "__main__":
    unittest.main()
