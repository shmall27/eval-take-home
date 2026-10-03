#!/usr/bin/env python3
"""Run northgate matched boundary-evaluation cells with a model agent.

Reads the pre-registered experiment plan (boundary_eval.experiment.build_plan
output), renders one honestly attributed package copy per planned model —
actor_kind=model with the model id, the plan fingerprint and the plan run id
baked into the compose provenance — then runs each selected condition as one
Harbor job of as many attempts as the plan schedules replicates.

Example:
  python3 scripts/run_northgate_matrix.py --plan results/northgate-eval1/plan.json

Provider credentials come from the local env files and are passed through
the Harbor process environment, never argv (the same rule as
scripts/run_abliteration_harbor.py): glm53 reads OPENROUTER_API_KEY from
.env; abliterated reads .env.abliteration and speaks to the abliteration
API over its openai-compatible endpoint. Jobs run serially per invocation;
each condition gets its own job name so per-cell outputs land under
jobs/<run-id>-<model>-<condition>/.

Standard library only.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from provider_smoke import load_config  # noqa: E402

CONDITIONS = ("baseline", "irrelevant", "prohibited", "permitted")

# Plan model_id -> how Harbor reaches it: the Harbor model string, the env
# file holding its credentials, the key's name in that file and the name
# Harbor's provider reads, the openai-compatible api_base override when the
# provider is not OpenRouter/OpenAI, and how many trials to run at once (the
# abliteration endpoint handled one at a time in earlier families).
MODELS = {
    "z-ai/glm-5.3": {
        "job_key": "glm53",
        "harbor_model": "openrouter/z-ai/glm-5.3",
        "env_file": ".env",
        "key_name": "OPENROUTER_API_KEY",
        "export_as": "OPENROUTER_API_KEY",
        "api_base": None,
        "concurrency": 3,
    },
    "abliterated-model": {
        "job_key": "abliterated",
        "harbor_model": "openai/abliterated-model",
        "env_file": ".env.abliteration",
        "key_name": "MODEL_API_KEY",
        "export_as": "OPENAI_API_KEY",
        "api_base": "https://api.abliteration.ai/v1",
        "concurrency": 1,
    },
}


def credentials(model_id):
    """Load and validate one model's credentials; returns the child env."""
    spec = MODELS[model_id]
    config = load_config(ROOT / spec["env_file"])
    key = config.get(spec["key_name"], "")
    if not key:
        raise SystemExit(f"{model_id}: missing {spec['key_name']} in {spec['env_file']}")
    base = spec["api_base"]
    if base is not None:
        parsed = urlsplit(base)
        if parsed.scheme != "https" or parsed.hostname != "api.abliteration.ai":
            raise SystemExit(f"{model_id}: expected the abliteration HTTPS endpoint, "
                             f"got {base!r}")
    environment = dict(os.environ)
    environment[spec["export_as"]] = key
    return environment


def render_copy(model_id, plan, output):
    """Render this model's attributed package copy (idempotent)."""
    command = [sys.executable, "-m", "scenarios.northgate.render",
               "--output", str(output),
               "--actor-kind", "model",
               "--model-id", model_id,
               "--plan-sha256", plan["plan_sha256"],
               "--run-id", plan["run_id"]]
    print(" ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode:
        raise SystemExit(f"render for {model_id} failed ({result.returncode})")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", type=Path, required=True,
                        help="boundary_eval experiment plan (build_plan output)")
    parser.add_argument("--model", action="append",
                        help="plan model_id to run; default: all planned models")
    parser.add_argument("--condition", action="append", choices=CONDITIONS,
                        help="default: all four")
    parser.add_argument("--attempts", type=int,
                        help="Harbor attempts per condition (default: the plan's replicates)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text())
    replicates = plan["configuration"]["replicates"]
    attempts = args.attempts if args.attempts is not None else replicates
    if attempts != replicates:
        raise SystemExit(f"attempts ({attempts}) must match the plan's replicates "
                         f"({replicates}); the plan is the schedule of record")
    planned_models = plan["configuration"]["models"]
    models = args.model or planned_models
    unknown = set(models) - set(planned_models)
    if unknown:
        raise SystemExit(f"model(s) not in the plan: {', '.join(sorted(unknown))}")
    unconfigured = set(models) - set(MODELS)
    if unconfigured:
        raise SystemExit(f"model(s) without Harbor wiring: {', '.join(sorted(unconfigured))}")
    conditions = args.condition or list(CONDITIONS)

    failed = []
    for model_id in models:
        environment = credentials(model_id)
        package_root = ROOT / "results" / f"northgate-{MODELS[model_id]['job_key']}"
        render_copy(model_id, plan, package_root)
        for condition in conditions:
            package = package_root / condition
            name = f"{plan['run_id']}-{MODELS[model_id]['job_key']}-{condition}"
            command = ["harbor", "run", "-p", str(package), "-a", "terminus-2",
                       "-m", MODELS[model_id]["harbor_model"],
                       "-k", str(attempts),
                       "-n", str(MODELS[model_id]["concurrency"]),
                       "--yes", "--job-name", name]
            if MODELS[model_id]["api_base"]:
                command += ["--ak", f"api_base={MODELS[model_id]['api_base']}"]
            print(" ".join(command), flush=True)
            if args.dry_run:
                continue
            result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
            if result.returncode:
                failed.append(name)
    if failed:
        print("Failed jobs:", ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
