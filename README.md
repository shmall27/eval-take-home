# Cathedral boundary evaluations

Harbor task packages for studying authorization-boundary behavior, with separate
measurements for answer correctness, target completion, and boundary activity.

## Evaluation families

| Family | Packages |
| --- | --- |
| Northgate | `tasks/northgate/{condition}` |
| Northgate hard | `tasks/northgate-hard/{condition}` |
| Northgate expert | `tasks/northgate-expert/{condition}` |
| Token Mint | `tasks/token-mint/{condition}` |
| Pivot Chain | `tasks/pivot-chain/{condition}` |
| Pivot Chain hard | `tasks/pivot-chain-hard/{condition}` |
| Pivot Chain expert | `tasks/pivot-chain-expert/{condition}` |
| Twin Bench | `tasks/twin-bench/{condition}` |
| Template Import | `tasks/template-import/{condition}` |
| Dispatch Hijack | `tasks/dispatch-hijack/{condition}` |
| Dispatch Hijack hard | `tasks/dispatch-hijack-hard/{condition}` |
| CRM | `tasks/crm/{explicit,implicit}` |
| Release Controller | `tasks/release-controller/{condition}` |
| Boundary diagnostics | `tasks/boundary-diagnostics/{case}` |

The four-condition families use `baseline`, `irrelevant`, `prohibited`, and
`permitted`. CRM compares two scope wordings and is not a four-condition study.
Each leaf directory is a self-contained Harbor package; the package READMEs
record their usage instructions. `scenarios/index.json` records family roles and
source locations.

## Running

`tasks/` is generated. Every family except CRM is rendered from its
`scenarios/` sources by that family's `render.py`, and boundary-diagnostics is
rendered from `boundary_eval/harbor.py` (`python3 -m boundary_eval.harbor
--output tasks/boundary-diagnostics`); only `tasks/crm` is hand-authored.
Verify the shipped packages are current with each renderer's `--check`:

```sh
python3 -m scenarios.northgate.render --output tasks/northgate --check
python3 -m scenarios.northgate.render --variant hard --output tasks/northgate-hard --check
python3 -m scenarios.northgate.render --variant expert --output tasks/northgate-expert --check
python3 -m scenarios.token_mint.render --output tasks/token-mint --check
python3 -m scenarios.pivot_chain.render --output tasks/pivot-chain --check
python3 -m scenarios.pivot_chain.render --variant hard --output tasks/pivot-chain-hard --check
python3 -m scenarios.pivot_chain.render --variant expert --output tasks/pivot-chain-expert --check
python3 -m scenarios.twin_bench.render --output tasks/twin-bench --check
python3 -m scenarios.template_import.render --output tasks/template-import --check
python3 -m scenarios.dispatch_hijack.render --output tasks/dispatch-hijack --check
python3 -m scenarios.dispatch_hijack.render --variant hard --output tasks/dispatch-hijack-hard --check
python3 -m scenarios.release_controller.render --output tasks/release-controller --check
```

Configure the model provider first: copy `.env.example` to `.env` (gitignored)
and paste your API key into `MODEL_API_KEY` (see [config/model.md](config/model.md)).

Run one package through Harbor:

```sh
harbor run -p tasks/token-mint/prohibited -a terminus-2 -m openrouter/z-ai/glm-5.3
```

A measured comparison goes through the declarative suite: freeze the plan
offline (the planner never launches anything), dry-run it, then execute — the
runner renders attributed per-model packages and records every cell:

```sh
python3 -m boundary_eval.suite plan --config config/eval-suite.toml --output results/suites/open-weight-comparison-v1.plan.json
python3 scripts/run_eval_suite.py --plan results/suites/open-weight-comparison-v1.plan.json --dry-run
python3 scripts/run_eval_suite.py --plan results/suites/open-weight-comparison-v1.plan.json
```

Raw Harbor jobs land under `jobs/` (ignored); attributed packages and the
execution record land under `results/suites/<run_id>/`. The curated oracle
summary is `results/validation.json`, and `scripts/summarize_jobs.py` builds
the propensity ladder for finished job directories.

## Measurement checks

These commands use synthetic records and local files:

```sh
python3 -m unittest tests.test_boundary_contract tests.test_boundary_collection tests.test_boundary_experiment
python3 -m unittest tests.test_northgate_measurement tests.test_scenario_measurement tests.test_collect_northgate_measurements
```

The full test directory also contains service integration tests.

## Repository layout

- `scenarios/`: scenario-specific sources, one package per family.
- `boundary_eval/`: shared contracts, evidence handling, scoring, analysis,
  and the environment realism kit.
- `tasks/`: self-contained Harbor packages, generated as in Running and
  committed deliberately — each package runs in Harbor without a render step;
  only `crm/` is hand-authored.
- `tests/`: shared unit tests, synthetic verifier regressions, and scenario checks.
- `scripts/`: validation, collection, and experiment utilities.
- `docs/`: the realism authoring guide for building a new scenario family.
- `config/`: provider configuration notes; credentials stay in ignored local files.
- `results/validation.json`: curated summary of saved oracle results.
- `results/` otherwise and `jobs/`: ignored working artifacts and raw run outputs.

The Python measurement tooling uses the standard library and Python 3.11 or
newer. Harbor is installed separately. This is a checkout-based project, with
no wheel or registered console entry points.
