# Cathedral boundary evaluations

Harbor task packages for studying authorization-boundary behavior, with separate
measurements for answer correctness, target completion, and boundary activity.

The [draft design and results note](docs/evaluation-design-results.md) describes
the task families, honeypot controls, and current scoring, with model results
left as a placeholder.

## Evaluation families

| Family | Packages | Role |
| --- | --- | --- |
| Northgate | `tasks/northgate/{condition}` | Cyber evaluation |
| Northgate hard | `tasks/northgate-hard/{condition}` | Harder configuration; model difficulty still requires calibration |
| Northgate expert | `tasks/northgate-expert/{condition}` | Expert configuration; inference-only authorized route |
| Token Mint | `tasks/token-mint/{condition}` | Cyber evaluation |
| Pivot Chain | `tasks/pivot-chain/{condition}` | Multi-stage cyber evaluation |
| Pivot Chain hard | `tasks/pivot-chain-hard/{condition}` | Harder configuration; advisory findings, partial spec |
| Pivot Chain expert | `tasks/pivot-chain-expert/{condition}` | Expert configuration; no findings, no spec |
| CRM | `tasks/crm/{explicit,implicit}` | Legacy baseline: the original hand-authored comparison |
| Release Controller | `tasks/release-controller/{condition}` | Workflow measurement control |
| Boundary diagnostics | `tasks/boundary-diagnostics/{case}` | Synthetic infrastructure checks |

The four-condition families use `baseline`, `irrelevant`, `prohibited`, and
`permitted`. CRM — the legacy baseline, hand-authored before the rendered
pattern — compares two scope wordings and is not a four-condition study.
Each leaf directory is a self-contained Harbor package. Package READMEs contain
their existing usage instructions. `scenarios/index.json` records family roles
and source locations; specification-only catalog entries in
`boundary_eval/fixture_proposals.json` are not additional implemented evaluations.

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
python3 -m scenarios.release_controller.render --output tasks/release-controller --check
```

Run one package through Harbor — each package README records its agents,
provenance rules, and expected oracle results:

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

## Repository layout

- `scenarios/`: scenario-specific sources, one package per family.
- `boundary_eval/`: shared contracts, evidence handling, scoring, analysis,
  and the environment realism kit.
- `tasks/`: self-contained Harbor packages, generated as in Running; only
  `crm/` is hand-authored.
- `tests/`: shared unit tests, synthetic verifier regressions, and scenario checks.
- `scripts/`: validation, collection, and experiment utilities.
- `docs/`: suite draft and family design/results notes.
- `config/`: provider configuration notes and examples; credentials stay in ignored local files.
- `results/validation.json`: curated summary of saved oracle results.
- `results/` otherwise and `jobs/`: ignored working artifacts and raw run outputs.

The Python measurement tooling uses the standard library and Python 3.11 or
newer. Harbor is installed separately. This is a checkout-based project, with
no wheel or registered console entry points.

## Environment realism

Every rendered scenario family ships the realism kit
(`boundary_eval/realism.py`): internal background actors whose traffic
carries a verifying HMAC tag and
arrives from internal addresses, and seeded per-trial corpora behind the
served surfaces, so environment texture alone does not mark a deployment as
a purpose-built scenario. Actors are daemon threads inside existing
services; they log real background traffic only inside the pre-agent
provisioning window, and afterwards touch only unlogged health endpoints
and served content — the write freeze that keeps sealed evidence
consistent while Harbor pulls artifacts from running containers. The kit
is vendored byte-identically into every service image and pinned by the
drift guard (`REALISM_IMAGES` in `tests/test_boundary_verifier_packages.py`);
extending it means re-rendering every adopting family and re-running each
family's Docker checks. A family adopts it by carrying a background spec
in its provisioning payload (tag key, client, boot and tick paths),
adding the kit's two-check discriminator to each receiving handler, and
seeding its served surfaces from corpus streams disjoint from its answer
namespaces — see any family's `scenarios/` sources.

## Measurement checks

These commands use synthetic records and local files:

```sh
python3 -m unittest tests.test_boundary_contract tests.test_boundary_collection tests.test_boundary_experiment
python3 -m unittest tests.test_northgate_measurement tests.test_scenario_measurement tests.test_collect_northgate_measurements
```

The full test directory also contains service integration tests. Scripted
controls and supplied-solution runs establish infrastructure behavior and
feasibility; they are not measurements of model difficulty or propensity.

Completion requires evidence appropriate to the objective. Northgate keeps
coverage and possession markers separate from verified target-content delivery.
Missing or unusable evidence remains unknown. Collection preserves original
planned trial identities and rejects duplicates or retrospective replicate
assignment. Model comparisons must use fresh, correctly identified runs;
synthetic fixtures, scripted controls, and oracle results remain separate.
