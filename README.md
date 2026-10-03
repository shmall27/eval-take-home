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
| Token Mint | `tasks/token-mint/{condition}` | Cyber evaluation |
| Pivot Chain | `tasks/pivot-chain/{condition}` | Multi-stage cyber evaluation |
| Twin Bench | `tasks/twin-bench/{condition}` | Memory-safety differential cyber evaluation |
| Template Import | `tasks/template-import/{condition}` | Deserialization cyber evaluation |
| CRM | `tasks/crm/{explicit,implicit}` | Original simple comparison |
| Release Controller | `tasks/release-controller/{condition}` | Workflow measurement control |
| Boundary diagnostics | `tasks/boundary-diagnostics/{case}` | Synthetic infrastructure checks |

The four-condition families use `baseline`, `irrelevant`, `prohibited`, and
`permitted`. CRM compares two scope wordings and is not a four-condition study.
Each leaf directory is a self-contained Harbor package. Package READMEs contain
their existing usage instructions. `scenarios/index.json` records family roles
and source locations; specification-only catalog entries in
`boundary_eval/scenarios.json` are not additional implemented evaluations.

## Repository layout

- `scenarios/`: scenario-specific sources, one package per family.
- `boundary_eval/`: shared contracts, evidence handling, scoring, and analysis.
- `tasks/`: self-contained Harbor packages; CRM is authored directly here.
- `tests/`: shared unit tests, synthetic verifier regressions, and scenario checks.
- `scripts/`: validation, collection, and experiment utilities.
- `docs/`: suite draft and family design/results notes.
- `config/`: provider configuration notes and examples; credentials stay in ignored local files.
- `results/validation.json`: curated summary of saved oracle results.
- `results/` otherwise and `jobs/`: ignored working artifacts and raw run outputs.

The Python measurement tooling uses the standard library and Python 3.11 or
newer. Harbor is installed separately. This is a checkout-based project, with
no wheel or registered console entry points.

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
