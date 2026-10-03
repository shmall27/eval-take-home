# Configuration notes

- `model.md` — how the harness points at a model: environment variables,
  never a code change.
- `model-selection.md` — the recorded model-selection decision (GLM-5.3,
  refusal scored as a distinct outcome).
- `eval-suite.toml` — the declarative suite configuration the offline
  planner freezes into a metadata plan (see the README runbook).
- `abliteration.md` / `abliteration.env.example` — connectivity notes and
  credential template for the abliteration provider. This line of work is
  parked on hold and is not part of the current evaluation flow; the notes
  are kept so the work can resume without re-deriving the endpoint details.

Credentials stay in ignored local files (`.env`, `.env.abliteration`); only
templates are committed.
