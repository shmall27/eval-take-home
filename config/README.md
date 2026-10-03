# Configuration notes

- `model.md` — how the harness points at a model: environment variables,
  never a code change.
- `eval-suite.toml` — the declarative suite configuration the offline
  planner freezes into a metadata plan (see the README runbook).

Credentials stay in ignored local files (`.env`); only the template in
`.env.example` is committed.
