# cathedral-take-home

AI cyber-capability evaluation harness (take-home for Cathedral).

## Architecture

The eval uses proven, standard tooling so it measures the **model**, not a
bespoke scaffold:

- **Agent loop + scoring: Inspect Cyber** (UK AISI). Its standard `basic_agent`
  (bash + python tools, submit action) plus milestone/flag scorers. Python.
- **Range / sandbox: Proxmox** via `inspect_proxmox_sandbox`, driving the nested
  Proxmox host we built (see [`infra/`](infra/)). Docker is the fast-iteration
  sandbox during development.
- **Model: GLM-5.3** (open-weight, reasoning) via OpenRouter, a swappable config
  value. See [`config/`](config/).

The task definition selects its sandbox, so the same task runs on Docker or
Proxmox unchanged.

## Run the smoke test

```
uv sync
uv run inspect eval harness/smoke_eval.py --model openrouter/z-ai/glm-5.3
uv run inspect view            # open the transcript in the log viewer
```

Needs `OPENROUTER_API_KEY` in `.env` (see `.env.example`; set it with
`bb secret request OPENROUTER_API_KEY --write-env .env`) and a running Docker.

**Status:** smoke test green on Docker (agent finds the flag, scorer returns full
credit). Running it on the Proxmox sandbox is the next step; see
[`docs/proxmox-sandbox-todo.md`](docs/proxmox-sandbox-todo.md).

## The model-swap contract

Three values, no code change: model string, base URL, key. Inspect names the
provider in the model string, e.g. `openrouter/z-ai/glm-5.3`. To swap endpoints,
change the `--model` argument and the matching key in `.env`.

## Layout

- `harness/` — the Inspect entry points (`smoke_eval.py`).
- `tasks/smoke/` — the one example task: `eval.yaml`, `compose.yaml`, resources.
- `config/` — model choice and the capability-vs-refusal rationale.
- `infra/` — the Proxmox host, Windows template, and network notes.
- `crates/range/` — a Rust range compiler. **Superseded for provisioning** by
  `inspect_proxmox_sandbox`; kept for reference and as the home for a future
  branching/snapshot engine, which the stock tooling does not do. See
  [`docs/range-contract-v0.md`](docs/range-contract-v0.md).
- `docs/` — contract, intrusion model, and the branching exploration notes.

## Containment

Sandboxes have no egress by default (Docker uses `network_mode: none`; the
Proxmox range has no route out, only an allowlisted proxy). Agentic cyber runs
have produced unsanctioned actions in permissive setups, so isolation is a
default here, not optional. See [`infra/range-host/README.md`](infra/range-host/README.md).
