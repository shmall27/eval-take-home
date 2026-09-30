# Cyber-Eval Harness — Base Layer Setup Spec (v0, original draft)

> Original draft produced while scoping. Assumes Python + Inspect AI.
> Superseded by the Rust-first direction; kept for reference.

## 0. Purpose (read first)

This spec sets up the **reusable base layer** for an AI cyber-capability evaluation
harness. The actual eval (task content, scoring rubric, the novel contribution) is
**not defined yet** — a spec for it arrives later. Your job is to build infrastructure
that is general enough to express whatever that eval turns out to be, and fast to
iterate on.

Optimize for: **model-portability, reproducibility, fast local iteration, and safe
containment.** Do not build the actual eval tasks beyond the one trivial example
called for below.

Primary validation model is **GLM-5.2** (open-weight, reached via an API endpoint).
The harness must treat the model as a swappable config value so it can later point at
a different endpoint with no code changes.

---

## 1. Non-goals (do NOT do these yet)

- Do **not** design or implement real cyber tasks, attack chains, or scoring rubrics
  beyond the single smoke-test task in §7.
- Do **not** build any network range / Active Directory lab yet. Just prove the
  Proxmox sandbox path works with a single throwaway VM.
- Do **not** hardcode the model, provider, token budget, or sandbox type anywhere
  except one central config.
- Do **not** enable network egress from sandboxes by default (see §8).

---

## 2. Tech stack (use these, don't substitute)

- **Python** ≥ 3.11 (Inspect requires ≥3.10; pin 3.11 or 3.12).
- **Inspect AI** (`inspect-ai`) — UK AISI's eval framework, MIT. This is the core.
- **Inspect Cyber** (`inspect-cyber`) — AISI extension for agentic cyber evals
  (repo: `UKGovernmentBEIS/inspect_cyber`). Provides cyber task/sandbox scaffolding.
- **Proxmox sandbox extension** — AISI's Inspect sandbox provider backed by VMs in a
  Proxmox instance. **VERIFY the exact package name and repo** from the Inspect
  extensions page (inspect.aisi.org.uk → extensions) before installing; do not guess.
- **Docker** — for the fast-iteration sandbox (container-per-run). Used during
  development; Proxmox is used for heavy multi-VM ranges.
- **uv** (preferred) or Poetry for dependency management — **must produce a committed
  lockfile.**

> ⚠️ **Version coupling:** Inspect Cyber pins to specific `inspect-ai` version ranges,
> and the Inspect API changes between minor versions. Pin the whole stack in a
> lockfile. Where this spec shows code, treat it as *illustrative* — verify every
> import, decorator, and signature against the **installed** version's docs before
> relying on it. If an API in this spec doesn't match what's installed, follow the
> installed version and note the divergence.

---

## 3. Repository layout

```
cyber-eval/
├── pyproject.toml            # deps, pinned
├── uv.lock (or poetry.lock)  # committed
├── .env.example              # documents required env vars (no secrets committed)
├── README.md                 # how to run; the portability claim (see §6)
├── config/
│   └── settings.py           # single source of truth: model, budgets, sandbox type
├── harness/
│   ├── __init__.py
│   ├── providers.py          # model provider resolution / swap logic
│   ├── runner.py             # pass@k × token-budget orchestration
│   └── scoring.py            # reusable milestone/partial-credit scorer helpers
├── sandboxes/
│   ├── docker/               # Dockerfile(s) + compose for fast-iteration sandbox
│   │   └── Dockerfile
│   └── proxmox/              # Proxmox sandbox config + one throwaway VM definition
│       └── README.md         # connection + template notes
├── tasks/
│   └── smoke/                # the ONE example task (see §7)
│       ├── task.py
│       └── resources/
├── logs/                     # Inspect eval logs (gitignored)
└── scripts/
    ├── smoke_docker.sh       # one-command smoke test on Docker sandbox
    └── smoke_proxmox.sh      # one-command smoke test on Proxmox sandbox
```

---

## 4. Prerequisites the human will provide

Leave these as documented env vars / config placeholders; do not block on them:

- Proxmox host reachable on the LAN: host/IP, API token or user+password, node name,
  storage pool, a network bridge, and a base VM template ID (a minimal Linux cloud
  image is fine for the throwaway VM).
- GLM-5.2 endpoint credentials: base URL + API key for whichever provider is used
  (see §5).
- A machine with Docker installed for the fast path.

Put every one of these in `.env.example` with a comment explaining it. Never commit
real secrets.

---

## 5. Model provider (the swap boundary)

The whole "I could run this on a preview model" claim rests on this being clean.

- Expose the model as a **single config value** (`config/settings.py`: `MODEL` +
  `MODEL_BASE_URL` + `MODEL_API_KEY` from env).
- GLM-5.2 is OpenAI-compatible via several routes (Z.ai API, or an aggregator like
  OpenRouter). Configure it through Inspect's OpenAI-compatible / custom-provider
  mechanism. **Verify the exact model string and provider prefix** Inspect expects for
  a custom base URL in the installed version — do not assume.
- Implement `harness/providers.py:get_model()` that returns an Inspect model handle
  built purely from config, so swapping to a different endpoint is a `.env` change.
- **Acceptance:** a `--model` / env override runs the smoke task against a *second*
  endpoint (any small model or a local one) with **zero code changes**. This must be
  demonstrated and documented in the README — it is a deliverable, not a nice-to-have.

---

## 6. README must state the portability contract

The README explains, in a few lines:

- What this harness is and how to run a smoke test.
- The exact three things to change to point at a new model endpoint (model string,
  base URL, key).
- That the harness was validated on GLM-5.2 and is model-agnostic by construction.

---

## 7. The one example task (smoke test only)

Build a single trivial task purely to exercise the full loop — **not** a real cyber
task. Suggested: a "capture the flag" where a flag string is placed in a file inside
the sandbox and the agent must read it and submit it, OR a tiny "find the hardcoded
secret in this script" task. Keep it solvable in a few steps.

It must exercise every layer:

- **Dataset/sample:** one sample with a known ground-truth flag.
- **Solver:** a basic ReAct-style agent with shell + (optionally) python tools running
  **inside the sandbox**. Use Inspect Cyber's agent/sandbox scaffolding rather than
  hand-rolling.
- **Scorer:** exact-match on the flag, **plus** demonstrate **milestone partial
  credit** — e.g. award partial score for reaching an intermediate state (file opened
  / correct host reached), full score for the flag. Put the reusable partial-credit
  logic in `harness/scoring.py` so future real tasks reuse it.

The same task definition must run unchanged on **both** the Docker sandbox and the
Proxmox sandbox (sandbox is selected by config, not baked into the task).

---

## 8. Sandboxing & containment (non-negotiable defaults)

- **Two sandbox backends, selected by config:**
  - **Docker** — container per run, fast reset, used for development. Set this up
    first and get the smoke test green on it before touching Proxmox.
  - **Proxmox** — VM-backed, for heavy/multi-host ranges later. Prove it with **one**
    throwaway VM: provision → run smoke task → tear down / snapshot-restore.
- **Egress off by default.** Sandboxes must have **no outbound internet** unless a task
  explicitly opts in. For Docker, use an internal/no-egress network; for Proxmox, put
  the VM on an isolated bridge/VLAN with no route to the internet. Document how to flip
  this per-task for the rare case a task needs it.
- **Reset between runs.** Docker: fresh container each run. Proxmox: snapshot the base
  state and restore before each attempt; measure restore time and note it (it caps runs
  per hour). Inspect/Proxmox sandbox snapshot support should be used rather than manual
  reprovisioning where possible — verify what the extension offers.
- **Rationale to put in a code comment / README:** agentic cyber runs have produced
  unsanctioned agent actions in permissive evals (data exfil attempts, attempts to push
  malicious code to public repos, fabricated identities to social-engineer maintainers).
  Default isolation is a safety requirement of this harness, not optional hygiene.

---

## 9. pass@k × token-budget runner

Build `harness/runner.py` as a reusable wrapper (this is spec-agnostic and will apply
to whatever the real eval becomes):

- Runs each task **k times** (configurable; default k=3 for dev).
- Sweeps a small set of **token budgets** (configurable list; default 2–3 points).
- Aggregates: mean success, milestone-completion, and **error bars** (standard error)
  per (task, budget) cell.
- Emits a machine-readable results file (JSON) and a short human-readable summary
  table.
- Never hardcodes k, budgets, or model — all from `config/settings.py` / CLI overrides.

---

## 10. Logging & transcripts

- Enable Inspect's native transcript/eval logging from the start; write to `logs/`
  (gitignored).
- Confirm you can open a run in the Inspect log viewer.
- Note in the README which analysis extensions exist (e.g. Inspect Viz for
  visualization, transcript-analysis tools) so they can be added later — but do not
  integrate them now.

---

## 11. Acceptance criteria (definition of done for the base layer)

1. `uv sync` (or `poetry install`) from a clean checkout reproduces the env from the
   committed lockfile.
2. `scripts/smoke_docker.sh` runs the example task on the **Docker** sandbox against
   **GLM-5.2**, agent solves it, scorer returns full credit, transcript is written and
   viewable.
3. The same task runs with **partial credit** demonstrated (force a near-miss and show
   the intermediate milestone scored).
4. `scripts/smoke_proxmox.sh` provisions **one** throwaway VM on the Proxmox host, runs
   the same task on the **Proxmox** sandbox, and tears down / restores cleanly.
5. Model **swap** demonstrated: same smoke task runs against a second endpoint via env
   change only, zero code edits.
6. `harness/runner.py` produces a `pass@k` × token-budget results JSON + summary table
   for the smoke task.
7. Sandboxes have **no internet egress** by default; this is verified (e.g. a
   `curl`/DNS probe from inside the sandbox fails) and the check is documented.
8. README documents: how to run, the 3-value model-swap contract, and the containment
   defaults.

---

## 12. Things to verify against current docs (flag, don't guess)

Surface these explicitly in your PR/notes rather than assuming:

- Exact package name + version of the **Proxmox sandbox** Inspect extension.
- The **`inspect-ai` version range** Inspect Cyber currently pins, and whether Python
  3.11 vs 3.12 matters for any dep.
- The correct Inspect **model string / provider prefix** for a custom OpenAI-compatible
  base URL (for GLM-5.2).
- Current Inspect **Task / Solver / Scorer API** shape (decorators, `generate`, dataset
  format) — reconcile the illustrative code here with the installed version.
- Whether the Proxmox sandbox extension exposes **snapshot/restore** primitives or
  whether reset must be scripted.

---

## 13. Open questions to raise back to the human

- Proxmox host specs (RAM/CPU) — caps how big a future range can be; report what's
  available.
- Preferred GLM-5.2 route (direct Z.ai vs aggregator) — affects cost + the provider
  string.
- Base VM template to standardize on for future range work.
