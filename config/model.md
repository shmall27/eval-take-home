# Model configuration

The harness treats the model as a config value. Pointing it at a different
endpoint is three environment variables, never a code change:

| Variable | Meaning | Default |
|---|---|---|
| `MODEL` | model string as the provider names it | `z-ai/glm-5.3` |
| `MODEL_BASE_URL` | OpenAI-compatible base URL (`/chat/completions` is appended) | `https://openrouter.ai/api/v1` |
| `MODEL_API_KEY` | API key | — |

## Chosen model: GLM-5.3

Open-weight, OpenAI-compatible, and chosen so the eval measures capability
rather than refusal (see [`model-selection.md`](model-selection.md)). GLM-5.3
replaced 5.2 in August 2026 at the same price and a larger context window.

**Validated 2026-10-01** via `scripts/model_probe.py`: endpoint answers, and
GLM-5.3 refused 0 of 4 authorized-lab security prompts. Route used: OpenRouter,
model `z-ai/glm-5.3`. Z.ai direct is the documented alternate.

Price per 1M tokens (checked 2026-10-01): input ~$1.40, output ~$4.40.
OpenRouter returns actual per-call `cost` in the `usage` object, so the harness
should record that rather than estimate.

### GLM-5.3 is a reasoning model

`completion_tokens` includes hidden **reasoning tokens**, and `message.content`
is `null` when the token cap is spent on reasoning before any answer (finish
reason `length`). Two consequences for the harness:

- Token budgets in the pass@k sweep must be large enough to clear reasoning,
  and must count reasoning tokens as spend. A budget that is too low yields an
  empty answer that is a truncation, not a failure or a refusal.
- The response parser must treat `content == null` as "no answer yet / truncated,"
  distinct from a refusal and from a wrong answer.

## Where the model is reached from

The model endpoint is called by the **harness**, which runs outside the range.
Range guests have no internet (that is the containment guarantee). So the key
and the egress to `api.z.ai` live with the orchestrator, never on the range
host's isolated bridges. Do not add the model endpoint to the range egress
allowlist.
