# Model configuration

The harness treats the model as a config value. Pointing it at a different
endpoint is three environment variables, never a code change:

| Variable | Meaning | Default |
|---|---|---|
| `MODEL` | model string as the provider names it | `glm-5.3` |
| `MODEL_BASE_URL` | OpenAI-compatible base URL (`/chat/completions` is appended) | `https://api.z.ai/api/paas/v4` |
| `MODEL_API_KEY` | API key | — |

## Chosen model: GLM-5.3

Open-weight, OpenAI-compatible, and chosen so the eval measures capability
rather than refusal (see [`model-selection.md`](model-selection.md)). GLM-5.3
replaced 5.2 in August 2026 at the same price and a larger context window.

Price per 1M tokens (Z.ai direct, checked 2026-10-01): input $1.40, cached
input $0.26, output $4.40. OpenRouter lists third-party hosts cheaper, but for
an eval pin one provider so runs stay comparable.

## Where the model is reached from

The model endpoint is called by the **harness**, which runs outside the range.
Range guests have no internet (that is the containment guarantee). So the key
and the egress to `api.z.ai` live with the orchestrator, never on the range
host's isolated bridges. Do not add the model endpoint to the range egress
allowlist.
