# Model configuration

The harness treats the model as a config value. Pointing it at a different
endpoint is three environment variables, never a code change:

| Variable | Meaning | Default |
|---|---|---|
| `MODEL` | model string as the provider names it | `z-ai/glm-5.3` |
| `MODEL_BASE_URL` | OpenAI-compatible base URL (`/chat/completions` is appended) | `https://openrouter.ai/api/v1` |
| `MODEL_API_KEY` | API key | — |

## Default: GLM-5.3 via OpenRouter

The defaults above are the OpenRouter route. The documented alternate is
Z.ai direct: `MODEL=glm-5.3`,
`MODEL_BASE_URL=https://api.z.ai/api/paas/v4`. Connectivity can be checked
with `scripts/provider_smoke.py`.

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

The model endpoint is called by the **harness**, which runs outside the task
containers. The API key stays with the orchestrator and is never copied into
task images.
