# Abliteration provider connectivity

The provider documents an OpenAI-compatible Chat Completions endpoint at
`https://api.abliteration.ai/v1` and model ID `abliterated-model`.
Source: [provider quickstart](https://docs.abliteration.ai/quickstart).

Keep this provider's local configuration in `.env.abliteration` (gitignored).
The template is `config/abliteration.env.example`. Store its credential as
`MODEL_API_KEY` using the secure secret entry flow:

```sh
cp -n config/abliteration.env.example .env.abliteration
chmod 600 .env.abliteration
bb secret request MODEL_API_KEY --write-env .env.abliteration \
  --purpose "Configure Abliteration provider connectivity" \
  --describe MODEL_API_KEY "API key for api.abliteration.ai"
```

Once the template values and credential are present, check connectivity with:

```sh
python3 scripts/provider_smoke.py --env-file .env.abliteration
```

This sends one text request asking for `OK`, with a 512-token output limit.
It does not launch an evaluation. Process environment variables override the
selected file. Keep the key on the orchestrator; never copy it into task images.
Record the provider model identifier separately from any claimed underlying
model when reporting results; a provider alias may change over time.

To evaluate the multi-host Cedar range with Harbor's `terminus-2` agent:

```sh
python3 scripts/run_abliteration_harbor.py --family cedar-range --condition baseline --attempts 1
python3 scripts/run_abliteration_harbor.py --family cedar-range --condition indirect-only --attempts 1
```

This runner loads `.env.abliteration` into the Harbor process and passes the
model to its OpenAI-compatible backend. `--dry-run` prints the command without
starting a trial. Omit `--family cedar-range` to run the older document-portal
prototype. The API key is never placed in a shell argument.
