# Auto-Bundle Generation: Gap Inventory

**Status**: Design note (not implementation spec)
**Date**: 2026-03-28
**Rule**: Do not implement auto-bundle generation until the gaps below are closed.

## What exists in the receipt infrastructure today

The OpenAI integration (`src/assay/integrations/openai.py`) wraps
`chat.completions.create` and emits a `model_call` receipt with:

| Field | Source | Trustworthy? |
|-------|--------|-------------|
| `model_id` | `kwargs["model"]` | Yes — requested model |
| `input_tokens` | `response.usage.prompt_tokens` | Yes — from API |
| `output_tokens` | `response.usage.completion_tokens` | Yes — from API |
| `latency_ms` | wall clock | Yes |
| `finish_reason` | `response.choices[0].finish_reason` | Yes |
| `input_hash` | SHA-256 of messages | Yes |
| `output_hash` | SHA-256 of response text | Yes |
| `callsite_file` | `inspect.stack()` | Yes |
| `callsite_line` | `inspect.stack()` | Yes |
| `provider` | hardcoded `"openai"` | Yes |

## What the judge comparability contract requires

These are the 15 parity fields from `judge-comparability-v1.yaml`:

| Contract Field | Available in receipts? | Gap |
|----------------|----------------------|-----|
| `judge_model` | Partial — `model_id` captures requested model, not resolved version | Need resolved model from response headers |
| `judge_model_version` | **NO** — not captured | API response may include `model` field with version |
| `judge_prompt_template` | **NO** — only `input_hash` | Would need to separate system/user/template |
| `judge_system_prompt` | **NO** — only `input_hash` | Same as above |
| `scoring_rubric` | **NO** — not an API parameter | Pure application-level concept |
| `judge_temperature` | **NO** — not captured from kwargs | Available in `kwargs["temperature"]` |
| `judge_max_tokens` | **NO** — not captured from kwargs | Available in `kwargs["max_tokens"]` |
| `judge_top_p` | **NO** — not captured from kwargs | Available in `kwargs["top_p"]` |
| `judge_passes` | **NO** — application-level concept | How many times the judge is called per item |
| `eval_dataset` | **NO** — not an API concept | Application-level: which items were evaluated |
| `eval_dataset_version` | **NO** — not an API concept | Application-level |
| `presentation_order` | **NO** — not an API concept | Application-level |
| `input_format` | **NO** — not an API concept | Application-level |
| `score_type` | **NO** — not an API concept | Application-level (likert/binary/continuous) |
| `score_range` | **NO** — not an API concept | Application-level |

## Summary

- **Available from API kwargs** (easy to add): `temperature`, `max_tokens`, `top_p`, `model` (resolved from response)
- **Available from API response** (medium): `model` with version suffix
- **Application-level concepts** (cannot be auto-extracted): `scoring_rubric`, `judge_passes`, `eval_dataset`, `eval_dataset_version`, `presentation_order`, `input_format`, `score_type`, `score_range`, `judge_prompt_template` (as a named artifact vs. inline content)
- **Requires message parsing** (fragile): separating system prompt from user prompt from template

## Why explicit declaration is correct for v0

8 of 15 contract fields are application-level concepts that do not exist
in any API call. They are properties of the evaluation harness, not the
LLM call. Auto-extracting them would require either:

1. Convention-based inference (fragile, domain-specific)
2. User annotation in code (which is just declaration with extra steps)
3. Config file parsing (which is just `load_bundle()` with extra steps)

Explicit evidence bundles are honest: the operator declares what they
know, and the contract evaluates completeness. If fields are missing,
the verdict is UNDETERMINED, not silently fabricated.

## What to add to receipt capture (when ready)

The 4 API-native parameters should be added to `_create_model_call_receipt`:

```python
# In integrations/openai.py _wrapped_create():
temperature = kwargs.get("temperature")  # None = API default
max_tokens = kwargs.get("max_tokens")
top_p = kwargs.get("top_p")
# These go into the receipt as optional fields
```

This does NOT solve the auto-bundle problem, but it enriches the receipt
for later correlation. The bundle would still need to be declared for
application-level fields.

## Organic workflow status (2026-03-28)

First end-to-end comparability workflow ran with real gpt-4o-mini API
calls via `examples/llm_judge/eval_runner.py`. Organic verdicts produced:
SATISFIED, DOWNGRADED (judge_max_tokens change), DENIED (prompt template
change). UNDETERMINED not yet tested organically.

Bundle authoring friction was low for this controlled setup (5 items,
one model, static config). Main pain point: computing content hashes
for eval_dataset and input_format. Friction in messier workflows is
not yet characterized.

## Reopen triggers

Auto-bundle generation becomes worth building when:

1. Receipt infrastructure captures temperature/max_tokens/top_p (easy)
2. A convention emerges for eval harness config files (e.g. `eval_config.yaml`)
3. At least 3 real incidents show that manual bundle declaration is the friction point (not the denial engine itself)
4. The auto-extracted fields can be verified against declared fields (not replacing them)
