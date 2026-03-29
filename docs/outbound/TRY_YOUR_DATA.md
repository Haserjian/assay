# Try Assay on your own eval data

**Who this is for:** You run LLM-as-judge evaluations and want to check
whether two runs are structurally comparable before claiming a delta.

**Time to first result:** Under 10 minutes if your eval pipeline
already tracks judge config in structured form. Longer if you need
to extract the 15 parity fields manually from your setup.

---

## Prerequisites

```bash
pip install assay-ai
```

You need two JSON files — one per evaluation run — describing the
conditions under which each run was produced. These are called
*evidence bundles*.

## Evidence bundle format

Each bundle is a JSON file with a `fields` object containing the
declared conditions of your evaluation run:

```json
{
  "label": "helpfulness eval — baseline (March 15)",
  "fields": {
    "judge_model": "gpt-4o",
    "judge_model_version": "gpt-4o-2024-08-06",
    "judge_prompt_template": "Rate the response on helpfulness from 1-5.\n...",
    "judge_system_prompt": "You are an expert evaluator.",
    "scoring_rubric": "1=not helpful ... 5=very helpful",
    "score_type": "likert",
    "score_range": "1-5",
    "judge_temperature": 0.0,
    "judge_max_tokens": 256,
    "judge_top_p": 1.0,
    "judge_passes": 1,
    "eval_dataset": "my-test-set-v2",
    "eval_dataset_version": "2024-03-01",
    "presentation_order": "fixed",
    "input_format": "question-response-pair"
  }
}
```

**Required fields for the v1 judge contract:** All 15 fields above.
If you omit fields, the verdict will be UNDETERMINED (not an error —
the tool tells you exactly which fields are missing).

**Where the field values come from:** Your eval pipeline config, your
judge prompt files, your dataset metadata. These are declarations about
what you ran, not about what the results were.

### Field reference

| Field | What it means | Match rule |
|-------|---------------|------------|
| `judge_model` | Model family (e.g. "gpt-4o") | exact |
| `judge_model_version` | Resolved version (e.g. "gpt-4o-2024-08-06") | exact |
| `judge_prompt_template` | The scoring prompt text | content hash |
| `judge_system_prompt` | System prompt for the judge | content hash |
| `scoring_rubric` | Rubric description | content hash |
| `score_type` | Score format (e.g. "likert", "binary") | exact |
| `score_range` | Score bounds (e.g. "1-5") | exact |
| `judge_temperature` | Sampling temperature | exact |
| `judge_max_tokens` | Max tokens for judge response | exact |
| `judge_top_p` | Top-p sampling parameter | exact |
| `judge_passes` | Number of judge passes per item | exact |
| `eval_dataset` | Dataset identifier or content hash | content hash |
| `eval_dataset_version` | Dataset version string | exact |
| `presentation_order` | Item ordering (e.g. "fixed", "shuffled") | exact |
| `input_format` | Input template hash or description | content hash |

**Content hash fields** can be provided as raw text (Assay hashes them)
or as pre-computed `sha256:<hex>` digests. Either works.

## Run the comparison

```bash
assay compare baseline.json candidate.json \
  -c contracts/judge-comparability-v1.yaml \
  --claim "candidate improved helpfulness by 8%"
```

### Possible verdicts

| Verdict | Meaning | Exit code |
|---------|---------|-----------|
| **SATISFIED** | All parity fields match. Claim is admissible. | 0 |
| **DENIED** | Instrument drifted. Claim is inadmissible. | 1 |
| **DOWNGRADED** | Minor mismatches. Claim admissible with caveat. | 1 |
| **UNDETERMINED** | Required fields missing. Cannot evaluate. | 2 |

The output shows exactly which fields matched, which mismatched (with
severity and rationale), and what actions are blocked or required.

## Try the included examples

The repo includes external-style example bundles you can run immediately:

```bash
# Drifted system prompt → DENIED
assay compare \
  examples/llm_judge/external/baseline.json \
  examples/llm_judge/external/candidate_drifted.json \
  -c contracts/judge-comparability-v1.yaml \
  --claim "candidate improved helpfulness"

# Matching config → SATISFIED
assay compare \
  examples/llm_judge/external/baseline.json \
  examples/llm_judge/external/candidate_matching.json \
  -c contracts/judge-comparability-v1.yaml \
  --claim "candidate improved helpfulness"
```

## What if my eval output doesn't match this format?

The evidence bundle is a *declaration* file, not an automated export.
You write it based on what you know about your eval run configuration.

If your eval pipeline already tracks judge config in a structured format
(YAML, JSON, or a config object), the mapping is straightforward:
pull the 15 field values from your config into the bundle format above.

If your pipeline does not track this metadata, that is itself the problem
Assay is designed to surface. The comparability contract makes implicit
configuration assumptions explicit and auditable.

**Adapters for specific eval frameworks** (Braintrust, LangSmith, custom
harnesses) do not yet exist. If your pipeline produces a different output
shape and you'd like to discuss integration, open an issue or reach out.

## What's next

- **Enforce in CI:** [Trust bootstrap](../specs/TRUST_BOOTSTRAP_SPEC_V0.md) sets up a GitHub Actions workflow that runs `assay compare` or `assay verify-pack` on every PR
- **Write your own contract:** The v1 contract is a starting point. You can define your own parity fields, match rules, and severity levels for your domain
- **Inspect evidence packets:** See [gallery scenarios 05 and 06](https://github.com/Haserjian/assay-proof-gallery) for reviewer-facing evidence
- **Verify in browser:** Use the [zero-install verifier](https://haserjian.github.io/assay-proof-gallery/verify.html) on any proof pack
- **Want us to do it?** We'll run the diagnostic on your eval data and install the full evidence gate. [Pilot details](../PILOT_PROGRAM.md)
