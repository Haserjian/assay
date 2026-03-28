# Assay Three-Layer Model

Version: 0.1.0
Created: 2026-03-28

## Purpose

Defines the three architectural layers that separate execution reality
from comparison conditions from claim adjudication. This separation
is what makes the comparability subsystem constitutional rather than
advisory.

## Layers

### Layer 1: Execution Reality

What happened technically.

| Aspect | Value |
|--------|-------|
| Question answered | "What did the system do?" |
| Artifacts | `model_call` receipts, traces, raw API responses |
| Source | SDK integrations, `assay run`, eval harness execution |
| Assay surface | `results.json`, raw score arrays, usage metadata |
| Lifecycle | Created during execution, immutable after |

Layer 1 records facts: which model responded, what tokens were used,
what scores were produced. It does not interpret whether those facts
are comparable to anything else.

### Layer 2: Declared Comparison Conditions

Under what methodological conditions should this run be interpreted.

| Aspect | Value |
|--------|-------|
| Question answered | "Under what instrument configuration was this measured?" |
| Artifacts | Evidence bundles (`evidence_bundle.json`) |
| Source | Operator declaration, eval harness config, `assay bundle init` |
| Assay surface | `EvidenceBundle.fields`, `requested_config`, `executed_config`, `field_sources` |
| Lifecycle | Declared at bundle creation, may reference Layer 1 artifacts |

Layer 2 is the declaration surface. It captures the 15 parity fields
that define the measurement instrument and evaluation surface.

**The 8/15 gap.** Of the 15 fields in the judge-comparability-v1
contract, only 7 can be extracted from Layer 1 execution artifacts
(`judge_model_version`, `judge_temperature`, `judge_max_tokens`,
`judge_top_p`, raw scores). The remaining 8 require operator
declaration:

| Field | Layer 1 extractable? |
|-------|---------------------|
| judge_model | No -- requested vs resolved model may differ |
| judge_model_version | Yes -- from API response |
| judge_prompt_template | No -- not in API response |
| judge_system_prompt | No -- not in API response |
| scoring_rubric | No -- eval harness concept, not API concept |
| score_type | No -- eval harness concept |
| score_range | No -- eval harness concept |
| judge_temperature | Yes -- from API request |
| judge_max_tokens | Yes -- from API request |
| judge_top_p | Yes -- from API request |
| judge_passes | No -- eval harness concept |
| eval_dataset | No -- eval harness concept |
| eval_dataset_version | No -- eval harness concept |
| presentation_order | No -- eval harness concept |
| input_format | No -- eval harness concept |

This gap is the known Layer 1 to Layer 2 projection loss. Auto-bundle
extraction can narrow but never fully close it, because some fields
are methodological declarations that have no API-level representation.

### Layer 3: Claim Adjudication

What statements are constitutionally allowed.

| Aspect | Value |
|--------|-------|
| Question answered | "May these two runs be compared?" |
| Artifacts | `ConstitutionalDiff` (verdict receipt), gate reports |
| Source | Comparability engine (`evaluate()`), `assay compare`, `assay gate compare` |
| Assay surface | `ConstitutionalDiff`, `Verdict`, `Consequence`, `Mismatch[]` |
| Lifecycle | Computed from Layer 2 inputs + contract, deterministic |

Layer 3 is the enforcement boundary. Given two Layer 2 bundles and a
contract, it produces a verdict (SATISFIED / DOWNGRADED / DENIED /
UNDETERMINED) and a consequence (which actions are blocked).

Layer 3 never examines Layer 1 artifacts directly. It operates
exclusively on declared Layer 2 fields.

## Projections Between Layers

| Projection | Direction | Lossy? | Notes |
|-----------|-----------|--------|-------|
| Execution to Declaration | Layer 1 -> Layer 2 | **Yes** | 8/15 fields cannot be auto-extracted. Operator must declare them. |
| Declaration to Adjudication | Layer 2 -> Layer 3 | No | Deterministic. Same bundles + same contract = same verdict. |
| Adjudication to Execution | Layer 3 -> Layer 1 | N/A | Not a valid projection. Verdicts do not reconstruct executions. |
| Execution to Adjudication | Layer 1 -> Layer 3 | **Invalid** | Skipping Layer 2 is not permitted. Raw execution data cannot be adjudicated without declared comparison conditions. |

## Canonical Artifact Table

| Artifact | Layer | Format | Location |
|----------|-------|--------|----------|
| Raw scores / API responses | 1 | JSON | `results.json` in run directory |
| Evidence bundle | 2 | JSON | `evidence_bundle.json` in run directory |
| Comparability contract | 2 (schema) | YAML | `contracts/<name>.yaml` |
| Constitutional diff | 3 | JSON (in-memory or serialized) | gate report output |
| Gate report | 3 | JSON | `gate_report_*.json` or `--save-report` output |

## Anti-Confusion Notes

**Outcome agreement is not evidence of comparability.** Two runs may
produce identical scores while being structurally incomparable (different
models, different prompts). Comparability is a property of the
measurement conditions, not the measurement results. Layer 3 verdicts
are derived from Layer 2 declarations, never from Layer 1 outcomes.

**Model version resolution is a Layer 1/Layer 2 boundary issue.** An
operator requests `gpt-4o-mini`; the API resolves to
`gpt-4o-mini-2024-07-18`. The bundle must capture both (`judge_model`
and `judge_model_version`) to distinguish "same family, different
version" from "different family entirely."

**Contracts are Layer 2 schema, not Layer 3 logic.** The contract
defines which fields matter and at what severity. The engine
(`evaluate()`) applies those rules mechanically. Changing the contract
changes the adjudication rules, not the adjudication logic.
