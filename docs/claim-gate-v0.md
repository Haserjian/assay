# Assay Claim Gate v0

Assay Claim Gate detects unsupported trust escalation across diffs.

It does not determine truth, certify compliance, or approve production use. It
turns ordinary repository and document diffs into a bounded report that says
which configured claim-boundary transitions appeared, what evidence was
required, what evidence was found, and whether the transition should pass,
needs review, or block.

```text
unsupported claim drift is detectable, attributable, and gateable
```

## Command

```bash
assay claim-gate diff \
  --base main \
  --head HEAD \
  --policy assay.claims.yml \
  --out claim_gate_report.json
```

Advisory mode exits 0 for `PASS` and `NEEDS_REVIEW`, and exits 2 for `BLOCK`.
Strict review mode exits 1 for `NEEDS_REVIEW`:

```bash
assay claim-gate diff \
  --base main \
  --head HEAD \
  --policy assay.claims.yml \
  --fail-on-review
```

## What It Catches

V0 is rule-based and deterministic. It detects transitions such as:

- `prototype_to_production`
- `possible_to_guaranteed`
- `may_might_could_to_does_will`
- `local_to_general`
- `demo_to_enterprise`
- `experimental_to_reliable`
- `suggestion_to_recommendation`
- `recommendation_to_policy`
- `partial_support_to_proven`
- `risk_reduced_to_safe`
- `observed_to_causal`

The rule is:

```text
transition + missing required evidence => configured verdict
```

The rule is not:

```text
claim sounds false => verdict
```

## Non-Claims

Claim Gate records bounded or aspirational language as `non_claims` when the
changed text includes markers such as `draft`, `roadmap`, `future goal`, or
`hypothesis`. This keeps roadmap language distinct from publishable claims.

## Example Files

The first cold-reader example lives in:

```text
docs/examples/claim-gate-v0/
  assay.claims.yml
  README_before.md
  README_after.md
  claim_gate_report.json
```
