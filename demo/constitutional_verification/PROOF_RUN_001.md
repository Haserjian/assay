# Proof Run 001

**Date**: 2026-03-24 17:42 UTC
**Operator**: Haserjian
**Setup**: `cd ~/assay-toolkit/demo/constitutional_verification && read -s ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY`
**Run**: `python3 run.py`

## Preflight

- Assessment file: found
- Evidence files: 3 found
- Anthropic key: present
- Model: claude-sonnet-4-6

## Phases completed

1. Analyst: extracted 7 claims from AI assessment (3 were in the original scenario, 4 were inferred by the analyst from the evidence gaps)
2. Verifier: graded all 7 claims (0 CONFIRMED, 1 PREDICTED, 3 AMBIGUOUS, 3 BLOCKED)
3. Witness: reviewed all 7, overrode 2 grades (AMBIGUOUS -> BLOCKED), issued honest-fail declaration

## Final outcome

- **Original AI assessment**: 7/7 COMPLIANT — READY FOR AUDIT
- **Constitutional verification**: 0/7 CONFIRMED — BLOCKED
- **Post-witness**: 1 Predicted, 1 Ambiguous, 5 Blocked
- **Honest-fail declaration**: issued (AI conclusion materially unsupported; 2 claims directly contradicted by evidence)

## Why this is a successful demo

The demo succeeded because the system did the right thing: it refused to pass through an unsupported AI conclusion.

- The AI assessment looked professional and authoritative
- The evidence contradicted it on MFA scope and IR testing cadence
- The witness caught the verifier being too generous on 2 claims
- The output is operator-legible without narration

A BLOCKED verdict on unsupported claims IS the target behavior. The system earns trust by proving what it can't verify, not by hiding it.

## Output files

```
demo_output/
  proof_summary.md              (human-readable report)
  receipts/
    verification_plan.json      (analyst output: 7 extracted claims)
    verification_results.json   (verifier output: per-claim grades)
    witness_verdict.json        (witness output: overrides + honest-fail)
```
