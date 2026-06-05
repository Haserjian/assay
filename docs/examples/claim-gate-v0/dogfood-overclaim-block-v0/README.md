# Claim Gate Dogfood: Overclaim BLOCK v0

First generated teeth-receipt for the claim-gate engine. A deliberately
overclaimed diff was run through `assay claim-gate diff` and the gate returned
`BLOCK` with two high-severity blocking transitions. The report in this
directory is generated tool output, not a hand-written fixture.

## What This Is

A bounded, reproducible scenario:

- `README_before.md` makes a bounded, honest claim (experimental prototype,
  possibility language, single local demo).
- `README_after.md` is a deliberate AI-style overclaim (production-ready,
  guarantees, safe, proven secure) with no supporting evidence in the repo.
- `claim_gate_report.json` is the generated report from running the existing
  claim-gate over the before/after diff.

The scenario mirrors the synthetic `overclaimed_ai_pr.rejected.proof-card.json`
fixture under `docs/public_surfaces/unaudited-delegation-v0/examples/`. This
dogfood turns that hand-written rejection fixture into a generated one.

## How It Was Generated

The scenario was built as an isolated throwaway Git repository with two commits
(`before`, then the overclaim `after`) and the canonical example policy
`../assay.claims.yml`. No Assay engine, CLI, workflow, or PR Gate code was
modified.

```bash
assay claim-gate diff \
  --repo <scenario-repo> \
  --base <before-commit> \
  --head <after-commit> \
  --policy assay.claims.yml \
  --out claim_gate_report.json
```

Exit code: `2` (advisory mode exits 2 for `BLOCK`).
The report was identical across two runs (deterministic).

## Generated Verdict

```text
verdict: BLOCK
transitions_detected: 3
blocking_transitions:  2
needs_review:          1
```

| transition_class | severity | verdict | missing evidence |
|---|---|---|---|
| `prototype_to_production` | high | `BLOCK` | production_deployment_receipt, reproducible_test_suite |
| `possible_to_guaranteed` | high | `BLOCK` | direct_evidence, reviewer_acceptance |
| `demo_to_enterprise` | medium | `NEEDS_REVIEW` | deployment_scope_receipt |

The overall verdict is `BLOCK` because at least one blocked transition was
detected with required evidence absent.

## What This Receipt Supports

- The claim-gate detects unsupported claim-boundary escalation on a real diff.
- It blocks closed when required evidence is missing.
- The block is deterministic and reproducible from the inputs in this directory.

## What This Receipt Does Not Support

- It does not prove the login code is insecure or secure.
- It does not evaluate runtime behavior, correctness, or exploitability.
- It does not prove an agent understood anything.
- `BLOCK` here is a claim-drift verdict, not a merge or production decision.

## Why The PR Gate Still Says `Claim: NOT_EVALUATED`

This is the important boundary. The PR Gate and the claim-gate are **two
different subsystems that share the word "claim."** This dogfood exercises the
claim-gate only. It does **not** change anything the PR Gate reports.

- The PR Gate `claim` channel is computed in
  `src/assay/pr_gate/policy.py` by `_claim_channel()`, which derives its value
  from CI **check-observation statuses** (`OBSERVED_PASS` / `OBSERVED_FAIL`),
  not from any claim-drift analysis.
- The PR Gate does **not** import or invoke `src/assay/claim_gate/`
  (`grep` for `claim_gate` under `src/assay/pr_gate/` returns nothing).
- Therefore a real claim-gate `BLOCK`, as produced here, leaves the PR Gate
  `claim` channel reading `NOT_EVALUATED`. The two are not yet wired together.

So this receipt proves the **catch capability exists**. It does not yet make the
PR Gate surface that catch.

## Named Integration Gap (Next Slice)

```text
standalone claim_gate BLOCK receipt        (this slice, done)
  -> wire claim_gate into PR Gate evaluation
  -> feed its verdict into the PR Gate claim channel
  -> Claim: NOT_EVALUATED becomes BLOCK/FAIL on overclaim   (next slice)
```

The wiring slice is intentionally **not** done here. It touches PR Gate policy,
evidence flow, verdict-vocabulary reconciliation (claim-gate emits
`PASS` / `NEEDS_REVIEW` / `BLOCK`; the PR Gate `claim` channel currently emits
`PASS` / `FAIL` / `NOT_EVALUATED`), tests, and comment rendering. It is the
right destination but a separate, wider change.
