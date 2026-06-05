# PR Gate Policy Layer

This document sketches a delegation-review layer that can sit above captured PR Gate evidence.

It is docs-only. It does not change the existing Assay PR Gate engine, command-line interface, workflow, or decision enum.

## Inputs

A Complexity Ceiling PR Gate policy needs:

- PR diff
- declared claim
- allowed scope
- forbidden scope
- invariant list
- test or replay evidence
- dependency boundary map
- code owner or review boundary hints

## Outputs

Draft-local verdict vocabulary:

```text
PASS
PASS_WITH_CAVEATS
NEEDS_SPLIT
INSUFFICIENT_EVIDENCE
FAIL
```

`PASS` means no policy reason was found to stop normal review for the evaluated channels. It does not mean automatic merge.

`PASS_WITH_CAVEATS` means the captured evidence supports a bounded review path, but named caveats or unevaluated channels remain.

`NEEDS_SPLIT` means the change should be divided before review because its scope, risk boundaries, or claim/evidence mismatch make one approval too expensive or ambiguous.

`INSUFFICIENT_EVIDENCE` means the declared claim may be narrow enough, but required receipts, checks, replay, or owner evidence are missing.

`FAIL` means captured evidence contradicts the declared claim or violates policy.

## Policy Questions

The policy should ask:

- Is the claim narrow enough to review?
- Does the diff stay inside allowed scope?
- Did it touch forbidden or risk-sensitive scope?
- Did it cross ownership, dependency, or public API boundaries?
- Are the named invariants represented by evidence?
- Does the evidence support the claim as written?
- Would an honest reviewer need the PR split before approval?

## Example Rule Shape

```json
{
  "rule_id": "claim_scope_mismatch",
  "if": {
    "declared_claim_type": "refactor_only",
    "runtime_behavior_changed": true
  },
  "then": {
    "verdict": "NEEDS_SPLIT",
    "reason": "claim says refactor-only but captured evidence shows runtime behavior changed"
  }
}
```

## Relation To Existing PR Gate

Existing Assay PR Gate already binds captured PR evidence to a signed review packet. This surface is a policy-story layer over delegated change review. It should preserve the existing PR Gate discipline:

- captured evidence first
- policy identity and hash
- explicit channels
- caveats
- `do_not_infer` boundaries
- human review remains outside the verdict

## Do Not Infer

A delegation-review verdict does not show that:

- code is correct
- code is secure
- the agent understood the system
- all tests passed unless named check evidence says so
- production approval was granted
- the PR should be merged automatically
