# Claim Firewall

A claim firewall prevents delegated work from escalating beyond the evidence captured for it.

It is not a static analyzer, a code-quality oracle, or a merge bot. It is a policy-bound claim/evidence gate.

## Primitive

```text
claim -> scope -> evidence -> policy -> verdict -> receipt
```

Each delegated change must make a claim small enough to review:

- what changed
- why it changed
- where it was allowed to change
- where it was not allowed to change
- which evidence supports the claim
- which evidence is missing
- what a reviewer must not infer

The firewall blocks claim escalation. It does not block useful work merely because it came from an AI agent.

## Claim Escalation

Claim escalation happens when a change says or implies more than its evidence supports.

Examples:

| Declared or implied claim | Required control |
|---|---|
| "Refactor only" | behavioral-equivalence evidence or clear `NEEDS_SPLIT` |
| "Makes auth secure" | security-specific evidence, ownership review, and narrow threat boundary |
| "All tests pass" | observed check evidence for the named checks and commit |
| "Safe to merge" | blocked wording in this surface; merge remains a human/process decision |
| "Agent followed policy" | captured policy evidence only; hidden intent is not evaluated |

## Review Verdicts

The firewall should prefer boring verdicts with reasons:

- `PASS`: no policy reason found to stop normal review for evaluated channels
- `PASS_WITH_CAVEATS`: review can proceed, but unevaluated channels or non-claims remain
- `NEEDS_SPLIT`: change is too broad for the declared claim or review boundary
- `INSUFFICIENT_EVIDENCE`: claim may be valid, but required evidence is absent
- `FAIL`: captured evidence contradicts the claim or violates policy

These verdicts are review evidence. They are not merge approvals.

## Invariant

The invariant across this surface:

```text
verified change evidence, not verified understanding
```

Assay does not prove that a model understood the codebase. It makes delegated change claims visible enough for bounded review.
