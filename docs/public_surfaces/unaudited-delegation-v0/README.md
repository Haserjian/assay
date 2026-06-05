# Unaudited Delegation v0

Why AI-generated change needs claim firewalls, receipts, and review boundaries.

AI made code cheap. Assay protects the scarce resource: trusted review.

This packet is a docs-only public surface. It explains how Assay frames the AI coding complexity ceiling as a delegation-governance problem, not as a claim that AI coding has a permanent cap.

Core boundary:

```text
verified change evidence, not verified understanding
```

Assay does not prove that an agent understood a codebase. Assay checks whether a delegated change made bounded claims supported by captured evidence under an explicit policy.

## Why This Exists

AI coding tools can produce plausible diffs faster than human reviewers can safely absorb them. The hard question is no longer only "can the model write code?" It is:

```text
Can a reviewer tell what was delegated, what changed, what evidence exists,
and what must not be inferred?
```

Unaudited Delegation v0 gives that question a small review surface.

## Delegation Ladder

```text
Level 0: AI writes code.
Level 1: AI writes code with tests.
Level 2: AI writes code with declared claims and scope.
Level 3: AI writes code with receipts and policy-bound evidence.
Level 4: AI-generated change becomes reviewable, replayable, and governable.
```

Assay lives at levels 2-4. AI pull requests are the first painful surface where this primitive is easy to see, but the underlying shape is more general:

```text
claim -> scope -> evidence -> policy -> verdict -> receipt
```

## Packet Files

- `COMPLEXITY_CEILING.md` explains why complexity is the ceiling on unaudited delegation.
- `CLAIM_FIREWALL.md` defines the claim-control primitive.
- `PR_GATE_POLICY.md` sketches a draft delegation-review policy layer for AI-generated changes.
- `COMPLEXITY_SIGNALS.md` lists reviewability signals and their limits.
- `examples/` contains illustrative proof-card examples.
- `COLD_READ.md` is a skeptical-reader check for the packet's boundaries.

## Related Assay Surfaces

- `docs/public_surfaces/agent-operating-policy-v0/` shows the adjacent agent-policy packet: human-readable policy, machine-readable projection, examples, and a PR Gate dogfood record.
- `docs/product/assay-pr-gate-dogfood-v0.md` describes the signed PR Gate loop this packet relies on as captured evidence, not as a merge decision.

## Non-Claims

This packet does not claim that Assay:

- proves software correctness
- proves code security
- proves a model or agent understood a repository
- replaces human review
- grants production approval
- turns PR Gate verdicts into merge decisions
- evaluates all architectural risk

It claims only a narrower thing: delegated changes should be made legible as bounded claims with captured evidence, explicit policy, caveats, and reviewable verdicts.
