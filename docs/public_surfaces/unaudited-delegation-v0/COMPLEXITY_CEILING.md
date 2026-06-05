# Complexity Ceiling

Complexity is not the ceiling on AI coding. Complexity is the ceiling on unaudited delegation.

That distinction matters. It avoids two errors:

- treating AI coding as permanently capped by today's tools
- claiming that Assay solves software complexity

Assay's narrower position is that a model alone cannot safely absorb arbitrary system complexity. A governed change system can raise the delegation boundary by making each change smaller, claimed, evidenced, checked, and reviewable.

## The Bottleneck

Writing code is only one cost in software work. The harder cost is understanding a system well enough to change it without breaking adjacent behavior.

AI can reduce the cost of generating code while increasing the amount of code and review surface that teams must understand. That turns reviewability into a control problem:

```text
messy codebase
-> repo map
-> explicit invariants
-> bounded agent task
-> patch
-> receipt
-> verifier report
-> proof card
-> human review
```

The model may still write the patch. It does not get to silently smuggle design decisions, scope expansion, or unsupported claims into the repository.

## Assay's Boundary

Assay does not prove understanding. Assay checks whether a delegated change makes bounded claims supported by captured evidence under an explicit policy.

The review surface should answer:

- What claim did the delegated change make?
- What files and modules were allowed?
- What files and modules were forbidden?
- Which invariants were supposed to hold?
- Which evidence was captured?
- Which policy made the verdict?
- Which caveats and non-claims remain?

The useful output is not only `PASS`. The high-value output is often:

```text
NEEDS_SPLIT
```

`NEEDS_SPLIT` means the change may contain useful work, but it crosses too many review boundaries to approve honestly as one unit.

## Design Implication

The system should reward small, legible delegation:

- one declared claim
- one bounded scope
- clear forbidden scope
- explicit invariants
- evidence paths
- deterministic review signals
- a proof card with caveats

The public wedge is AI-generated pull requests. The reusable category is delegation governance.
