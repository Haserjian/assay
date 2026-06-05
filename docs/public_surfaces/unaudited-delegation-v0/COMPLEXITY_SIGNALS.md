# Complexity Signals

Complexity signals are reviewability signals, not truth metrics.

They help decide whether a delegated change is small enough, evidenced enough, and bounded enough for honest review.

## Signals

| Signal | What it asks | Example use |
|---|---|---|
| `files_touched` | How much review surface exists? | large count can raise `review_load` |
| `modules_crossed` | How many ownership or design areas changed? | auth plus billing plus config may trigger `NEEDS_SPLIT` |
| `public_api_changed` | Did external contracts move? | requires API evidence or owner review |
| `test_delta_present` | Did tests change with behavior? | missing tests can become `INSUFFICIENT_EVIDENCE` |
| `behavioral_equivalence_evidence` | Is a refactor-only claim supported? | absent evidence can block a "no behavior change" claim |
| `diff_size` | How much changed text must be reviewed? | large diffs can raise review load even in one module |
| `claim_scope_match` | Does the diff match the declared claim? | "cleanup" touching runtime policy may fail |
| `dependency_boundary_crossing` | Did the change alter dependency direction or coupling? | broad dependency changes often need splitting |
| `reviewer_cognitive_load_estimate` | Can one reviewer honestly approve this unit? | bucketed as `low`, `medium`, `high`, or `too_high` |

## Review Load Buckets

Use buckets instead of fake precision:

```text
low        small local change with direct evidence
medium     bounded change with clear owner and tests
high       broad change requiring careful cross-module review
too_high   cannot be reviewed honestly as one PR
```

`reviewer_cognitive_load_estimate` is a policy signal. It is not a measurement of reviewer competence.

## NEEDS_SPLIT Triggers

A policy may return `NEEDS_SPLIT` when:

- one PR crosses unrelated product boundaries
- a refactor claim includes runtime behavior changes
- a diff modifies public API and internals together
- tests are updated in a way that masks behavior changes
- generated code changes too many files for one accountable review
- ownership boundaries are crossed without owner evidence

## Caveats

These signals do not prove correctness or design quality. They make review burden visible so a human does not have to infer it from a large, plausible diff.
