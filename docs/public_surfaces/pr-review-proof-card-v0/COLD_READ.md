# Cold Read

Use this as a stranger test for PR Review Proof Card v0.

A reader should be able to answer these questions without knowing Assay
internals.

## Reader Questions

1. Who is this card for?
2. What decision does it support?
3. What is the canonical source of truth?
4. What ran?
5. What failed?
6. What did not run?
7. What evidence was unavailable or not derived?
8. What should not be inferred?
9. Did the card make a `NEEDS_REVIEW` result look like a badge?
10. Did the card imply merge-readiness?

## Passing Answer

The reader should answer:

- This is for a maintainer or tech lead reviewing an AI-assisted PR.
- It supports deciding whether to proceed to review, require more evidence, or
  block.
- The signed Verification Report is the canonical source of truth.
- Integrity passed and Trust policy passed.
- Claim failed because Claim Gate blocked two trust-escalating transitions.
- Replay was not run.
- No required-check observations were recorded.
- Some evidence-reference hashes were unavailable because the source report
  recorded them as `null`.

The reader should also say:

```text
The card shows which checks ran and where evidence stops.
It does not assert truth, correctness, safety, security, or merge-readiness.
```

## Failing Answer

The cold read fails if the reader infers that:

- the code is secure;
- all possible tests passed;
- the AI made a good design decision;
- replay was performed;
- production approval was granted;
- `NEEDS_REVIEW` is a green badge;
- the card replaces the signed Verification Report;
- the card is a generic Proof Card schema.

## Non-Authority Check

The reader must be able to identify `comment.md` as a rendered review surface,
not as authority. The source precedence must be clear:

1. signed Verification Report;
2. decision object;
3. pack manifest;
4. rendered comment.
