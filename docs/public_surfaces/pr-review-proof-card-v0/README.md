# PR Review Proof Card v0

PR Review Proof Card v0 is an observed reader projection over one real Assay
PR Gate artifact.

It is for a maintainer or tech lead reviewing an AI-assisted pull request at
the review moment. It supports one decision:

```text
proceed to review, require more evidence, or block
```

Core invariant:

```text
A Proof Card displays which checks ran and where the evidence stops.
It does not assert truth, correctness, safety, security, or merge-readiness.
Absence of a check is shown, never hidden.
```

## Why This Is Not Generic Proof Card v0

This packet names one consumer and one call site before defining a reusable
shape:

- Consumer: maintainer or tech lead.
- Call site: GitHub PR comment or downloaded Assay PR Gate artifact.
- Source: a real `assay-pr-gate-report` artifact.
- Decision: proceed to review, require more evidence, or block.

That keeps the surface tied to a deciding moment instead of turning Proof Card
into an abstract badge.

## Source Artifact

The observed example is derived from GitHub Actions run `27047357238`, artifact
`assay-pr-gate-report`, for PR `#161`.

Source precedence:

1. `signed-report/verify_report.json` is the canonical signed report source.
2. `decision.json` may be used for matching PR Gate decision fields.
3. `proof-pack/pack_manifest.json` may be used for evidence-pack structure.
4. `comment.md` may be used only as rendered-output comparison, not as
   authority.

The signed Verification Report remains canonical. This card is a reader
projection and is not independent evidence.

## Files

- `SOURCE_ARTIFACT.md` records the source run, artifact, subject, and local
  convenience copy used for this derivation.
- `DERIVATION.md` maps fields from the PR Gate artifact into the observed card.
- `examples/pr_161_needs_review.observed.json` is the generated observed
  projection.
- `COLD_READ.md` is a skeptical-reader check for the surface.

## What The Card Can Say

This observed card can say:

- the PR Gate decision was `NEEDS_REVIEW`;
- the recommended action was `require_human_approval`;
- Integrity passed;
- Claim failed because Claim Gate blocked two trust-escalating transitions;
- Replay was `NOT_RUN`;
- Trust policy passed;
- no required-check observations were recorded in the artifact;
- the evidence pack and expected workflow identity are named by the signed
  report.

## What The Card Cannot Say

This observed card must not claim:

- the code is secure;
- all possible tests passed;
- the AI made a good design decision;
- replay was performed;
- production approval was granted;
- the PR is ready to merge;
- the underlying code change is correct.

Those limits are part of the card. They are not footnotes.

## Why There Is No Schema Yet

No `proof_card.schema.json` is included in this slice.

A schema would turn the observed shape into a contract before the projection is
proven across more real artifacts. This packet records one observed shape from
one real PR Gate artifact first. A future schema should be derived only after
there is enough observed output and a clear generator or validation path.
