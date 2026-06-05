# Assay PR Gate Comment v0

The PR comment is not the product. The signed review decision is the product.
The PR comment is the required delivery surface because it appears at the pull
request review moment.

This document defines the first rendered comment contract.

## Goals

- Show the review decision without requiring a dashboard.
- Make the evidence binding visible in the comment body.
- Preserve verdict-channel discipline.
- Avoid implying the code is secure, correct, or production-approved.
- Link to the signed evidence pack and Verification Report.

## Required Fields

Every Assay PR Gate comment must include:

- overall decision
- recommended action
- reason
- subject repo, PR, head commit, and diff hash
- verdict channels
- Evidence Box
- Verification Report
- Signature Proof
- Do Not Infer footer
- expected signer identity

## Canonical NEEDS_REVIEW Comment

```text
Assay PR Gate: NEEDS_REVIEW

Recommended action: require_human_approval
Reason: touched risk path auth/**

Subject:
- repo: Haserjian/assay
- PR: #123
- head commit: abc123
- diff hash: sha256:...

Verdict channels:
- Integrity: PASS
- Claim: NOT_EVALUATED
- Replay: NOT_RUN
- Trust policy: NEEDS_REVIEW - touched auth/session.py

Evidence:
- Evidence Box: proof-pack/pack_manifest.json
- Verification Report: signed-report/verify_report.json
- Signature Proof: signed-report/verify_report.sigstore.json

Do not infer:
- code is secure
- all possible tests passed
- AI made a good design decision
- replay was performed
- production approval was granted

Signed by expected workflow:
https://github.com/Haserjian/assay/.github/workflows/assay-pr-gate.yml@refs/heads/main
```

## Decision Rendering

Use exactly these labels:

```text
PASS - proceed to normal review
NEEDS_REVIEW
BLOCK
ERROR
```

Do not render `PASS` as "safe to merge." `PASS` only means Assay found no
policy reason to stop normal review.

## Recommended Action Rendering

Use exactly these action identifiers:

```text
proceed
require_human_approval
request_codeowner_review
rerun_required_check
block_missing_evidence
block_required_check_failed
block_integrity_failed
block_untrusted_signer
manual_triage
```

Each action can have a human sentence next to it, but the identifier itself
must remain stable.

## Claim Wording

Do not write:

```text
Tests passed.
```

Write:

```text
Claim: PASS - claim_gate report verdict PASS
```

or:

```text
Claim: FAIL - claim_gate BLOCK: possible_to_guaranteed
```

If no `claim_gate_report` is present, write:

```text
Claim: NOT_EVALUATED
```

The Claim channel must not treat ordinary required-check observations as claim
truth. Required checks belong in check observations, trust-policy reasons, or
the top-level recommendation.

## Evidence Wording

Use the three-object model:

| Human name | Meaning |
|---|---|
| Evidence Box | The evidence pack being reviewed. |
| Verification Report | What Assay decided about the evidence. |
| Signature Proof | Who signed the public Verification Report. |

Do not require readers to learn Sigstore, Cosign, or pack internals from the
comment. Those belong in linked technical details.

## Snapshot Cases

The eventual renderer should have stable snapshots for:

- `PASS`
- `NEEDS_REVIEW`
- `BLOCK`
- `ERROR`

Minimum planned snapshot paths:

```text
tests/pr_gate/snapshots/comment_pass.md
tests/pr_gate/snapshots/comment_needs_review.md
tests/pr_gate/snapshots/comment_block.md
tests/pr_gate/snapshots/comment_error.md
```

## Non-Claims

The comment must not claim:

- the code is secure
- all relevant tests passed
- AI made a good design decision
- replay was performed
- production approval was granted
- legal or compliance approval was granted
