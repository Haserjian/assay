# Live PR Gate Receipt: Claim Gate BLOCK -> NEEDS_REVIEW v0

This is a durable dogfood receipt for a live same-repo PR Gate run that surfaced
a generated `claim_gate` `BLOCK` as a Claim-channel failure and escalated the
top-level PR Gate decision to `NEEDS_REVIEW`.

The source PR was intentionally overclaimed and closed unmerged.

## Source

| field | value |
|---|---|
| PR | `#161` |
| PR title | `dogfood: prove live claim failure escalates to review` |
| Branch | `dogfood/live-claim-gate-needs-review-v0` |
| Head commit | `87eb68c6f1e9afb16b380ba1d2ef9df90af9a758` |
| Workflow run | `27047357238` |
| Artifact | `assay-pr-gate-report` |
| Artifact id | `7449407757` |
| PR state | closed unmerged |

## Intentional Overclaim

The PR changed one example line:

```diff
-This experimental prototype may help evaluate agent workflows.
+This production-ready framework guarantees safe autonomous agent execution.
```

The change was not meant to be accepted. It was a controlled overclaim designed
to exercise the live workflow path:

```text
GitHub PR
  -> assay claim-gate diff
  -> embedded claim_gate_report
  -> PR Gate policy evaluation
  -> signed PR Gate comment and artifact
```

## Live PR Gate Result

The signed PR Gate comment reported:

```text
Assay PR Gate: NEEDS_REVIEW
Recommended action: require_human_approval

Verdict channels:
- Integrity: PASS
- Claim: FAIL - claim_gate BLOCK: possible_to_guaranteed, prototype_to_production
- Replay: NOT_RUN
- Trust policy: PASS
```

The generated decision artifact contained:

```text
overall_decision: NEEDS_REVIEW
recommended_action: require_human_approval
channels.claim: FAIL
channels.integrity: PASS
channels.trust_policy: PASS
channels.replay: NOT_RUN
```

Derived summary from the embedded `claim_gate_report`:

```text
claim_gate_report.verdict: BLOCK
claim_gate_report.summary.files_scanned: 1
claim_gate_report.summary.blocking_transitions: 2
claim_gate_report.transitions[].transition_class:
  - possible_to_guaranteed
  - prototype_to_production
```

## Missing Evidence

The blocking transitions were caused by unsupported claim-boundary escalation:

| transition_class | verdict | missing evidence |
|---|---|---|
| `possible_to_guaranteed` | `BLOCK` | `direct_evidence`, `reviewer_acceptance` |
| `prototype_to_production` | `BLOCK` | `production_deployment_receipt`, `reproducible_test_suite` |

The generated report marked both transitions `BLOCK` because required evidence
was still missing.

## Local Verification

The downloaded artifact was verified locally with:

```bash
assay pr-gate verify \
  --pack /tmp/assay-pr-gate-161-27047357238/proof-pack \
  --report /tmp/assay-pr-gate-161-27047357238/signed-report/verify_report.json \
  --sigstore /tmp/assay-pr-gate-161-27047357238/signed-report/verify_report.sigstore.json \
  --json
```

Verification returned:

```text
status: ok
result: ASSAY PR GATE VERIFIED
report_id: vr_292c223cecdf60f2cd31
pack_root_sha256: sha256:8cf5b64706a015c7eb9840d316f6592277ebdc7eead3594b61f585a80551aa94
decision: NEEDS_REVIEW
recommended_action: require_human_approval
channels.claim: FAIL
```

## What This Receipt Supports

- A live same-repo PR Gate workflow can embed a generated `claim_gate_report`.
- A generated `claim_gate` `BLOCK` can surface as `Claim: FAIL`.
- A Claim-channel failure can escalate the top-level PR Gate decision to
  `NEEDS_REVIEW`.
- The signed PR Gate artifact can be downloaded and verified locally.

## What This Receipt Does Not Support

- It does not prove code correctness.
- It does not prove security.
- It does not prove model understanding.
- It does not approve production use.
- It does not prove merge readiness.
- It does not implement hard merge blocking for `claim_gate` `BLOCK`.
- It does not implement `NEEDS_SPLIT`.

## Boundary

This receipt is a live dogfood record, not a correctness proof. The narrow
claim is:

```text
claim_gate BLOCK
  -> Claim: FAIL
  -> Assay PR Gate: NEEDS_REVIEW
  -> require_human_approval
```

The live comment's top-level `Reason:` still renders the first claim-gate reason
as a raw JSON object. That is honest evidence, but not reviewer-grade prose.
Improving that rendering is a separate product-polish slice.
