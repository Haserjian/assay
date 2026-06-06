# Assay PR Gate Policy v0

This document defines the first PR Gate policy profile:

```text
coding_pr_v0
```

The policy is intentionally small. Its job is to map captured pull request
facts to a stable review decision and recommended action.

## Decision Enum

```text
PASS
NEEDS_REVIEW
BLOCK
ERROR
```

`PASS` means Assay found no policy reason to stop normal review. It does not
mean the PR should be merged automatically.

## Recommended Action Enum

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

No free-form action identifiers in v0. `block_missing_evidence` means a
required evidence item was absent. `block_required_check_failed` means the
required check was observed and concluded unsuccessfully.

## Initial Rules

Rules are evaluated from most severe to least severe. Evaluator severity order
is fixed by the implementation; YAML order is illustrative and must not affect
the output.

| Rule | Decision | Recommended action |
|---|---|---|
| `integrity_failed` | `BLOCK` | `block_integrity_failed` |
| `untrusted_signer` | `BLOCK` | `block_untrusted_signer` |
| `required_check_failed` | `BLOCK` | `block_required_check_failed` |
| `required_check_missing` | `NEEDS_REVIEW` | `rerun_required_check` |
| `risk_path_touched` | `NEEDS_REVIEW` | `require_human_approval` |
| default | `PASS` | `proceed` |

## Risk Paths

Initial risk paths:

```yaml
risk_paths:
  - "auth/**"
  - "billing/**"
  - ".github/workflows/**"
  - "infra/**"
  - "pyproject.toml"
  - "package-lock.json"
  - "requirements*.txt"
```

These are example defaults. Consumer repos must be able to override them.

## Required Checks

Initial required checks:

```yaml
required_checks:
  - "tests"
```

The Claim channel is evaluated from embedded `claim_gate_report` evidence:

```text
claim_gate PASS         -> Claim PASS
claim_gate NEEDS_REVIEW -> Claim FAIL
claim_gate BLOCK        -> Claim FAIL
claim_gate absent       -> Claim NOT_EVALUATED
```

A claim_gate FAIL also escalates the top-level decision so the gate never
recommends `proceed` while the Claim channel reads `FAIL`. The escalation is
conservative and only applies when no rule already fired:

```text
claim_gate NEEDS_REVIEW -> overall NEEDS_REVIEW (require_human_approval)
claim_gate BLOCK        -> overall NEEDS_REVIEW (require_human_approval)
```

Rule-based outcomes take priority. A real `BLOCK` rule (for example a failed
required check) is never downgraded by claim_gate, and v0 does not let
claim_gate `BLOCK` hard-block a merge on its own; it routes to human review.

Required check observations are still captured and can drive policy decisions,
but they do not by themselves make the Claim channel `PASS`. It is not:

```text
All tests passed.
```

## Hash Inputs

`policy_sha256` is the SHA-256 hash of the parsed policy object after RFC
8785/JCS canonical JSON serialization. YAML formatting changes must not change
the hash.

`diff_sha256` belongs to capture, not policy evaluation. The PR Gate capture
contract defines it as the SHA-256 hash of the exact bytes emitted by
`git diff --binary --full-index <base_sha> <head_sha>` unless the evidence
explicitly records a different `diff_source`.

## Output Shape

Policy evaluation should produce:

```json
{
  "overall_decision": "NEEDS_REVIEW",
  "recommended_action": "require_human_approval",
  "reasons": [
    {
      "rule": "risk_path_touched",
      "path": "auth/session.py",
      "matched_pattern": "auth/**"
    }
  ],
  "channels": {
    "integrity": "PASS",
    "claim": "NOT_EVALUATED",
    "replay": "NOT_RUN",
    "trust_policy": "NEEDS_REVIEW"
  }
}
```

## Acceptance Tests

The policy evaluator must cover:

- clean PR
- risk path touched
- required check missing
- required check failed
- claim_gate report absent
- claim_gate PASS
- claim_gate NEEDS_REVIEW
- claim_gate BLOCK
- integrity failed
- untrusted signer
- multiple reasons with deterministic ordering

## Example Policy

The concrete example file lives at:

```text
docs/examples/pr-gate-v0/assay-policy.yml
```
