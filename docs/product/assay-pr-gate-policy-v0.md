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
block_integrity_failed
block_untrusted_signer
manual_triage
```

No free-form action identifiers in v0.

## Initial Rules

Rules are evaluated from most severe to least severe.

| Rule | Decision | Recommended action |
|---|---|---|
| `integrity_failed` | `BLOCK` | `block_integrity_failed` |
| `untrusted_signer` | `BLOCK` | `block_untrusted_signer` |
| `required_check_failed` | `BLOCK` | `block_missing_evidence` |
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

The first bounded claim is only:

```text
Observed check "<name>" concluded "<conclusion>" for commit "<sha>".
```

It is not:

```text
All tests passed.
```

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
    "claim": "PASS",
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
- integrity failed
- untrusted signer
- multiple reasons with deterministic ordering

## Example Policy

The concrete example file lives at:

```text
docs/examples/pr-gate-v0/assay-policy.yml
```
