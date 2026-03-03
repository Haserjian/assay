# QA Contract (v1)

This repository uses a machine-readable QA contract at [`.github/qa_contract.yaml`](.github/qa_contract.yaml).

Purpose:
- Keep core CI invariants stable.
- Catch accidental workflow drift before merge.

Validator:
- [`scripts/ci/validate_qa_contract.py`](scripts/ci/validate_qa_contract.py)

CI enforcement:
- [`.github/workflows/qa-contract-drift.yml`](.github/workflows/qa-contract-drift.yml)

Current tier:
- `public` toolkit baseline
