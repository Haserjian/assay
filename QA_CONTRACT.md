# QA Contract (v2)

This repository uses a machine-readable QA contract at [`.github/qa_contract.yaml`](.github/qa_contract.yaml).

Purpose:
- Keep core CI invariants stable.
- Catch accidental workflow drift before merge.

Validator:
- [`scripts/ci/validate_qa_contract.py`](scripts/ci/validate_qa_contract.py)

CI enforcement:
- [`.github/workflows/qa-contract-drift.yml`](.github/workflows/qa-contract-drift.yml)

## Tier model

The contract now supports multiple tiers under `tiers:`.

- `public` (active tier in this repo)
  - requires pinned action refs (`@ref`)
  - supports required/advisory check lists
- `private_strict` (template tier)
  - extends `public`
  - enables `require_uses_sha: true`

Use `--tier` to validate a non-default tier:

```bash
python scripts/ci/validate_qa_contract.py --tier private_strict
```

## Less brittle step matching

`required_steps` supports structured matching in addition to exact names:

- `name` (exact)
- `name_contains`
- `run_contains`
- `uses`

This reduces false drift failures from cosmetic step-name edits while preserving contract intent.
