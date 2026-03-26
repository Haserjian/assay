# Ship Receipt: Verifier Trust-Boundary Fixes

**Date:** 2026-03-26
**Status:** Committed in `15a44d9`

## Bug Class

- Replay judge trusted ADC content before authenticating it.
- Replay judge accepted ADC signer substitution unless the bytes themselves were left invalid.
- Witness refresh re-signed ADC sidecars without first authenticating the existing credential.

## Files Changed

- `src/assay/replay_judge.py`
- `src/assay/commands.py`
- `tests/assay/test_replay_judge.py`
- `tests/assay/test_witness.py`
- `docs/assay_domain_audit_adjudication.md`
- `docs/assay_hash_signature_surface_map.md`

## Tests Added

- Replay judge rejects tampered ADC by treating it as absent.
- Replay judge rejects ADC re-signed by a non-pack signer.
- Witness refresh rejects ADC re-signed by a non-pack signer.

## Commands Run

```bash
cd /Users/timmybhaserjian/assay && uv run pytest tests/assay/test_replay_judge.py tests/assay/test_witness.py -q
```

## Scope Boundary

- Fixed in this slice:
  - ADC verify-before-compare in replay judgment
  - ADC signer binding to the pack manifest signer
  - witness refresh ADC verification before re-signing
- Not touched in this slice:
  - Untracked audit and migration docs under `docs/`
  - Broader hash-substrate or manifest-v2 design work

## Remaining Known Open Parity Issue

- Schema-validation depth and other non-P0 cross-implementation differences from the audit remain out of scope for this slice.
