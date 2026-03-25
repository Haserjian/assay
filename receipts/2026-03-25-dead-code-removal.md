# Ship Receipt: to_jcs_bytes Dead Code Removal

**Date:** 2026-03-25
**System Version Hash:** bef8de9d804df2d33f32d7c898280b8e

## What Shipped

Final cleanup of the to_jcs_bytes() extraction. Removed all dead code:
`to_jcs_bytes()`, `_prepare_for_canonicalization()`, the 26-line
`normalize_legacy_fields` SourceFileLoader fallback, and the unused
`strip_signatures` import. Migrated 9 test files from `to_jcs_bytes`
to `jcs_canonicalize`. EXTRACTION_PLAN.md is fully complete.

## Evidence Summary

- **Tests:** 2678 passed, 11 skipped
- **Gauntlet:** not run (mechanical cleanup)
- **Crosswalk:** not run (single-repo)
- **Plan adherence:** on-plan (completes EXTRACTION_PLAN.md)
- **Dangerous diffs:** none
- **Secrets check:** clear

## Files Changed

| File | Change |
|------|--------|
| `src/assay/_receipts/canonicalize.py` | Removed dead functions + imports, updated docstring |
| `tests/assay/test_adc_emitter.py` | Import swap |
| `tests/assay/test_evidence_pack.py` | Import swap |
| `tests/assay/test_integrity_mutants.py` | Import swap (4 inline imports) |
| `tests/assay/test_layer2_projection.py` | Removed equivalence tests, added migration tests |
| `tests/assay/test_lifecycle_receipt.py` | Import swap (2 inline imports) |
| `tests/assay/test_proof_pack.py` | Import swap |
| `tests/assay/test_replay_judge.py` | Import swap |
| `tests/assay/test_replay_judge_cli.py` | Import swap |
| `tests/assay/test_witness.py` | Import swap |

## Commit

`670129e` — refactor(canonicalization): remove to_jcs_bytes and dead Layer 3 machinery

## Component Hashes

```
commands:  92c76b56ac7d4d34fb1dc33723e535de
hooks:     fa2675f5309ed42511c849316e6ac226
agents:    4e6bf7c987cdffea8c1973336977a531
canon_map: 1da45504be1e2d1073678aeda9573d17
settings:  d08f97b5380199633bf9368758aa4cb1
```
