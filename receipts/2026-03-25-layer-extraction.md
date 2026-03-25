# Ship Receipt: to_jcs_bytes() Layer Extraction

**Date:** 2026-03-25
**System Version Hash:** 91c337d1e235c218b043bc7df5b56ad3

## What Shipped

Complete extraction of the three verification layers from the entangled
`to_jcs_bytes()` call path, per `docs/contracts/EXTRACTION_PLAN.md`.

- Layer 3 (`normalize_legacy_fields`): verified vestigial, bypassed in proof path
- Layer 2 (`prepare_receipt_for_hashing`): extracted as explicit projection helper
  with versioned exclusion set, root-only stripping doctrine, no silent swallowing
- Layer 1 (`jcs.canonicalize`): all external callers now import directly
- `to_jcs_bytes()` has zero external callers; retained internally for
  `compute_payload_hash` and `verify_jcs_stability`

## Evidence Summary

- **Tests:** 2677 passed, 11 skipped (baseline was 2650/11; +27 contract tests)
- **Gauntlet:** not run (no attack-report.md)
- **Crosswalk:** not run (no drift-report.md)
- **Plan adherence:** on-plan (followed EXTRACTION_PLAN.md sequencing exactly)
- **Dangerous diffs:** none (0 TODOs/FIXMEs added, no CI/CD changes, no deleted tests)
- **Secrets check:** clear

## Commits

| SHA | Message |
|-----|---------|
| `5b5566e` | fix(verification): harden proof-boundary invariants and metadata semantics |
| `d8ac435` | refactor(canonicalization): extract Layer 2 projection helper and migrate two callers |
| `93b73bd` | test(canonicalization): add Layer 2 projection contract tests and root-only doctrine |
| `4bdb327` | refactor(canonicalization): migrate remaining Group B callers and reclassify evidence_pack |
| `d5f4d24` | refactor(canonicalization): migrate all Group A callers to jcs_canonicalize() |

## Files Changed

28 files, +2147/-87 lines:

**Source (20 files):**
canonicalize.py, integrity.py, proof_pack.py, evidence_pack.py,
acceptance.py, adc_emitter.py, claim_verifier.py, coverage.py,
episode.py, lifecycle_receipt.py, lockfile.py, passport_sign.py,
replay_judge.py, residual_risk.py, reviewer_packet_compile.py,
reviewer_packet_events.py, reviewer_packet_verify.py, run_cards.py,
vendorq_models.py, schemas/pack_manifest.schema.json

**Tests (2 files):**
test_integrity_mutants.py (+267 lines), test_layer2_projection.py (new, 267 lines)

**Docs (6 files):**
docs/contracts/ — VERIFICATION_LAYERS.md, BOUNDARY_MAP.md,
PACK_CONTRACT.md, OPEN_CONTRACT_DECISIONS.md, TEST_VECTOR_SPEC.md,
EXTRACTION_PLAN.md

## Component Hashes

```
commands: 92c76b56ac7d4d34fb1dc33723e535de
hooks:    b09a6bafd37c966c30a5f40175a64f43
agents:   4e6bf7c987cdffea8c1973336977a531
canon_map:1da45504be1e2d1073678aeda9573d17
settings: d08f97b5380199633bf9368758aa4cb1
```

## Remaining Work

- `to_jcs_bytes()` deprecation note (optional — zero external callers already)
- `compute_payload_hash` and `verify_jcs_stability` still use old internal pipeline
- Dead `normalize_legacy_fields` import machinery in canonicalize.py (cleanup)
