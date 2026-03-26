# Ship Receipt: Post-Extraction Contract Reconciliation

**Date:** 2026-03-25
**Commit:** 65055fe
**System Version Hash:** 0d991610c8778002fa2762b44648d7f1

## What Shipped

Docs-only reconciliation pass syncing 4 contract documents to the
post-extraction code reality. No code changed. Replaces stale claims
about contaminated pipelines with code-cited current architecture.

## Evidence Summary

- Tests: 2678 passed, 11 skipped
- Gauntlet: not run (docs-only, no code changes)
- Crosswalk: not run (single-repo)
- Plan adherence: on-plan (bounded mismatch map → targeted edits)
- Dangerous diffs: none
- Secrets check: clear

## Changes by Document

**BOUNDARY_MAP.md**: Rewrote "BOUNDARY VIOLATION" section as "LAYER 2 —
Explicit Receipt Projection (clean, freezable)". Updated call chain
diagram to show clean L1/L2 architecture. Updated integrity.py caveats
(head_hash and stability check resolved). Updated summary table.

**PACK_CONTRACT.md**: Section 4 now freezable (was "NOT YET FREEZABLE").
Removed contamination caveats from Sections 5, 8, 11. Marked head_hash
resolved in Section 10. Updated verification step descriptions.

**OPEN_CONTRACT_DECISIONS.md**: Marked 5 OCDs as RESOLVED with dates
and evidence citations:
- OCD-2: prepare_receipt_for_hashing() is explicit Layer 2
- OCD-3: normalize_legacy_fields confirmed vestigial, deleted
- OCD-4: head_hash failure → explicit E_MANIFEST_TAMPER
- OCD-8: signature_scope field corrected + poison-pill tests
- OCD-10: descriptive field doctrine + schema hardening

**TEST_VECTOR_SPEC.md**: Unblocked payload hash vectors (OCD-2/3
resolved). Updated prerequisites (only OCD-1 remains).

## Freeze-Readiness After This Pass

| Document | Status |
|----------|--------|
| VERIFICATION_LAYERS.md | GREEN |
| EXTRACTION_PLAN.md | GREEN (COMPLETE) |
| BOUNDARY_MAP.md | GREEN |
| PACK_CONTRACT.md | GREEN (except §5 hash format — OCD-1) |
| OPEN_CONTRACT_DECISIONS.md | GREEN |
| TEST_VECTOR_SPEC.md | YELLOW-GREEN (OCD-1 blocks corpus) |

## Remaining Open Decisions

| OCD | Level | Blocks |
|-----|-------|--------|
| OCD-1 | HIGH | Hash format, test vectors, corpus generation |
| OCD-5 | LOW | Merkle domain separation (v1) |
| OCD-6 | LOW | _trace_id naming |
| OCD-7 | LOW | Strict mode default |
| OCD-9 | MEDIUM | Direct/indirect verifier obligations |

## Component Hashes

- commands: ff635cbc26673a7f11f5c440051cd03d
- hooks: 36c40763507bb95c1d042eada2b7282a
- agents: 11a76bd4ec8a076c076130967f56ab58
- canon_map: 2af3c9791341843e157325104667b962
- settings: 94d9069210f380b68328c2e7e568fd6e
