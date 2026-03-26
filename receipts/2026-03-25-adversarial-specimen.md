# Ship Receipt: First Adversarial Pack Conformance Specimen

**Date:** 2026-03-25
**Commit:** a27ffd6
**System Version Hash:** 6c167d6cd0a2c1c201171a3f052c3a41

## What Shipped

First preregistered adversarial conformance vector: single-byte tamper
in receipt_pack.jsonl (byte 62: 'c' → 'x', making 'conformance-r001'
into 'xonformance-r001'). File size unchanged.

Expected and confirmed: `E_MANIFEST_TAMPER` on `receipt_pack.jsonl`
at file hash verification (step 1), before Ed25519 signature checking.

## Evidence Summary

- Tests: 2724 passed, 11 skipped
- Gauntlet: not run (specimen addition, no design change)
- Crosswalk: not run (single repo)
- Dangerous diffs: none
- Secrets check: clear

## Files Changed

- `tests/contracts/test_conformance_vectors.py` — added TestAdversarialTamperedReceipt (5 tests)
- `tests/contracts/vectors/pack/tampered_receipt_content/` — 5-file tampered pack
- `tests/contracts/vectors/pack/tampered_receipt_content_spec.json` — preregistration

## Corpus Status After This Ship

| Family | Vectors | Tests |
|--------|---------|-------|
| JCS (Layer 1) | 16 golden | 18 |
| Merkle (Layer 1) | 4 golden + 2 adversarial | 4 |
| Receipt projection (Layer 2) | 3 golden + 2 assertions | 4 |
| Pack golden (full pipeline) | 1 specimen | 15 |
| **Pack adversarial** | **1 specimen** | **5** |
| **Total** | **29** | **46** |

## Component Hashes

- commands: ff635cbc26673a7f11f5c440051cd03d
- hooks: b4fba594f5347b5582a950eb3f95ec5e
- agents: 11a76bd4ec8a076c076130967f56ab58
- canon_map: 2af3c9791341843e157325104667b962
- settings: d08f97b5380199633bf9368758aa4cb1
