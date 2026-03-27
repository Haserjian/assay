# Ship Receipt: Subject Binding + Admissibility + Gate

**Date**: 2026-03-27
**Target commit**: 5563927
**System Version Hash**: 6c167d6cd0a2c1c201171a3f052c3a41

## What Shipped

Subject binding, admissibility contract with structured reason codes, fail-closed gate script, and hardening fixes from review critique.

## Findings Addressed

| Finding | Status | Evidence |
|---------|--------|----------|
| P1: admissible too weak | Improved | Now checks integrity + subject + bundle. Reason codes. Freshness advisory by design in v1. |
| P2: E_PKT_REF_MISMATCH spec/code split | Fixed | Spec reclassified to DEGRADING. Regression test locks classification. |
| P3: bundle=False still admissible | Fixed | Non-bundled → NOT_SELF_CONTAINED → inadmissible. Tested. |
| P4: subject_digest untyped | Fixed at format level | sha256:<64hex> enforced. CLI rejects 40-char SHA-1 with diagnostic. |

## What Is Honestly Not Yet Fixed

- Freshness enforcement: schema present, enforcement deferred to first buyer signal
- Policy failure → inadmissible: reason code pattern exists, no policy engine yet
- Gate-script integration tests: verifier tests cover the logic, shell tests not written
- Per-subject-type canonicalization rules: needs real usage to specify

## Evidence

- Tests: 2718 passed, 11 skipped, 0 failed (35 compiled packet tests: 12 truth table + 8 e2e + 10 subject/admissibility + 3 classification + 2 unit)
- Gauntlet: not run
- Crosswalk: not run

## Files Changed

| File | Status | Delta |
|------|--------|-------|
| src/assay/compiled_packet.py | MODIFIED | +159 lines (subject, admissibility, digest format) |
| src/assay/commands.py | MODIFIED | +50 lines (CLI digest validation, subject args) |
| docs/specs/PACKET_SEMANTICS_V1.md | MODIFIED | 1 line (E_PKT_REF_MISMATCH reclassification) |
| tests/assay/test_compiled_packet.py | MODIFIED | +345/-118 lines (35 tests, rewrites for subject) |
| scripts/assay-gate.sh | NEW | 67 lines |

## Component Hashes

```
commands: ff635cbc26673a7f11f5c440051cd03d
hooks: b4fba594f5347b5582a950eb3f95ec5e
agents: 11a76bd4ec8a076c076130967f56ab58
canon_map: 2af3c9791341843e157325104667b962
settings: d08f97b5380199633bf9368758aa4cb1
```
