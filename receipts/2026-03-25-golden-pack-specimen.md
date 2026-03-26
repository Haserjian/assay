# Ship Receipt: Golden Pack Conformance Specimen

**Date:** 2026-03-25
**System Version Hash:** a9da176b292b6baeb02b80a28820ea44

## What Shipped

One commit on Assay main (unpushed):

### Assay (commit 2e25242)
- **What:** First full-pipeline conformance artifact — real 5-file proof pack specimen
- **Artifact:** `tests/contracts/vectors/pack/golden_minimal/` (5 pack files + expected_outputs.json)
- **Tests:** 15 new conformance tests exercising all 11 verification steps
- **Suite:** 2719 passed, 11 skipped (was 2704 at session start)

## Verification Steps Exercised

1. Schema validation
2. Expected files present (all 5)
3. File hash verification (SHA-256)
4. Receipt count cross-check
5. Head hash computation
6. Attestation hash check
7. Detached signature parity
8. Unsigned manifest reconstruction
9. Ed25519 verification (self-contained, embedded pubkey)
10. D12 invariant (pack_root_sha256 == attestation_sha256)
11. signer_pubkey_sha256 fingerprint

## Evidence

- Tests: 2719 passed, 11 skipped, 0 failures
- Dangerous diffs: 0 secrets, 0 TODO/FIXME
- Specimen self-contained: verifies with keystore=None using embedded signer_pubkey
- Deterministic: 32 zero-byte Ed25519 seed + fixed timestamp = reproducible pack (TEST ONLY key material)

## Decisions

- Used `-f` to force-add `receipt_pack.jsonl` past `.gitignore` `*.jsonl` rule — conformance fixture, not generated artifact
- README explicitly marks deterministic key as test-only
- Specimen is a real directory (not JSON abstraction) — matches how packs actually exist

## What Remains

- 1 unpushed commit — push next session
- Next target: one minimal adversarial (tampered) pack specimen
- After that: release prep (semver bump + changelog)
