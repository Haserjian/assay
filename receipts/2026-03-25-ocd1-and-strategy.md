# Ship Receipt: OCD-1 Resolution + Language Strategy Hardening

**Date:** 2026-03-25
**System Version Hash:** a9da176b292b6baeb02b80a28820ea44

## What Shipped

Two cross-repo commits closing the contract-freeze arc:

### Assay (commit b570130)
OCD-1 resolved: `compute_payload_hash()` now returns raw hex instead of
prefixed `sha256:hex`. The algorithm is declared at manifest level via
`hash_alg`, not per-value. This was the last HIGH blocker. 0 HIGH OCDs
remain. 6 of 10 resolved.

### Loom (commit 3f8faa71)
Language strategy doc hardened from governing essay into operational
constitution. Four new sections: Interop Boundary (DSSE/in-toto/Sigstore),
Threat Model (8 named adversaries), Verifier Error Taxonomy (8 failure
categories), Reopen Triggers (6 conditions). Plus: fifth decision axis
(ecosystem interop), concrete portability gate artifacts, interface-centric
verification table, Phase 1 progress, tightened evidence claims.

## Evidence Summary

- Tests: 2678 passed, 11 skipped (Assay)
- Gauntlet: not run (OCD-1 is a small format change; strategy doc is doc-only)
- Crosswalk: not run (repos are complementary, not conflicting)
- Dangerous diffs: none
- Secrets check: clear

## Freeze-Readiness After This Ship

| Area | Status |
|------|--------|
| PACK_CONTRACT.md (all 12 sections) | GREEN — freezable |
| BOUNDARY_MAP.md | GREEN |
| VERIFICATION_LAYERS.md | GREEN |
| OPEN_CONTRACT_DECISIONS.md | GREEN (6/10 resolved, 0 HIGH) |
| TEST_VECTOR_SPEC.md | GREEN (corpus generation unblocked) |
| Language strategy | GREEN (operational, not just strategic) |

## Open OCDs Remaining

| OCD | Level | Blocks |
|-----|-------|--------|
| OCD-5 | LOW | Merkle domain separation (v1) |
| OCD-6 | LOW | _trace_id naming |
| OCD-7 | LOW | Strict mode default |
| OCD-9 | MEDIUM | Direct/indirect verifier obligations (2 edge vectors) |

None block contract freeze or release.

## Component Hashes

- commands: ff635cbc26673a7f11f5c440051cd03d
- hooks: 36c40763507bb95c1d042eada2b7282a
- agents: 11a76bd4ec8a076c076130967f56ab58
- canon_map: 2af3c9791341843e157325104667b962
- settings: d08f97b5380199633bf9368758aa4cb1
