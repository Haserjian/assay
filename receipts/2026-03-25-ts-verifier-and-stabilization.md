# Ship Receipt: TypeScript Verifier + Stabilization

**Date:** 2026-03-25
**System Version Hash:** 6c167d6cd0a2c1c201171a3f052c3a41

## What Shipped

### assay-verify-ts (new repo — Haserjian/assay-verify-ts)

Independent TypeScript pack verifier, built from contract spec and
conformance corpus. Two implementations now agree on all corpus vectors.

**Commits:**
- `3e72dba` — feat: first implementation (verifier + JCS + 36 tests)
- `21e01e1` — chore: CI, development docs, TODO items, wording sweep
- `d209fd6` — fix(ci): checkout corpus before running tests

**Tests:** 36 across 6 suites
- 17 JCS conformance (Layer 1)
- 6 golden pack pipeline
- 3 adversarial tampered receipt
- 5 path containment (traversal, absolute, abort-before-read)
- 2 duplicate receipt_id (PK-A06)
- 3 malformed manifest shape (crash resistance)

**CI:** Green on Node 20 + 22. Cross-repo corpus sync via sparse
checkout of Haserjian/assay.

**Key finding:** Python's scientific notation formatting (1E21) deviates
from RFC 8785's ECMAScript-native form (1e+21). Named as Assay JCS
Profile v1 — explicit deviation, not hidden shim.

**Security fixes during review:**
- Path containment enforced for ALL manifest-driven paths before any I/O
- Duplicate receipt_id detection added (PK-A06)
- Malformed manifest shape handled gracefully (Array.isArray guards)

### Assay (1 commit)

- `769737d` — docs(contract): rename §3 to Assay JCS Profile v1

## Evidence Summary

- Tests: 36 pass (TS), 2724 pass (Python)
- CI: green on both Node 20 and 22
- Gauntlet: not run (new repo bootstrap)
- Crosswalk: cross-repo corpus sync verified via CI
- Dangerous diffs: none
- Secrets check: clear

## Cross-Implementation Agreement

Both Python and TypeScript produce identical results for:
- 16 JCS golden vectors (exact canonical bytes + SHA-256)
- 1 golden pack specimen (full 11-step pipeline)
- 1 adversarial specimen (E_MANIFEST_TAMPER on tampered receipt)

## Component Hashes

- commands: ff635cbc26673a7f11f5c440051cd03d
- hooks: b4fba594f5347b5582a950eb3f95ec5e
- agents: 11a76bd4ec8a076c076130967f56ab58
- canon_map: 2af3c9791341843e157325104667b962
- settings: d08f97b5380199633bf9368758aa4cb1
