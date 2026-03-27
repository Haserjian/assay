# Ship Receipt: Compiled Packet v1

**Date**: 2026-03-26
**Commit**: aec6ffb
**System Version Hash**: 6c167d6cd0a2c1c201171a3f052c3a41

## What Shipped

Compiled packet v1 — the first reviewer-ready evidence artifact system in Assay.

Introduces a four-object model:
- **Proof pack** (existing, unchanged) — trust root
- **Claim binding** (new primitive) — maps questionnaire items to evidence
- **Compiled packet** (new artifact) — reviewer-facing composition layer
- **Verification result** (new output) — two-axis independent verdict

## Key Decisions

- Claim bindings are operator-authored artifacts validated by the compiler, not inferred truths
- `confidence` field cut from v1 (fake precision without mechanistic definition)
- `binding_status` and `evidence_basis` are orthogonal axes
- Verifier produces two-axis verdict: `integrity_verdict` + `completeness_verdict`
- Top-level verdict derived via pure function with exhaustive truth table (12 cells)
- DEGRADED (compromised nested evidence) distinguished from PARTIAL (coverage gaps)
- Packet root identity roots over questionnaire + bindings + pack refs (content, not metadata)

## Evidence

- **Tests**: 2705 passed, 11 skipped, 0 failed (22 new compiled packet tests)
- **Tamper matrix**: 5 scenarios tested (modified binding, missing pack, broken sig, corrupted nested receipt, missing manifest)
- **Truth table**: all 12 integrity x completeness cells tested
- **No regressions**: full test suite green
- **Gauntlet**: not run (first implementation, no attack surface yet)
- **Crosswalk**: not run

## Files Changed

| File | Status | Lines |
|------|--------|-------|
| src/assay/compiled_packet.py | NEW | 859 |
| src/assay/commands.py | MODIFIED | +154 |
| docs/specs/COMPILED_PACKET_SPEC_V1.md | NEW | 773 |
| docs/specs/PACKET_SEMANTICS_V1.md | NEW | 190 |
| tests/assay/test_compiled_packet.py | NEW | 242 |

## Component Hashes

```
commands: ff635cbc26673a7f11f5c440051cd03d
hooks: b4fba594f5347b5582a950eb3f95ec5e
agents: 11a76bd4ec8a076c076130967f56ab58
canon_map: 2af3c9791341843e157325104667b962
settings: d08f97b5380199633bf9368758aa4cb1
```

## Next

- TS verifier parity against PACKET_SEMANTICS_V1.md truth table
- Claim-level verification summaries in verifier output
- Reviewer-facing rendering (executive summary, claim table)
- First real external reviewer feedback loop
