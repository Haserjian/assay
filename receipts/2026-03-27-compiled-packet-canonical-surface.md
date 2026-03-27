# Ship Receipt: Compiled Packet Canonical Surface (P0 + P1)

**Date**: 2026-03-27
**Commits**: e382d5f (P0), 6030c3f (P1)
**System Version Hash**: edc918d9a472e300882c9ed8a1adc3c2

## What Shipped

Two-commit arc establishing the compiled packet as a canonical, documented,
testable, and demonstrable product surface.

### P0 — Contract Truth (e382d5f)

**`docs/packets.md`** — routing authority. Names both packet systems (compiled =
canonical general-purpose, reviewer = VendorQ-specific), their relationship, planned
convergence, comparison table, and quick-reference commands. This is the single file
everything else references.

**`docs/specs/COMPILED_PACKET_VERIFY_CONTRACT.md`** — external contract for
`assay packet verify --json`. Full field reference (schema_version, packet_id,
packet_root_sha256, integrity_verdict, completeness_verdict, verdict, admissible,
admissibility_reasons, subject, pack_results, coverage, warnings, errors), exit code
semantics, error code table with severity levels, three worked examples (PARTIAL+admissible,
NOT_SELF_CONTAINED, TAMPERED), consumer patterns for shell/Python/TS, and stability
guarantees. Freezes the interop membrane before external integrators build against it.

**`docs/specs/COMPILED_PACKET_ARCHITECTURE.md`** — canonical architecture note.
Three-layer model (evidence/truth/decision), core primitives, verify/gate boundary,
non-goals, freshness gap, one-sentence version.

**`docs/ROADMAP.md`** — compiled packet subsystem added to Shipped table: packet
init/compile, packet verify --json, subject binding + admissibility + gate.

**`docs/WHAT_ASSAY_DOES_TODAY.md`** — Step 5 now shows both packet paths with
commands. Terminology section adds compiled packet definition with the log/product
wedge sentence. Who-does-what section references packets.md. "One paragraph" summary
includes compiled packet.

**`receipts/2026-03-27-verify-exit-code-contract.md`** — ship receipt for c04a386
that was produced during the session but not yet committed to the repo.

### P1 — Operational Usability (6030c3f)

**`examples/compiled_packet/questionnaire.csv`** — 4-question minimal questionnaire.
No VendorQ dependency.

**`examples/compiled_packet/demo.sh`** — full lifecycle demo: init → compile → verify
(human-readable + --json) → gate (PASS) → tamper subject_digest → gate (BLOCKED).
Computes `subject_digest` by hashing the questionnaire file — realistic pattern.
Passes `bash -n` syntax check. Does three jobs: dev onboarding, buyer demo asset,
regression fixture.

**`tests/assay/test_gate_shell.py`** — 10 shell-level integration tests for
`scripts/assay-gate.sh` via subprocess against real compiled packets:
- PASS on bundled INTACT packet
- BLOCKED on non-bundled (NOT_SELF_CONTAINED)
- BLOCKED on tampered manifest (subject_digest mutated)
- BLOCKED on tampered bindings (claim_bindings.jsonl overwritten)
- BLOCKED on missing directory
- BLOCKED on empty directory (INVALID manifest)
- BLOCKED on no argument
- stdout shows subject identifier on PASS
- stdout shows integrity verdict
- stderr contains reason line on BLOCK

**`docs/ci-integration.md`** — Stage 6 added: compiled packet gate with YAML CI
example. Terminology section distinguishes diff gate (assay diff, Stages 1–4) from
packet gate (assay-gate.sh, Stage 6). Pointer to packets.md added to Read next.

**`docs/START_HERE.md`** — reviewer-packets.md reference updated to packets.md,
routing readers to both packet systems.

**`docs/FULL_PICTURE.md`** — Layer 3.5 inserted in the four-layer architecture.
Describes compiled packet: questionnaire + claim bindings, subject binding, two-axis
verdict. Includes wedge sentence. Pointers to packets.md and architecture note.

## Evidence

| Check | Result |
|-------|--------|
| Tests | 2728 passed, 11 skipped, 1 failed (pre-existing version mismatch — unrelated) |
| Gate shell tests | 10/10 pass |
| Gauntlet | Not run |
| Crosswalk | Not run |
| No secrets in commits | Pass |
| No CI/CD files modified | Pass |
| receipts/ directory intact | Pass |
| demo.sh bash syntax | Pass (`bash -n`) |
| No tests deleted | Pass |
| Plan adherence | On-plan (P0 and P1 as designed) |

## What Is Honestly Not Yet Fixed

- Gate shell tests don't cover the "verifier crashes before emitting JSON" path
  (would require mocking the assay binary — judged not worth the complexity)
- P2 surfaces (README, for-compliance, pilot docs) not yet updated
- Freshness enforcement still advisory/schema-only
- Policy engine still hardcoded (`policy_id: "default"`)
- TS verifier parity with compiled packet not implemented

## Files Changed

| File | Status | Notes |
|------|--------|-------|
| docs/packets.md | NEW | Routing authority for both packet systems |
| docs/specs/COMPILED_PACKET_VERIFY_CONTRACT.md | NEW | External JSON output contract |
| docs/specs/COMPILED_PACKET_ARCHITECTURE.md | NEW | Canonical architecture note |
| docs/ROADMAP.md | MODIFIED | Compiled packet added to Shipped table |
| docs/WHAT_ASSAY_DOES_TODAY.md | MODIFIED | Step 5 fork, terminology, wedge sentence |
| receipts/2026-03-27-verify-exit-code-contract.md | NEW | Previously untracked receipt |
| examples/compiled_packet/questionnaire.csv | NEW | 4-question minimal questionnaire |
| examples/compiled_packet/demo.sh | NEW | Full lifecycle demo script |
| tests/assay/test_gate_shell.py | NEW | 10 shell-level gate integration tests |
| docs/ci-integration.md | MODIFIED | Stage 6 + diff gate/packet gate naming |
| docs/START_HERE.md | MODIFIED | packets.md routing |
| docs/FULL_PICTURE.md | MODIFIED | Layer 3.5 compiled packet |

## Component Hashes

```
commands: ff635cbc26673a7f11f5c440051cd03d
hooks: b4fba594f5347b5582a950eb3f95ec5e
agents: 11a76bd4ec8a076c076130967f56ab58
canon_map: 2af3c9791341843e157325104667b962
settings: 33e24152ef8d701f9e07ed8e9c321c23
```
