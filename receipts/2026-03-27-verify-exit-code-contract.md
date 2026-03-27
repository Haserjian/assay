# Ship Receipt: Verify Exit Code Contract + Gate Stderr Isolation

**Date**: 2026-03-27
**Target commit**: c04a386
**System Version Hash**: edc918d9a472e300882c9ed8a1adc3c2

## What Shipped

Two contract fixes in the compiled packet subsystem, closing findings from post-merge critique of ad6db9b.

**Exit code semantics (commands.py)**

`assay packet verify` previously exited 0/1 based on `result.admissible` — answering the gate's policy question, not the verifier's structural question. A command named "verify" must exit based on verification outcome (integrity), not admissibility policy.

- Before: `raise typer.Exit(0 if result.admissible else 1)`
- After: `raise typer.Exit(0 if result.integrity_verdict == "INTACT" else 1)`

Exit 0 = INTACT (structurally sound; PARTIAL coverage is honest, not a failure).
Exit 1 = TAMPERED / DEGRADED / INVALID (structural problem).

Admissibility remains available in `--json` output for callers (e.g. assay-gate.sh) that need it.
The gate is unaffected: it reads JSON directly and enforces `INTEGRITY == INTACT && ADMISSIBLE == True` independent of the verifier's exit code.

**Gate stderr isolation (assay-gate.sh)**

Previously: `assay packet verify "$PACKET_DIR" --json 2>/dev/null`. If the verifier crashed before emitting JSON, stderr was discarded and the operator saw only "GATE BLOCKED: verifier failed to produce output" with no diagnostic context.

After: stderr captured via mktemp tempfile, read after the command completes, displayed on both failure paths (empty stdout, unparseable JSON). Tempfile is cleaned up unconditionally before any exit path.

## Evidence

| Check | Result |
|-------|--------|
| Tests | 2718 passed, 11 skipped, 1 failed (pre-existing version mismatch in `test_roadmap_version_matches_pyproject`, unrelated) |
| Compiled packet tests (35) | All pass |
| Gauntlet | Not run |
| Crosswalk | Not run |
| Guardian verdict | CLEAR — all 8 invariants pass |
| No secrets in diff | Pass |
| No tests deleted | Pass |
| receipts/ directory intact | Pass |
| `print()` used in `--json` branch (not `console.print()`) | Pass |
| `set -euo pipefail` present in gate | Pass |
| mktemp cleanup before exit paths | Pass |
| Gate fail-closed logic unaffected | Pass |
| No CI/CD files modified | Pass |

## What Is Honestly Not Yet Fixed

- Gate shell integration tests: no shell-level tests for assay-gate.sh behavior written
- Freshness enforcement: advisory/schema-only in v1, deferred to first buyer signal
- Policy engine: `policy_id = "default"` is scaffolding, no real policy objects
- TS verifier parity: assay-verify-ts not yet extended to verify compiled packets against PACKET_SEMANTICS_V1

## Files Changed

| File | Status | Delta |
|------|--------|-------|
| src/assay/commands.py | MODIFIED | +4/-3 lines (exit code semantics) |
| scripts/assay-gate.sh | MODIFIED | +17/-4 lines (stderr tempfile capture) |

## Component Hashes

```
commands: ff635cbc26673a7f11f5c440051cd03d
hooks: b4fba594f5347b5582a950eb3f95ec5e
agents: 11a76bd4ec8a076c076130967f56ab58
canon_map: 2af3c9791341843e157325104667b962
settings: 33e24152ef8d701f9e07ed8e9c321c23
```
