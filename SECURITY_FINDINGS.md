# Security Findings — Adversarial Simulation (2026-03-29)

This document records findings from an adversarial red-team simulation
covering four attack surfaces: crypto/signing, comparability engine,
cross-verifier divergence, and ledger integrity.

**Net posture after this session**: Local verifier integrity improved
substantially across Python, TypeScript, and browser surfaces. Trust
labeling now distinguishes cryptographic validity from signer identity.
**However, append-only ledger trust remains open** — the ledger is
rewritable by anyone with file access until signed checkpoint anchoring
lands (P1a). Do not treat this session as full closure on history integrity.

---

## Closed findings

Closure tiers per `docs/security/REMEDIATION_DOCTRINE.md`.

| ID | Finding | Closure tier | Fix | Tests |
|----|---------|-------------|-----|-------|
| F0a | Gemini `generate_content(` pattern never matched in scanner | EXPLOITED-AND-PATCHED | Removed trailing `(` from `_HIGH_PATTERNS` | `test_generate_content_detected`, `test_generate_content_async_detected` |
| F0b | `assay scan /nonexistent` → exit 0 (false-clean) | EXPLOITED-AND-PATCHED | Added path existence + is_dir guards | `test_nonexistent_path_raises`, `test_file_path_raises` |
| P0 | Content hash mixed-mode spoof in comparability engine | EXPLOITED-AND-PATCHED | Reject mixed raw/hash in `_content_hash_match()` | `test_content_hash_mixed_mode_rejected`, `test_content_hash_attacker_prehash_spoof`, `test_content_hash_same_representation_still_works` |
| P1b | Verify-pack says "VERIFIED" without disclosing signer identity is unpinned | HARDENED | Emit warning when `--lock` not used; surface in terminal, JSON, and gallery UI | `test_unlocked_pass_emits_warning_in_terminal`, `test_unlocked_pass_emits_warning_in_json`, `test_locked_pass_does_not_emit_warning` |
| P2a | TypeScript verifier missing per-receipt required field validation | HARDENED | Added `REQUIRED_RECEIPT_FIELDS` check to `verify-core.ts` | `test_missing_type_field`, `test_missing_timestamp_field` |
| P2b | Gallery browser bundle is stale (missing base64 try/catch, sig/pubkey length checks) | HARDENED | Rebuilt from current `assay-verify-ts` source. **Residual**: will recur without CI freshness gate. | Bundle rebuilt and copied |
| P3a | Future timestamps in receipts not rejected by default | HARDENED | Added `max_future_hours=24.0` default in `verify_pack_manifest()` | `test_future_timestamp_rejected_by_default`, `test_near_future_timestamp_accepted`, `test_future_guard_disabled_with_zero` |
| P3b | Optional field engine bug (UNDETERMINED instead of SATISFIED for missing OPTIONAL fields) | HARDENED | Filter `missing_fields` by `REQUIRED` only | Latent — no current exposure (v1 contract marks all 15 fields REQUIRED) |
| P3c | `bool True == int 1` type confusion in `_exact` and `_within_threshold` match rules | HARDENED | Added `type(a) is not type(b)` guard in both functions | Covered by existing `test_exact_bool`, `test_exact_numeric`, `test_within_threshold_no_threshold_falls_back_exact` |

---

## Open findings

| ID | Finding | Severity | Closure tier | Next step |
|----|---------|----------|-------------|-----------|
| P1a | Ledger has no external anchor — all 4 chain attacks succeed | HIGH | DESIGN-TRACK | Implement genesis-to-tip chaining + signed checkpoint (see `assay-ledger/docs/DESIGN_SIGNED_CHECKPOINT.md`, tracked at Haserjian/assay-ledger#9) |
| P2c | Scanner cannot detect 4 evasion patterns (getattr, eval, subprocess, raw HTTP) | MEDIUM | DOCUMENTED | See `docs/SCANNER_LIMITATIONS.md`. Runtime instrumentation is future work. |

---

## Predicted findings — verified

| ID | Prediction | Observed | Disposition |
|----|-----------|----------|-------------|
| P-7 | `assay explain` and `assay bundle init` missing from `--help` | NOT CONFIRMED — both are visible in `--help` output. `explain` under "Operate", `bundle init` under "Governance" → "bundle" → "init". | NOT-A-BUG |
| P-8 | `--witness rekor` raises `NotImplementedError` at runtime | CONFIRMED — `WitnessError("Rekor witness type is not yet implemented.")` raised at runtime. No fallback. Flag appeared in `--help` with no indication it was unimplemented. | HARDENED — `--help` text now reads "not yet implemented". Capability advertising mismatch closed. |
| P-9 | `assay patch .` instruments only one file | NOT A BUG — `assay patch` adds monkey-patching imports to the single best entrypoint file, which then intercepts all SDK calls process-wide at import time. Single-file selection is the correct design for import-time monkey-patching. | NOT-A-BUG |

---

## Pre-existing issues (surfaced by QA, not introduced this session)

| ID | Issue | Severity | Closure tier | Next step |
|----|-------|----------|-------------|-----------|
| QA-1 | Falsy-value receipt field check: both Python (`not receipt.get(f)`) and TypeScript (`!receipt[f]`) treat `""` and `0` as "missing" when they are "present but invalid." Verifiers agree, but the shared behavior conflates missing with present-but-invalid. | LOW (correctness debt) | DOCUMENTED | Fix both to distinguish missing from present-but-falsy. Low urgency until schemas evolve or error messages become evidence. |
| QA-2 | No CI gate verifies gallery bundle (`assay-proof-gallery/docs/assay-verify.js`) matches current `assay-verify-ts` build output. P2b class guaranteed to recur. | MEDIUM | DOCUMENTED | Add CI step: build bundle from TS source, diff against checked-in gallery bundle, fail if diverged. |

---

## Remaining risk notes

The fixes in this session close the specific reproduced attack paths.
They do not constitute proof of exhaustive coverage:

- **P0**: No known remaining risk from the tested spoof path. Other
  comparability edge cases may exist but were not surfaced.
- **P1b**: Trust-boundary warning now present in tested CLI, JSON, and
  browser flows. Wording clarity for non-technical operators is untested.
- **P2a/P2b**: Parity restored for the tested corpus and field cases.
  Residual implementation drift risk is reduced, not eliminated.
- **P1a**: **Major open gap.** Ledger append-only claims are conditional
  on local trust boundaries until signed checkpoint anchoring lands.

---

## Trust model clarification

This adversarial simulation revealed three distinct meanings of "verification"
being partially conflated in the system:

1. **Cryptographic validity** — signature math checks out (Ed25519 verification).
   This is the strongest layer. No breaks found.

2. **Identity binding** — the signer is who you expect (`--lock` with
   pinned fingerprints). Without `--lock`, any keypair can produce a
   valid signature. Now surfaced via warning in default output.

3. **Transparency anchoring** — the ledger is append-only and externally
   witnessed. Currently the ledger chain has no external anchor.
   Design track opened for signed checkpoints.

The correct summary for leadership: **local verification got meaningfully
safer; ledger tamper-evidence is still not globally trustworthy.**

---

## Files changed

| File | Repo | Change |
|------|------|--------|
| `src/assay/comparability/match_rules.py` | assay-toolkit | P0: reject mixed raw/hash, P3c: type guard |
| `src/assay/comparability/engine.py` | assay-toolkit | P3b: OPTIONAL field filter |
| `src/assay/integrity.py` | assay-toolkit | P3a: future-timestamp guard |
| `src/assay/commands.py` | assay-toolkit | P1b: signer-not-pinned warning |
| `tests/assay/test_comparability.py` | assay-toolkit | P0 regression tests |
| `tests/assay/test_exit_code_contract.py` | assay-toolkit | P1b regression tests |
| `tests/assay/test_integrity_mutants.py` | assay-toolkit | LOC budget update for P3a |
| `tests/assay/test_adversarial_attacks.py` | assay-toolkit | P3a: 3 future-timestamp regression tests |
| `docs/SCANNER_LIMITATIONS.md` | assay-toolkit | P2c documentation |
| `docs/security/REMEDIATION_DOCTRINE.md` | assay-toolkit | Standing remediation doctrine + closure tiers |
| `docs/security/RELEASE_SECURITY_CHECKLIST.md` | assay-toolkit | Pre-release security gate |
| `src/verify-core.ts` | assay-verify-ts | P2a: required receipt field check |
| `src/verify.test.ts` | assay-verify-ts | P2a tests |
| `docs/assay-verify.js` | assay-proof-gallery | P2b: rebuilt bundle + P1b warning |
| `docs/verify.html` | assay-proof-gallery | P1b: signer-not-pinned warning in UI |
| `docs/DESIGN_SIGNED_CHECKPOINT.md` | assay-ledger | P1a: design note |
