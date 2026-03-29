# Security Remediation Doctrine

Standing rules for adversarial simulation and security remediation sessions.
These are not guidelines — they are gate requirements.

---

## Four rules

### 1. Exploit fixes require regression tests

A patch is not a fix until a test proves the specific attack path is dead.

The test must reproduce the attack (not just test the happy path).
If the exploit involved a specific input shape, the test must use that shape.

### 2. Parity fixes require shared corpus

When fixing divergence between verifier implementations (Python, TypeScript,
browser), add a shared fixture set that all verifiers must agree on.

One corpus, same verdicts. If a new verifier is added later, it must pass
the same corpus before shipping.

### 3. Trust-label fixes require wording review

When changing what "verified," "passed," or any trust-bearing label means
to an operator, the wording must be reviewed for non-technical clarity.

Three meanings that must never be conflated:
- **Cryptographic validity** — signature math checks out
- **Identity binding** — signer is who you expect
- **Transparency anchoring** — history is externally witnessed

If the system says "VERIFIED" and means only the first, the label is
doing more work than it can carry.

### 4. History claims require external anchor or local-only label

A self-referential hash chain is not tamper-evident against a writer.

Until signed checkpoints or external anchoring (Rekor, RFC 3161, CT-style
log heads) exist, any "append-only" or "tamper-evident" claim must be
qualified as "locally consistent, not externally anchored."

Do not let UX or documentation imply stronger guarantees than the
architecture delivers.

---

## Closure tiers

Not all fixes are the same kind of closed. Use the correct label.

| Tier | Meaning | Evidence required |
|------|---------|-------------------|
| **EXPLOITED-AND-PATCHED** | Specific attack path reproduced and closed | Regression test that exercises the attack |
| **HARDENED** | Defense added for a class of issue, not just one instance | Test + design note explaining the invariant |
| **DOCUMENTED** | Known limitation honestly stated | Documentation that names the boundary |
| **DESIGN-TRACK** | Structural fix requires architecture work | Design note with threat model and migration plan |
| **NOT-A-BUG** | Investigated and determined to be working as designed | Repro steps showing correct behavior + rationale |

Do not use "FIXED" as a closure label. It is ambiguous between
EXPLOITED-AND-PATCHED and HARDENED. Say which one you mean.

---

## Closeout discipline

At the end of any security remediation session, the writeup must:

1. **Not overclaim.** "No remaining risk" should be "no known remaining
   risk from tested paths." A green test suite proves regression safety,
   not semantic completeness.

2. **Re-test predictions.** Predicted findings from prior sessions must
   be reproduced or disproved, not carried forward as assumptions.
   Disproved predictions are a sign of calibration health.

3. **Match capability advertising to reality.** If a CLI flag, badge,
   or help text implies a capability that is not implemented, that is a
   product honesty issue, not a cosmetic nit.

4. **State what is open.** A remediation session that closes 9 of 10
   findings and buries the 10th is worse than one that closes 8 and
   clearly labels the remaining 2.

---

## Origin

Extracted from the 2026-03-29 adversarial simulation session, which
demonstrated all four useful audit outcomes:
- True bug (P0: comparability spoof)
- True design weakness (P1a: ledger anchoring)
- True limitation (P2c: scanner evasion)
- False alarm (P-7: commands were actually visible; P-9: design was correct)

That distribution is the calibration signal that the review loop
produces truth, not just issue volume.
