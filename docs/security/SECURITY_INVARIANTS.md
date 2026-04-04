# Assay Security Invariants

**Authority**: This file records the live security truths that remain after the 2026-04-03 adjudication. Historical false alarms and mixed-contract findings are settled in [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md) and should not be re-imported here as active breakage.

Each invariant has:
- **ID** — stable identifier for discussion and follow-up
- **Claim** — the current truth that must remain true
- **Status** — ENFORCED | PARTIAL | OPEN
- **Control** — the document, test, or code path that currently holds the line
- **Break signal** — what would re-open the issue

---

## INV-01: Proof-Pack Contract Separation

**Claim**: Assay proof-pack verification is judged against the proof-pack contract in [`docs/contracts/PACK_CONTRACT.md`](../contracts/PACK_CONTRACT.md), not against richer gateway/reference receipt schemas.

**Status**: PARTIAL

**Control**:
- `docs/contracts/PACK_CONTRACT.md`
- [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md)

**Break signal**: A doc, test, or audit again treats proof-pack verification as broken by comparing it to a different receipt contract surface.

---

## INV-02: Gate Versus Verify Split

**Claim**: `assay verify-pack` is the cryptographic proof-pack verification surface. `assay gate check` is evidence-readiness scoring and receipt-presence analysis, not cryptographic verification.

**Status**: PARTIAL

**Control**:
- `src/assay/score.py`
- [`SECURITY_POSTURE_TODAY.md`](SECURITY_POSTURE_TODAY.md)
- AgentMesh README clarification

**Break signal**: Public materials or CI guidance claim that `assay gate check` validates signatures, digests, or full proof-pack integrity.

---

## INV-03: Trusted Signer Is Narrower Than Full Authorization

**Claim**: At the low-level ReceiptV2 verifier layer, `trusted_signer` means the resolver returned matching key material for that layer. Full signer authorization remains a higher-level policy decision and depends on bootstrap and deployment policy.

**Status**: PARTIAL

**Control**:
- `src/assay/_receipts/v2_verify.py`
- [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md)

**Break signal**: Docs or release materials describe `trusted_signer` as if it were a complete default authorization verdict, or imply a non-empty signer policy is active by default when it is not.

---

## INV-04: Unsupported PQ Algorithms Must Stay Explicit

**Claim**: Current builds must present reserved PQ algorithms as unsupported, not as active end-to-end verification capability.

**Status**: PARTIAL

**Control**:
- `src/assay/_receipts/v2_types.py`
- `src/assay/_receipts/v2_sign.py`
- `src/assay/_receipts/v2_verify.py`
- `tests/assay/test_v2_sign.py`, `tests/assay/test_v2_verify.py`

**Break signal**: PQ algorithms are described as currently verified or emitted end-to-end without an actual cryptographic implementation and passing conformance coverage.

---

## INV-05: Ledger Witness Scope Must Stay Honest

**Claim**: Witnessed Assay Ledger entries currently attest the signed manifest and attestation linkage only. They do not independently recompute full proof-pack contents from the original pack tree.

**Status**: PARTIAL

**Control**:
- `assay-ledger/README.md`
- `assay-ledger/.github/workflows/accept-submission.yml`
- [`SECURITY_POSTURE_TODAY.md`](SECURITY_POSTURE_TODAY.md)
- [`LEDGER_SCOPE_DECISION.md`](LEDGER_SCOPE_DECISION.md)

**Break signal**: Any current-state material claims full-pack independent re-verification without a protocol and workflow change that actually performs it.

---

## INV-06: JCS Is Not The Place For Unicode Normalization Policy

**Claim**: RFC 8785 JCS preserves parsed string data as-is. Lack of Unicode normalization is not a JCS bug in Assay. Any ASCII-only or confusable-aware rule belongs in a higher-level field-name or schema policy.

**Status**: ENFORCED

**Control**:
- RFC 8785 behavior captured in `docs/contracts/PACK_CONTRACT.md`
- [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md)

**Break signal**: A future audit or product surface re-frames JCS string preservation as a verifier defect instead of a higher-layer policy choice.

---

## INV-07: Confusable Hardening Is Not Active Yet

**Claim**: Assay does not currently advertise ASCII-only or confusable-aware field-name filtering above JCS. That remains an optional hardening step, not a current guarantee.

**Status**: OPEN

**Control**:
- [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md)
- [`CLAIM_LEDGER.md`](CLAIM_LEDGER.md)

**Break signal**: Public language implies spoof-resistant field-name filtering before an actual validation policy is implemented.

---

## INV-08: Stronger Signer Bootstrap Requires An Explicit Choice

**Claim**: Assay's current operating decision is to keep default signer posture loose/local until a non-empty trusted signer policy is explicitly activated. Public language must not imply stronger default authorization than that.

**Status**: PARTIAL

**Control**:
- [`SECURITY_POSTURE_TODAY.md`](SECURITY_POSTURE_TODAY.md)
- [`CLAIM_LEDGER.md`](CLAIM_LEDGER.md)
- [`SIGNER_BOOTSTRAP_DECISION.md`](SIGNER_BOOTSTRAP_DECISION.md)

**Break signal**: Public assurance language implies strong default signer authorization without a corresponding active policy path.

---

## Invariant Health Summary

| ID | Invariant | Status |
|----|-----------|--------|
| INV-01 | Proof-pack contract separation | PARTIAL |
| INV-02 | Gate versus verify split | PARTIAL |
| INV-03 | Trusted signer semantics | PARTIAL |
| INV-04 | Unsupported PQ posture | PARTIAL |
| INV-05 | Ledger witness scope honesty | PARTIAL |
| INV-06 | JCS normalization boundary | ENFORCED |
| INV-07 | Confusable hardening not active | OPEN |
| INV-08 | Signer bootstrap default is explicit | PARTIAL |

This is the live posture after adjudication: one retired phantom, several clarified current truths, and one optional hardening lane rather than an all-surfaces panic state.

---

## Maintenance Protocol

When a new audit finding appears:
1. Decide whether it is a live invariant, a hardening candidate, or a retired false alarm.
2. Record false alarms in the adjudication memo, not as active breakage here.
3. Update [`CLAIM_LEDGER.md`](CLAIM_LEDGER.md), [`SECURITY_POSTURE_TODAY.md`](SECURITY_POSTURE_TODAY.md), and the relevant decision note in the same change when public language is affected.
