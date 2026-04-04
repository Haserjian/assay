# Assay Claim Ledger

**Authority**: This ledger tracks the public-facing security and assurance claims that remain valid after the 2026-04-03 adjudication. When a stale draft or pre-adjudication audit note conflicts with this file, [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md) controls.

Current operating decisions on signer bootstrap and ledger scope are recorded in [`SIGNER_BOOTSTRAP_DECISION.md`](SIGNER_BOOTSTRAP_DECISION.md) and [`LEDGER_SCOPE_DECISION.md`](LEDGER_SCOPE_DECISION.md).

Every public-facing claim about what Assay does must appear here, mapped to the exact test, contract, or artifact that backs it. If the proof does not exist or the caveat is missing, the claim must not ship.

Format:
- **Claim** — exact language used or proposed in public materials
- **Proof** — the test, contract, or artifact that backs it
- **Status** — PROVEN | QUALIFIED | UNPROVEN
- **Caveat** — the required qualifier when the claim is narrower than the strongest possible reading

---

## Signing & Canonicalization

| # | Claim | Proof | Status | Caveat |
|---|-------|-------|--------|--------|
| C-01 | "Assay cryptographically signs proof-pack receipts using Ed25519." | `tests/assay/test_v2_sign.py`, `tests/assay/test_v2_verify.py` | PROVEN | — |
| C-02 | "Assay detects tampering with attested receipt fields." | `tests/assay/test_v2_sign.py`, `tests/assay/test_v2_verify.py`, `tests/contracts/vectors/pack/tampered_receipt_content/` | PROVEN | This covers attested fields only. Fields intentionally excluded from the projection are outside that guarantee. |
| C-03 | "Assay uses RFC 8785 JCS canonicalization before signing." | `tests/contracts/vectors/jcs_vectors.json`, `docs/contracts/PACK_CONTRACT.md` | PROVEN | JCS preserves parsed string data as-is. Assay's current field-name hardening is a higher-level ASCII-only policy above JCS, not a JCS extension. |
| C-04 | "Assay currently supports post-quantum receipt verification." | — | UNPROVEN | **Do not use this language.** Current builds recognize PQ algorithm identifiers but report them as unsupported, and do not emit or verify PQ signatures end-to-end. |

---

## Verification Surface

| # | Claim | Proof | Status | Caveat |
|---|-------|-------|--------|--------|
| C-05 | "`assay verify-pack` verifies proof-pack integrity and declared claims offline." | `docs/contracts/PACK_CONTRACT.md`, `tests/assay/test_v2_verify.py` | PROVEN | This is the proof-pack verification surface. It should not be conflated with score/report commands. |
| C-06 | "`assay gate check` cryptographically verifies proof packs." | — | UNPROVEN | **Do not use this language.** `assay gate check` is evidence-readiness scoring, not cryptographic proof-pack verification. |
| C-07 | "An independent TypeScript verifier can verify Assay proof packs." | `docs/contracts/PACK_CONTRACT.md`, `assay-verify-ts` implementation | QUALIFIED | This applies to the Assay proof-pack contract only. Do not generalize it to richer gateway/reference receipt schemas or broader cross-surface conformance claims without a dedicated same-contract parity corpus. |
| C-08 | "Assay enforces a non-empty authorized signer policy by default." | — | UNPROVEN | **Do not use this language.** Current operating posture keeps signer bootstrap loose/local until a non-empty trusted signer policy is explicitly activated. At the low-level ReceiptV2 verifier layer, `trusted_signer` is narrower than full authorization. |

---

## Ledger & Provenance

| # | Claim | Proof | Status | Caveat |
|---|-------|-------|--------|--------|
| C-09 | "Assay Ledger is append-only and tamper-evident." | `assay-ledger` chain validation and checkpoint flow | PROVEN | The normal CI path detects append violations. Admin force-push remains an out-of-band repository power. |
| C-10 | "Witnessed ledger entries attest the signed manifest and attestation linkage." | `assay-ledger/README.md`, `assay-ledger/witness_verify.py`, `assay-ledger/.github/workflows/accept-submission.yml` | QUALIFIED | Current witness scope is manifest/attestation only. Full-pack verification still requires the original pack and `assay verify-pack`. |
| C-11 | "Assay Ledger independently re-verifies full proof-pack contents before acceptance." | — | UNPROVEN | **Do not use this language.** That stronger claim requires a protocol/workflow change. Current public ledger claims remain at manifest/attestation witness scope. |

---

## Hardening & Boundaries

| # | Claim | Proof | Status | Caveat |
|---|-------|-------|--------|--------|
| C-12 | "Assay rejects non-ASCII field names before projection and attestation input formation." | `src/assay/_receipts/canonicalize.py`, `tests/contracts/parity/test_invariants.py`, `tests/contracts/vectors/regression/homoglyph_field_bypass_spec.json` | PROVEN | This is an ASCII-only field-name policy. Do not market broader Unicode TR39-style confusable or mixed-script screening unless that additional logic is implemented. |

---

## Claim Ledger Health Summary (2026-04-04)

| Status | Count | Claims |
|--------|-------|--------|
| PROVEN | 6 | C-01, C-02, C-03, C-05, C-09, C-12 |
| QUALIFIED | 2 | C-07, C-10 |
| UNPROVEN | 4 | C-04, C-06, C-08, C-11 |

**Do not use C-04, C-06, C-08, or C-11 in public-facing material until the posture changes and the corresponding proof is added here.**

---

## Maintenance Protocol

When adding a new public claim:
1. Add a row with status `UNPROVEN`.
2. Add the proof or contract that would justify the claim.
3. Add the required caveat if the claim is narrower than a strong marketing reading.
4. Flip the status only after the proof exists.

When an adjudication retires or narrows an old claim:
1. Update this ledger immediately.
2. Update [`SECURITY_INVARIANTS.md`](SECURITY_INVARIANTS.md), [`SECURITY_POSTURE_TODAY.md`](SECURITY_POSTURE_TODAY.md), and the relevant decision note in the same sweep.
3. Do not leave contradictory nearby drafts in place.
