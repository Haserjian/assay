# Release-Readiness Passport v1

Claim discipline memo for the Assay passport and governance surface.
Every public statement about Assay must fall into exactly one of these bands.
If a claim is not Green, it does not appear in public copy.

---

## Green (safe to claim publicly)

- Signed, content-addressed passport artifacts (Ed25519 + JCS canonicalization).
- Deterministic lifecycle governance: challenge, supersede, revoke -- all cryptographically signed.
- `verify` answers structural validity; `status` answers reliance posture under configurable policy.
- X-Ray diagnostic grades passport structure (A-F) with improvement path.
- Trust Diff compares two passports and flags regressions.
- Reproducible seeded referee gallery with worked examples.
- Offline verification without network access.
- 10-step demo command (`assay passport demo`).
- README truth boundary explicitly separates "proves today" from "future scope."
- Release invariant tests enforce public-surface claims.

---

## Yellow (true but needs careful framing)

- X-Ray works on passport JSON structure, not arbitrary URLs or PDFs. Must say "passport diagnostic" not "trust scanner."
- Trust Diff is a CLI primitive, not an enterprise workflow product. Must say "compare two passports" not "enterprise diff."
- Authority model is issuer-fingerprint only. "Designated authority" is reserved, not implemented.
- Policy modes (permissive/buyer-safe/strict) are implementation detail. Use verdict language (PASS/WARN/FAIL) publicly.
- Gallery artifacts are seeded/deterministic. Must not imply they come from real third-party systems.
- Demo receipts (unsigned) exist for backward compat. Must not be confused with production evidence.

---

## Red (do not claim)

- "Scan any vendor trust page" -- X-Ray analyzes passport JSON, not arbitrary URLs or PDFs.
- "Mint from your SOC 2 report" -- mint works from proof packs, not external documents.
- "AI trust score" or "trust rating" -- Assay provides evidence-based verdicts, not scores.
- "Automated compliance" -- Assay produces evidence for compliance decisions, not compliance itself.
- "Enterprise Trust Diff product" -- primitive exists, product does not.
- "Scan your vendor's security posture" -- Assay does not scan external systems.
- "Designated authority model" -- only issuer fingerprint matching is implemented.
- "Real-time governance monitoring" -- governance is batch evidence, not live.

---

```
Last verified: 2026-03-15
Governing references: EXPOSURE_MATRIX.md, GOVERNANCE_RECEIPT_CONTRACT.md
Enforced by: tests/assay/test_passport_release_invariants.py
```
