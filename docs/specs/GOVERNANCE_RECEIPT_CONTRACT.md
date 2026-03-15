# Governance Receipt Contract

**Status:** Active
**Since:** v1.17 (2026-03-14)

## Architecture Delta

The passport stack moved from signed artifacts with local state toggles
to signed artifacts with verified governance receipts and explicit reliance
semantics.

Three rules govern the passport object model:

1. **Signed passports are immutable.** Once signed, a passport's file bytes
   must not change. Supersession linkage lives in the signed supersession
   receipt, not in the passport body.

2. **Governance truth lives in signed lifecycle receipts.** Challenge,
   supersession, and revocation are Ed25519-signed events with content-addressed
   identity. Unsigned demo helpers (`create_demo_*`) are non-production.

3. **`verify` and `status` are explicitly separated by contract.** `verify`
   answers whether the artifact is structurally valid. `status` answers whether
   it should be relied on under a policy mode. They were previously
   under-separated; they are now distinct surfaces with different exit code
   semantics.

## Single Source of Governance Truth

Canonical governance events are **verified lifecycle receipts** — Ed25519-signed,
content-addressed, JCS-canonicalized JSON envelopes defined in
`LIFECYCLE_RECEIPT_SPEC_V0_1.md`.

No policy decision may be based on unverified filesystem presence alone.

## Authority Model

| Event | Who may issue | Verified against |
|---|---|---|
| Challenge | Any identified actor | Embedded pubkey (self-certifying) |
| Supersession | Original passport issuer | Issuer fingerprint matches passport signer |
| Revocation | Issuer or designated authority | Issuer fingerprint matches passport signer |

## Governance Ingestion

`derive_governance_dimensions()` in `lifecycle_receipt.py` is the single entry
point for governance evidence ingestion. It produces two orthogonal facts:

- **governance_status**: `none | challenged | superseded | revoked`
  Priority: revoked > superseded > challenged > none

- **event_integrity**: `no_events | all_valid | some_invalid`
  Tracks whether all signed receipts on disk verified successfully.

Both facts feed into `compute_verdict()` via `extract_dimensions()`.

## `verify` vs `status`

These are intentionally separate surfaces with different contracts:

| | `passport verify` | `passport status` |
|---|---|---|
| **Question** | Is this artifact structurally valid? | Given verified evidence, what is the reliance posture? |
| **Scope** | Signature + content-addressed ID + lifecycle state | All 6 verification dimensions + policy mode |
| **Output** | VALID/INVALID/UNSIGNED + state | PASS/WARN/FAIL verdict |
| **Exit codes** | 0=valid, 1=invalid/stale, 2=tampered | 0=PASS, 1=WARN, 2=FAIL |
| **Policy-sensitive** | No | Yes (permissive/buyer-safe/strict) |

`verify` answers "can I trust this object?" `status` answers "should I rely on it?"
These must not be collapsed into a single surface.

## Unsigned Demo Receipts

Old-format unsigned receipts (no `signature`, no `event_id`) are accepted for
backward compatibility and demo workflows via `--demo` flag.

Constraints on unsigned demo receipts:
- They do **not** contribute to `event_integrity` (unsigned = `no_events`)
- They **do** contribute to `governance_status` (a challenge is a challenge)
- They must not be confused with production evidence

Signed receipts are the default for all CLI commands. `--demo` is an explicit
opt-in to the unsigned path.

## Passport Immutability After Signing

A signed passport must not be mutated after signing. Doing so breaks the
content-addressed ID and signature.

The `supersede` command respects this: if both passports are signed, relationship
fields are **not** written to the passport body. The supersession receipt is the
canonical source of chain linkage, not the passport body.

Unsigned passports may have relationship fields updated as a convenience.

## Implementation Map

| Concern | Module | Function |
|---|---|---|
| Receipt creation | `lifecycle_receipt.py` | `create_signed_{challenge,supersession,revocation}_receipt()` |
| Receipt verification | `lifecycle_receipt.py` | `verify_lifecycle_receipt()` |
| Authority check | `lifecycle_receipt.py` | `check_issuer_authority()` |
| Governance ingestion | `lifecycle_receipt.py` | `derive_governance_dimensions()` |
| Verdict computation | `verdict.py` | `compute_verdict()` |
| Dimension extraction | `verdict.py` | `extract_dimensions()` |
| Demo-only (unsigned) | `passport_lifecycle.py` | `create_demo_{challenge,supersession,revocation}_receipt()` |
