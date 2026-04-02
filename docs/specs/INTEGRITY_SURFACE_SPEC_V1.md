# Integrity Surface Specification v1

**Status:** normative
**Scope:** pack verification pipeline — receipt, attestation, manifest
**Supersedes:** none (first explicit spec for these surfaces)
**Audience:** current Python implementation maintainers; future multi-language implementors

This document defines the canonical byte surfaces, exclusion sets, verification order,
and normative constraints that govern pack integrity in Assay. It is a clarification of
existing behavior, not a redesign. Where it says "normative," implementations must comply;
where it says "informational," implementations may vary.

---

## 1. Canonical Byte Surfaces

Each artifact kind produces a distinct byte surface for hashing. The surfaces differ by
serialization route, not by domain-tag prefix.

### 1.1 File entry hash

```
bytes_hashed = file_path.read_bytes()   # raw binary, no canonicalization
hash         = SHA256(bytes_hashed)
stored_in    = manifest.files[i].sha256
```

Source: `integrity.py:297`.

### 1.2 Attestation hash

```
bytes_hashed = JCS(attestation_dict)    # RFC 8785, full object, no field stripping
hash         = SHA256(bytes_hashed)
stored_in    = manifest.attestation_sha256
              manifest.pack_root_sha256  (must equal attestation_sha256 per D12)
```

Source: `integrity.py:437`, `proof_pack.py:528–529`.

### 1.3 Receipt payload hash

```
projected    = receipt_dict − {signatures, signature, cose_signature, receipt_hash, anchor}
               (Layer 2 exclusion set v0; root-level only)
bytes_hashed = JCS(projected)           # RFC 8785
hash         = SHA256(bytes_hashed)
stored_in    = receipt.payload_hash     (when present; used for receipt-level signing)
```

Source: `canonicalize.py:46–88, 105`.
The exclusion set is versioned (`_SIGNATURE_FIELD_SETS`, currently `v0` only).

### 1.4 Manifest signing base

```
unsigned     = manifest_dict − {"signature", "pack_root_sha256"}
               (hardcoded exclusion; NOT derived from manifest.signature_scope)
bytes_signed = JCS(unsigned)            # RFC 8785
signature    = Ed25519.sign(bytes_signed, private_key)
stored_in    = manifest.signature       (base64-encoded)
               pack_signature.sig       (raw bytes, detached copy)
```

Source: `integrity.py:501–508`.

**Normative rule:** The exclusion set for the manifest signing base is `{"signature",
"pack_root_sha256"}` as hardcoded in the verifier. The `manifest.signature_scope` field
is **descriptive only**. Verifiers MUST use the hardcoded exclusion set and MUST NOT
derive it from `signature_scope`. Older packs carry a legacy `signature_scope` value that
omits `pack_root_sha256`; those packs are still valid because the verifier is not influenced
by that field.

---

## 2. Verification Order

The following order is normative for `verify_pack_manifest()`. Steps are listed in
execution sequence. Later steps may depend on earlier ones but must not reorder.

| Step | Name | Check | Source |
|------|------|-------|--------|
| 1 | validate_schema | Manifest passes JSON Schema | `integrity.py:241` |
| 2 | validate_paths | All file paths contained in pack_dir | `integrity.py:263` |
| 3 | validate_file_hashes | SHA256(file bytes) matches manifest.files[i].sha256 | `integrity.py:287` |
| 4 | validate_receipts | Recomputed head_hash matches manifest; receipt count matches | `integrity.py:~332` |
| 5 | validate_attestation | SHA256(JCS(attestation)) matches manifest.attestation_sha256 | `integrity.py:436` |
| 6 | verify_signature | Ed25519 over JCS(unsigned manifest) verifies against embedded pubkey | `integrity.py:511` |
| 7 | check_d12_invariant | manifest.pack_root_sha256 == manifest.attestation_sha256 | `integrity.py:564` |
| 8 | freshness_check | Attestation timestamp within max_age_hours (optional) | `integrity.py:573` |

**Key ordering properties:**
- Attestation hash (step 5) is verified before the manifest signature (step 6).
- Manifest signature (step 6) is verified before the D12 consistency check (step 7).
- No unsigned artifact influences a trust decision before its hash or signature is verified.

---

## 3. D12 Invariant

`manifest.pack_root_sha256 == manifest.attestation_sha256`

D12 is a **consistency invariant**, not the primary integrity barrier.

- Primary integrity for the attestation is established at step 5 (attestation hash check).
- D12 at step 7 asserts that the two manifest fields referring to the attestation agree.
  If D12 fails after step 5 passes, that indicates manifest incoherence — an internal
  reference that disagrees with itself, signaling a producer/pipeline invariant failure.
- D12 failure after successful attestation hash + signature verification would require
  either signer key compromise or hash collision. It is retained as a canary and
  referential integrity check, not as a primary trust gate.

**Normative rule:** Both `pack_root_sha256` and `attestation_sha256` MUST equal
`SHA256(JCS(attestation))`. A manifest where both fields are present and equal but
neither equals the actual attestation hash fails at step 5, not step 7.

---

## 4. Receipt Field Constraints

### 4.1 `receipt.type` — normative enum (to be enforced)

The `type` field is required in all receipts (`REQUIRED_RECEIPT_FIELDS`, `integrity.py:110`).
In the current Python reference verifier, its value is checked for presence
only; no enum is enforced in code.

**Normative rule (closes spec gap):** Verifiers SHOULD reject receipts with unknown type
values. The following values are currently recognized:

```
model_call
guardian_verdict
```

Additional values require explicit schema version registration. Unknown type values
encountered during verification should produce a warning in lenient mode and an error in
strict mode.

**Current enforcement status:** presence only in the Python reference verifier
(`integrity.py:120`). Enum validation is **not yet implemented** in
`verify_receipt()`. This is a known under-specification; future multi-language
implementations MUST enforce the closed enum.

**Dispatch note:** `receipt.type` is informational in the pack verification path. It does
not drive code branching in `verify_pack_manifest()` or `verify_receipt()`. The risk from
the current under-specification is cross-implementation divergence, not current logic
compromise.

### 4.2 Numeric field type constraints

Receipt fields `cost`, `latency_ms`, and `token_count` are listed as optional recognized
fields in `schema.py` with no type constraint. Floating-point values are currently
admissible in these fields.

**Normative rule:** To ensure stable JCS canonicalization across implementations:
- `latency_ms` MUST be an integer (milliseconds, truncated).
- `token_count` MUST be an integer.
- `cost` SHOULD be a string-encoded decimal when monetary precision is required;
  floating-point values are permitted for informational use but MUST NOT appear in
  hash-critical paths.

**Rationale:** RFC 8785 specifies deterministic number encoding, but Python's
`Decimal(str(float))` representation may differ from Go/Rust float-to-decimal conversion
for certain IEEE 754 values. Integer fields are unambiguous across all implementations.

---

## 5. Implementation-Distinct vs Type-Enforced

File entry hashes (raw bytes) and attestation hashes (JCS JSON bytes) produce byte
surfaces that are distinct in the current implementation via different serialization
routes. Under normal operation, confusing them is not a practical attack path; absent a
serialization or control bug, it would require breaking the hash assumption.

However, this distinction is **not enforced by a typed API or domain-separated hash
construction**. Both use the same `_sha256_hex(bytes)` function. The safety comes from
different callers passing different serializations.

**This is a hardening surface for future implementors.** A multi-language implementation
that accidentally passed JCS-serialized bytes to a file hash slot, or vice versa, would
produce a verification mismatch that is difficult to diagnose. Domain-tagged hashing
(e.g., `SHA256("assay:file:v1:" || bytes)`) would make such bugs immediate rather than
silent.

This is not an active vulnerability in the current single-language deployment. It is
noted here as a named hardening target for the first multi-language verification path.

---

## 6. What Is Normative vs Implementation Detail

| Item | Status |
|------|--------|
| Exclusion set for receipt hashing (`v0`) | **Normative** — must match exactly |
| Exclusion set for manifest signing base | **Normative** — hardcoded, not derived from `signature_scope` |
| Verification order (steps 1–8) | **Normative** — order must be preserved |
| D12: both fields must equal SHA256(JCS(attestation)) | **Normative** |
| `receipt.type` closed enum | **Normative (spec gap)** — not yet code-enforced; future impls must enforce |
| `latency_ms`, `token_count` must be integers | **Normative** |
| `cost` float vs string-decimal | **Recommended** — float permitted, string-decimal preferred |
| `_sha256_hex()` function reused across artifact kinds | **Implementation detail** — safe today; hardening target for multi-language |
| `signature_scope` field value | **Descriptive only** — verifiers must not use it to derive exclusion set |

---

## 7. Open Items

The following items are out of scope for this spec but are recorded to prevent loss:

1. **Domain-tagged hashing** — if a second implementation language ships, consider
   prefixed hash construction (`SHA256("<domain>:" || bytes)`) to make cross-artifact
   confusion an immediate error rather than a silent mismatch.

2. **`receipt.type` enum enforcement** — add `VALID_RECEIPT_TYPES` frozenset to
   `integrity.py` and enforce in `verify_receipt()`. Should be a one-function change.

3. **Float prohibition** — add type constraints to `latency_ms` and `token_count` in
   `schema.py` and/or the receipt JSON Schema when one is introduced.

## 8. Port Checklist

For an implementation-facing conformance gate, see
[INTEGRITY_PORT_COMPATIBILITY_CHECKLIST.md](./INTEGRITY_PORT_COMPATIBILITY_CHECKLIST.md).
That checklist turns the normative spec into a concrete verifier-port acceptance
standard.
