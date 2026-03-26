# Assay Hash and Signature Surface Map

**Date**: 2026-03-26
**Status**: Inventory (read-only, no recommendations)
**Scope**: Every proof-critical hash and signature computation in `src/assay/`

This document maps the exact byte surface for every hash and signature
operation. It does not recommend changes — it records what is.

Archive note: the cross-implementation TS comparisons below are preserved as
audit context. The referenced TS verifier is not present in this workspace.

---

## Hash Surface Table

| Artifact Kind | Canonicalization | Bytes Hashed | Verifier Entrypoint | Current Domain Binding | Current Type Binding | Cross-Lang Coupling | Migration Sensitivity |
|---------------|-----------------|-------------|--------------------|-----------------------|---------------------|--------------------|-----------------------|
| **Receipt digest (head_hash)** | Layer 2 (strip v0 sigs) → Layer 1 (JCS RFC 8785) | `JCS(receipt - {anchor, cose_signature, receipt_hash, signature, signatures})` | `integrity.py:204` | None | Position-dependent (last receipt = head) | Python + TS both compute identically | HIGH — head_hash stored in attestation, propagated to ADC |
| **Attestation digest** | Layer 1 (JCS RFC 8785) | `JCS(attestation_dict)` | `integrity.py:437`, build: `proof_pack.py:529` | None | Structural (attestation has unique key set) | Python + TS both compute identically | HIGH — stored as `attestation_sha256` and `pack_root_sha256` (D12) |
| **Manifest signing base** | Layer 1 (JCS RFC 8785) | `JCS(manifest - {signature, pack_root_sha256})` | `integrity.py:502-508`, build: `proof_pack.py:608` | None | Exclusion set hardcoded in both impls | Python + TS both reconstruct identically | CRITICAL — changing this breaks all existing signatures |
| **File content hash** | None (raw bytes) | Raw file bytes from disk | `integrity.py:297`, build: `proof_pack.py:534-544` | None | Filename in manifest `files[].path` | Python + TS both compute identically | LOW — file hashes are per-pack, not cross-referenced |
| **Signer fingerprint** | None (raw bytes) | Raw 32-byte Ed25519 public key | `integrity.py:517`, `keystore.py:168`, build: `proof_pack.py:588` | None | Field name `signer_pubkey_sha256` | Python + TS both compute identically | MEDIUM — fingerprint is identity anchor |
| **Policy hash** | None or JCS | Default: `b"default-policy-v0"`. Provided: opaque. | Not directly verified (attestation-level) | None | Field name `policy_hash` | Compared but not recomputed by verifier | LOW — opaque to verifier |
| **Suite hash** | None | `suite_id.encode()` | Not directly verified | None | Field name `suite_hash` | Compared but not recomputed | LOW — opaque to verifier |
| **Claim set hash** | JCS (when from specs) | `JCS([ClaimSpec.to_dict() ...])` or `claim_set_id.encode()` | Not directly verified | None | Field name `claim_set_hash` | Compared but not recomputed | LOW — opaque to verifier |
| **Merkle root** | None (raw byte concat) | `SHA256(left_32bytes \|\| right_32bytes)` for nodes; `bytes.fromhex(leaf_hex)` for leaves | `merkle.py:compute_merkle_root` | None (length-based: leaf=32B, node=64B) | None | Not in TS verifier (Python only) | LOW — not in pack verification pipeline |
| **ADC credential_id** | Layer 1 (JCS RFC 8785) | `JCS(adc_body - {credential_id, signature})` | `replay_judge.py:458-480` | `sha256:` prefix on stored value | Field name `credential_id` | Not in TS verifier | LOW — self-referential identity |
| **Passport ID** | Layer 1 (JCS RFC 8785) | `JCS(passport_body - {passport_id, signature})` | `passport_sign.py:117` | `sha256:` prefix on stored value | Field name `passport_id` | Not in TS verifier | LOW — separate artifact class |
| **Lifecycle event ID** | Layer 1 (JCS RFC 8785) | `JCS(event_body - {event_id, signature})` | `lifecycle_receipt.py` (self-verify) | `sha256:` prefix on stored value | Field name `event_id` | Not in TS verifier | LOW — separate artifact class |
| **Replay judgment ID** | Layer 1 (JCS RFC 8785) | `JCS(judgment_body)` | `replay_judge.py:342` | None | Field name `judgment_id` | Not in TS verifier | LOW — derived artifact |
| **Deterministic pack seed** | Layer 1 (JCS RFC 8785) | `JCS({run_id, receipt_pack_sha256, policy_hash, ...})` | None (internal to builder) | None | None | Python only | NONE — internal |

---

## Signature Surface Table

| Artifact Kind | Signing Input | Algorithm | Signer | Verifier | Exclusion Set | Cross-Lang |
|---------------|--------------|-----------|--------|----------|---------------|------------|
| **Pack manifest** | `JCS(manifest - {signature, pack_root_sha256})` | Ed25519 (PyNaCl/libsodium) | `proof_pack.py:609` via `ks.sign_b64()` | `integrity.py:525-527` via `VerifyKey.verify()` | `{signature, pack_root_sha256}` hardcoded | Python: PyNaCl. TS: @noble/ed25519 |
| **ADC** | `JCS(adc_body + credential_id - {signature})` | Ed25519 | `adc_emitter.py:86-87` via `sign_fn()` | `replay_judge.py:53-83`, `replay_judge.py:468-480`; `commands.py:3544-3558` | `{signature}` | Python only |
| **Passport** | `JCS(passport_body + passport_id - {signature})` | Ed25519 | `passport_sign.py:61-62` | `passport_sign.py:107-127` | `{passport_id, signature}` for ID; `{signature}` for signing | Python only |
| **Lifecycle receipt** | `JCS(event_body + event_id - {signature})` | Ed25519 | `lifecycle_receipt.py:100-101` | `lifecycle_receipt.py` (self-contained) | `{event_id, signature}` for ID; `{signature}` for signing | Python only |
| **Replay judgment** | `JCS(judgment_body + judgment_id)` | Ed25519 | `replay_judge.py:344` via `sign_fn()` | Not verified (produced artifact) | `{signature}` excluded implicitly (added after ID) | Python only |

---

## Canonical Byte Surfaces (Exact)

### Receipt → head_hash

```
input = receipt_dict
step 1: prepared = prepare_receipt_for_hashing(input, version="v0")
        → strips root-level keys in {anchor, cose_signature, receipt_hash, signature, signatures}
        → Pydantic model → dict if needed
        → unwrap_frozen() if needed
step 2: canonical = jcs_canonicalize(prepared)
        → RFC 8785, UTF-16-BE key sort, compact separators
        → Assay JCS Profile v1 (uppercase E deviation)
step 3: head_hash = SHA256(canonical).hexdigest()
```

### Attestation → attestation_sha256

```
input = attestation_dict  (plain dict, no Pydantic model)
step 1: canonical = jcs_canonicalize(input)
        → same JCS as above, but NO Layer 2 stripping
step 2: attestation_sha256 = SHA256(canonical).hexdigest()
```

### Manifest → signature

```
input = unsigned_manifest_dict
        → contains all manifest fields EXCEPT {signature, pack_root_sha256}
        → these two fields are added AFTER signing
step 1: canonical = jcs_canonicalize(input)
step 2: signature = Ed25519.sign(signing_key, canonical)
step 3: signature_b64 = base64(signature)
step 4: signed_manifest = {**unsigned_manifest, "signature": signature_b64, "pack_root_sha256": attestation_sha256}
```

### File → file_hash

```
input = raw file bytes read from disk (or in-memory during build)
step 1: file_hash = SHA256(input).hexdigest()
        → no canonicalization, no stripping, no prefix
```

### Signer → fingerprint

```
input = raw 32-byte Ed25519 public key (from NaCl VerifyKey.encode())
step 1: fingerprint = SHA256(input).hexdigest()
```

---

## Cross-Implementation Parity Status

| Surface | Python | TypeScript | Parity |
|---------|--------|-----------|--------|
| Manifest signing exclusions | `{signature, pack_root_sha256}` | `{signature, pack_root_sha256}` | IDENTICAL |
| Receipt v0 exclusions | `{anchor, cose_signature, receipt_hash, signature, signatures}` | `{anchor, cose_signature, receipt_hash, signature, signatures}` | IDENTICAL |
| JCS key sort | UTF-16-BE bytes | JS native string comparison (UTF-16 code units) | IDENTICAL for BMP; UNTESTED for supplementary |
| JCS number encoding | Decimal arithmetic, uppercase E | JSON.stringify + regex, uppercase E | IDENTICAL for normal range; DIVERGENT for int > 2^53-1 |
| Empty-pack sentinel | `SHA256(b"empty")` substitution | None | DIVERGENT |
| Schema validation | Full JSON Schema Draft 2020-12 | Two-field array check | DIVERGENT |
| Missing pubkey handling | Keystore fallback → E_PACK_SIG_INVALID if no key | Archived TS audit note; verifier source not present in this workspace | ARCHIVAL |
| signature_scope usage | Descriptive only (ignored by verifier) | Descriptive only (ignored by verifier) | IDENTICAL |
