# to_jcs_bytes() Extraction Plan

**Date**: 2026-03-25
**Status**: COMPLETE — fully executed 2026-03-25.
**Purpose**: Separate the three verification layers in code, matching the VERIFICATION_LAYERS.md doctrine.

> **Completion note (2026-03-25):** All steps executed. `to_jcs_bytes()` removed
> (zero callers). `prepare_receipt_for_hashing()` is the explicit Layer 2 API.
> All ~50 call sites migrated. Layer 3 (`normalize_legacy_fields`) confirmed
> vestigial and removed. 2678 tests pass. See commits `5b5566e`..`670129e`.
>
> **API break:** `to_jcs_bytes` removed from `__all__`. This is a semver event
> for `assay-ai` on PyPI. Next release must bump minor (or major if strict).

---

## Current State

`to_jcs_bytes()` is the single entry point for all JCS canonicalization. It calls `_prepare_for_canonicalization()` which runs Layer 3 (normalization), Layer 2 (projection/stripping), and Layer 1 (pure RFC 8785) in a single entangled call chain.

**50+ call sites** across 20 files. All of them go through the full pipeline regardless of whether they need it.

---

## Call-Site Classification

### Group A: Pure canonicalization callers (Layer 1 only)

These pass **plain dicts** with no Pydantic models, no signature fields to strip, no legacy data. The preparation pipeline runs as a no-op for them (or should).

| File | Line | What it does | Prep needed? |
|------|------|-------------|-------------|
| `integrity.py` | 400 | Hash attestation dict | No — plain dict from JSON |
| `integrity.py` | 465 | Canonicalize unsigned manifest (signing fields already excluded) | No |
| `proof_pack.py` | 94 | Hash deterministic seed material | No |
| `proof_pack.py` | 352 | Hash claim spec list | No |
| `proof_pack.py` | 527 | Hash attestation object | No |
| `proof_pack.py` | 607 | Canonicalize unsigned manifest for signing | No |
| `reviewer_packet_compile.py` | 430-431 | Hash boundary/mapping payloads | No |
| `reviewer_packet_compile.py` | 457 | Canonicalize unsigned packet manifest | No |
| `reviewer_packet_verify.py` | 339 | Canonicalize unsigned packet manifest | No |
| `acceptance.py` | 96, 162 | Canonicalize acceptance receipt for signing/verifying | No |
| `adc_emitter.py` | 83, 86, 205, 209 | Hash/sign ADC bodies | No |
| `passport_sign.py` | 56, 61, 116, 122 | Hash/sign passport bodies | No |
| `lifecycle_receipt.py` | 94, 100, 311, 337 | Hash/sign lifecycle receipts | No |
| `replay_judge.py` | 102, 160, 342, 344 | Hash/sign judgment bodies | No |
| `reviewer_packet_events.py` | 24, 44, 92 | Sign/hash events | No |
| `lockfile.py` | 104, 110, 420, 433 | Hash lockfile data | No |
| `run_cards.py` | 47 | Hash run card specs | No |
| `vendorq_models.py` | 73 | Hash vendorq objects | No |
| `claim_verifier.py` | 459 | Hash claim canonical objects | No |
| `residual_risk.py` | 69 | Hash risk data | No |
| `coverage.py` | 125 | Hash coverage data | No |
| `episode.py` | 109 | Hash episode data | No |

**~40 call sites.** These should migrate to a pure Layer 1 function.

### Group B: Receipt canonicalization callers (Layer 2 — need projection)

These pass **receipt objects** that may contain signature fields. They depend on `strip_signatures()` to produce the correct hash.

| File | Line | What it does | Prep needed? |
|------|------|-------------|-------------|
| `integrity.py` | 140, 142 | JCS stability check on receipts | Yes — strips signatures, unwraps Pydantic |
| `integrity.py` | 196 | Head hash computation on receipts | Yes |
| `proof_pack.py` | 421 | JSONL line generation for receipts | Yes — receipts may be Pydantic models |
| `evidence_pack.py` | 45, 195, 341 | Hash/serialize evidence entries | Maybe — depends on entry types |
| `commands.py` | 958-986 | `compute_payload_hash()` calls | Yes |
| `_receipts/canonicalize.py` | 140-141 | `verify_jcs_stability()` | Yes |

**~10 call sites.** These need an explicit Layer 2 projection step before Layer 1 canonicalization.

### Group C: Compatibility normalization callers (Layer 3)

These depend on `normalize_legacy_fields()`:

| File | Line | Evidence |
|------|------|---------|
| Unknown | Unknown | No call site explicitly depends on legacy normalization. The function runs silently and may be a complete no-op for all current data. |

**0 known explicit callers.** Legacy normalization may be vestigial.

---

## Minimal Extraction Plan

### Step 1: Add pure Layer 1 public entry point (LOW RISK)

Create `jcs_canonicalize()` in `_receipts/jcs.py` that is just `_jcs_canonicalize()` made public:

```python
# jcs.py — add public alias
def jcs_canonicalize(obj: Any) -> bytes:
    """RFC 8785 canonical JSON bytes. Pure Layer 1 — no preparation."""
    return _serialize(obj).encode("utf-8")
```

This is the same as the existing `canonicalize()` function already exported. Verify it's a clean Layer 1 path.

**Risk**: None. Additive change, no existing code touched.

### Step 2: Migrate Group A callers (LOW RISK, incremental)

Change each Group A call from:
```python
to_jcs_bytes(plain_dict)
```
to:
```python
from assay._receipts.jcs import canonicalize
canonicalize(plain_dict)
```

Or use the existing `canonicalize()` function from `jcs.py` which IS the pure Layer 1 function. It's already public.

**Key insight**: `jcs.py:canonicalize()` already exists and is pure Layer 1. Group A callers should import from `jcs` directly instead of `canonicalize` module.

**Risk**: Low. Each migration is a one-line import change. Can be done file by file, tested incrementally.

### Step 3: Extract explicit Layer 2 projection function (MEDIUM RISK)

Create `prepare_receipt(receipt, *, strip_version="v0")` as a named, versioned, failure-visible function:

```python
# New file or section in canonicalize.py
def prepare_receipt(obj, *, strip_version="v0"):
    """Layer 2: project a receipt for hashing/signing.

    Converts Pydantic models to dicts, strips signature fields per
    the versioned field set. Raises on failure (no silent swallowing).
    """
    data = _to_plain_dict(obj)  # model_dump or dict passthrough
    data = strip_signatures(data, version=strip_version)
    return data
```

Group B callers become:
```python
prepared = prepare_receipt(receipt)
canonical = canonicalize(prepared)
```

**Risk**: Medium. Requires touching Group B call sites and ensuring the new explicit pipeline produces identical results to the old implicit one.

### Step 4: Quarantine or remove Layer 3 normalization (MEDIUM RISK)

Since no call site explicitly depends on `normalize_legacy_fields()`:
1. Add a test that runs the full receipt corpus through `normalize_legacy_fields()` and asserts it's a no-op (output == input for all data)
2. If confirmed no-op, remove it from the pipeline
3. If some data is transformed, document the transformation and make it an explicit preprocessing step

**Risk**: Medium. Requires verifying against real data corpus.

### Step 5: Deprecate `to_jcs_bytes()` (LATER)

Once all callers are migrated, `to_jcs_bytes()` can be deprecated with a warning, then eventually removed. Not urgent — it can remain as a convenience alias that logs a deprecation warning.

---

## Recommended Sequencing

1. **Step 1** (now): Verify `jcs.py:canonicalize()` is clean Layer 1. It already exists.
2. **Step 2** (next): Migrate 5-10 of the clearest Group A callers (integrity.py, proof_pack.py manifest paths). Run full suite after each batch.
3. **Step 4** (before Step 3): Verify whether `normalize_legacy_fields()` is a no-op. If so, remove it from the pipeline. This simplifies Step 3.
4. **Step 3** (after): Create the explicit Layer 2 function and migrate Group B callers.
5. **Step 5** (later): Deprecate `to_jcs_bytes()`.

---

## Risk Notes

- **Test fallout**: Each Group A migration changes an import. If any Group A caller was accidentally depending on `strip_signatures()` (e.g., passing a dict that coincidentally has a field named "signature"), the migration would change the hash output. Must verify with full test suite after each batch.
- **Compatibility**: `to_jcs_bytes()` is used in tests. Don't break the public API immediately — deprecate, don't delete.
- **The `canonicalize` module exports**: `to_jcs_bytes` is in `__all__`. Keep it until deprecation.
