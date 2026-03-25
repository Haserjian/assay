# Verification Layers Doctrine

**Date**: 2026-03-25
**Status**: ACTIVE — governs all contract docs and code changes.

---

## The Problem

The current codebase conflates three distinct operations into a single call path (`to_jcs_bytes()` → `_prepare_for_canonicalization()` → `_jcs_canonicalize()`). This makes it impossible to state what "JCS canonicalization" means without also describing signature stripping, legacy normalization, and Pydantic unwrapping.

That conflation is a contract contamination bug. It must be resolved before any freeze.

---

## Three Layers

### Layer 1: Pure Canonicalization

**Input**: Plain JSON-compatible value (dict, list, str, int, float, bool, None).
**Output**: RFC 8785 canonical UTF-8 bytes.
**Contract**: Deterministic. No side effects. No environment sensitivity. No domain knowledge.

Corresponds to `_jcs_canonicalize()` in `jcs.py` — the pure RFC 8785 implementation.

**Rules**:
- No signature stripping
- No legacy normalization
- No Pydantic unwrapping
- No import fallbacks
- No silent exception handling
- Input must already be a plain JSON-compatible structure

A second implementation can reproduce this from the RFC 8785 specification alone.

### Layer 2: Projection (Signing View)

**Input**: A structured object (receipt, manifest, attestation) plus an explicit projection rule.
**Output**: The exact plain dict that is meant to be canonicalized, hashed, or signed.

This is where "exclude `signature` and `pack_root_sha256`" belongs. This is where "strip these 5 signature-related fields from a receipt" belongs.

**Rules**:
- Projection rules are explicit, versioned, and documented
- The rule set is a contract surface (second implementations must reproduce it)
- Failures MUST be visible (no silent exception swallowing)
- The projection function takes the rule version as a parameter
- Output is a plain dict suitable for Layer 1

**Current code location**: Split across `pyd.py:strip_signatures()`, `integrity.py:432-435`, and the implicit projection in `proof_pack.py:572-590`.

### Layer 3: Compatibility Normalization

**Input**: Legacy data variants from older receipt formats.
**Output**: Modern equivalent structure, suitable for Layer 2.

**Rules**:
- Versioned: each normalization transform has a named version
- Fenced: never runs inside the hash/sign path unless deliberately invoked by the caller
- Deterministic: no environment-dependent behavior (no PYTHONPATH-sensitive imports, no SourceFileLoader fallbacks)
- Test-vectorized: each normalization rule has golden input/output pairs
- Failures MUST be visible

**Current code location**: `normalize_legacy_fields()` in `_receipts/compatibility.py`, imported via fragile fallback in `canonicalize.py:27-52`.

---

## Constitutional Prohibition

**No environment-dependent transform may exist in any path that influences signed bytes, hashed bytes, or equality comparisons.**

This means:
- No import fallbacks in the hash path
- No PYTHONPATH-sensitive behavior in the hash path
- No "try: ... except Exception: pass" in the hash path
- No Pydantic-version-dependent serialization in the hash path

If a transform depends on the runtime environment, it belongs in Layer 3 (compatibility) and must be explicitly invoked before data enters the hash path.

---

## Naming Convention

| Old (overloaded) | New (precise) |
|-----------------|---------------|
| "JCS canonicalization" (of a receipt) | Layer 2 projection + Layer 1 canonicalization |
| "JCS stability check" | Pipeline stability check (tests Layer 2 + Layer 1 round-trip) |
| "to_jcs_bytes(receipt)" | Full pipeline (Layer 3 + Layer 2 + Layer 1, currently entangled) |
| "_jcs_canonicalize(dict)" | Pure Layer 1 canonicalization |
| "payload hash" | Layer 2 projection → Layer 1 canonicalization → SHA-256 |

Do not use "JCS" to describe any operation that includes Layer 2 or Layer 3 behavior.

---

## How This Governs Contract Docs

Every statement in PACK_CONTRACT.md about hashing, signing, or verifying must be classifiable as one of:

1. **Pure canonicalization rule** (Layer 1)
2. **Projection / signature-scope rule** (Layer 2)
3. **Compatibility rule** (Layer 3)
4. **Optional stricter verifier behavior**

Any statement that straddles two layers stays unfrozen until the code separates them.

---

## How This Governs Test Vectors

Vectors must be organized into three families:

1. **Pure JCS vectors**: Test Layer 1 only. Not blocked by pipeline decisions.
2. **Projection / signature-base vectors**: Test Layer 2. Blocked until projection rules are frozen.
3. **Pipeline / compatibility vectors**: Test Layer 3 + full pipeline. Blocked until all layers are separated.

---

## Enforcement

Before any contract freeze, require these code moves:

1. Extract a pure Layer 1 entry point (`jcs_canonicalize(plain_dict)`) that does NOT call `_prepare_for_canonicalization()`
2. Extract an explicit Layer 2 projection function (`project_for_signing(obj, version, rule_set)`) with documented exclusion sets
3. Make `signature_scope` derive from the same source of truth as the projection function
4. Remove or fence Layer 3 transforms from proof-critical paths
5. Make any missing recomputation in a claimed-value comparison an explicit failure — no silent skips
