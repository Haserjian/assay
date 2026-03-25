# Verification Core Boundary Map

**Date**: 2026-03-25
**Scope**: `src/assay/` — modules involved in receipt hashing, signing, canonicalization, Merkle operations, and pack verification.
**Purpose**: Classify every verification-path module as mechanical, semantic, or mixed — and name the boundary violations precisely.

---

## Why This Exists

A second implementation (e.g., TypeScript browser verifier) must reproduce identical verification results given the same pack. That is only possible if the mechanical verification contract is fully separable from semantic interpretation.

This document maps where the boundary is clean and where it leaks.

---

## Classification

### MECHANICAL — Pure (freezable, portable)

These modules contain only deterministic operations with no semantic knowledge. A second implementation can reimplement them from specification alone.

| Module | Lines | Contract | Notes |
|--------|-------|----------|-------|
| `_receipts/jcs.py` | 104 | RFC 8785 JSON Canonicalization Scheme | Pure serialization. UTF-16-BE key sort, Decimal number encoding, `json.dumps(ensure_ascii=False)` for string escaping. No external dependencies beyond stdlib. |
| `_receipts/merkle.py` | 99 | SHA-256 Merkle tree with odd-node duplication | Pure tree operations. Leaves are hex strings, internal node = `SHA256(left \|\| right)`, no domain separation. |
| `keystore.py` | 220 | Ed25519 key management (file-based) | Pure crypto. PyNaCl/libsodium calls. Signer ID validation, atomic key writes, fingerprint = `SHA256(raw_pubkey_bytes)`. |
| `manifest_schema.py` | 99 | JSON Schema validation (Draft 2020-12) | Pure schema enforcement. Fail-closed on missing schemas. No semantic judgment. |
| `failure_mechanisms.py` | 50 | Error code → mechanism family mapping | Pure lookup table. 15 error codes → 5 mechanism families. No interpretation. |

### MECHANICAL — Mostly Clean (freezable with noted caveats)

These modules are primarily mechanical but contain minor policy decisions or fragile fallbacks that a second implementation must know about.

| Module | Lines | Contract | Caveats |
|--------|-------|----------|---------|
| `integrity.py` | 577 | Pack verification engine | **Caveat 1**: `verify_receipt` strict mode (lines 124-136) checks for `schema_version`, `policy_hash`/`governance_hash`, `signature`/`payload_hash` — these are policy choices about what "strict" means. **Caveat 2**: `verify_receipt_pack` head_hash computation (line 192-195) silently passes on canonicalization failure, falling back to previous receipt's hash. See OPEN_CONTRACT_DECISIONS. **Caveat 3**: `verify_pack_manifest` line 524 re-shadows `attestation` variable from line 356. **Caveat 4**: The JCS stability check (lines 139-154) uses `to_jcs_bytes()` which goes through the full contaminated preparation pipeline. It tests pipeline stability, not pure JCS (Layer 1) stability. See VERIFICATION_LAYERS.md. |
| `pack_verify_policy.py` | 37 | Pack entry inspection | `_ALLOWED_SUPPLEMENTARY_DIRS` and `_ALLOWED_LEGACY_ROOT_SIDECARS` are policy constants. Mechanical in execution, policy in definition. |

### BOUNDARY VIOLATION — Semantic Leaks in Mechanical Path

**This is the headline finding.** These modules sit in the hash-computation path but contain semantic knowledge that does not belong there.

#### `_receipts/canonicalize.py` (lines 63-86) — PRIMARY VIOLATION

**What happens**: `_prepare_for_canonicalization()` is called by `to_jcs_bytes()`, which means ALL JCS operations in the system go through the contaminated path. This includes not just receipt payload hashing, but also manifest signing (`proof_pack.py:601`), attestation integrity hashing (`proof_pack.py:527`), the JCS stability check in the verifier (`integrity.py:140`), and head hash computation (`integrity.py:193`). Inside that preparation:

1. **Pydantic model serialization** (line 65-72): Calls `model_dump(mode="json")` or `.dict()`. This applies Pydantic's JSON serialization rules (e.g., datetime → string, enum → value). The exact output depends on which Pydantic version is running.

2. **Frozen container unwrapping** (line 74): Delegates to `pyd.unwrap_frozen()`. Recursively converts Pydantic frozen models to plain dicts. Necessary for JCS, but the boundary between "unwrap for serialization" and "interpret model structure" is blurred.

3. **Legacy field normalization** (lines 76-79): Calls `normalize_legacy_fields()` with **silent exception swallowing** (`except Exception: pass`). This means:
   - Migration logic runs inside the hash path
   - Failures are invisible
   - A second implementation that doesn't know about legacy fields will hash different bytes
   - The function itself is imported via a fragile fallback mechanism (lines 27-52) that tries normal import, then falls back to `SourceFileLoader` with hardcoded path resolution

4. **Signature field stripping** (lines 81-84): Calls `strip_signatures()` with **silent exception swallowing** (`except Exception: pass`). This means:
   - The hash path knows which fields are "signatures" — that is semantic knowledge
   - The field set `{signatures, signature, cose_signature, receipt_hash, anchor}` is hardcoded in `pyd.py:267-274` with no versioning
   - A second implementation must strip the exact same fields to produce the same hash
   - Failures are invisible

**Impact on second implementations**: If a TypeScript verifier does not implement the exact same preparation pipeline — same Pydantic unwrapping, same legacy normalization, same signature stripping, same silent failure handling — it will compute different hashes for the same receipt. The "mechanical" path is not actually reproducible from JCS spec alone.

**Recommended fix direction**: Move signature stripping and legacy normalization to explicit, versioned preprocessing steps that run BEFORE the data enters the canonicalization path. The canonicalization path should accept only plain dicts with no further transformation.

#### `_receipts/compat/pyd.py` (lines 254-331) — SECONDARY VIOLATION

**What happens**: This file is nominally a Pydantic compatibility shim, but it also contains:

1. **`is_signature_field()`** (lines 254-274): Hardcoded set of 5 field names that are considered "signature-related." This is semantic knowledge — which fields are signatures is a domain concept, not a serialization concern.

2. **`strip_signatures()`** (lines 312-331): Uses `is_signature_field()` to filter dict keys. Called from the hash path in `canonicalize.py`.

3. **`unwrap_frozen()`** (lines 277-309): Recursively unwraps Pydantic models and frozen containers. The decision to call `model_dump(mode="json")` vs `.dict()` is Pydantic-version-dependent behavior embedded in the verification path.

**Impact**: These functions belong in a preparation/preprocessing module, not in a Pydantic compatibility layer. Their current placement makes it hard for a second implementation to know they exist — you'd have to trace the call chain from `compute_payload_hash` through `_prepare_for_canonicalization` through `unwrap_frozen` and `strip_signatures` to find them.

### SEMANTIC / GOVERNANCE — Not Portable

These modules contain business logic, judgment, or interpretation that a second implementation should NOT try to reproduce. They consume verification results but do not produce them.

| Module | Lines | Role |
|--------|-------|------|
| `claim_verifier.py` | 479 | Business rules: verify claims against evidence, claim specs, policy hash |
| `reviewer_packet_verify.py` | 950 | Checkpoint settlement verification with claim matrix — domain logic |
| `evidence_pack.py` | 420 | Export trace + verification for patent defense — orchestration |
| `witness.py` | 457 | RFC 3161 timestamping — calls `openssl ts` CLI, I/O bound |
| `passport_sign.py` | 140 | Passport JSON signing — application-level signing workflow |

### MIXED — Mechanical Core with Semantic Additions

| Module | Lines | Mechanical Part | Semantic Part |
|--------|-------|-----------------|---------------|
| `proof_pack.py` | 742 | Pack building, file writing, JSONL serialization, manifest construction, Ed25519 signing | Claim verification (lines 450-454), transcript generation (lines 514-524), PACK_SUMMARY generation (lines 673-682), ADC emission (lines 631-668) |
| `decision_receipt_verify.py` | 117 | Ed25519 signature verification | Interpretation of what "verified" means for a Decision Receipt |

### IO / PRESENTATION — Environment-Dependent

| Function/Module | Location | Role |
|-----------------|----------|------|
| `detect_ci_binding()` | `proof_pack.py:107-147` | Reads environment variables (GITHUB_ACTIONS, GITHUB_SHA, etc.) |
| `_generate_transcript()` | `proof_pack.py:215-296` | Markdown rendering of verification results |
| `explain_pack` / `render_md` | `explain.py` (imported lazily) | Human-readable pack summary |

---

## Call Chain: Hash Path (Critical for Second Implementations)

This is the exact sequence of operations that produces the bytes that get signed:

```
ANY CALLER using to_jcs_bytes()
  ├─ compute_payload_hash(receipt)              # receipt hashing
  ├─ integrity.py:140 — JCS stability check     # verifier
  ├─ integrity.py:193 — head hash               # verifier
  ├─ integrity.py:376 — attestation hash         # verifier
  ├─ proof_pack.py:601 — manifest signing        # builder
  └─ proof_pack.py:527 — attestation hash        # builder
       │
       ▼
  to_jcs_bytes(obj)                              # canonicalize.py:55
    └─ _prepare_for_canonicalization(obj)         # Layer 3+2 (contaminated)
    │    ├─ model_dump(mode="json") OR .dict()   # Pydantic serialization
    │    ├─ unwrap_frozen(data)                  # pyd.py:277 — recursive unwrap
    │    ├─ normalize_legacy_fields(data)        # SILENT EXCEPT PASS (Layer 3)
    │    └─ strip_signatures(data)               # SILENT EXCEPT PASS (Layer 2)
    └─ _jcs_canonicalize(prepared_data)          # jcs.py:21 — pure Layer 1
    └─ hashlib.sha256(canonical_bytes)           # stdlib → OpenSSL
```

Everything above the `_jcs_canonicalize` line is preparation (Layers 2+3). Everything from `_jcs_canonicalize` down is pure mechanical (Layer 1). The boundary violation is that ALL JCS operations — including manifest signing and the verifier's own stability checks — go through the contaminated path. See VERIFICATION_LAYERS.md for the three-layer doctrine.

---

## Summary Table

| Classification | Modules | Portable? |
|---------------|---------|-----------|
| **Pure mechanical** | jcs.py, merkle.py, keystore.py, manifest_schema.py, failure_mechanisms.py | Yes — from spec alone |
| **Mostly mechanical** | integrity.py, pack_verify_policy.py | Yes — with documented caveats |
| **Boundary violation** | canonicalize.py, pyd.py (signature/unwrap functions) | No — requires knowledge of Python-specific preparation pipeline |
| **Semantic/governance** | claim_verifier.py, reviewer_packet_verify.py, evidence_pack.py, witness.py, passport_sign.py | Not applicable — not part of verification contract |
| **Mixed** | proof_pack.py, decision_receipt_verify.py | Mechanical core extractable; semantic parts stay in Python |
| **IO/presentation** | detect_ci_binding, transcript generation, explain_pack | Environment-dependent — not part of contract |
