# Verification Core Boundary Map

**Date**: 2026-03-25 (reconciled post-extraction 2026-03-25)
**Scope**: `src/assay/` — modules involved in receipt hashing, signing, canonicalization, Merkle operations, and pack verification.
**Purpose**: Classify every verification-path module as mechanical, semantic, or mixed. Document the current clean layer separation.

---

## Why This Exists

A second implementation (e.g., TypeScript browser verifier) must reproduce identical verification results given the same pack. That is only possible if the mechanical verification contract is fully separable from semantic interpretation.

This document maps where the boundary is clean. Historical boundary violations were resolved 2026-03-25 via the canonicalization extraction (see EXTRACTION_PLAN.md).

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
| `integrity.py` | ~606 | Pack verification engine | **Caveat 1**: `verify_receipt` strict mode (lines 124-136) checks for `schema_version`, `policy_hash`/`governance_hash`, `signature`/`payload_hash` — these are policy choices about what "strict" means. **Caveat 2 (resolved)**: head_hash failure now sets `head_hash = None` and triggers explicit `E_MANIFEST_TAMPER` downstream — no silent skip (`integrity.py:195-202, 373-395`). **Caveat 3**: `verify_pack_manifest` re-shadows `attestation` variable. **Caveat 4 (resolved)**: The stability check now uses explicit `prepare_receipt_for_hashing()` (Layer 2) + `jcs_canonicalize()` (Layer 1) — no contaminated pipeline (`integrity.py:142-146`). |
| `pack_verify_policy.py` | 37 | Pack entry inspection | `_ALLOWED_SUPPLEMENTARY_DIRS` and `_ALLOWED_LEGACY_ROOT_SIDECARS` are policy constants. Mechanical in execution, policy in definition. |

### LAYER 2 — Explicit Receipt Projection (clean, freezable)

*This section replaces the former "BOUNDARY VIOLATION" section. The violations described there were resolved 2026-03-25 via the canonicalization extraction. See EXTRACTION_PLAN.md for the full history.*

#### `_receipts/canonicalize.py` — Layer 2 API

**Current state**: `prepare_receipt_for_hashing(receipt, version="v0")` is the explicit Layer 2 projection function (`canonicalize.py:46-88`). It:

1. Converts Pydantic models to plain dicts (`model_dump(mode="json")` or `.dict()`)
2. Recursively unwraps frozen containers via `unwrap_frozen()`
3. Strips top-level signature fields per a versioned exclusion set (`_SIGNATURE_FIELD_SETS` at `canonicalize.py:35-43`)
4. Returns a plain dict suitable for `jcs_canonicalize()` (Layer 1)

**What was removed**:
- `to_jcs_bytes()` — deleted, zero callers remain
- `_prepare_for_canonicalization()` — deleted
- `normalize_legacy_fields()` — confirmed vestigial, import machinery deleted (including `SourceFileLoader` fallback)
- Silent `except Exception: pass` — no longer exists in any hash path

**Single source of truth for signature exclusion**: `_SIGNATURE_FIELD_SETS` dict in `canonicalize.py:35-43`, versioned by key (currently only `"v0"`). The v0 set is `{signatures, signature, cose_signature, receipt_hash, anchor}` — root-level only.

**Portability**: A second implementation needs to:
1. Implement `_SIGNATURE_FIELD_SETS["v0"]` — 5 named fields
2. Strip those fields from root level only
3. Pass the result to RFC 8785 canonicalization
This is fully specifiable without reading the Python source.

#### `_receipts/compat/pyd.py` — Pydantic compatibility (narrowed scope)

`unwrap_frozen()` remains in `pyd.py` and is called by `prepare_receipt_for_hashing()`. This is acceptable — it converts Pydantic frozen containers to plain dicts, which is a necessary mechanical step before JCS. The `strip_signatures()` and `is_signature_field()` functions remain in `pyd.py` but are **no longer called from any hash path** — `prepare_receipt_for_hashing()` uses its own `_SIGNATURE_FIELD_SETS` directly.

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

## Call Chains: Current Architecture (post-extraction)

Two distinct entry points, cleanly separated by layer:

```
RECEIPT HASHING (Layer 2 → Layer 1)
  ├─ integrity.py:142 — stability check
  ├─ integrity.py:200 — head hash
  ├─ compute_payload_hash()
  └─ proof_pack.py JSONL line generation
       │
       ▼
  prepare_receipt_for_hashing(receipt)      # canonicalize.py:46 — Layer 2
    ├─ model_dump / .dict() / passthrough   # Pydantic → plain dict
    ├─ unwrap_frozen(data)                  # frozen containers → plain
    └─ strip root-level signature fields    # per _SIGNATURE_FIELD_SETS["v0"]
       │
       ▼
  jcs_canonicalize(prepared_dict)           # jcs.py:21 — pure Layer 1 (RFC 8785)


PLAIN DICT HASHING (Layer 1 only)
  ├─ integrity.py:400 — attestation hash
  ├─ integrity.py:467 — manifest signing base
  ├─ proof_pack.py — attestation, seed, claim hashes
  └─ all other callers (~40 sites)
       │
       ▼
  jcs_canonicalize(plain_dict)              # jcs.py:21 — pure Layer 1 (RFC 8785)
```

Layer 1 is pure RFC 8785. Layer 2 is explicit projection. No Layer 3 exists (removed — was vestigial). No silent exception handling in any hash path. See VERIFICATION_LAYERS.md.

---

## Summary Table

| Classification | Modules | Portable? |
|---------------|---------|-----------|
| **Pure mechanical (Layer 1)** | jcs.py, merkle.py, keystore.py, manifest_schema.py, failure_mechanisms.py | Yes — from spec alone |
| **Explicit projection (Layer 2)** | canonicalize.py (`prepare_receipt_for_hashing`) | Yes — versioned exclusion set, fully specifiable |
| **Mostly mechanical** | integrity.py, pack_verify_policy.py | Yes — with documented caveats (strict mode is policy) |
| **Semantic/governance** | claim_verifier.py, reviewer_packet_verify.py, evidence_pack.py, witness.py, passport_sign.py | Not applicable — not part of verification contract |
| **Mixed** | proof_pack.py, decision_receipt_verify.py | Mechanical core extracted; semantic parts stay in Python |
| **IO/presentation** | detect_ci_binding, transcript generation, explain_pack | Environment-dependent — not part of contract |
