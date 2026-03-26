# Proof Pack Contract v0

**Date**: 2026-03-25
**Pack format version**: 0.1.0
**Manifest version**: 1.0.0
**Status**: DRAFT — extracted from code, not yet frozen.

This document records the behavioral contract of Assay Proof Packs as observed in the current codebase. Each section distinguishes:

- **Current behavior**: what the code does today
- **Frozen contract**: what a second implementation MUST reproduce
- **Open decision**: unresolved questions (see OPEN_CONTRACT_DECISIONS.md)

### Governing Rule: Descriptive Fields Are Not Dispatch Inputs

**For verification, algorithms, covered fields, and proof-critical behavior are defined by this contract, not by descriptive metadata fields embedded in the manifest or attestation, unless a field is explicitly designated normative.**

Manifests and attestations contain fields like `hash_alg`, `signature_alg`, `canon_version`, `head_hash_algorithm`, `pack_version`, and `manifest_version`. These are metadata for human readers and tooling introspection. Verifiers MUST NOT use these fields to determine which algorithms to use, which fields to cover, or how to behave. The contract defines all proof-critical behavior. See OCD-10 in OPEN_CONTRACT_DECISIONS.md.

---

## 1. Pack Layout

### Current behavior

A Proof Pack is a directory containing exactly 5 kernel files plus optional sidecars:

```
pack_dir/
  receipt_pack.jsonl          # Receipts, one JCS-canonical JSON per line
  verify_report.json          # Machine-readable verification results
  verify_transcript.md        # Human-readable summary
  pack_manifest.json          # Signed root envelope (readable JSON, not JCS)
  pack_signature.sig          # Detached Ed25519 signature (raw bytes, not base64)
  _unsigned/                  # Optional: unsigned narrative sidecars
    PACK_SUMMARY.md           # Human-readable pack explanation
    decision_credential.json  # Optional ADC
```

Legacy sidecars (`PACK_SUMMARY.md`, `decision_credential.json`) may also appear at pack root for backward compatibility.

### Frozen contract

- The 5 kernel files are REQUIRED and their names are fixed
- `_unsigned/` is the only allowed supplementary directory
- `pack_signature.sig` contains raw Ed25519 signature bytes (NOT base64)
- `pack_manifest.json` is stored as pretty-printed JSON (`json.dumps(indent=2)`), but its signature covers JCS-canonicalized bytes of the unsigned manifest
- `receipt_pack.jsonl` uses UTF-8 encoding

### Open decision

- Should legacy root-level sidecars be rejected in future versions? Currently warned, not errored.

---

## 2. JSONL Format (receipt_pack.jsonl)

### Current behavior

- One JCS-canonical JSON object per line
- Non-empty packs end with exactly one trailing newline
- Empty packs produce a 0-byte file (no newline)
- Receipts are sorted by `(_trace_id or run_id, seq, receipt_id)`
- Blank lines are skipped during parsing (`if not ln.strip(): continue`)

### Frozen contract

- One JSON object per line, UTF-8 encoding
- Trailing newline after last line
- Empty pack = 0 bytes
- Sort order: `(run_id, seq, receipt_id)` ascending
- **Builder obligation**: Each line MUST be JCS-canonical (RFC 8785, Layer 1)
- **Verifier obligation**: The verifier enforces line canonicality indirectly via file hash integrity (SHA-256 of entire file bytes must match manifest). A verifier MAY additionally check JCS-canonical formatting per line but is not required to

### Open decision

- `_trace_id` vs `run_id` as primary sort key — currently `_trace_id` takes precedence. Should `_trace_id` be eliminated from the contract? See OPEN_CONTRACT_DECISIONS.
- Should blank lines be rejected (error) or tolerated (skip)?

---

## 3. JCS Canonicalization (Assay JCS Profile v1)

### Current behavior (`_receipts/jcs.py`)

- Object keys sorted by UTF-16-BE byte order (RFC 8785 requirement)
- No whitespace between tokens (compact separators)
- Strings: delegated to `json.dumps(value, ensure_ascii=False, separators=(",", ":"))`
- Integers: `str(value)` — no size limit
- Floats: converted to `Decimal(str(value))`, normalized, formatted as:
  - `"0"` for zero (no negative zero distinction)
  - Plain notation when `-6 <= adjusted_exponent <= 20`
  - Scientific notation with capital `E` otherwise
- `Decimal` type accepted alongside `float` and `int`
- Non-finite floats (`inf`, `-inf`, `NaN`): REJECTED (ValueError)
- Non-string keys: REJECTED (TypeError)
- `None` → `"null"`, `True` → `"true"`, `False` → `"false"`
- Lists/tuples serialized as arrays; bytes/bytearray NOT treated as sequences
- `Mapping` types (dict, OrderedDict, etc.) serialized as objects

### Frozen contract

- **Assay JCS Profile v1** — based on RFC 8785 with one documented deviation
- UTF-16-BE key sort
- Compact separators, no whitespace
- Non-finite floats rejected
- Non-string keys rejected
- Number formatting follows RFC 8785 thresholds (-6 ≤ adjusted ≤ 20 → plain notation)
- **Deviation**: Scientific notation uses uppercase `E` without explicit `+` sign (`1E21` not `1e+21`). This is Python-originated behavior frozen into the conformance corpus. See `assay-verify-ts/CANONICALIZATION_PROFILE.md` for full details.

### Open decision

- The `Decimal` type support is Python-specific. Should the contract specify number precision handling? See OPEN_CONTRACT_DECISIONS.
- `json.dumps(ensure_ascii=False)` means non-ASCII characters pass through unescaped. Is this the intended contract? RFC 8785 says yes, but it's worth freezing explicitly.

---

## 4. Payload Preparation (Layer 2 Projection)

### Current behavior (`_receipts/canonicalize.py:46-88`)

Before JCS canonicalization, receipts pass through `prepare_receipt_for_hashing(receipt, version="v0")`:

1. Pydantic model → dict via `model_dump(mode="json")` or `.dict()`, or dict passthrough
2. `unwrap_frozen()` — recursively converts frozen containers to plain dicts/lists
3. Strip top-level signature fields per versioned exclusion set `_SIGNATURE_FIELD_SETS["v0"]`
4. Return plain dict for Layer 1 canonicalization

No legacy normalization (removed — was vestigial). No silent exception swallowing. Failures raise to caller.

### Frozen contract

- `prepare_receipt_for_hashing()` is the canonical Layer 2 projection function
- Signature field exclusion set v0: `{signatures, signature, cose_signature, receipt_hash, anchor}` — root-level only
- The exclusion set is versioned via `_SIGNATURE_FIELD_SETS` dict (`canonicalize.py:35-43`)
- Unknown version → `ValueError` (fail closed)
- Unsupported receipt type → `TypeError` (fail closed)
- A second implementation must strip the same v0 field set at root level, then pass the result to RFC 8785 canonicalization

### Open decision

- None for the current Layer 2 API. The extraction is complete (see EXTRACTION_PLAN.md).

---

## 5. Hash Algorithms and Output Formats

### Current behavior

All hash output is raw lowercase hex:

| Function | Returns | Example |
|----------|---------|---------|
| `compute_payload_hash()` | raw hexdigest | `"a1b2c3d4..."` |
| `compute_payload_hash_hex()` | raw hexdigest (alias) | `"a1b2c3d4..."` |
| `_sha256_hex()` | raw hexdigest | `"a1b2c3d4..."` |

OCD-1 resolved (2026-03-25): the prefixed format (`sha256:hex`) was removed from `compute_payload_hash()`. The algorithm is declared at the manifest level via `hash_alg`, not per-value.

### Frozen contract

- **SHA-256** is the hash algorithm for all mechanical verification (Layer 1)
- **SHA-512** is optionally supported for payload hashing via `compute_payload_hash(obj, algorithm="sha512")`. This function uses the clean Layer 2 projection (`prepare_receipt_for_hashing`) followed by Layer 1 canonicalization (`canonicalize.py:105`)
- Merkle operations use SHA-256 exclusively
- File manifest hashes use SHA-256 exclusively
- Pubkey fingerprint = `SHA256(raw_32_byte_ed25519_pubkey).hexdigest()`

### Open decision

- **RESOLVED (2026-03-25)**: Raw hex is the canonical format for all proof pack hashes. The `hash_alg` field in the manifest declares the algorithm. See OCD-1.

---

## 6. Ed25519 Signing and Verification

### Current behavior (`keystore.py`, `integrity.py`)

**Signing**:
1. Compute `JCS(unsigned_manifest)` — the manifest without `signature` and `pack_root_sha256` fields
2. Sign canonical bytes with Ed25519 via PyNaCl (libsodium)
3. Store signature as base64 in `pack_manifest.json.signature`
4. Store raw signature bytes in `pack_signature.sig`

**Verification** (`integrity.py:438-473`):
1. Reconstruct unsigned manifest: remove `signature` and `pack_root_sha256`
2. Canonicalize with JCS
3. Prefer embedded `signer_pubkey` (base64-encoded 32-byte Ed25519 public key)
4. Verify `signer_pubkey_sha256` matches `SHA256(decoded_pubkey_bytes)`
5. Verify Ed25519 signature against canonical bytes
6. Fall back to keystore if no embedded pubkey

**Key format**:
- Private key: raw 32 bytes at `~/.assay/keys/{signer_id}.key` (chmod 0600)
- Public key: raw 32 bytes at `~/.assay/keys/{signer_id}.pub` (chmod 0644)
- Signer ID: `[A-Za-z0-9._-]+`, must not start with `.`
- Default signer ID: `"assay-local"`

### Frozen contract

- Ed25519 (RFC 8032) is the signature algorithm
- Signature scope: `JCS(manifest_without_signature_and_pack_root_sha256)`
- Fields excluded from signing: `signature`, `pack_root_sha256`
- `pack_manifest.json.signature`: base64-encoded Ed25519 signature
- `pack_signature.sig`: raw Ed25519 signature bytes (64 bytes)
- Detached sig MUST equal decoded manifest signature
- Embedded `signer_pubkey`: base64-encoded 32-byte Ed25519 public key
- `signer_pubkey_sha256`: `SHA256(raw_pubkey_bytes).hexdigest()`
- `signature_alg`: `"ed25519"`
- `signature_scope`: `"JCS(pack_manifest_excluding_signature_and_pack_root_sha256)"` — the field value must exactly match the actual exclusion set used during signing

### Open decision

- **RESOLVED (2026-03-25)**: The `signature_scope` field previously said `"JCS(pack_manifest_without_signature)"` but the code excluded both `signature` AND `pack_root_sha256`. The field value has been corrected in `proof_pack.py` to match the actual exclusion set. Existing packs in the wild may carry the old field value; verifiers should not use this field to determine the exclusion set — it is informational. The exclusion set is defined by the contract: `{signature, pack_root_sha256}`.

---

## 7. Merkle Tree Operations

### Current behavior (`_receipts/merkle.py`)

- Leaves are hex-encoded strings (expected: 64-char SHA-256 hex)
- Leaf bytes: `bytes.fromhex(leaf_hex)` — no additional hashing
- Internal node: `SHA256(left_bytes || right_bytes)` — simple concatenation
- Odd count: duplicate last node (`left == right`)
- Empty tree root: `SHA256(b"").hexdigest()` = `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
- Inclusion proof order: bottom-up, sibling nodes
- Proof verification: left/right determined by `index % 2` (even = left, odd = right)
- `compute_merkle_leaf_from_value(hex)`: returns `SHA256(bytes.fromhex(hex)).hexdigest()`

### Frozen contract

- SHA-256 for all Merkle operations
- Leaves are hex strings, converted via `bytes.fromhex()`
- Internal node = `SHA256(left || right)` with no domain separation prefix
- Odd-count duplication of last node
- Empty tree = `SHA256(b"")`
- Inclusion proof: bottom-up sibling list, left/right by index parity

### Open decision

- **Domain separation**: Current implementation has NO prefix distinguishing leaf nodes from internal nodes. This is a known second-preimage weakness for certain attack models. Not urgent at current scale, but must be specified for v1. See OPEN_CONTRACT_DECISIONS.
- No validation that input hex strings are valid hex or correct length

---

## 8. Receipt Schema

### Current behavior (`integrity.py:105-156`)

**Required fields** (non-strict mode): `receipt_id`, `type`, `timestamp`

**Additional strict-mode fields**: `schema_version`, `policy_hash` OR `governance_hash`, `signature` OR `payload_hash`

**Timestamp format**: ISO 8601, parsed with `datetime.fromisoformat(ts.replace("Z", "+00:00"))`

**JCS stability check**: `JCS(receipt)` → parse JSON → `JCS(parsed)` must produce identical bytes

### Frozen contract

- `receipt_id`, `type`, `timestamp` are always required
- `timestamp` must be valid ISO 8601
- **Canonicalization stability** is verified for every receipt: Layer 2 projection (`prepare_receipt_for_hashing`) followed by Layer 1 canonicalization (`jcs_canonicalize`) must produce identical bytes when the output is parsed and re-canonicalized (`integrity.py:142-146`). No Layer 3 normalization is involved.
- Duplicate `receipt_id` values within a pack are rejected

### Open decision

- Only 3 required fields in non-strict mode — is this too permissive for a contract?
- Strict mode field requirements are policy. Should strict mode be the default for second implementations?

---

## 9. Manifest Structure

### Current behavior (`proof_pack.py:572-612`)

The signed manifest contains:

```json
{
  "pack_id": "pack_{timestamp}_{uuid8}",
  "pack_version": "0.1.0",
  "manifest_version": "1.0.0",
  "hash_alg": "sha256",
  "attestation": { ... },
  "attestation_sha256": "<SHA256(JCS(attestation))>",
  "suite_hash": "<SHA256(suite_id.encode())>",
  "claim_set_id": "...",
  "claim_set_hash": "<SHA256(JCS(claim_specs))>",
  "receipt_count_expected": 42,
  "files": [
    {"path": "receipt_pack.jsonl", "sha256": "...", "bytes": 1234},
    {"path": "verify_report.json", "sha256": "...", "bytes": 567},
    {"path": "verify_transcript.md", "sha256": "...", "bytes": 890}
  ],
  "expected_files": [
    "receipt_pack.jsonl", "verify_report.json", "verify_transcript.md",
    "pack_manifest.json", "pack_signature.sig"
  ],
  "signer_id": "assay-local",
  "signer_pubkey": "<base64(32-byte-ed25519-pubkey)>",
  "signer_pubkey_sha256": "<SHA256(raw_pubkey_bytes)>",
  "signature_alg": "ed25519",
  "signature_scope": "JCS(pack_manifest_excluding_signature_and_pack_root_sha256)",
  "signature": "<base64(ed25519_signature)>",
  "pack_root_sha256": "<same as attestation_sha256>"
}
```

**D12 invariant**: `pack_root_sha256 == attestation_sha256`. The attestation is the single immutable identifier for the evidence unit.

**Circular dependency note**: `pack_manifest.json` and `pack_signature.sig` cannot be in the `files` array (manifest can't contain its own hash). Their integrity is protected by the Ed25519 signature.

### Frozen contract

- All fields listed above are present in the manifest. Of these, `signature` and `pack_root_sha256` are **excluded** from the signed content — the signature covers `JCS(manifest minus {signature, pack_root_sha256})`
- D12 invariant: `pack_root_sha256 == attestation_sha256`
- `files` array covers `receipt_pack.jsonl`, `verify_report.json`, `verify_transcript.md`
- `expected_files` lists all 5 kernel files
- File entries include `path`, `sha256`, and `bytes`
- Schema validation via JSON Schema (Draft 2020-12) at both build and verify time

### Open decision

- None for the structure. The manifest is the best-specified part of the system.

---

## 10. Attestation Structure

### Current behavior (`proof_pack.py:479-512`)

```json
{
  "pack_format_version": "0.1.0",
  "fingerprint_version": 1,
  "pack_id": "...",
  "run_id": "...",
  "suite_id": "...",
  "suite_hash": "...",
  "verifier_version": "1.18.0",
  "canon_version": "jcs-rfc8785",
  "canon_impl": "receipts.jcs",
  "canon_impl_version": "1.18.0",
  "policy_hash": "...",
  "claim_set_id": "...",
  "claim_set_hash": "...",
  "receipt_integrity": "PASS|FAIL",
  "claim_check": "PASS|FAIL|N/A",
  "discrepancy_fingerprint": "...|null",
  "assurance_level": "L0",
  "proof_tier": "signed-pack",
  "mode": "shadow|enforced|breakglass",
  "head_hash": "<SHA256(JCS(last_receipt))>",
  "head_hash_algorithm": "last-receipt-digest-v0",
  "time_authority": "local_clock",
  "n_receipts": 42,
  "timestamp_start": "...",
  "timestamp_end": "...",
  "ci_binding": { ... } | null,
  "valid_until": "..." | null,
  "superseded_by": "..." | null
}
```

### Frozen contract

- `receipt_integrity`: `"PASS"` or `"FAIL"` — no other values
- `head_hash_algorithm`: `"last-receipt-digest-v0"` — meaning: SHA256(JCS(last receipt in sorted order))
- `canon_version`: `"jcs-rfc8785"` — the canonicalization standard
- Attestation is hashed via `SHA256(JCS(attestation))` to produce `attestation_sha256`
- Schema validated at both build and verify time

### Open decision

- **RESOLVED (2026-03-25)**: `head_hash` failure now produces explicit `E_MANIFEST_TAMPER` instead of silent skip (`integrity.py:373-395`). See OCD-4.
- `time_authority` is always `"local_clock"` — no witness-anchored time yet in attestation

---

## 11. Verification Steps (integrity.py)

### Current behavior — exact order

**Single receipt** (`verify_receipt`):
1. Check required fields: `receipt_id`, `type`, `timestamp`
2. Validate timestamp as ISO 8601
3. (Strict only) Check `schema_version`, `policy_hash`/`governance_hash`, `signature`/`payload_hash`
4. JCS stability test: canonicalize → parse → re-canonicalize → compare bytes

**Receipt pack** (`verify_receipt_pack`):
1. Run `verify_receipt` on each receipt
2. Detect duplicate `receipt_id` values
3. Compute running head_hash (SHA256(JCS(last receipt))); on failure, sets `head_hash = None` (no silent retention of stale value)

**Pack manifest** (`verify_pack_manifest`):
1. JSON Schema validation (fail closed)
2. Inspect pack entries for unexpected files (warnings)
3. Verify file hashes (SHA-256 per file in `files` array)
4. Path containment check (no escape from pack directory)
5. Parse `receipt_pack.jsonl`, verify receipt count against `receipt_count_expected`
6. Recompute receipt integrity, cross-check against attestation `receipt_integrity` and `head_hash`
7. Verify `attestation_sha256` matches `SHA256(JCS(attestation))`
8. Verify Ed25519 signature (embedded pubkey preferred, keystore fallback)
9. Verify `signer_pubkey_sha256` matches `SHA256(decoded_pubkey_bytes)`
10. Verify detached signature matches manifest signature bytes
11. Verify D12: `pack_root_sha256 == attestation_sha256`
12. (Optional) Freshness check: age ≤ `max_age_hours`
13. (Optional) CI binding: exact match on `commit_sha`

### Frozen contract

- Steps 1-11 constitute the mechanical verification contract. Steps 4 and 6 use the clean Layer 2 → Layer 1 pipeline (`prepare_receipt_for_hashing` + `jcs_canonicalize`). No contaminated paths remain (OCD-2 and OCD-3 resolved).
- Steps 12-13 are optional and policy-configured
- Verification MUST fail closed: any error → `passed = False`
- File hash verification uses SHA-256 only

---

## 12. Error Codes

### Current behavior (`integrity.py`, `failure_mechanisms.py`)

| Code | Mechanism Family | Meaning |
|------|-----------------|---------|
| `E_SCHEMA_UNKNOWN` | schema_mismatch | Missing required field or schema_version |
| `E_TIMESTAMP_INVALID` | stale_evidence | Unparseable ISO 8601 timestamp |
| `E_CANON_MISMATCH` | schema_mismatch | JCS round-trip instability or canonicalization failure |
| `E_DUPLICATE_ID` | schema_mismatch | Duplicate receipt_id in pack |
| `E_MANIFEST_TAMPER` | tamper_detected | File hash mismatch, missing file, attestation hash mismatch, receipt count mismatch |
| `E_PACK_SIG_INVALID` | tamper_detected | Signature verification failure, missing signature, detached sig mismatch |
| `E_PACK_OMISSION_DETECTED` | tamper_detected | Receipt count doesn't match manifest expectation |
| `E_PACK_STALE` | stale_evidence | Pack age exceeds max_age_hours |
| `E_SIG_MISSING` | witness_gap | Missing receipt-level signature (strict mode) |
| `E_SIG_INVALID` | tamper_detected | Invalid receipt-level signature |
| `E_POLICY_MISSING` | policy_conflict | Missing policy_hash/governance_hash (strict mode) |
| `E_CHAIN_BROKEN` | witness_gap | Receipt chain integrity failure |
| `E_CI_BINDING_MISSING` | policy_conflict | CI binding required but absent |
| `E_CI_BINDING_MISMATCH` | policy_conflict | CI commit_sha doesn't match expected |
| `E_PATH_ESCAPE` | tamper_detected | File path escapes pack directory |

### Frozen contract

- Error codes are string constants, not enums
- Each error includes: `code`, `message`, optional `receipt_index`, optional `field`, optional `failure_mechanism`
- Mechanism families: `stale_evidence`, `schema_mismatch`, `witness_gap`, `tamper_detected`, `policy_conflict`
- Second implementations MUST produce the same error codes for the same failure conditions

---

## 13. Canonical Fault Classes

*Added 2026-03-26. Fault classes sit above raw error codes and provide cross-implementation comparability even when outward code paths differ.*

Fault classes are the vocabulary for "what kind of thing went wrong," independent of which verification step or code path detected it.

### Fault Class Table

| Fault Class | Meaning | Error Codes | Adversarial Specimens |
|------------|---------|-------------|----------------------|
| `file_integrity_violation` | Pack file content does not match manifest declaration | `E_MANIFEST_TAMPER` (hash mismatch, missing file, count mismatch) | tampered_receipt_content, missing_kernel_file |
| `signature_authenticity_failure` | Ed25519 signature is invalid, missing, or detached sig disagrees | `E_PACK_SIG_INVALID` | tampered_signature |
| `structural_invariant_violation` | Pack-level invariant broken (D12, attestation hash) | `E_MANIFEST_TAMPER` (on `pack_root_sha256` or `attestation_sha256`) | d12_invariant_break |
| `containment_violation` | Manifest-controlled path escapes pack root | `E_PATH_ESCAPE` | path_traversal |
| `receipt_identity_violation` | Duplicate receipt_id within a pack | `E_DUPLICATE_ID` (receipt-level) or `E_MANIFEST_TAMPER` on `receipt_integrity` (pack-level) | duplicate_receipt_id |
| `schema_violation` | Missing required fields, malformed structure | `E_SCHEMA_UNKNOWN`, `E_CANON_MISMATCH` | — |
| `temporal_violation` | Timestamp invalid or pack too old | `E_TIMESTAMP_INVALID`, `E_PACK_STALE` | — |
| `policy_violation` | Missing policy hash, CI binding mismatch | `E_POLICY_MISSING`, `E_CI_BINDING_MISSING`, `E_CI_BINDING_MISMATCH` | — |

### Cross-Implementation Note

For `receipt_identity_violation`, implementations may differ in which raw code surfaces:
- Python's pack verifier detects duplicates via `verify_receipt_pack` (receipt-level), then surfaces the failure as `E_MANIFEST_TAMPER` on `receipt_integrity` (pack-level cross-check)
- TypeScript detects duplicates directly at the pack level as `E_DUPLICATE_ID`

Both are valid. The fault class is the same. Second implementations MUST detect the fault; they MAY report it at either the receipt or pack level.

---

## 14. Verification Stages

*Added 2026-03-26. Stage names are the provisional shared vocabulary for verification traces.*

### Stage Map

| Stage | What It Checks | Contract Section |
|-------|---------------|-----------------|
| `validate_shape` | Manifest structure (fields are correct types) | §0 (schema validation) |
| `validate_paths` | All manifest-driven paths contained within pack root | §11 step 4 |
| `validate_file_hashes` | SHA-256 per file matches manifest; expected files present | §11 steps 1-1b |
| `validate_receipts` | JSONL parse, receipt count, duplicate IDs, head hash cross-check | §11 steps 2-2c |
| `validate_attestation` | SHA256(JCS(attestation)) matches manifest field | §11 step 3 |
| `verify_signature` | Detached sig parity, unsigned manifest reconstruction, Ed25519, fingerprint | §11 steps 4a-4c |
| `check_d12_invariant` | pack_root_sha256 == attestation_sha256 | §11 step 4d |

### Stage Topology

Stage topology is **informational**, not normative. Implementations:
- MUST produce the same pass/fail verdict and error codes (normative)
- MAY organize their verification into different internal stages
- SHOULD use these stage names when emitting audit traces for interoperability

### Python ↔ TypeScript Stage Mapping

| Stage | Python Location | TS Location | Mechanism Divergence |
|-------|----------------|-------------|---------------------|
| `validate_shape` | `integrity.py` JSON Schema (Draft 2020-12) | `verify.ts` Array.isArray guards | Python uses formal schema validator; TS uses manual type guards. Same intent. |
| `validate_paths` | `integrity.py:251-303` | `verify.ts` isContainedPath() | Identical logic |
| `validate_file_hashes` | `integrity.py:248-291` | `verify.ts` file hash loop | Identical logic |
| `validate_receipts` | `integrity.py:306-395` | `verify.ts` JSONL parse + checks | Python sub-delegates to verify_receipt_pack; TS does it inline |
| `validate_attestation` | `integrity.py:397-405` | `verify.ts` attestation hash check | Identical logic |
| `verify_signature` | `integrity.py:407-519` | `verify.ts` signature block | Identical logic |
| `check_d12_invariant` | `integrity.py:521-528` | `verify.ts` D12 check | Identical logic |

### Adversarial Specimen → Fault Class → Failing Stage

| Specimen | Fault Class | Expected Failing Stage | Python Code | TS Code |
|----------|------------|----------------------|-------------|---------|
| tampered_receipt_content | file_integrity_violation | validate_file_hashes | `E_MANIFEST_TAMPER` | `E_MANIFEST_TAMPER` |
| tampered_signature | signature_authenticity_failure | verify_signature | `E_PACK_SIG_INVALID` | `E_PACK_SIG_INVALID` |
| missing_kernel_file | file_integrity_violation | validate_file_hashes | `E_MANIFEST_TAMPER` | `E_MANIFEST_TAMPER` |
| d12_invariant_break | structural_invariant_violation | check_d12_invariant | `E_MANIFEST_TAMPER` | `E_MANIFEST_TAMPER` |
| path_traversal | containment_violation | validate_paths | `E_PATH_ESCAPE` | `E_PATH_ESCAPE` |
| duplicate_receipt_id | receipt_identity_violation | validate_receipts | `E_MANIFEST_TAMPER`* | `E_DUPLICATE_ID` |

*Python surfaces duplicate detection as receipt_integrity mismatch at the pack level. See Cross-Implementation Note in §13.
