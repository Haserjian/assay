# Test Vector Specification

**Date**: 2026-03-25
**Status**: DRAFT — depends on PACK_CONTRACT.md resolution of open decisions.
**Purpose**: Define the golden and adversarial test corpus that any second implementation must pass.

---

## Principles

1. **Vectors derive from the contract, not the code.** If a vector tests Python-specific behavior that isn't in the contract, it's a test of the Python implementation, not a contract vector.
2. **Golden vectors prove correct behavior.** Input + expected output. A conforming implementation MUST produce the exact output.
3. **Adversarial vectors prove rejection.** Malformed input + expected error. A conforming implementation MUST reject with the specified error code.
4. **Open decisions block specific vectors.** Vectors that depend on unresolved OCD items are marked BLOCKED with the OCD reference.

---

## Corpus Structure

```
tests/contracts/
  vectors/
    jcs/
      golden/           # known-input → known-canonical-bytes
      adversarial/      # malformed input → expected rejection
    merkle/
      golden/           # known-leaves → known-root, known-proofs
      adversarial/      # malformed leaves → expected failure
    pack/
      golden/           # complete valid packs with known verification results
      adversarial/      # tampered packs with expected error codes
    receipt/
      golden/           # valid receipts with known canonical hashes
      adversarial/      # malformed receipts with expected errors
  expected/
    jcs_vectors.json    # machine-readable expected outputs
    merkle_vectors.json
    pack_vectors.json
    receipt_vectors.json
```

---

## JCS Vectors (`jcs/`)

### Golden

| ID | Input | Expected Canonical Bytes (UTF-8) | Tests |
|----|-------|--------------------------------|-------|
| JCS-G01 | `{}` | `{}` | Empty object |
| JCS-G02 | `{"b":1,"a":2}` | `{"a":2,"b":1}` | Key sorting |
| JCS-G03 | `{"β":1,"α":2}` | Sorted by UTF-16-BE | Unicode key sort (non-ASCII) |
| JCS-G04 | `{"a\u0000b":1,"a":2}` | Sorted by UTF-16-BE with null | Embedded null in key |
| JCS-G05 | `[1, 2, 3]` | `[1,2,3]` | Array, no whitespace |
| JCS-G06 | `{"a": null}` | `{"a":null}` | Null value |
| JCS-G07 | `{"a": true, "b": false}` | `{"a":true,"b":false}` | Boolean values |
| JCS-G08 | `{"a": 0}` | `{"a":0}` | Zero integer |
| JCS-G09 | `{"a": -0.0}` | `{"a":0}` | Negative zero → "0" (see note below) |
| JCS-G10 | `{"a": 1e20}` | `{"a":100000000000000000000}` | Large number in plain notation (adjusted=20) |
| JCS-G11 | `{"a": 1e21}` | `{"a":1E21}` | Large number in scientific notation (adjusted=21) |
| JCS-G12 | `{"a": 1e-6}` | `{"a":0.000001}` | Small number in plain notation (adjusted=-6) |
| JCS-G13 | `{"a": 1e-7}` | `{"a":1E-7}` | Small number in scientific notation (adjusted=-7) |

**Cross-implementation note on number inputs**: Number inputs in this table are specified as typed programming-language values, not JSON text. JSON does not have negative zero (`-0` in JSON text parses to `0` per most parsers). JCS-G09 tests the case where a language-level `-0.0` float is canonicalized. In JavaScript, `-0` is a distinct value; in Python, `float('-0.0')` preserves the sign bit. Per RFC 8785 (ES6 `JSON.stringify` semantics), negative zero MUST serialize as `"0"`. The RFC 8785 errata specifically address this. Cross-implementation vectors should provide inputs in both JSON text form (where `-0` is not representable) and language-native form (where applicable).
| JCS-G14 | `{"a": "hello\nworld"}` | `{"a":"hello\nworld"}` | String with escaped newline |
| JCS-G15 | `{"a": "日本語"}` | `{"a":"日本語"}` | Non-ASCII string (ensure_ascii=False) |
| JCS-G16 | Nested 3-deep object | Sorted at every level | Deep nesting |
| JCS-G17 | `{"": 1}` | `{"":1}` | Empty string key |
| JCS-G18 | `999999999999999999999` | `999999999999999999999` | Very large integer |

### Adversarial

| ID | Input | Expected | Tests |
|----|-------|----------|-------|
| JCS-A01 | `{"a": Infinity}` | ValueError | Non-finite float |
| JCS-A02 | `{"a": NaN}` | ValueError | NaN |
| JCS-A03 | `{1: "a"}` | TypeError | Non-string key |
| JCS-A04 | `{"a": b"bytes"}` | TypeError | bytes value (not a JSON type) |

---

## Merkle Vectors (`merkle/`)

### Golden

| ID | Leaves (hex) | Expected Root (hex) | Tests |
|----|-------------|--------------------|----- |
| MK-G01 | `[]` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Empty tree |
| MK-G02 | `[SHA256("a").hex()]` | Same as input leaf | Single leaf (root = leaf) |
| MK-G03 | `[leaf_a, leaf_b]` | `SHA256(bytes.fromhex(leaf_a) + bytes.fromhex(leaf_b)).hex()` | Two leaves |
| MK-G04 | `[leaf_a, leaf_b, leaf_c]` | Computed: last node duplicated | Three leaves (odd count) |
| MK-G05 | 8 leaves | Full binary tree root | Power-of-2 count |
| MK-G06 | 7 leaves | Tree with duplication at multiple levels | Non-power-of-2 |

For each golden tree with >1 leaf, also provide:
- Inclusion proofs for leaf index 0, last index, and a middle index
- Expected `verify_merkle_inclusion` result: `True`

### Adversarial

| ID | Input | Expected | Tests |
|----|-------|----------|-------|
| MK-A01 | Proof with wrong index | `verify_merkle_inclusion` → `False` | Index mismatch |
| MK-A02 | Proof with one byte flipped in sibling | `False` | Tampered proof |
| MK-A03 | Proof for non-existent leaf | `False` | Leaf not in tree |
| MK-A04 | Empty proof for non-single tree | `False` | Missing proof nodes |

---

## Receipt Vectors (`receipt/`)

### Golden

| ID | Receipt | Expected | Tests |
|----|---------|----------|-------|
| RC-G01 | `{"receipt_id":"r1","type":"test","timestamp":"2026-01-01T00:00:00Z"}` | No errors | Minimal valid receipt |
| RC-G02 | Same as RC-G01 + `schema_version`, `policy_hash`, `signature` | No errors (strict mode) | Full strict receipt |
| RC-G03 | Receipt with nested objects | JCS stability verified | Complex structure |
| RC-G04 | Receipt with unicode values | JCS stability verified | Non-ASCII content |

For each golden receipt, provide:
- Expected JCS canonical bytes (exact)
- Expected SHA-256 hash of canonical bytes

**BLOCKED by OCD-1**: Hash format (prefixed vs raw) must be resolved before finalizing expected hashes.

### Adversarial

| ID | Receipt | Expected Error | Tests |
|----|---------|---------------|-------|
| RC-A01 | `{"type":"test","timestamp":"2026-01-01T00:00:00Z"}` | `E_SCHEMA_UNKNOWN` (missing receipt_id) | Missing required field |
| RC-A02 | `{"receipt_id":"r1","type":"test","timestamp":"not-a-date"}` | `E_TIMESTAMP_INVALID` | Bad timestamp |
| RC-A03 | `{"receipt_id":"r1","type":"test","timestamp":"2026-01-01T00:00:00Z"}` × 2 in pack | `E_DUPLICATE_ID` | Duplicate receipt_id |
| RC-A04 | Receipt where JCS(receipt) → parse → JCS differs | `E_CANON_MISMATCH` | Round-trip instability |

---

## Pack Vectors (`pack/`)

### Golden

| ID | Pack Contents | Expected Verification | Tests |
|----|--------------|----------------------|-------|
| PK-G01 | Minimal valid pack (1 receipt, valid manifest, valid signature) | `VerifyResult(passed=True)` | Happy path |
| PK-G02 | Pack with 10 receipts, all valid | `passed=True`, `receipt_count=10` | Multi-receipt |
| PK-G03 | Empty pack (0 receipts, 0-byte JSONL) | `passed=True`, `receipt_count=0` | Empty pack |
| PK-G04 | Pack with CI binding | `passed=True` + CI binding fields present | CI-bound pack |
| PK-G05 | Pack built with `deterministic_ts` | Bit-identical rebuild | Deterministic reproducibility |

**Generation**: Golden packs should be built using `ProofPack.build()` with `deterministic_ts` to ensure reproducibility. The expected verification results should be captured alongside.

### Adversarial — Tamper Detection

| ID | Modification | Expected Error | Tests |
|----|-------------|---------------|-------|
| PK-A01 | Flip one byte in `receipt_pack.jsonl` | `E_MANIFEST_TAMPER` (hash mismatch) | File tampering |
| PK-A02 | Delete `verify_report.json` | `E_MANIFEST_TAMPER` (file missing) | Missing kernel file |
| PK-A03 | Replace `pack_signature.sig` with random bytes | `E_PACK_SIG_INVALID` | Signature tampering |
| PK-A04 | Edit a receipt's `receipt_id` in JSONL | `E_MANIFEST_TAMPER` (hash mismatch) | Receipt tampering |
| PK-A05 | Change `receipt_count_expected` in on-disk manifest JSON (no re-signing) | `E_PACK_SIG_INVALID` (signature no longer matches modified content) | Manifest field tampering without re-signing |
| PK-A06 | Add duplicate receipt_id across two receipts | `E_DUPLICATE_ID` | Duplicate injection |
| PK-A07 | Replace attestation but keep old `attestation_sha256` | `E_MANIFEST_TAMPER` | Attestation tampering |
| PK-A08 | Set `pack_root_sha256` ≠ `attestation_sha256` | `E_MANIFEST_TAMPER` | D12 invariant violation |
| PK-A09 | Use `../../../etc/passwd` as file path | `E_PATH_ESCAPE` | Path traversal |
| PK-A10 | Make detached sig differ from manifest sig | `E_PACK_SIG_INVALID` | Sig file mismatch |

### Adversarial — Schema/Format

| ID | Modification | Expected Error | Tests |
|----|-------------|---------------|-------|
| PK-A11 | JSONL with blank lines between receipts | Skipped (current) or error (if contract tightened) | Blank line handling |
| PK-A12 | JSONL with non-JSON line | `E_MANIFEST_TAMPER` (parse failure) | Malformed JSONL |
| PK-A13a | JSONL with non-canonical JSON (pretty-printed) + original manifest file hash | `E_MANIFEST_TAMPER` (file bytes changed → hash mismatch) | Non-canonical JSONL detected via file integrity |
| PK-A13b | JSONL with non-canonical JSON (pretty-printed) + manifest re-signed with matching file hash | **BLOCKED** — requires contract decision on whether verifier must directly check per-line canonicality (see OCD-9) | Cooperating builder with non-canonical JSONL |
| PK-A14 | Manifest missing `signer_pubkey` | Schema validation failure | Missing embedded key |
| PK-A15 | Wrong `signer_pubkey_sha256` for correct pubkey | `E_PACK_SIG_INVALID` | Fingerprint mismatch |

### Adversarial — Freshness/CI

| ID | Modification | Expected Error | Tests |
|----|-------------|---------------|-------|
| PK-A16 | Pack with timestamp 48h old, `max_age_hours=24` | `E_PACK_STALE` | Staleness |
| PK-A17 | CI binding with wrong commit SHA | `E_CI_BINDING_MISMATCH` | CI mismatch |
| PK-A18 | `require_ci_binding=True` but no CI binding | `E_CI_BINDING_MISSING` | Missing CI |

---

## Vector File Format

Each vector file (`*_vectors.json`) should be:

```json
{
  "format_version": "0.1.0",
  "generated_by": "assay contract corpus generator",
  "generated_at": "2026-03-25T00:00:00Z",
  "vectors": [
    {
      "id": "JCS-G01",
      "category": "golden",
      "input": {},
      "expected_output": "e30=",
      "expected_output_encoding": "base64",
      "description": "Empty object",
      "blocked_by": null
    }
  ]
}
```

For pack vectors, the `input` field references a directory path within the corpus, and `expected_output` is a `VerifyResult` JSON.

---

## Blocked Vectors

These vectors cannot be finalized until the referenced OCD item is resolved:

| Vector | Blocked By | Reason |
|--------|-----------|--------|
| All receipt hash expectations | OCD-1 | Hash output format (prefixed vs raw) |
| PK-A11, PK-A13b | PACK_CONTRACT / OCD-9 | JSONL strictness level / direct vs indirect enforcement |
| All payload hash vectors | OCD-2, OCD-3 | Signature stripping and legacy normalization in hash path |

**Important**: JCS golden vectors (JCS-G*) test pure Layer 1 canonicalization and are NOT blocked by OCD-2 or OCD-3. Merkle vectors (MK-G*, MK-A*) test pure Layer 1 operations and are also not blocked. Only receipt vectors, pack vectors, and payload hash vectors that involve the full preparation pipeline (Layers 2+3) are blocked by the pipeline contamination decisions. See VERIFICATION_LAYERS.md for the three-layer doctrine.

---

## Corpus Generation

The corpus should be generated programmatically from a script that:

1. Creates golden packs using `ProofPack.build()` with `deterministic_ts`
2. Captures the exact verification result
3. Generates adversarial variants by mutating golden packs
4. Captures the expected error codes
5. Outputs all vectors in the JSON format above

The generation script itself is part of the contract — it documents how vectors are produced and can be re-run after contract changes.

**Prerequisite**: OCD-1, OCD-2, OCD-3 must be resolved before corpus generation can produce stable vectors.
