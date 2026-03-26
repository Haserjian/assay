# Assay Domain Audit Adjudication

**Date**: 2026-03-26
**Status**: Adjudication memo (corrected from initial analysis)
**Scope**: Hash/signature domain confusion and adjacent trust-surface findings

This memo reclassifies every finding from the domain confusion analysis into
one of four categories. Claims that require SHA-256 preimage/collision
assumptions are explicitly downgraded. Proven call paths are shown with exact
file and line references.

Historical note: Finding 1 was addressed in the working tree by binding ADC
signature verification to the pack signer in `src/assay/replay_judge.py`.
The memo below preserves the pre-fix adjudication record so the audit trail
remains readable.

The TypeScript references below are archived audit notes from an external
comparison pass; the referenced TS verifier is not present in this workspace.

---

## Classification Key

| Label | Meaning |
|-------|---------|
| **LIVE_EXPLOIT** | Demonstrated exploitable path. Attacker model and capability shown. No crypto break required. |
| **SPEC_AMBIGUITY** | Cross-implementation behavioral divergence traceable to underspecified contract. |
| **HARDENING** | Defense-in-depth improvement. No current exploit, but absence weakens future proof-tier confidence. |
| **THEORETICAL_ONLY** | Requires SHA-256 preimage, collision, or structurally implausible input construction. Not a live exploit. |

---

## Finding 1: ADC consumed without signature verification

**Classification: LIVE_EXPLOIT**

**Attacker model**: Local filesystem modifier with write access to pack directory
(specifically `_unsigned/decision_credential.json`).

**Call path**:
1. `replay_judge.py:423` — `_load_optional_json(get_decision_credential_path(original_pack_dir))` loads ADC as plain JSON. No signature check.
2. `replay_judge.py:158` — `adc.get("credential_id")` read into artifact summary.
3. `replay_judge.py:205-220` — `original_adc.get("evidence_manifest_sha256")` compared against `original_root` (pack_root_sha256). Trust-relevant comparison. Unsigned.
4. `replay_judge.py:222-275` — `policy_hash`, `claim_namespace`, `claim_ids`, `integrity_result`, `overall_result`, `claim_results` read from ADC and used in divergence detection.
5. `replay_judge.py:277` — `_unsigned_digest(original_adc, ...)` computes hash over ADC body for byte-equivalence check.
6. `replay_judge.py:342-344` — signed judgment artifact built from these comparisons.

**Missing check**: In the pre-fix state, no function `verify_adc_signature()` existed anywhere in `src/assay/`. The `adc_emitter.py:86` writes a `signature` field into the ADC. No code read it.

**Exploit**: Replace `_unsigned/decision_credential.json` with a re-signed or unsigned ADC containing modified `evidence_manifest_sha256`, `overall_result`, or `claim_results`. The replay judge produces a signed judgment based on tampered inputs. The judgment carries the judge's Ed25519 signature, giving it an appearance of cryptographic authority over data the judge never verified.

**Blast radius**: Limited to replay judgment path. `verify_pack_manifest()` (the primary verification pipeline) does NOT read the ADC — it only verifies the 5-file kernel.

**Immediate mitigation**: Before reading any ADC field in `replay_judge.py`, verify the ADC's own Ed25519 signature against the embedded `signer_pubkey`. Fail closed if signature is absent, invalid, or pubkey is missing.

---

## Finding 2: TS verifier skips Ed25519 when signer_pubkey absent

**Classification: LIVE_EXPLOIT**

**Attacker model**: Malicious pack producer who omits `signer_pubkey` from manifest.

**Call path**:
1. `verify-core.ts:373` — `let signatureOk = true;` (initialized to true).
2. `verify-core.ts:377-401` — If `signatureB64` exists, decode it and check detached sig parity. This can pass.
3. `verify-core.ts:415` — `if (signatureBytes && signerPubkeyB64)` — if `signer_pubkey` is absent (undefined), the entire Ed25519 verification block is skipped.
4. `verify-core.ts:448` — `signatureOk` is still `true` from step 1. Stage recorded as "ok".
5. `verify-core.ts:469` — `passed: errors.length === 0` — returns `true`.

**Python comparison**: Python `integrity.py:533-540` falls back to keystore if embedded pubkey is absent. If neither pubkey nor keystore is available, Python emits `E_PACK_SIG_INVALID`. Python never silently passes without a key.

**Exploit**: Produce a pack with a valid `signature` field and matching `pack_signature.sig`, but omit `signer_pubkey`. The signature can be generated with any key — it will never be checked. TS verifier returns `passed: true`.

**Immediate mitigation**: In TS verifier, if `signatureBytes` exists but `signerPubkeyB64` is absent, emit `E_PACK_SIG_INVALID`. Do not allow signatureOk to remain true without Ed25519 verification.

---

## Finding 3: Empty-pack head_hash sentinel divergence

**Classification: SPEC_AMBIGUITY**

**Python behavior**: `integrity.py:399-402` — When receipt count is 0 and head_hash is null, substitutes `SHA256(b"empty")` as sentinel. A Python-built empty pack records this sentinel in `attestation.head_hash`.

**TS behavior**: `verify-core.ts:315-324` — Loop never executes for empty packs. `headHash` stays `null`. Lines 328-343: if `claimedHead` exists (it does — Python put the sentinel there), TS compares `null !== sentinel_hash` → emits `E_MANIFEST_TAMPER`.

**Result**: A valid empty-receipt pack built by Python fails TS verification.

**Contract gap**: The empty-pack sentinel is not specified in `PACK_CONTRACT.md`. Neither implementation is "wrong" — the contract is silent.

**Mitigation**: Add empty-pack sentinel behavior to PACK_CONTRACT.md §10. Add a conformance vector: valid empty-receipt pack.

---

## Finding 4: Schema validation depth divergence

**Classification: SPEC_AMBIGUITY**

**Python**: `integrity.py:241` calls `validate_signed_manifest()` from `pack_verify_policy.py` — full JSON Schema (Draft 2020-12) validation. Returns early on failure (lines 242-258).

**TS**: `verify-core.ts:175-188` — Checks only that `manifest.files` and `manifest.expected_files` are arrays. No JSON Schema validation. Does not short-circuit.

**Result**: Malformed manifests that Python rejects at schema stage may pass TS and produce different/unpredictable errors downstream.

**Mitigation**: Either add JSON Schema validation to TS, or explicitly document that schema validation is OPTIONAL in the contract and later stages must be robust to malformed input.

---

## Finding 5: Receipt exclusion set version negotiation

**Classification: SPEC_AMBIGUITY**

**Python**: `canonicalize.py:35-43` — `_SIGNATURE_FIELD_SETS` is a versioned dict. `prepare_receipt_for_hashing()` accepts a `version` parameter (default "v0"). Future versions can add new exclusion sets.

**TS**: `verify-core.ts:107-113` — `SIGNATURE_FIELDS_V0` hardcoded. No version parameter. No negotiation path.

**Result**: If Python introduces a v1 exclusion set, TS silently continues using v0. Hashes diverge for receipts that contain fields in the v1 set but not v0.

**Mitigation**: Add exclusion set version to conformance fixtures. When a new version is introduced, it must be accompanied by TS implementation before deployment.

---

## Finding 6: Receipt ↔ attestation JCS hash collision

**Classification: THEORETICAL_ONLY**

**Prior claim**: "A receipt and attestation with identical canonical bytes produce the same hash."

**Correction**: This is true in principle (same hash function, no domain prefix) but not constructible from current schemas. Receipt required fields are `{receipt_id, type, timestamp}`. Attestation required fields are `{pack_format_version, fingerprint_version, receipt_integrity, head_hash, ...}`. The key sets are entirely disjoint. Producing identical JCS bytes requires either:
- A SHA-256 collision (2^128 work), or
- A schema revision that introduces shared key names between receipts and attestations.

**No test asserts key-set disjointness**. This is the real residual: not a collision, but an invariant that protects structural separation without being enforced.

**Mitigation**: Add an invariant test asserting receipt and attestation required-key disjointness. This is cheap insurance against future schema drift.

---

## Finding 7: File hash = attestation hash

**Classification: THEORETICAL_ONLY**

**Prior claim**: "An attacker can craft receipt_pack.jsonl whose raw bytes equal JCS bytes of a valid attestation."

**Correction**: This requires constructing a single JSONL line that is simultaneously:
- Valid JSON matching the JCS encoding of a ~20-key attestation object
- Accepted by the receipt parser

The receipt parser calls `json.loads()` on each line — so the bytes must be valid JSON. But the JSONL line must also be a valid receipt (with `receipt_id`, `type`, `timestamp`) to pass `verify_receipt_pack()`. An attestation object does NOT contain these fields. The receipt verification would catch the mismatch.

More precisely: the file hash comparison in `verify_pack_manifest` checks raw bytes against the manifest entry and does NOT re-validate receipt content at that stage. But the head_hash cross-check (lines 386-421) would then fail because the recomputed head_hash from the tampered JSONL would not match the attestation's head_hash.

**This is not constructible without also breaking head_hash verification.** Downgraded from the prior analysis.

---

## Finding 8: head_hash = compute_payload_hash(last_receipt)

**Classification: HARDENING**

**Fact**: `integrity.py:204` and `canonicalize.py:105` compute the identical operation: `SHA256(JCS(prepare_receipt_for_hashing(receipt)))`. The head_hash of a pack IS the payload hash of its last receipt.

**Not an exploit**: This is intentional. The definitions are the same by design.

**Residual risk**: Downstream consumers cannot distinguish "receipt-level hash" from "chain head" without position context. If a system stores payload hashes and head_hashes in the same namespace, confusion is possible. No current code path does this.

**Mitigation**: Domain-separated hashing would make `head_hash("receipt", ...)` different from a standalone `payload_hash("receipt", ...)` if desired — but this is a design choice, not a bug fix.

---

## Finding 9: Domain-separated hashing (substrate-level)

**Classification: HARDENING**

All proof-critical hashes in Assay use `SHA256(JCS(object))` with no domain prefix. Seven distinct artifact types share the same hash construction:

| Hash domain | Location | Current prefix |
|-------------|----------|----------------|
| Receipt digest | integrity.py:204 | None |
| Attestation digest | proof_pack.py:529 | None |
| Manifest signing base | proof_pack.py:608 | None |
| File content | integrity.py:297 | None |
| Policy/suite/claim | proof_pack.py:345-355 | None |
| Merkle nodes | merkle.py:33 | None |
| Signer fingerprint | keystore.py:168 | None |

Standard cryptographic practice uses domain separation to prevent cross-context reuse. NIST cSHAKE/KMAC uses function-name/customization strings. RFC 9162 (Certificate Transparency) prefixes Merkle leaves (0x00) and nodes (0x01) to prevent second-preimage attacks.

**No current exploit demonstrated.** This is defense-in-depth for:
- Future schema evolution
- Cross-system replay prevention (Assay ↔ CCIO)
- Formal cryptographic soundness

---

## Finding 10: Cross-system replay (Assay ↔ CCIO)

**Classification: HARDENING (unconfirmed)**

**Hypothesis**: If CCIO's `epistemic_kernel.py` computes `SHA256(JCS(obj))` on claim objects with the same algorithm and no domain prefix, hashes are interchangeable.

**Status**: UNCONFIRMED. The MEMORY.md note from 2026-03-19 flags: "CCIO `src/core/epistemic_kernel.py` may be duplicate truth center with Assay's. Resolve before committing." No inspection of CCIO hashing was performed in this audit.

**Required**: Read `~/ccio-main-clean/src/core/epistemic_kernel.py` and compare hash construction. Until confirmed, this remains hypothetical.

---

## Finding 11: Merkle leaf/node domain confusion

**Classification: HARDENING**

**Fact**: `merkle.py:33` computes internal nodes as `SHA256(left_bytes || right_bytes)` where inputs are 32-byte digests. Leaves enter as 32-byte hex strings decoded to raw bytes. The ONLY domain separation is input length: leaves = 32 bytes, internal nodes = 64 bytes.

**Standard practice**: RFC 9162 uses `SHA256(0x00 || leaf)` for leaves and `SHA256(0x01 || left || right)` for internal nodes.

**No current exploit**: Assay's Merkle tree is used for inclusion proofs, not for core pack identity. Attack requires crafting a 64-byte leaf value that happens to match an internal node's concatenated children — which requires controlling both children's hashes (SHA-256 preimage).

**Mitigation**: If Merkle operations are ever promoted to a proof-critical path, add leaf/node domain prefixes per RFC 9162.

---

## Finding 12: Duplicate _sha256_hex definitions

**Classification: HARDENING**

Three independent definitions exist: `integrity.py:89`, `proof_pack.py:47`, `adc_emitter.py:23`. All identical today. Silent divergence risk if one is modified.

**Mitigation**: Extract to a shared module (e.g., `_receipts/digest.py`). Low priority but reduces maintenance surface.

---

## Summary

### Proven now
| # | Finding | Classification | Attacker | Immediate action |
|---|---------|---------------|----------|-----------------|
| 1 | ADC consumed without signature verification | **LIVE_EXPLOIT** | Filesystem writer | Verify ADC sig before field read in replay_judge.py |
| 2 | TS skips Ed25519 when signer_pubkey absent | **LIVE_EXPLOIT** | Pack producer | Emit E_PACK_SIG_INVALID when pubkey missing in TS |

### Likely but requires contract decision
| # | Finding | Classification | Action |
|---|---------|---------------|--------|
| 3 | Empty-pack sentinel divergence | SPEC_AMBIGUITY | Specify in PACK_CONTRACT.md |
| 4 | Schema validation depth | SPEC_AMBIGUITY | Document as optional or require in both |
| 5 | Exclusion set version negotiation | SPEC_AMBIGUITY | Gate new versions on cross-impl readiness |

### Hardening required (no current exploit)
| # | Finding | Classification | Action |
|---|---------|---------------|--------|
| 6 | Receipt ↔ attestation key-set disjointness | THEORETICAL_ONLY | Add invariant test |
| 7 | File ↔ attestation hash | THEORETICAL_ONLY | No action needed |
| 8 | head_hash = payload_hash | HARDENING | Domain separation if desired |
| 9 | No domain-separated hashing | HARDENING | Substrate v2 migration |
| 10 | Cross-system replay | HARDENING (unconfirmed) | Inspect CCIO first |
| 11 | Merkle leaf/node confusion | HARDENING | RFC 9162-style prefixes if promoted |
| 12 | Duplicate _sha256_hex | HARDENING | Extract to shared module |
