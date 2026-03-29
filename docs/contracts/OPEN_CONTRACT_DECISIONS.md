# Open Contract Decisions

**Date**: 2026-03-25 (reconciled post-extraction 2026-03-25; OCD-11/OCD-12 added 2026-03-29)
**Status**: 6 of 12 items resolved. 0 HIGH remain. 2 MEDIUM remain (OCD-9, OCD-11). 4 LOW remain (OCD-5, OCD-6, OCD-7, OCD-12).

These are questions that must be answered before the Proof Pack contract can be fully frozen for second implementations.

Each item records: the question, current behavior, options, and a preliminary recommendation. Resolved items are marked with date and evidence.

---

## OCD-1: Canonical Hash Output Format — RESOLVED (2026-03-25)

**Blocker level**: ~~HIGH~~ → **RESOLVED**.

**Current behavior**: Two formats coexist:
- `compute_payload_hash()` → `"sha256:a1b2c3..."` (prefixed)
- `_sha256_hex()` → `"a1b2c3..."` (raw)
- File hashes, head hash, attestation hash, Merkle leaves, pubkey fingerprint all use raw format
- Only `compute_payload_hash()` uses the prefixed format

**The problem**: A second implementation needs exactly one answer per field. Currently, if you're verifying a manifest, all hashes are raw hex. But if you're verifying a receipt payload hash, it might be prefixed. The `compute_payload_hash_hex()` shim exists specifically because callers need the raw format even from the "canonical" function.

**Options**:
1. **Standardize on raw hex everywhere.** Remove the prefix from `compute_payload_hash()`. Simplest. The `hash_alg` field in the manifest already declares the algorithm.
2. **Standardize on prefixed everywhere.** Change all internal hashes to `sha256:hex`. More self-describing, but requires updating every hash comparison.
3. **Freeze current split.** Document which fields use which format. Workable but awkward.

**Resolution**: Option 1 implemented. `compute_payload_hash()` now returns raw hex (`canonicalize.py:115`). `compute_payload_hash_hex()` retained as alias for backward compatibility. `commands.py` normalization workarounds updated to strip prefix from stored hashes (backward compatible with old prefixed data). 2678 tests pass. Evidence: `canonicalize.py:114-115`, `test_layer2_projection.py::TestMigrationEquivalence`.

---

## OCD-2: Signature Stripping in Hash Path — RESOLVED (2026-03-25)

**Blocker level**: ~~HIGH~~ → **RESOLVED**.

**Current behavior**: `_prepare_for_canonicalization()` calls `strip_signatures()` inside the hash path with silent exception swallowing. The stripped field set `{signatures, signature, cose_signature, receipt_hash, anchor}` is hardcoded in `pyd.py:267-274`.

**The problem**: The canonicalization module knows which fields are signatures. This is semantic knowledge in the mechanical path. A second implementation must either:
- Replicate the exact same set of stripped fields (fragile)
- OR receive pre-stripped data (clean)

Silent `except Exception: pass` means failures are invisible. If stripping fails, the hash includes signature fields, producing a different hash than when stripping succeeds — with no indication.

**Options**:
1. **Move stripping to explicit preprocessing.** Callers must strip before calling canonicalization. Canonicalization becomes pure RFC 8785. Most portable.
2. **Version the stripped field set.** Keep stripping in the hash path but make the field set explicit, versioned, and failure-visible. Less clean but lower code churn.
3. **Remove stripping entirely.** Require that data entering the hash path is already clean. Breaking change for existing callers.

**Additional finding (audit 2026-03-25)**: The contamination is not limited to `compute_payload_hash()`. `to_jcs_bytes()` itself calls `_prepare_for_canonicalization()`, meaning the manifest signing path (`proof_pack.py:601`), attestation hashing (`proof_pack.py:527`), the JCS stability check (`integrity.py:140`), and head hash computation (`integrity.py:193`) ALL go through the contaminated preparation pipeline. The fix must separate:
- `jcs_canonicalize(plain_dict)` — pure Layer 1 (RFC 8785 only)
- `project_for_signing(obj, rule_version)` — explicit Layer 2 projection
- The current `to_jcs_bytes(receipt)` — full pipeline (Layers 3+2+1, to be deprecated or renamed)

See VERIFICATION_LAYERS.md for the three-layer doctrine.

**Resolution**: Option 1 implemented. `prepare_receipt_for_hashing(receipt, version="v0")` is the explicit Layer 2 projection function (`canonicalize.py:46-88`). Versioned exclusion set at `_SIGNATURE_FIELD_SETS` (`canonicalize.py:35-43`). `to_jcs_bytes()` and `_prepare_for_canonicalization()` deleted. No silent exception swallowing remains. All callers migrated. 2678 tests pass. Evidence: commits `5b5566e`..`670129e`, `test_layer2_projection.py`.

---

## OCD-3: Legacy Normalization in Hash Path — RESOLVED (2026-03-25)

**Blocker level**: ~~HIGH~~ → **RESOLVED**.

**Current behavior**: `_prepare_for_canonicalization()` calls `normalize_legacy_fields()` with silent exception swallowing. The function is imported via a fragile fallback mechanism (`SourceFileLoader` with hardcoded path).

**The problem**: Legacy normalization transforms the data before hashing. If a second implementation doesn't know about this transformation:
- It will hash the un-normalized data
- The hashes won't match
- There is no error indicating why

If the import fails (which it silently handles), the normalization is skipped entirely — and the hash path produces a different hash than when normalization succeeds.

**Options**:
1. **Make normalization an explicit versioned step.** Like OCD-2, move it out of the hash path. Callers must normalize before hashing.
2. **Eliminate legacy normalization.** If all existing data has been migrated, remove the code. If not, run a one-time migration.
3. **Document the normalization rules.** Freeze them as part of the contract so second implementations can reproduce them.

**Additional finding (audit 2026-03-25)**: The `SourceFileLoader` fallback mechanism makes normalization behavior dependent on PYTHONPATH and whether a `receipts` package exists on the system. If the fallback import succeeds on one machine but fails on another, the same receipt produces different hashes on different machines. This is environmentally non-deterministic behavior in a proof-critical path. See VERIFICATION_LAYERS.md constitutional prohibition: "No environment-dependent transform may exist in any path that influences signed bytes, hashed bytes, or equality comparisons."

**Resolution**: Option 2 implemented. `normalize_legacy_fields()` confirmed vestigial — `compatibility.py` does not exist, function was always identity, zero external callers, zero test dependencies. Entire import machinery (including `SourceFileLoader` fallback) deleted from `canonicalize.py`. No environment-dependent transforms remain in any proof-critical path. Evidence: `canonicalize.py` has no reference to `normalize_legacy_fields`.

---

## OCD-4: Head Hash Failure Behavior — RESOLVED (2026-03-25)

**Blocker level**: ~~MEDIUM~~ → **RESOLVED**.

**Current behavior** (`integrity.py:192-195`):
```python
try:
    head_hash = _sha256_hex(to_jcs_bytes(receipt))
except Exception:
    pass
```

If canonicalization of the last receipt fails, `head_hash` silently retains the value from the previous receipt. No error is reported. The `VerifyResult` reports this head hash as if it represents the last receipt.

**The problem**: "Head hash" is supposed to identify the state of the pack. If it silently refers to a different receipt than the last one, the attestation's `head_hash` may not match a recomputation that handles the same failure differently.

This is worse than a wrong answer — it's a silent wrong answer.

**Options**:
1. **Hard-fail on head hash computation failure.** If any receipt in the pack fails canonicalization, the pack fails verification. Strictest.
2. **Set head_hash to None on failure.** Explicitly signal that head hash is unavailable. Let callers decide.
3. **Report the failure as a warning/error and use the last successful hash.** Make the fallback visible.
4. **Keep current behavior but document it.** Freeze the silent fallback as the contract.

**Downstream analysis (audit 2026-03-25)**: Option 2 as originally recommended creates a new silent path. If `recomputed.head_hash` is None:
- The builder (`proof_pack.py:503`) falls back to `_sha256_hex(b"empty")`, so the attestation would claim a specific head_hash
- The verifier (`integrity.py:366`) checks `if claimed_head and recomputed.head_hash and ...` — if `recomputed.head_hash` is None, the comparison is **silently skipped**
- Result: the attestation claims a head_hash, but the verifier doesn't verify it. This is worse than a visible failure.

**Resolution**: Hybrid of Options 1 and 2. Canonicalization failure sets `head_hash = None` (not stale retention). Downstream, if attestation claims a head_hash but recomputed is None, verifier emits explicit `E_MANIFEST_TAMPER` (not silent skip). Empty-pack sentinel (`SHA256(b"empty")`) handled as special case. Constitutional rule enforced: **if an attestation claims a value and the verifier cannot recompute the comparator, the result is an explicit error.** Evidence: `integrity.py:195-202` (None on failure), `integrity.py:373-395` (explicit error), `test_integrity_mutants.py::TestHeadHashNoSilentSkip` (2 regression tests).

---

## OCD-5: Merkle Domain Separation

**Blocker level**: LOW (not urgent) — must be specified for vNext.

**Current behavior**: Internal Merkle nodes use `SHA256(left || right)` with no prefix. Leaf nodes enter as hex strings converted via `bytes.fromhex()`. There is no byte prefix distinguishing a leaf hash from an internal hash.

**The problem**: Without domain separation, a malicious actor could potentially construct a tree where an internal node is mistaken for a leaf or vice versa (second-preimage attack). At current pack sizes (tens to hundreds of receipts), this is not practically exploitable. But for a formal contract, it must be specified.

**Options**:
1. **Add domain separation in vNext.** Leaf = `SHA256(0x00 || leaf_bytes)`, internal = `SHA256(0x01 || left || right)`. Standard approach (RFC 6962).
2. **Freeze current behavior.** Document the absence of domain separation as the v0 contract. Add separation in v1.
3. **Add domain separation now.** Breaking change for existing packs.

**Recommendation**: Option 2 for v0, Option 1 for v1. Current packs work correctly without it. Breaking existing packs to add domain separation is premature. But the v0 contract MUST explicitly state that no domain separation exists, so second implementations don't accidentally add it.

---

## OCD-6: _trace_id vs run_id

**Blocker level**: LOW — internal naming, but affects sort order contract.

**Current behavior**: Receipt sorting uses `_trace_id` as primary key with `run_id` as fallback. `_receipt_run_id()` accepts either field but fails on conflict. The `_trace_id` field has a leading underscore suggesting it's internal.

**Options**:
1. **Standardize on `run_id`.** Deprecate `_trace_id` in the contract. Existing data retains both.
2. **Freeze current behavior.** Document the precedence rule.

**Recommendation**: Option 1. `run_id` is the canonical name in the manifest and attestation. `_trace_id` should be accepted for backward compatibility but not required by the contract.

---

## OCD-7: Non-Strict vs Strict Mode as Default

**Blocker level**: LOW — policy decision.

**Current behavior**: Non-strict mode requires only `receipt_id`, `type`, `timestamp`. Strict mode additionally requires `schema_version`, `policy_hash`/`governance_hash`, `signature`/`payload_hash`.

**The problem for second implementations**: Which mode is the contract? If a browser verifier implements only non-strict, it accepts receipts that the Python verifier in strict mode would reject.

**Options**:
1. **Contract specifies minimum fields only.** Second implementations check what's present.
2. **Contract defines levels.** Level 0 = 3 fields. Level 1 = strict fields. Both are valid.
3. **Strict is the contract default.** Non-strict is a compatibility mode.

**Recommendation**: Option 2. Define verification levels explicitly. A second implementation declares which level it supports. The pack's `assurance_level` field can be used to indicate which level was applied at build time.

---

## Resolution Process

Each OCD item should be resolved by:
1. Choosing an option with rationale
2. Updating PACK_CONTRACT.md to reflect the decision (moving from "Open decision" to "Frozen contract")
3. Implementing the change in code if needed
4. Adding test vectors that verify the resolved behavior
5. Recording the decision date

No item should be resolved by "whatever the code currently does" unless that behavior is deliberately correct. The point of this document is to prevent accidentally canonizing bugs as eternal contract.

---

## OCD-10: Descriptive Manifest/Attestation Fields vs Normative Verifier Behavior — RESOLVED (2026-03-25)

**Blocker level**: ~~HIGH~~ → **RESOLVED** (doctrine established, schema hardened, regression tests installed).

**Core rule**: **Verifiers MUST NOT derive algorithmic behavior, covered-component behavior, version-conditional verification behavior, or other proof-critical behavior from descriptive manifest/attestation fields unless the contract explicitly designates that field as normative.**

**Descriptive fields are not dispatch inputs.**

**Origin**: The `signature_scope` fix (OCD-8) exposed a general failure pattern: a field name sounds executable, verifier behavior is actually hardcoded elsewhere, docs/schema/artifacts can drift, an honest second implementation may trust the field, reality forks. This OCD names the entire bug family.

### Fields in scope

**Algorithm-looking (higher risk)** — these invite executable branching:

| Field | Location | Emitted Value | Verifier Behavior |
|-------|----------|--------------|-------------------|
| `hash_alg` | manifest | `"sha256"` | Hardcodes SHA-256. Field is never read. |
| `signature_alg` | manifest | `"ed25519"` | Hardcodes Ed25519 via PyNaCl. Field is never read. |
| `head_hash_algorithm` | attestation | `"last-receipt-digest-v0"` | Hardcodes SHA256(JCS(last receipt)). Field is never read. |
| `canon_version` | attestation | `"jcs-rfc8785"` | Hardcodes RFC 8785 via `_jcs_canonicalize()`. Field is never read. |

**Version/documentary (lower risk)** — less likely to trigger branching but still descriptive-only:

| Field | Location | Emitted Value | Verifier Behavior |
|-------|----------|--------------|-------------------|
| `pack_version` | manifest | `"0.1.0"` | Not read by verifier. |
| `manifest_version` | manifest | `"1.0.0"` | Not read by verifier. |

### Normative rule

- Covered fields for signing are contract-defined: `{signature, pack_root_sha256}`.
- Hash and signature algorithms used for verification are contract-defined: SHA-256 and Ed25519.
- Version strings do not alter verifier behavior unless explicitly designated normative by contract text.
- Descriptive fields may be validated for consistency or surfaced in diagnostics, but they do not control proof-critical execution.

### Consequence for future evolution

Any future change that intends field-driven dispatch must:
1. Explicitly designate the field as normative in the contract
2. Define verifier behavior for each allowed value
3. Add interop vectors proving both old and new values verify correctly
4. Document migration semantics for existing packs

### Regression coverage

- `signature_scope`: Poison-pill tests in `test_integrity_mutants.py::TestSignatureScopeInvariant`
- `hash_alg`: Schema defense test in `test_integrity_mutants.py::TestDescriptiveFieldInvariant`
- `signature_alg`: Poison-pill test in `test_integrity_mutants.py::TestDescriptiveFieldInvariant`

### Sub-decision: signature_alg schema posture

**Current state**: `signature_alg` now constrained to `enum: ["ed25519"]` in `pack_manifest.schema.json`.

**Comparison**: `hash_alg` uses `enum: ["sha256"]` — constrained, defense in depth.

**Recommendation**: **Constrain to `enum: ["ed25519"]`** for defense in depth.

**Pros**:
- Prevents packs with misleading `signature_alg` values from passing schema validation
- Matches the `hash_alg` pattern — consistent defensive posture
- All existing tests and fixtures use `"ed25519"` — no compatibility impact
- If a future algorithm is added, the schema change is a one-line enum extension paired with contract update and verifier code — exactly the process OCD-10 requires

**Cons**:
- Marginally less flexible for experimental signers (but those should not be producing proof packs)
- Requires schema update when adding algorithms (but that's the correct forcing function)

**Verdict**: Constrain. Implemented — `pack_manifest.schema.json` now has `enum: ["ed25519"]` for `signature_alg`. Regression test: `test_integrity_mutants.py::TestDescriptiveFieldInvariant::test_signature_alg_schema_prevents_misleading_values`.

---

## OCD-8: signature_scope Field vs Code Mismatch — RESOLVED (2026-03-25)

**Blocker level**: ~~HIGH~~ → **RESOLVED**.

**Current behavior**: The manifest field `signature_scope` previously contained `"JCS(pack_manifest_without_signature)"`. The actual signing code (`integrity.py:432-435`) excludes both `signature` AND `pack_root_sha256`.

**The problem**: A second implementation reading the manifest would see the field value and might exclude only `signature`, not also `pack_root_sha256`. Signature verification would fail. This is signature ambiguity in the worst possible place.

**Resolution (partial)**: The field value in `proof_pack.py` has been corrected to `"JCS(pack_manifest_excluding_signature_and_pack_root_sha256)"`. However:
- Existing packs in the wild carry the old field value
- The contract must specify that verifiers should NOT use the `signature_scope` field to determine the exclusion set — it is informational
- The actual exclusion set `{signature, pack_root_sha256}` is defined by the contract, not the field value

**Fully resolved**: Field value corrected (`proof_pack.py:607`), schema accepts both old and new values (`pack_manifest.schema.json`), normative comment in verifier code (`integrity.py:455-467`), poison-pill regression tests prove verifier ignores field value (`test_integrity_mutants.py::TestSignatureScopeInvariant`). PACK_CONTRACT.md Section 6 updated. OCD-10 generalizes this fix to the entire descriptive-field class.

---

## OCD-9: Direct vs Indirect Verifier Obligations

**Blocker level**: MEDIUM — architectural, affects all verifier-contract statements.

**Current behavior**: Several properties are enforced indirectly rather than directly checked:

| Property | Enforcement | Direct? |
|----------|------------|---------|
| JSONL lines are JCS-canonical | File hash integrity (SHA-256 of whole file) | Indirect — verifier checks file hash, not per-line canonicality |
| Receipt sort order | File hash integrity | Indirect |
| Signature base formation | Hardcoded exclusion set in `integrity.py:432-435` | Direct |
| Head hash correctness | Comparison of recomputed vs claimed head_hash | Direct — explicit `E_MANIFEST_TAMPER` on unrecomputable comparator (OCD-4 resolved) |
| Attestation integrity | `SHA256(JCS(attestation))` vs `attestation_sha256` | Direct |
| Receipt count | `len(parsed)` vs `receipt_count_expected` | Direct |

**The problem**: Without a clear doctrine of what the verifier directly enforces vs what is only indirectly guaranteed, second implementations may over- or under-verify. A browser verifier that doesn't download the raw JSONL file but receives parsed receipts via API would lose all indirectly-enforced properties.

**Options**:
1. **Document the distinction explicitly.** Each PACK_CONTRACT section marks properties as "direct verifier check" or "indirect (via file hash integrity)."
2. **Require all properties to be directly checked.** Adds verifier complexity but eliminates indirect-enforcement gaps.
3. **Define verification profiles.** "Full pack verification" (checks everything, needs raw files). "Receipt-only verification" (checks individual receipt integrity, no file-level guarantees).

**Recommendation**: Option 1, with Option 3 as a future refinement. The distinction between direct and indirect enforcement must be visible in the contract so second implementations can make informed decisions about what they're actually verifying.

**Clarification artifact**: `docs/contracts/OCD-9_DIRECT_VS_INDIRECT_VERIFIER_OBLIGATIONS.md`

**Current status**: partially clarified. Direct obligations are now enumerated as explicit verifier checks; indirect obligations are identified as properties only guaranteed through verified enclosing artifacts or builder discipline. The remaining open question is whether JSONL canonicality should stay indirect or be promoted to a direct verifier obligation in a future profile.

---

## OCD-11: OPTIONAL + INVALIDATING Field Combination in Comparability Contracts

**Blocker level**: MEDIUM — contract language is ambiguous; current behavior is silent and incorrect.

**Date raised**: 2026-03-29 (adversarial audit sprint)

**Current behavior** (`src/assay/comparability/engine.py:149-156`): Fields marked `requirement=OPTIONAL` (or `DERIVED`) skip all evaluation logic entirely, including severity checks. A field declared `OPTIONAL` with `severity=INVALIDATING` silently produces no verdict effect, even when both bundles provide the field with different values.

**The problem**: `OPTIONAL + INVALIDATING` is semantically contradictory. "INVALIDATING" means "a mismatch here makes the comparison inadmissible." "OPTIONAL" means "skip checks when absent." These cannot coexist as a meaningful contract statement. A contract author who writes this combination is either expressing:

1. "If the field is missing from either bundle, don't penalize. But if both declare it and they differ, that's an invalidating mismatch." (The "binding when present on both sides" interpretation)
2. Or they made an error — they intended REQUIRED.

The current code silently implements a third interpretation: "ignore this field entirely, always." This is the wrong answer in both cases.

**Options**:

1. **Reject at load time.** `OPTIONAL + INVALIDATING` is a validation error in `load_contract()`. The contract is invalid. Contract authors must choose: `REQUIRED + INVALIDATING` (always enforced) or `OPTIONAL + DEGRADING` or lower (only checked when present). This is the cleanest contract language — no silent behavior.
2. **Define as "binding when present on both sides."** OPTIONAL fields skip when absent from either bundle. When present in both, apply severity normally. This is more expressive but adds a third evaluation path and makes contracts harder to reason about.

**Doctrine decision**: **Option 1.** Reject at load time.

Rationale: The comparability contract is a trust artifact. Ambiguous combinations in trust artifacts are bugs, not features. The contract language should be unambiguous: if a mismatch is invalidating, the field must be required. If it can be absent, the mismatch cannot be invalidating. Forcing contract authors to choose eliminates the silent-ignore failure mode without adding evaluation complexity.

**Implementation**: Add validation in `contract.py` `load_contract()`: if any `ParityField` has `severity=INVALIDATING` and `requirement=OPTIONAL` (or `DERIVED`), raise `ContractValidationError` with a message naming the field and the contradictory combination.

**Test to add**: `test_optional_invalidating_rejected_at_load()` in `tests/assay/test_comparability.py`.

**Not yet implemented** — awaiting this doctrine record before code change.

---

## OCD-12: Unsigned Lockfile (Trust Root Without Cryptographic Protection)

**Blocker level**: LOW (design track) — not a correctness bug, but a trust boundary gap.

**Date raised**: 2026-03-29 (adversarial audit sprint)

**Current behavior**: `assay.lock` contains the signer fingerprint allowlist and verification thresholds that govern what evidence is accepted. The lockfile itself has no cryptographic signature. Any actor with write access to the repository can modify the allowlist and commit the change without detection.

**The problem**: The lockfile is the root of trust for `assay verify-pack --lock`. A root of trust that is itself unprotected is a contradiction. The gap: a compromised or coerced actor can add their own key fingerprint to the allowlist, commit it to the repo, and all packs signed with that key will pass verification. There is no out-of-band evidence that the lockfile was modified.

**Mitigating factors**:
- Git commit history records lockfile changes (but git history is rewritable without signed commits).
- CODEOWNERS + branch protection rules can require human review of lockfile changes (process control, not cryptographic).
- The lockfile's own content is hashed when loaded; a verifier can detect mid-session tampering but not pre-session substitution.

**Options**:

1. **Process control only.** Add CODEOWNERS rule requiring a designated reviewer's approval on any PR touching `assay.lock`. No code change. Cheapest. Relies on platform (GitHub PR review) rather than cryptography.
2. **Receipt chain embedding (intermediate).** When a pack is verified against a lockfile, embed the lockfile's SHA-256 hash in the `verify_report.json`. Future verification of the same pack can confirm the lockfile hash hasn't drifted since the pack was verified. Creates a chain-of-custody record without requiring a signing key for the lockfile itself. Does not protect against a fresh substitution before any pack exists.
3. **CI-held key signing.** During `assay lock update`, require the lockfile to be signed by a CI-held key (separate from operator keys). The signature is stored alongside the lockfile. `verify-pack --lock` checks the lockfile signature before trusting the allowlist. Requires key ceremony for the CI-held key and secret provisioning (`ci-org-trust-gate.yml` infrastructure).
4. **Out-of-band commitment.** After each lockfile update, publish the lockfile hash to an append-only log (e.g., Rekor). Verifiers can confirm the lockfile matches its transparency log entry.

**Recommended path**: Option 1 immediately (zero cost, reasonable process control). Option 3 when the `ci-org-trust-gate.yml` key ceremony is complete (the infrastructure already exists — it just requires provisioning). Option 2 as a useful intermediate artifact regardless.

**Not a casual inline fix**: The lockfile is a root-of-trust artifact. Changes to how it is protected must go through the trust-tier design path, not be made as incidental code edits. This record is the design gate before any implementation.

**Dependency**: Option 3 depends on the CI org trust gate key ceremony (tracked separately in the workflow file comment). Do not implement Option 3 before the ceremony is complete.

---

## OCD-13: ConstitutionalDiff Output is Unsigned

**Blocker level**: MEDIUM — provenance gap, not a code bug.

**Date raised**: 2026-03-29 (five-agent synthesis)

**Current behavior**: `assay compare` writes a plain JSON file (`ConstitutionalDiff`). It has no signature, no binding to any signing key, and no chain to the proof pack. Anyone with file access can change the verdict field.

**The problem**: The proof pack path is signed. The comparability path is not. If a reviewer receives a ConstitutionalDiff alongside a proof pack, they have no way to verify the diff was produced by the same operator, against the same data, using the same contract. This is either a security gap or a positioning gap — it cannot be neither.

**Options**:

1. **Sign the diff.** Use the existing Ed25519 infrastructure to sign the ConstitutionalDiff JSON when it is produced. The diff becomes a receipt-grade artifact. Adds ~20 lines to the compare command.
2. **Document it as non-evidence.** Add a clear statement everywhere: "ConstitutionalDiff is a utility output, not a tamper-evident artifact. It is not signed and should not be presented as proof." No code change.
3. **Bind without signing.** Embed the diff's content hash in the next emitted proof pack receipt. Creates a chain-of-custody record without requiring a standalone signature.

**Recommended**: Option 1 if the diff is part of buyer-facing deliverables. Option 2 if it is only used internally. Do not leave it unnamed.

**Not yet decided.**

---

## OCD-14: Contract Identity Not Bound to Evaluation Output

**Blocker level**: LOW — provenance gap.

**Date raised**: 2026-03-29 (five-agent synthesis)

**Current behavior**: `ConstitutionalDiff` includes `contract_hash` (the hash of the contract's parity fields). This is computed by `ComparabilityContract.content_hash()` and embedded in the output. However, it is not cryptographically bound — a user could run with contract A, then present the output as if it were governed by contract B.

**Existing mitigation**: The `contract_hash` field is present in the output, which enables a reviewer to recompute and compare. But there is no signed binding.

**Recommended**: If OCD-13 is resolved by signing the diff (Option 1), the contract_hash is automatically covered by the signature. No additional mechanism needed. If OCD-13 uses Option 2, then contract binding requires a separate receipt linking pack → contract → diff.

**Depends on**: OCD-13 decision.

**Not yet decided.**
