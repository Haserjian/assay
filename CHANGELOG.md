# Changelog

All notable changes to Assay are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.19.0] - 2026-03-25

### Deprecated

- **`adapt_ccio_refusalstone_to_denial_record`** deprecated in favor of
  `adapt_guardian_refusal_to_denial_record`. The old name leaked a private
  repo's vocabulary into the public PyPI API surface. It remains available
  as a compatibility alias in 1.19.0 but emits a `DeprecationWarning`.
  Migration is a rename-only change.

### Internal API changes

These changes affect `assay._receipts.canonicalize`, a private submodule
(underscore-prefixed). These functions were not in top-level `assay.__all__`;
any downstream use was unsupported internal imports.

- **`to_jcs_bytes()` removed.** This function conflated Layer 1 (JCS
  canonicalization) with Layer 2 (receipt projection / signature stripping).
  Replaced by the explicit two-step pipeline:
  `prepare_receipt_for_hashing()` then `jcs_canonicalize()`.
- **`compute_payload_hash()` return format changed.** Now returns raw hex
  (e.g., `a1b2c3...`) instead of prefixed format (`sha256:a1b2c3...`).
  Resolves OCD-1 (Open Contract Decision #1). Callers that parsed the
  `sha256:` prefix must update.
- **`compute_payload_hash_hex()` is unaffected** — retained as a trivial
  alias. Both functions now return identical raw hex output. Callers using
  `compute_payload_hash_hex()` require no changes.

### Added

- **`prepare_receipt_for_hashing()`** — explicit Layer 2 receipt projection.
  Strips root-level signature fields (v0 exclusion set: `anchor`,
  `cose_signature`, `receipt_hash`, `signature`, `signatures`) and returns
  a plain dict ready for JCS canonicalization.
- **First conformance corpus** (developer/verifier quality infrastructure):
  - 16 JCS canonicalization vectors (Layer 1, RFC 8785)
  - 4 golden + 2 adversarial Merkle tree vectors (Layer 1)
  - 3 golden + 2 assertion receipt projection vectors (Layer 2)
  - 1 golden signed pack specimen (full 11-step verification pipeline)
  - 1 adversarial tampered pack specimen (`E_MANIFEST_TAMPER`)
  - 46 conformance tests exercising all vectors
- **Pack contract documentation** — `PACK_CONTRACT.md` (12 sections),
  `VERIFICATION_LAYERS.md`, `BOUNDARY_MAP.md`, `EXTRACTION_PLAN.md`,
  `TEST_VECTOR_SPEC.md`, `OPEN_CONTRACT_DECISIONS.md`.

### Fixed

- **`head_hash` silent skip eliminated.** Previously, if `head_hash` was
  absent from the manifest, the verifier silently skipped the check. Now
  raises `E_MANIFEST_TAMPER` with an explicit error message.
- **`signature_scope` field corrected** in newly built packs. Schema
  accepts both old and new values for backward compatibility.
- **`signature_alg` schema tightened** to `enum: ["ed25519"]`. Previously
  accepted any string.

### Compatibility / Migration Notes

**If you imported `to_jcs_bytes` from `assay._receipts.canonicalize`:**

```python
# Before (1.18.0)
from assay._receipts.canonicalize import to_jcs_bytes
canonical_bytes = to_jcs_bytes(receipt)

# After (1.19.0)
from assay._receipts.canonicalize import prepare_receipt_for_hashing
from assay._receipts.jcs import canonicalize as jcs_canonicalize
prepared = prepare_receipt_for_hashing(receipt)
canonical_bytes = jcs_canonicalize(prepared)
```

**If you parsed the `sha256:` prefix from `compute_payload_hash`:**

```python
# Before (1.18.0)
hash_str = compute_payload_hash(obj)  # "sha256:a1b2c3..."
raw_hex = hash_str.split(":", 1)[1]

# After (1.19.0)
raw_hex = compute_payload_hash(obj)   # "a1b2c3..."
```

`compute_payload_hash_hex()` continues to work unchanged.

**Existing signed packs are not affected.** The verification pipeline
accepts both old and new `signature_scope` values. Packs built with
1.18.0 verify correctly under 1.19.0.

## [1.18.0] - 2026-03

### Added
- Episode SDK: runtime evidence bridge, settlement gate, closed-episode immutability, and orphan detection
- Epistemic kernel: checkpoint lifecycle, contradiction runtime emission, and protocol claim/contradiction invariant registry with verifier
- Proof posture triad: falsifier tracking, residual risk, and proof debt assessment
- Trust infrastructure: signer registry, acceptance matrix, optional trust evaluation for proof packs, and `--enforce-trust-gate` for verify-pack
- Decision receipt trust evaluation with verification and reviewer rendering
- CI-org signer trust gate bootstrap for organizational CI pipelines
- Constitutional circulation loop with posture claim eligibility
- `assay doctor` contradiction closure check (Stage 3a) and governance anchor validation (Stage 3b)
- Tier monotonicity assertion for decision receipts
- Authority snapshot seam in ADC emission
- Evidence readiness documentation and crawlability infrastructure
- Canonical Evidence Semantics Matrix

### Fixed
- Witness lifecycle: ADC now updated to witnessed state after `assay witness` runs
- Fingerprint-primary identity binding enforcement in trust evaluation
- Trust authorization gaps closed in signer verification
- Trust policy load errors surfaced instead of swallowed
- Path containment enforced for manifest-listed files in verifier
- Atomic pack publication via staging directory prevents partial writes
- Keystore and verifier IO hardening (symlink traversal, permission checks)
- FalsifierSpec and TIER_CAP_TABLE restoration for Python 3.9 compatibility
- Test stability: frozen datetime tz-awareness and policy_loop time-freeze

### Changed
- Receipt schema upgraded to v0.2.0 with `GovernanceEmissionError` enforcement
- Signer ID validation stricter: dot-prefixed IDs now rejected in local keystore

## [1.17.0] - 2026-03

### Added
- Decision Receipt v0.1.0 schema, validator, and CLI (`assay decision-receipt validate`)
- CLI validator and buyer-facing example for Decision Receipts
- Adversarial tests: missing-file and base64 signature mutation
- Release-truth CI workflow (Python 3.9-3.12, ubuntu + macOS)

### Fixed
- Python 3.9 compatibility: future annotations in commands.py
- CI YAML indentation bug in release-truth workflow
- Regulatory wording on landing page (Article 12 characterization)
- Final CTA on landing page aligned with golden path (`assay try`)

### Changed
- README top block rewritten: headline, Run/Prove/Promote, exit codes, scan stat
- Landing page hero: eyebrow/headline/consequence hierarchy
- Browser verifier version updated to v1.17.0
- Scan study stat made precise to sample size

## [1.16.0] - 2026-02

### Added
- Passport lifecycle: mint, sign, verify, render, challenge, supersede, diff, x-ray
- MCP Notary Proxy with policy engine (audit/enforce modes)
- Golden path: `assay try` as 15-second first-contact demo
- CLI authority demotion: 8 visible commands, 31+ hidden
- VendorQ workflow: ingest, compile, verify, export, lock
- Reviewer packet renderer with gallery snapshot tests
- Evidence Readiness Score (`assay score`)
- CI gate generation (`assay ci init github`)

### Fixed
- Windows compatibility for `assay try` and proof pack byte handling
- Demo-challenge directory handling for SHA256SUMS

## [1.15.0] - 2026-01

### Added
- Initial PyPI release (`pip install assay-ai`)
- Core evidence compiler: scan, run, verify-pack
- Ed25519 signing with local keystore
- Five integrations: OpenAI, Anthropic, Google Gemini, LiteLLM, LangChain
- Completeness contracts and coverage checking
- Proof pack format: receipt_pack.jsonl, pack_manifest.json, pack_signature.sig
