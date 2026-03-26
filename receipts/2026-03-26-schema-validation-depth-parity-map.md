# Follow-Up Map: Schema-Validation-Depth Parity

**Date:** 2026-03-26
**Status:** Mapping only, no code changes
**Scope:** Python `assay` verifier vs TypeScript `assay-verify-ts` verifier

## Question

Where does Python enforce manifest and attestation structure more deeply than
TypeScript, and which side should be treated as canonical?

## Current Implementations

### Python

Python verifies schema first in `integrity.py` via
`validate_signed_manifest(manifest)`, which delegates to
`manifest_schema.validate_manifest()` and the bundled Draft 2020-12 JSON Schema.
If schema validation fails, verification stops immediately with
`E_MANIFEST_TAMPER`.

Evidence:

- `src/assay/integrity.py` — `validate_schema` stage before all other checks
- `src/assay/pack_verify_policy.py` — fail-closed wrapper
- `src/assay/manifest_schema.py` — Draft202012Validator over bundled schemas
- `src/assay/schemas/pack_manifest.schema.json`
- `src/assay/schemas/attestation.schema.json`

### TypeScript

TypeScript currently has a shallow `validate_shape` stage. It checks only that
`manifest.files` and `manifest.expected_files` are arrays, then continues into
path, file-hash, receipt, attestation, signature, and D12 checks. It does not
run the Python manifest schema or an equivalent structural validator.

Evidence:

- `../assay-verify-ts/src/verify-core.ts` — `validate_shape` only checks array-ness

## Divergence Classes

### 1. Required top-level manifest fields

Python rejects manifests missing required fields such as:

- `pack_id`
- `pack_version`
- `manifest_version`
- `hash_alg`
- `attestation_sha256`
- `suite_hash`
- `claim_set_id`
- `claim_set_hash`
- `signer_id`
- `signer_pubkey`
- `signer_pubkey_sha256`
- `signature_alg`
- `signature_scope`
- `signature`
- `pack_root_sha256`

TypeScript does not reject these at the shape stage. It may later fail for a
subset of them if a downstream check happens to use the field, but that is not
equivalent to Python's fail-closed schema gate.

### 2. Additional-properties rejection

Python rejects unknown top-level manifest fields and unknown attestation fields
because both schemas set `additionalProperties: false`.

TypeScript currently ignores unknown fields entirely.

### 3. Nested field typing and pattern constraints

Python enforces nested constraints such as:

- `files[*].sha256` must be lowercase 64-char hex
- `files[*].bytes` must be integer `>= 0`
- `files[*]` objects must contain `path`, `sha256`, and `bytes`
- `expected_files` items must be non-empty strings
- `hash_alg` must be `"sha256"`
- `signature_alg` must be `"ed25519"`
- `signature_scope` must be one of the allowed descriptive strings
- attestation enums and required fields must be valid

TypeScript does not enforce these structurally. It uses some values
operationally, but malformed values can reach later verification stages.

### 4. Attestation schema depth

Python validates the embedded `attestation` object through `$ref` to
`attestation.schema.json`.

TypeScript only verifies `attestation_sha256` against canonicalized attestation
bytes when `attestation_sha256` is present, plus the D12 equality check. It does
not validate required attestation fields or attestation enums.

### 5. Failure mode shape

Python's failure mode is:

- stage: `validate_schema`
- result: immediate fail-closed return
- error class: `E_MANIFEST_TAMPER`
- message includes schema-specific field path

TypeScript's failure mode is currently one of:

- no early structural error at all
- later failure in a different stage for a different reason
- successful verification if malformed-but-unused fields are present

## Canonicality Read

For manifest and attestation structure, Python is currently canonical. The
contracted behavior is not just "arrays must exist"; it is "manifest must pass
runtime schema validation before any other verification logic."

This is supported by:

- code path order in `integrity.py`
- fail-closed wrapper in `pack_verify_policy.py`
- explicit schema tests in Assay's Python suite

## Decision To Make

The follow-up slice should answer one question explicitly:

Should TypeScript adopt equivalent manifest/attestation schema enforcement, or
should the contract be weakened to the current TS shallow-shape model?

Current evidence favors adopting Python-equivalent enforcement in TypeScript.

## Resolution

- This note records the pre-fix analysis.
- TS now enforces the canonical schema gate in `validate_schema`.
- The earlier late-failure `verify_signature` / `E_PACK_SIG_INVALID` state is historical.
- Keep this file as the rationale for why the schema gate was added, not as a description of current verifier behavior.

## Parity Acceptance Target

TypeScript should match Python's effective verifier contract on malformed
manifest and attestation structure:

- fail before trust-relevant verification steps when manifest or attestation
  schema is invalid
- surface `E_MANIFEST_TAMPER` as the effective error class where feasible
- avoid silently tolerating malformed-but-unused fields if Python rejects them
  at the schema gate
- preserve a dedicated early structural stage rather than letting malformed
  schema bleed into later hash, receipt, or signature stages

## Proposed Next Step

Do not patch immediately. First add parity fixtures that isolate these cases:

1. Missing required top-level field
2. Unknown extra top-level field
3. Bad `hash_alg`
4. Bad `signature_alg`
5. Malformed nested `files[*]`
6. Attestation missing required field
7. Attestation enum violation

Then decide whether TS should:

- embed a schema validator, or
- hand-implement the minimum equivalent invariants

## Commit Boundary Note

This is a new chapter after the verifier trust-boundary and empty-pack parity
work. It should not be folded into the previous fix commit.
