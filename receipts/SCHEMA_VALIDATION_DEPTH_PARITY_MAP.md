Status: decision artifact only; no behavior change until a canonical outcome is recorded and corresponding tests/corpus are added.

trust-boundary repair is closed; next is a non-P0 schema/parity decision pass

Scope: Python `src/assay/manifest_schema.py` + `src/assay/integrity.py` schema gate vs TS `assay-verify-ts/src/verify-core.ts` structural handling.

Execution basis:
- Python schema results were executed by loading `src/assay/manifest_schema.py` directly in a throwaway venv and calling `validate_manifest(...)`.
- TS results were executed by `verifyPack()` from `assay-verify-ts/dist/verify.js` against a synthetic signed pack harness captured in `/tmp/schema-depth-report.json`.
- The `integrity.py` wrapper was inspected and would surface Python schema failures as `validate_schema` / `E_MANIFEST_TAMPER`, but the direct schema module was the executed Python path here.

Governing rules for this chapter:
- No patching until each specimen has a named divergence, a contract-vs-drift classification, and a proposed canonical outcome.
- Keep specimens varied across failure shapes.
- Use only these classifications: `contract`, `implementation drift`, `missing corpus coverage`, `intentional profile difference`.
- Use `intentional profile difference` only if truly necessary.
- Scope only manifest/attestation structure enforcement depth.
- Keep this separate from ADC trust repair, replay/witness paths, and historical cleanup.

## SVD-001 — missing top-level required field

### Failure shape
missing top-level required field

### Minimal JSON
```json
{
  "hash_alg": "__omitted__"
}
```

Python result
- pass/fail: fail
- stage/code: `validate_manifest` (surface maps to `validate_schema`) / `E_MANIFEST_TAMPER` in the wrapper
- note: `validate_manifest` returned `(root): 'hash_alg' is a required property`

TS result
- pass/fail: pass
- stage/code: `verifyPack` / no error code
- note: `validate_shape` only checked `files` and `expected_files` array-ness; the signed pack otherwise passed all stages

Divergence summary
- Python rejects the missing top-level schema field; TS accepts the same malformed manifest when the pack is otherwise signed and hash-consistent.

Classification
- implementation drift

Proposed canonical outcome
- Fail closed at the schema gate before path, hash, receipt, attestation, or signature work begins.

Tests / corpus needed
- Add a shared schema-depth fixture for a signed pack with `hash_alg` omitted and assert Python schema rejection plus TS fail-closed rejection once TS grows a real schema gate.

## SVD-002 — missing nested required field

### Failure shape
missing nested required field

### Minimal JSON
```json
{
  "attestation": {
    "run_id": "__omitted__"
  }
}
```

Python result
- pass/fail: fail
- stage/code: `validate_manifest` (surface maps to `validate_schema`) / `E_MANIFEST_TAMPER` in the wrapper
- note: `validate_manifest` returned `attestation: 'run_id' is a required property`

TS result
- pass/fail: pass
- stage/code: `verifyPack` / no error code
- note: TS does not structurally validate nested attestation required fields; the pack passed once attestation hash and signature were coherent

Divergence summary
- Python enforces nested attestation shape through JSON Schema; TS currently treats the attestation as opaque data so long as downstream hash/signature checks still line up.

Classification
- implementation drift

Proposed canonical outcome
- Reject missing nested attestation fields at the schema gate and stop before semantic verification.

Tests / corpus needed
- Add a fixture for `attestation.run_id` missing, with expected Python schema error and TS structural rejection once parity exists.

## SVD-003 — wrong scalar type in nested object

### Failure shape
wrong scalar type in nested object

### Minimal JSON
```json
{
  "attestation": {
    "n_receipts": "1"
  }
}
```

Python result
- pass/fail: fail
- stage/code: `validate_manifest` (surface maps to `validate_schema`) / `E_MANIFEST_TAMPER` in the wrapper
- note: `validate_manifest` returned `attestation.n_receipts: '1' is not of type 'integer'`

TS result
- pass/fail: pass
- stage/code: `verifyPack` / no error code
- note: TS uses `n_receipts` operationally only indirectly; the wrong scalar type did not trip a structural gate

Divergence summary
- Python rejects the wrong scalar type in a nested attestation field; TS accepts it because there is no nested type enforcement in the current verifier path.

Classification
- implementation drift

Proposed canonical outcome
- Enforce nested scalar types structurally, not by later operational coincidence.

Tests / corpus needed
- Add a fixture for `attestation.n_receipts` as a string and verify the schema gate rejects it before later stages.

## SVD-004 — extra unknown field at depth

### Failure shape
extra/unknown field at depth

### Minimal JSON
```json
{
  "attestation": {
    "experimental_depth_note": "not-normative"
  }
}
```

Python result
- pass/fail: fail
- stage/code: `validate_manifest` (surface maps to `validate_schema`) / `E_MANIFEST_TAMPER` in the wrapper
- note: `validate_manifest` returned `attestation: Additional properties are not allowed ('experimental_depth_note' was unexpected)`

TS result
- pass/fail: pass
- stage/code: `verifyPack` / no error code
- note: TS ignores unknown attestation members once the pack is otherwise coherent

Divergence summary
- Python rejects unknown nested fields because the schema sets `additionalProperties: false`; TS currently tolerates them.

Classification
- implementation drift

Proposed canonical outcome
- Reject unknown nested fields at the same structural depth as required fields, so the verifier does not silently normalize or ignore unexpected attestation payload.

Tests / corpus needed
- Add a corpus vector for an unknown attestation field and assert both implementations fail structurally rather than proceeding to semantic checks.

## SVD-005 — malformed nested array/object member

### Failure shape
malformed nested array/object member

### Minimal JSON
```json
{
  "files": [
    {
      "path": "receipt_pack.jsonl",
      "sha256": "valid-hex",
      "bytes": "not-an-integer"
    }
  ]
}
```

Python result
- pass/fail: fail
- stage/code: `validate_manifest` (surface maps to `validate_schema`) / `E_MANIFEST_TAMPER` in the wrapper
- note: `validate_manifest` returned `files.0.bytes: 'not-an-integer' is not of type 'integer'`

TS result
- pass/fail: pass
- stage/code: `verifyPack` / no error code
- note: the current TS path only uses `bytes` as a non-fatal size comparison hint, so the malformed type does not stop verification

Divergence summary
- Python enforces nested object-member typing inside `files[]`; TS currently allows a malformed member to survive as a warning-only condition.

Classification
- implementation drift

Proposed canonical outcome
- Make malformed `files[]` members fail closed at schema depth rather than degrading into a warning path.

Tests / corpus needed
- Add a `files[0].bytes` type-error fixture and a corpus assertion that this is rejected structurally, not downgraded to a warning.

## Decision

- The contract evidence is already strong: Python schema validation is the intended structural gate, and `verify-core.ts` only has a shallow array-shape check.
- The five initial specimens are fully code-grounded at the core/schema level:
  - Python was executed through the actual schema module.
  - TS was executed through the actual `verifyPack()` core.
- The only nuance is that the Python `stage/code` pair is inferred from the `integrity.py` wrapper, because the direct schema module returns schema strings rather than structured verifier errors.
- No intentional profile difference is justified here.
- The canonical outcome is to bring TS up to the Python/contract depth, not to weaken Python to the current TS surface.

## TS Reconciliation Note

Pre-fix TS behavior was specimen-dependent. On the observed harness, the seven
schema-depth specimens bypassed the missing `validate_schema` gate and failed
later at different stages, including `validate_file_hashes`,
`validate_receipts`, `validate_attestation`, and `verify_signature`.

That late failure pattern was still a mismatch, not parity, because the
structural rejection happened at the wrong boundary.

## Post-Implementation Resolution

- The `verify_signature` / `E_PACK_SIG_INVALID` state above was the pre-fix TS baseline, not the current verifier behavior.
- TS now enforces a fail-closed `validate_schema` stage before `validate_shape` and all downstream verification logic.
- The seven schema-depth specimens now fail at `validate_schema` with `E_MANIFEST_TAMPER`, matching the canonical Python structural boundary.
- Keep the earlier specimen table as historical evidence for why the schema gate was added.
