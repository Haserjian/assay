# Ship Receipt: Schema Gate Implementation

**Date:** 2026-03-26
**Status:** Working-tree implementation receipt; behavior changed in TS only

## What Changed

- Added AJV-backed manifest and attestation schema validation to the TS verifier.
- Inserted a fail-closed `validate_schema` stage before `validate_shape` and all downstream verification stages.
- Kept failure mapping on the structural gate as `E_MANIFEST_TAMPER`.
- Updated the schema-depth parity tests so the 7 specimens assert the canonical structural boundary.
- Reworked auxiliary tests to stay schema-valid where they are meant to exercise later stages.
- Rebuilt the browser bundle to keep the tracked artifact in sync with the verifier source.

## Files Touched

- `/Users/timmybhaserjian/assay-verify-ts/src/verify-core.ts`
- `/Users/timmybhaserjian/assay-verify-ts/src/schema-definitions.ts`
- `/Users/timmybhaserjian/assay-verify-ts/src/schema-validation.ts`
- `/Users/timmybhaserjian/assay-verify-ts/src/verify.test.ts`
- `/Users/timmybhaserjian/assay-verify-ts/package.json`
- `/Users/timmybhaserjian/assay-verify-ts/package-lock.json`
- `/Users/timmybhaserjian/assay-verify-ts/browser/assay-verify.js`

## Validation

```bash
cd /Users/timmybhaserjian/assay-verify-ts && npm run build && node --test dist/verify.test.js
cd /Users/timmybhaserjian/assay && uv run --extra dev pytest -q tests/contracts/test_schema_validation_depth.py
```

## Outcome

- TS now rejects schema-depth malformed specimens at the same structural boundary as Python.
- The prior `verify_signature` / `E_PACK_SIG_INVALID` late-failure state is historical.
- The schema-depth chapter is now implemented rather than just mapped.
