# Schema Gate Implementation Choice

**Status:** decision artifact only; no behavior change until the chosen TS structural gate is implemented and covered by parity tests/corpus.

**Chapter:** schema-validation depth parity follow-up

## Decision Question

TypeScript currently rejects the schema-depth specimens too late, at
`verify_signature` with `E_PACK_SIG_INVALID`, while Python rejects them at the
structural schema gate with `validate_schema` / `E_MANIFEST_TAMPER`.

The implementation choice is whether TS should:

1. adopt schema-backed manifest/attestation validation, or
2. hand-roll only the minimum equivalent structural invariants.

## Inspected Code Paths

- `/Users/timmybhaserjian/assay/src/assay/manifest_schema.py`
- `/Users/timmybhaserjian/assay/src/assay/integrity.py`
- `/Users/timmybhaserjian/assay/src/assay/pack_verify_policy.py`
- `/Users/timmybhaserjian/assay/src/assay/schemas/pack_manifest.schema.json`
- `/Users/timmybhaserjian/assay/src/assay/schemas/attestation.schema.json`
- `/Users/timmybhaserjian/assay-verify-ts/src/verify-core.ts`
- `/Users/timmybhaserjian/assay-verify-ts/src/verify.test.ts`
- `/Users/timmybhaserjian/assay/receipts/SCHEMA_VALIDATION_DEPTH_PARITY_MAP.md`

## Candidate A: Schema-Backed Validation

Use a real JSON Schema validator in TS and apply it before path, hash, receipt,
attestation, or signature work.

Pros:

- Matches the Python contract surface directly.
- Covers the full depth of current divergence classes:
  - missing required fields
  - unknown extra fields
  - nested scalar type constraints
  - nested object member constraints
  - attestation shape and enum constraints
- Lowers long-term drift risk because the validator expresses the contract once.

Cons:

- Introduces a dependency or validator integration cost in TS.
- May require care around bundle/runtime shape.

## Candidate B: Hand-Rolled Equivalent Gate

Implement only the current structural invariants directly in TS.

Pros:

- Can be smaller if runtime constraints make schema validation awkward.
- Can be tailored to the exact manifest/attestation subset needed today.

Cons:

- Higher drift risk.
- Easy to miss depth-specific rules already enforced by Python schemas.
- Harder to prove equivalence as the contract grows.

## Required Invariants

Any TS solution must fail closed at the same structural boundary as Python for
the current schema-depth corpus:

- missing required top-level manifest fields
- missing required nested attestation fields
- wrong scalar types in nested objects
- unknown extra fields at depth
- malformed nested array/object members
- attestation enum / shape violations

## Constraint Check

No concrete runtime or bundle constraint has yet been established that would
disqualify schema-backed validation.

If a later constraint appears, it must be explicit and measurable:

- browser/runtime compatibility
- unacceptable bundle growth
- inability to use the validator in the current TS execution model

## Decision

Prefer **schema-backed validation** in TS.

Only fall back to a hand-rolled equivalent gate if a concrete runtime or bundle
constraint makes schema validation materially impractical.

## Why This Is Canonical

- Python already expresses the contract as real schemas and enforces them
  before any later verification stage.
- The current TS behavior is not merely shallow; it is structurally late.
- The current corpus shows a uniform mismatch, not a subtle per-specimen edge.
- A schema-backed gate is the least dangerous way to restore structural parity.

## Next Required Evidence

Before patching TS behavior:

1. keep the shared schema-depth corpus fixed
2. record the selected TS gate shape
3. add executable parity tests that assert fail stage and effective error class
4. implement the chosen gate

## Remaining Uncertainty

The only unresolved question is implementation shape, not canonical boundary:

- schema-backed validator, or
- narrowly equivalent hand-rolled structural gate

The evidence presently favors schema-backed validation.
