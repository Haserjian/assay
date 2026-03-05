# VendorQ Verifier Spec (v1)

VendorQ verifier is fail-closed. It validates answer payloads against cryptographic evidence packs and optional `vendorq.lock`.

## Rule Codes

- `VQ001_MISSING_CITATION`: factual `ANSWERED|PARTIAL` claim has no evidence refs.
- `VQ002_EVIDENCE_REF_NOT_FOUND`: evidence ref cannot resolve to pack/receipt/pointer.
- `VQ003_PACK_HASH_MISMATCH`: lock mismatch on pack digests/hash bindings.
- `VQ004_NUMERIC_CLAIM_NO_NUMERIC_SOURCE`: metric claim has no numeric evidence path.
- `VQ005_PROHIBITED_COMMITMENT`: commitment language contains prohibited terms.
- `VQ006_STALE_EVIDENCE`: evidence older than freshness policy window.
- `VQ007_SCHEMA_INVALID`: payload fails VendorQ schema validation.
- `VQ008_ANSWER_STATUS_INVALID_FOR_CONTENT`: status/content contradiction.
- `VQ009_YES_WITHOUT_SUPPORT`: `answer_bool=true` lacks affirmative evidence.
- `VQ010_CLAIM_TYPE_POLICY_VIOLATION`: claim type disallowed by policy profile.

## Strict Mode

`--strict` upgrades stale evidence from warning to error.

## Exit Contract

- `0`: verification pass
- `2`: verification failed
- `3`: bad input (missing files / invalid CLI paths)

## Evidence Navigation Chain

Verifier emits deterministic chain entries:

- `question_id`
- `answer_id`
- `evidence_ref`
- `receipt_pointer`
- `pack_digest`
- `verify_command`

This enables replay-grade auditor workflows.

## Scope Clarification

Verifier output attests that packet claims are traceable to cited evidence in the provided proof packs.
It does **not** assert legal/commercial compliance by itself.

## Multi-Pack Note (v1)

`vendorq compile` currently uses a primary-pack heuristic for default answer drafting in non-metric categories.
`vendorq verify` resolves and validates all explicitly referenced packs.
