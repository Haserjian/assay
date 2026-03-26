# OCD-9: Direct vs Indirect Verifier Obligations

**Status**: partially clarified; no verifier behavior changed.

## Question

When the Proof Pack verifier claims it "verifies" a property, is that property:

1. directly checked by the verifier itself, or
2. only indirectly guaranteed because it is part of already-verified file bytes,
   hashes, signatures, or other enclosing artifacts?

The contract needs a stable distinction so second implementations do not
overclaim what the verifier actually proves.

## Current Ambiguity

The contract already says some checks are indirect, but the doctrine is not
stated as a general rule.

Current examples of ambiguity:

- `PACK_CONTRACT.md` says line canonicality is enforced indirectly via file hash
  integrity, but it also leaves room for optional direct checking.
- `PACK_CONTRACT.md` lists stage names and verification steps, but does not
  label each obligation as "direct" or "indirect."
- `TEST_VECTOR_SPEC.md` blocks `PK-A11` and `PK-A13b` pending OCD-9, which
  means the vector corpus still needs a contract-level decision on whether JSONL
  canonicality is a direct verifier obligation or only an indirect guarantee.
- `ATTESTATION_SEMANTICS.md` separates mechanical integrity from semantic
  evaluation, but does not define the direct/indirect verifier taxonomy.

## Evidence Inspected

- `/Users/timmybhaserjian/assay/docs/contracts/PACK_CONTRACT.md`
- `/Users/timmybhaserjian/assay/docs/contracts/ATTESTATION_SEMANTICS.md`
- `/Users/timmybhaserjian/assay/docs/contracts/TEST_VECTOR_SPEC.md`
- `/Users/timmybhaserjian/assay/src/assay/integrity.py`
- `/Users/timmybhaserjian/assay-verify-ts/src/verify-core.ts`
- `/Users/timmybhaserjian/assay-verify-ts/src/verify.test.ts`
- `/Users/timmybhaserjian/assay/receipts/SCHEMA_VALIDATION_DEPTH_PARITY_MAP.md`

## Direct Obligations

These are properties the verifier explicitly checks by recomputing, parsing, or
comparing the artifact it receives:

- manifest schema validity
- attestation schema validity
- path containment
- per-file SHA-256 matches against manifest declarations
- receipt count matches `receipt_count_expected`
- duplicate receipt ID detection
- recomputed head hash matches the attestation claim
- `SHA256(JCS(attestation))` matches `attestation_sha256`
- detached signature parity and Ed25519 signature verification
- `signer_pubkey_sha256` matches the decoded public key bytes
- D12 invariant: `pack_root_sha256 == attestation_sha256`

These are "direct" because the verifier itself performs the check and can
report an explicit failure stage and error code.

## Indirect Obligations

These are properties that follow from verified artifacts or builder discipline,
but are not separately asserted as their own verifier step:

- JSONL line canonicality for `receipt_pack.jsonl`
- receipt ordering as serialized in the JSONL file
- blank-line discipline in JSONL parsing
- any format property that is only implied by whole-file hash integrity

These are "indirect" because the verifier may protect them by hashing or
parsing the enclosing artifact, but it does not independently inspect every
sub-property unless the contract says so.

## Proposed Canonical Wording

Use a three-part rule in the contract:

1. A property is **directly verified** when the verifier explicitly checks it
   from the raw artifact it receives and can attach a dedicated failure stage or
   error.
2. A property is **indirectly guaranteed** when it is protected only because an
   enclosing artifact was directly verified, and the verifier does not separately
   inspect the sub-property.
3. A property is **builder-only** when it is required of pack construction but
   is not currently enforced by the verifier itself.

Applied to the current pack verifier:

- file hashes, signature checks, schema checks, attestation hash checks, and D12
  are direct verifier obligations
- JSONL canonicality is currently an indirect guarantee, not a direct verifier
  obligation
- future direct canonicality checks would need an explicit contract update and a
  dedicated stage or error path

## Consequences for Tests / Parity / Docs

- Parity vectors must say whether they are exercising a direct or indirect
  obligation.
- `PK-A11` and `PK-A13b` remain the right blocked vectors until the contract
  decides whether JSONL canonicality should stay indirect or be promoted to a
  direct verifier obligation.
- Stage names should not be used to imply verification of a property that is
  only indirectly guaranteed.
- Documentation should avoid saying the verifier "checks" a property directly if
  it only gains that property through file-hash integrity or builder discipline.

## Remaining Uncertainty

The main unresolved question is whether JSONL canonicality should remain an
indirect guarantee or become a direct verifier obligation in a future profile.

Secondary uncertainty:

- whether any future API that consumes parsed receipts rather than raw files can
  legitimately claim the same indirect guarantees as the file-based verifier
- whether receipt ordering should be treated as direct or indirect when the
  verifier never sees the on-disk bytes

This chapter reduces ambiguity for current pack verification, but it does not
force a vNext decision on those future profiles.
