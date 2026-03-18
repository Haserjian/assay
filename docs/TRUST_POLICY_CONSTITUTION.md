# Trust Policy Constitution v0.1

**Status**: Governing document for the Assay trust evaluation model.
**Scope**: Defines the four-stage trust chain. Implementation starts in assay-toolkit;
other repos adopt incrementally.

## Purpose

Assay verification machinery answers: "Is this artifact structurally intact and
cryptographically consistent?" Trust policy answers: "Given these verified facts,
should I accept this artifact for this purpose?"

This document defines the model that separates those questions.

## Terms

- **artifact class**: what kind of evidence object (proof_pack, witness_envelope, ledger_entry, adc)
- **schema family**: version/generation of the artifact format (e.g., pack_version 0.1.0)
- **declared purpose**: what the artifact claims to be for (ci_attestation, publication, internal_evidence)
- **verification fact**: a descriptive, judgment-free observation from the verifier
- **grant**: an explicit permission for a signer to sign a specific artifact class/scope
- **policy target**: the consumer context evaluating acceptance (local_verify, ci_gate, publication)
- **trust evaluation**: the composed result of classify + verify + authorize + accept

## Four-Stage Model

```
classify → verify → authorize → accept
```

Each stage produces a distinct output. No stage modifies the output of a prior stage.

### Stage 1: Classify

Determine what the artifact is.

**Input**: raw artifact (manifest dict, envelope, entry)
**Output**: `ArtifactClassification`

Fields:
- `artifact_class`: proof_pack | witness_envelope | ledger_entry | adc
- `schema_version`: declared format version
- `declared_purpose`: ci_attestation | publication | internal_evidence | unknown
- `provenance`: source repo, CI binding, tool version (if available)

Unknown or ambiguous classifications must never silently escalate to accepted.

### Stage 2: Verify

Establish facts about the artifact's integrity and structure.

**Input**: artifact + classification
**Output**: `VerificationFacts`

Fields:
- `integrity_passed`: bool
- `signature_valid`: bool | None (None if no signature material)
- `signer_id`: extracted signer identifier
- `signer_fingerprint`: SHA-256 of signer public key
- `embedded_pubkey`: bool (whether pack carries its own public key)
- `schema_recognized`: bool
- `error_codes`: list of verification error codes
- `warning_codes`: list of verification warnings

**Invariant**: verification facts are descriptive, not normative. No judgment words
(trusted, approved, sufficient, accepted) appear in fact fields.

### Stage 3: Authorize

Determine whether the signer is recognized and granted permission.

**Input**: verification facts + signer registry
**Output**: `AuthorizationDecision`

Fields:
- `subject`: signer_id + signer_fingerprint
- `status`: authorized | recognized | unrecognized | revoked
- `matched_grants`: list of grants that apply
- `reason_codes`: list of machine-readable reasons
- `lifecycle_state`: active | rotated | revoked

Status semantics:
- `authorized`: signer is in registry, has matching grant for this artifact class/purpose
- `recognized`: signer is in registry but lacks a grant for this specific use
- `unrecognized`: signer is not in registry
- `revoked`: signer is in registry but lifecycle state is revoked
- `not_evaluated`: no registry was provided (trust policy not loaded)

Wave 1: authorization matches on `artifact_class` and `purpose` only.
Scope-based grants are reserved for future use.

**Invariant**: recognized does not imply authorized. Authorization requires an
explicit grant, not just registry presence.

**Invariant**: revoked signers are never authorized, regardless of grants.

### Stage 4: Accept

Determine whether the artifact is acceptable for a specific consumer target.

**Input**: classification + verification facts + authorization decision + acceptance policy
**Output**: `AcceptanceDecision`

Fields:
- `decision`: accept | warn | reject | not_evaluated
- `target`: the policy target being evaluated
- `rationale`: human-readable explanation
- `reason_codes`: machine-readable list

Decision semantics:
- `accept`: target policy satisfied
- `warn`: usable, but policy deviation exists — must surface reason_codes
- `reject`: not usable for this target
- `not_evaluated`: no acceptance policy was provided

**Invariant**: acceptance is always for a named target, never abstract.

**Invariant**: `warn` must always include a machine-readable reason code.
It is not "soft accept" — it means a specific policy deviation was detected.

## Non-Implications

These must remain explicit to prevent semantic drift:

1. **Verified does not imply approved.** Structural integrity says nothing about
   signer authorization or artifact acceptability.

2. **Authorized does not imply accepted.** A signer may be authorized to produce
   an artifact class but the artifact may not meet acceptance criteria for a
   specific target (e.g., stale, wrong mode, insufficient witness level).

3. **Accepted does not imply trusted in perpetuity.** Acceptance is evaluated at
   a point in time against current policy. Revocation, policy change, or new
   evidence can invalidate prior acceptance.

4. **Registry presence does not imply authorization.** A signer can be recognized
   (known to the system) without having any grants.

## Current Code Anchors

| Stage | Module | Function/Object |
|-------|--------|-----------------|
| Classify | (new) `src/assay/trust/` | `classify_artifact()` |
| Verify | `src/assay/integrity.py` | `verify_pack_manifest()` → `VerifyResult` |
| Verify | `src/assay/keystore.py` | signer metadata via `signer_info()` |
| Authorize | (new) `src/assay/trust/` | `authorize_signer()` |
| Accept | (new) `src/assay/trust/` | `evaluate_acceptance()` |
| Compose | (new) `src/assay/trust/` | `evaluate_trust()` → `TrustEvaluation` |

Existing `verify_pack_manifest()` is unchanged. Trust evaluation is a separate
layer that consumes its results.

## Initial Policy Targets

| Target | Description | Typical use |
|--------|-------------|-------------|
| `local_verify` | Developer verifying a pack locally | Lenient: accept with warnings |
| `ci_gate` | CI pipeline gating a merge/deploy | Moderate: require signature + known signer |
| `publication` | Publishing to ledger or public gallery | Strict: require authorized signer + full integrity |

## Wave 1 Invariants

1. Verification facts are descriptive, not normative.
2. Authorization never modifies verification results.
3. Acceptance is always target-specific.
4. Unknown or ambiguous classifications never silently escalate to accepted.
5. Revoked signers are never authorized.
6. Enforcement is a caller choice, not a verifier side effect.

## Out of Scope (Wave 1)

- KMS or HSM key backends
- Key revocation infrastructure beyond lifecycle state in registry
- Retroactive reclassification of existing artifacts
- Transitive or recursive trust (trust graph semantics)
- Cross-repo trust federation
- Acceptance policy for consumers that don't exist yet
