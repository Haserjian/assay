# CI-Org Signer Operating Model v1

**Status**: operating model for organization-controlled CI signers.

`ci-org` is the signer class for team CI, protected-branch verification, and any claim stronger than bounded local reproducibility. It is not an operator convenience key and not a founder laptop key.

## Scope

In scope:

- CI signer issuance
- storage and custody
- bootstrap into CI
- rotation
- revocation
- verifier acceptance

Out of scope:

- HSM or KMS implementation details
- Sigstore / T2 trust
- hardware attestation
- multi-org federation

## Roles

- **Policy owner**
  - defines which verifier profiles accept `ci-org`
  - maintains `trust/signers.yaml`, `trust/acceptance.yaml`, and any lockfile allowlists
- **Key custodian**
  - creates, rotates, revokes, and archives `ci-org` signer material
- **CI operator**
  - injects signer material into the CI workflow
  - ensures jobs fail closed when signer bootstrap is unavailable
- **Verifier**
  - accepts only the fingerprints and grants allowed by policy

## Signer lifecycle

### Issue

To issue a new CI signer:

1. generate or import a signer with a concrete ID such as `ci-org-main`
2. record its fingerprint in `trust/signers.yaml`
3. assign `signer_class: ci-org`
4. grant `proof_pack` authority only for the contexts intended to trust it

Wave 1 example registry entry:

```yaml
- signer_id: ci-org-main
  signer_class: ci-org
  fingerprint: "<sha256-of-pubkey>"
  lifecycle: active
  grants:
    - artifact_class: proof_pack
      purpose: "*"
  notes: "Org-controlled signer for CI and publication contexts."
```

### Store

Rules:

- the private key never lives in the repo
- the private key lives in CI secrets or another org-controlled secret manager
- the public key fingerprint may live in repo policy files
- exported private key material must be treated as credential material, not developer convenience state

### Bootstrap into CI

The CI job should be boring and explicit:

1. load signer material from CI secrets
2. import or activate the signer at job start
3. run the Assay sign / verify flow under that signer
4. fail closed if the signer is missing or unusable

Operational invariants:

- no fallback to `operator-local`
- no fallback to `local-drill`
- no silent downgrade to unsigned or locally signed publication claims

Current repo bootstrap path:

- `.github/workflows/ci-org-trust-gate.yml`
- `scripts/ci/bootstrap_ci_org_signer.py`
- `scripts/ci/build_ci_attestation_pack.py`

The current rollout uses a temporary trust overlay rooted in `trust/`.
That overlay exists only because the committed registry intentionally
starts with `signers: []` until a stable org fingerprint is ready to pin
in repo policy.

## Acceptance rules

This is the operating interpretation of the trust policy:

- `local_verify`
  - may accept `local-drill`
  - may accept `operator-local`
  - may accept `ci-org`
- `ci_gate`
  - must require `ci-org` with explicit grant
- `publication`
  - must require `ci-org` with explicit grant
- `operator-local`
  - never sufficient for external or publication trust claims

In Wave 1, this is enforced through registry presence, grants, and target-specific acceptance rules rather than direct signer-class evaluation.

## Rotation

Rotation is additive before subtractive.

Required sequence:

1. issue the new signer, for example `ci-org-main-2026q2`
2. add the new fingerprint to policy
3. deploy CI using the new signer
4. verify that new packs are using the new fingerprint
5. revoke the old signer entry
6. remove the old fingerprint from stricter allowlists as appropriate

The old signer may remain necessary for historical verification, but it should stop being sufficient for active trust gates once revocation is policy-effective.

## Revocation

Revocation is by fingerprint, not nickname alone.

If `ci-org` signer material is compromised:

1. mark the signer `revoked` in `trust/signers.yaml`
2. remove or reject the compromised fingerprint in verifier policy and lockfiles
3. issue a replacement `ci-org` signer
4. require subsequent CI and publication flows to use the replacement fingerprint

Policy consequence:

- a revoked signer must fail `ci_gate`
- a revoked signer must fail `publication`

Historical note:

- old packs may remain cryptographically valid as artifacts
- they become policy-insufficient for active trust gates once the signer is revoked

## Failure semantics

If CI signer bootstrap fails:

- the signing job fails closed
- there is no fallback to `operator-local`
- there is no fallback to `local-drill`

If signer usage and policy files disagree:

- verifier rejects
- the discrepancy is treated as a trust failure, not an informational warning

If a pack is signed by a valid but ungranted signer:

- local verification may still accept or warn, depending on policy
- `ci_gate` and `publication` must reject

## Worked example

Example lifecycle:

1. issue `ci-org-main`
2. record its fingerprint in `trust/signers.yaml`
3. grant `proof_pack` authority
4. configure CI to import and activate `ci-org-main`
5. verify packs with:

```bash
assay verify-pack ./proof_pack_* \
  --trust-target ci_gate \
  --trust-policy-dir trust \
  --enforce-trust-gate
```

6. rotate to `ci-org-main-2026q2`
7. update policy to include the new fingerprint
8. cut CI over to the new signer
9. revoke the old fingerprint

## Current status

- `ccio-brainstem-local` proves bounded local reproducibility
- it is valid for `local_verify`
- it is not sufficient for `ci_gate` or `publication`
- this document defines the intended `ci-org` operating model
- production issuance and custody may still be pending
