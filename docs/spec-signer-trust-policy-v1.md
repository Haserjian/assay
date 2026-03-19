# Signer Trust Policy v1

**Status**: operating policy for signer classes, target acceptance, and lifecycle boundaries.

This document answers a narrower question than signature validity:

> which signatures should count for which claims?

Assay already proves whether a pack is structurally intact and cryptographically consistent. This policy defines which signer identities are sufficient for local drills, CI gates, and external/public claims.

For how `ci-org` should exist operationally, see
[spec-ci-org-signer-operating-model-v1.md](spec-ci-org-signer-operating-model-v1.md).

## Core boundary

`ccio-brainstem-local` proves bounded local reproducibility. It does **not** imply org trust or external trust.

That sentence should remain true everywhere this signer appears.

## Scope

This policy covers:

- signer classes
- verification targets
- bootstrap expectations
- rotation and revocation

It does **not** define a full PKI, HSM backend, or organization-wide trust federation.

## Wave 1 implementation note

Wave 1 trust enforcement is not signer-class-aware in code.

What the verifier actually evaluates today is:

- registry presence
- lifecycle state
- explicit grants
- target-specific acceptance rules

So in Wave 1, signer classes are policy metadata. Their enforcement is encoded like this:

- `local-drill` and `operator-local`
  - present in the registry so they are known
  - no broad `proof_pack` grants
  - evaluate as `recognized`, not `authorized`
- `ci-org`
  - present in the registry
  - explicit `proof_pack` grants
  - evaluate as `authorized`

This is deliberate. It prevents local drill signers from silently inheriting CI or publication meaning just because their signatures are valid.

## Signer classes

### `local-drill`

Use for bounded local reproducibility drills.

- bootstrap: self-generated on the operator machine
- trust meaning: known local signer for replay and instrumentation drills
- sufficient for:
  - `local_verify`
- not sufficient for:
  - `ci_gate`
  - `publication`

Operational rule:

- register the signer by fingerprint
- do not grant publication or CI authority

Example:

```bash
assay key generate ccio-brainstem-local
assay key info --json ccio-brainstem-local
```

### `operator-local`

Use for bounded internal operator work that is not just a named drill but still remains machine- or operator-local.

- bootstrap: self-generated on the operator machine
- trust meaning: known internal signer for local verification
- sufficient for:
  - `local_verify`
- not sufficient for:
  - `ci_gate`
  - `publication`

Operational rule:

- treat like `local-drill` unless a stronger internal policy is explicitly adopted

### `ci-org`

Use for organization-controlled CI and protected workflows.

- bootstrap: imported or generated under org-controlled workflow custody
- trust meaning: signer can back merge/deploy or publication claims
- sufficient for:
  - `ci_gate`
  - `publication`

Required controls:

- explicit registry grant
- branch protection or equivalent workflow identity controls
- defined rotation policy

## Acceptance matrix

Wave 1 target acceptance should be read this way:

| Target | Accept | Warn | Reject |
|---|---|---|---|
| `local_verify` | `authorized`, `recognized` | `unrecognized` | `revoked`, failed integrity |
| `ci_gate` | `authorized` | none | `recognized`, `unrecognized`, `revoked`, failed integrity |
| `publication` | `authorized` | none | `recognized`, `unrecognized`, `revoked`, failed integrity |

Interpretation:

- local verification can use known local signers
- CI and publication require an explicitly granted signer
- a cryptographically valid local drill signer is still policy-insufficient for stronger contexts

## Registry encoding

`trust/signers.yaml` is the registry plus policy metadata.

Example local drill signer:

```yaml
- signer_id: ccio-brainstem-local
  signer_class: local-drill
  fingerprint: "<sha256-of-pubkey>"
  lifecycle: active
  grants: []
  notes: "Known local drill signer. Proves bounded reproducibility only."
```

Example CI signer:

```yaml
- signer_id: assay-ci-org
  signer_class: ci-org
  fingerprint: "<sha256-of-pubkey>"
  lifecycle: active
  grants:
    - artifact_class: proof_pack
      purpose: "*"
  notes: "Org-controlled signer accepted for CI/publication contexts."
```

## Bootstrap rules

### Local drill bootstrap

Allowed:

- self-generate on the machine
- set active locally
- use for bounded local proof generation

Not implied:

- org endorsement
- shared team trust
- external acceptance

### Operator-local bootstrap

Allowed:

- self-generate on the machine
- register in policy if the team wants the signer to be recognized locally

Not implied:

- deployment authority
- public proof authority

### CI bootstrap

Expected:

- org-controlled key material or workflow-issued identity
- registry entry pinned by fingerprint
- verifier policy that accepts only granted CI signers for `ci_gate` and `publication`

## Rotation and revocation

Use fingerprint-first policy language. Human-readable signer names help operators, but verifier policy must ultimately bind to fingerprints.

### Rotation

Safe sequence:

1. generate or import the new signer
2. add the new fingerprint to policy
3. cut over active use
4. retire or revoke the old signer

Rotation should be additive before subtractive.

### Revocation

If a signer is compromised:

1. mark it revoked in the registry
2. remove or reject its fingerprint in verifier policy / lockfiles
3. require subsequent packs to use a replacement signer

Revocation should be communicated by fingerprint, not nickname alone.

## Lockfile and verifier examples

Local drill verification can remain intentionally lenient:

```bash
assay verify-pack ./proof_pack_* \
  --trust-target local_verify \
  --trust-policy-dir trust
```

CI should evaluate against the stricter target:

```bash
assay verify-pack ./proof_pack_* \
  --trust-target ci_gate \
  --trust-policy-dir trust \
  --enforce-trust-gate
```

Lockfiles remain a separate integrity/trust root. A stricter lockfile can pin allowed fingerprints even when trust policy is present:

```yaml
signer_policy:
  mode: allowlist
  allowed_fingerprints:
    - "<ci-org-fingerprint>"
```

## Decision summary

The current `brainstem` drill moved local reproducibility from founder-only to team-runnable under bounded local conditions.

What it did **not** do is authorize `ccio-brainstem-local` for CI or external claims.

That is the intended boundary.
