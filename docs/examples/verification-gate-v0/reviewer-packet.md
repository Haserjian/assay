# Reviewer Packet Lite: Verification Gate v0 Sample

This packet summarizes the committed Verification Gate v0 sample for a
reviewer. It is a worked example of the Reviewer Packet Lite template, not a
claim of production authorization or legal compliance.

## Packet Metadata

- Packet title: Verification Gate v0 signed report sample
- Owner: Assay project
- Review date: 2026-05-08
- Repository or system: `Haserjian/assay`
- Workflow or claim set: PR verification artifact from Assay PR `#116`
- Assay version: `1.23.0`
- Verification profile: `integrity_required`

## Claim Set

| Claim ID | Claim | Status | Notes |
|---|---|---|---|
| claim-001 | The PR workflow emitted a portable `verify_report.json` for one evidence pack. | Supported by sample artifact | The committed sample includes `verify_report.json` and `pack_manifest.json`. |
| claim-002 | The report and manifest bind to the same pack root. | Passed | Both files name `88444482656580c864b9b879d877e82a05359c5f3970ec385b64f7777f73a053`. |
| claim-003 | The report signature verifies against the expected GitHub Actions workflow identity. | Passed | `cosign verify-blob` returns `Verified OK` for the PR `#116` workflow identity. |
| claim-004 | Claim, replay, and trust-policy channels were evaluated. | Not evaluated | The sample explicitly reports `NOT_EVALUATED` / `NOT_RUN` for those channels. |

## Evidence Included

| Evidence ID | Artifact | Supports Claim | Notes |
|---|---|---|---|
| evidence-001 | `pack_manifest.json` | claim-001, claim-002 | Evidence object manifest. |
| evidence-002 | `verify_report.json` | claim-001, claim-002, claim-004 | Verification judgment. |
| evidence-003 | `verify_report.sigstore.json` | claim-003 | Provenance bundle for the judgment signature. |
| evidence-004 | `verify.stdout.json` | operator diagnostics | Included for traceability, not the portable public contract. |

## Verification Result

`pack_manifest.json` is the evidence object manifest.

`verify_report.json` is the verification judgment.

`verify_report.sigstore.json` is the provenance of that judgment.

| Field | Value |
|---|---|
| `pack_root_sha256` | `88444482656580c864b9b879d877e82a05359c5f3970ec385b64f7777f73a053` |
| `pack_manifest_sha256` | `8cd434764e92546c279544d179b20c3c92922eeba52148655fb0820e1fe57c07` |
| `integrity_verdict` | `PASS` |
| `claim_verdict` | `NOT_EVALUATED` |
| `replay_verdict` | `NOT_RUN` |
| `trust_verdict` | `NOT_EVALUATED` |
| `overall_verdict` | `PASS` |
| `evaluation_profile` | `integrity_required` |
| `required_channels` | `integrity` |
| `optional_channels` | `claim`, `replay`, `trust` |
| `unevaluated_channels` | `claim`, `replay`, `trust` |
| `overall_reason` | `required_channels_passed; optional_channels_not_evaluated=claim,replay,trust` |

## Scope: What This Covers

- The committed sample report and manifest name the same pack root.
- The report states separate verdict channels.
- The integrity-required channel passed.
- The report signature verifies against the expected GitHub Actions workflow
  identity for PR `#116`.

## Scope: What This Does Not Cover

- Full claim evaluation.
- Replay evaluation.
- Trust-policy evaluation.
- Production authorization.
- Legal or compliance certification.
- Ledger acceptance.
- Scorecard interpretation.
- Upstream data authenticity beyond included evidence.

## Honest Failures / Missing Evidence

| Item | Type | Explanation | Next Evidence Needed |
|---|---|---|---|
| Claim channel | Not evaluated | No claim set was evaluated in this sample. | Add a scoped claim set and claim evaluator. |
| Replay channel | Not run | Replay was not run in this sample. | Add replay fixture and replay result. |
| Trust channel | Not evaluated | Workflow/signing policy trust was not evaluated as a report channel. | Add trust policy expectations and evaluation result. |

## Tamper Checks

- Pack root: `88444482656580c864b9b879d877e82a05359c5f3970ec385b64f7777f73a053`
- Manifest status: report and manifest pack roots match
- Signature status: `cosign verify-blob` returns `Verified OK`
- Files checked:
  - `pack_manifest.json`
  - `verify_report.json`
  - `verify_report.sigstore.json`

## How To Verify Locally

From the repository root:

```bash
bash scripts/verify_verification_gate_sample.sh
```

That script prints the verdict channels, confirms the report/manifest pack
root match, and verifies the Sigstore bundle with:

```bash
cosign verify-blob verify_report.json \
  --bundle verify_report.sigstore.json \
  --certificate-identity "https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use the exact workflow identity for the run being trusted. Do not verify only
that some valid signer signed the report.

## Challenge Path / How To Dispute

- Missing-evidence challenge: identify which claim needs claim/replay/trust
  evaluation and provide the expected evidence.
- Tamper challenge: alter a committed sample file and rerun the verification
  script; verification should fail.
- Replay request: request a replay-enabled sample instead of this
  integrity-required sample.
- Counterevidence submission: attach an alternate report, manifest, or bundle
  and state which field disagrees.
- Owner or contact: Assay project maintainer.

## Appendix: Artifact Hashes

| Artifact | SHA-256 |
|---|---|
| `pack_manifest.json` | `8cd434764e92546c279544d179b20c3c92922eeba52148655fb0820e1fe57c07` |
| `verify.stdout.json` | `55d8bd7622a4a94fb6e600d36d8dfa2e9f33f647c4c8b83e8a4c0dcd6c58a53d` |
| `verify_report.json` | `049cc59c974ca39b05e7ee891af6a02649c51395bafde8ad86388756d242c3a5` |
| `verify_report.sigstore.json` | `39ebaf034048010ff86ece88720d64161269959b5b980a707f76e3f9c057a15c` |
