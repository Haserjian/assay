# Reviewer Packet - Worked Example: Signed Verification Report

This packet summarizes the committed Verification Gate v0 sample for a
reviewer. It is a worked example of the Reviewer Packet Lite template, not a
claim of production authorization or legal compliance.

Plain English: this sample is a signed Verification Report for an Evidence
Box. It proves the Evidence Box passed an integrity check and that the
Verification Report was signed by the expected GitHub workflow. It does not
prove the software is secure, compliant, production-approved, or fully
evaluated.

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
| claim-001 | The PR workflow emitted a portable `verify_report.json` for one evidence pack. | Supported by sample artifact | The committed sample includes a complete `proof-pack/` and a signed public report under `signed-report/`. |
| claim-002 | The public report and proof-pack manifest bind to the same pack root. | Passed | Both files name `88444482656580c864b9b879d877e82a05359c5f3970ec385b64f7777f73a053`. |
| claim-003 | The public report signature verifies against the expected GitHub Actions workflow identity. | Passed | `cosign verify-blob` returns `Verified OK` for the PR `#116` workflow identity. |
| claim-004 | Claim, replay, and trust-policy channels were evaluated. | Not evaluated | The sample explicitly reports `NOT_EVALUATED` / `NOT_RUN` for those channels. |

## Evidence Included

| Evidence ID | Artifact | Supports Claim | Notes |
|---|---|---|---|
| evidence-001 | `proof-pack/pack_manifest.json` | claim-001, claim-002 | Evidence object manifest. |
| evidence-002 | `signed-report/verify_report.json` | claim-001, claim-002, claim-004 | Public verification judgment. |
| evidence-003 | `signed-report/verify_report.sigstore.json` | claim-003 | Provenance bundle for the judgment signature. |
| evidence-004 | `signed-report/verify.stdout.json` | operator diagnostics | Included for traceability, not the portable public contract. |
| evidence-005 | `proof-pack/receipt_pack.jsonl` | proof-pack integrity | Empty receipt pack for this zero-receipt sample. |
| evidence-006 | `proof-pack/verify_report.json` | proof-pack integrity | Hash-covered report inside the proof pack. |
| evidence-007 | `proof-pack/verify_transcript.md` | proof-pack integrity | Human-readable transcript inside the proof pack. |
| evidence-008 | `proof-pack/pack_signature.sig` | proof-pack integrity | Detached Ed25519 proof-pack signature. |

## Verification Result

`proof-pack/pack_manifest.json` is the evidence object manifest.

`signed-report/verify_report.json` is the public verification judgment.

`signed-report/verify_report.sigstore.json` is the provenance of that public
judgment.

There are two signatures in this sample. `proof-pack/pack_signature.sig`
belongs to the proof pack itself. `signed-report/verify_report.sigstore.json`
belongs to the public Verification Report.

The sample script verifies the Sigstore signature on the public Verification
Report and checks proof-pack manifest hashes. The tamper demo also uses
`assay verify-pack` to show that changing a file inside the proof pack is
rejected. The proof pack's Ed25519 signature,
`proof-pack/pack_signature.sig`, is present in this sample; the public reviewer
walkthrough focuses on the signed Verification Report and does not make a
trust claim about the proof-pack signer identity.

The certificate identity must exactly match
`https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge`.
This is the workflow identity for this sample. Future runs will have their own
expected workflow identity. This is an exact identity check, not a substring
search; a workflow from another repo or fork would not satisfy the command.

| Field | Value |
|---|---|
| `pack_root_sha256` | `88444482656580c864b9b879d877e82a05359c5f3970ec385b64f7777f73a053` |
| `pack_manifest_sha256` | `8cd434764e92546c279544d179b20c3c92922eeba52148655fb0820e1fe57c07` |
| `integrity_verdict` | `PASS` |
| `claim_verdict` | `NOT_EVALUATED` |
| `replay_verdict` | `NOT_RUN` |
| `trust_verdict` | `NOT_EVALUATED` |
| `overall_verdict` | `PASS` for `integrity_required` |
| `evaluation_profile` | `integrity_required` |
| `required_channels` | `integrity` |
| `optional_channels` | `claim`, `replay`, `trust` |
| `unevaluated_channels` | `claim`, `replay`, `trust` |
| `overall_reason` | `required_channels_passed; optional_channels_not_evaluated=claim,replay,trust` |

## Verdict Channels

| Channel | Result | Plain English |
|---|---|---|
| Integrity | `PASS` | The evidence pack matched its manifest. |
| Claim | `NOT_EVALUATED` | This sample did not judge whether a claim was true. |
| Replay | `NOT_RUN` | This sample did not rerun behavior. |
| Trust | `NOT_EVALUATED` | This sample did not apply a trust policy. |
| Overall | `PASS` | The required integrity channel passed. |

Important: overall `PASS` only means the required integrity check passed for
the `integrity_required` profile. It does not mean every possible check was
run. A screenshot of `overall_verdict=PASS` without `evaluation_profile` is
incomplete.

## Scope: What This Covers

- The committed sample report and manifest name the same pack root.
- The committed `proof-pack/` directory contains every file listed in
  `proof-pack/pack_manifest.json`.
- The public report states separate verdict channels.
- The integrity-required channel passed.
- The public report signature verifies against the expected GitHub Actions
  workflow identity for PR `#116`.

## Scope: What This Does Not Cover

- Full claim evaluation.
- Replay evaluation.
- Trust-policy evaluation.
- Production authorization.
- Legal or compliance certification.
- Ledger acceptance.
- Scorecard interpretation.
- Upstream data authenticity beyond included evidence.

## Do Not Say / Say This Instead

| Do Not Say | Say This Instead |
|---|---|
| This proves the AI was right. | This proves the signed report passed the integrity-required verification profile. |
| This proves the repo is secure. | This sample does not evaluate repository security. |
| This proves compliance. | This sample is not a legal or compliance certification. |
| Every claim passed. | Claim, replay, and trust channels were not evaluated in this sample. |

## Honest Failures / Missing Evidence

| Item | Type | Explanation | Next Evidence Needed |
|---|---|---|---|
| Claim channel | Not evaluated | No claim set was evaluated in this sample. | Add a scoped claim set and claim evaluator. |
| Replay channel | Not run | Replay was not run in this sample. | Add replay fixture and replay result. |
| Trust channel | Not evaluated | Workflow/signing policy trust was not evaluated as a report channel. | Add trust policy expectations and evaluation result. |

## Tamper Checks

- Pack root: `88444482656580c864b9b879d877e82a05359c5f3970ec385b64f7777f73a053`
- Manifest status: public report and proof-pack manifest pack roots match
- Signature status: `cosign verify-blob` returns `Verified OK`
- Files checked:
  - `proof-pack/pack_manifest.json`
  - `signed-report/verify_report.json`
  - `signed-report/verify_report.sigstore.json`

## What Would Make This Fail?

- Changing the signed public report after signing.
- Supplying a Sigstore bundle that does not match the report.
- Verifying against the wrong GitHub Actions identity.
- Changing proof-pack files so they no longer match `pack_manifest.json`.
- Removing a file listed in the proof-pack manifest.

The tamper demo shows two failure modes: changing the signed public report
breaks Sigstore verification, and changing a file inside the proof pack causes
`assay verify-pack` to reject the pack.

## How To Verify Locally

From the repository root:

```bash
bash scripts/verify_verification_gate_sample.sh
```

That script prints the verdict channels, confirms the report/manifest pack
root match, confirms the proof-pack file set is present, and verifies the
Sigstore bundle with:

```bash
cosign verify-blob signed-report/verify_report.json \
  --bundle signed-report/verify_report.sigstore.json \
  --certificate-identity "https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use the exact workflow identity for the run being trusted. Do not verify only
that some valid signer signed the report.

To see the tamper checks:

```bash
python3 -m pip install assay-ai  # if the assay command is not installed
bash scripts/demo_tamper_verification_gate_sample.sh
```

Expected result:

```text
Clean sample result: VERIFIED OK
Report tamper result: REJECTED
Pack tamper result: REJECTED
```

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

## Appendix: Public Report Artifact Hashes

| Artifact | SHA-256 |
|---|---|
| `signed-report/verify.stdout.json` | `55d8bd7622a4a94fb6e600d36d8dfa2e9f33f647c4c8b83e8a4c0dcd6c58a53d` |
| `signed-report/verify_report.json` | `049cc59c974ca39b05e7ee891af6a02649c51395bafde8ad86388756d242c3a5` |
| `signed-report/verify_report.sigstore.json` | `39ebaf034048010ff86ece88720d64161269959b5b980a707f76e3f9c057a15c` |

## Appendix: Proof-Pack File Hashes

| Artifact | SHA-256 |
|---|---|
| `proof-pack/pack_manifest.json` | `8cd434764e92546c279544d179b20c3c92922eeba52148655fb0820e1fe57c07` |
| `proof-pack/pack_signature.sig` | `81816affc8aac43f15f032ee4820b4ebbe504801a017ad7ccd8c0d6b4ed58904` |
| `proof-pack/receipt_pack.jsonl` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `proof-pack/verify_report.json` | `1ace3f4aae77aaa5c34272a5ab9c4fde3921673936aec186052547f513b5da75` |
| `proof-pack/verify_transcript.md` | `d2ba93896ba683fc51159a3bed158f8f65f2923f710f91b35c87120cd1ab4fc2` |

## Glossary

- Evidence Box: the proof pack named by `proof-pack/pack_manifest.json`.
- Verification Report: the signed public judgment in
  `signed-report/verify_report.json`.
- Signature Proof: the Sigstore bundle in
  `signed-report/verify_report.sigstore.json`.
- Inspection Note: older/internal wording for Verification Report.
