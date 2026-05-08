# Reviewer Packet Lite Template

Use this template to summarize one bounded proof packet for a reviewer who
needs to understand what was claimed, what evidence was included, what passed,
what failed, and what remains out of scope.

## Packet Metadata

- Packet title:
- Owner:
- Review date:
- Repository or system:
- Workflow or claim set:
- Assay version:
- Verification profile:

## Claim Set

List each claim in plain language.

| Claim ID | Claim | Status | Notes |
|---|---|---|---|
| claim-001 |  |  |  |

## Evidence Included

List the included files, workflow artifacts, test results, receipts, or logs.

| Evidence ID | Artifact | Supports Claim | Notes |
|---|---|---|---|
| evidence-001 |  |  |  |

## Verification Result

`pack_manifest.json` is the evidence object manifest.

`verify_report.json` is the verification judgment.

`verify_report.sigstore.json` is the provenance of that judgment.

| Field | Value |
|---|---|
| `pack_root_sha256` |  |
| `integrity_verdict` |  |
| `claim_verdict` |  |
| `replay_verdict` |  |
| `trust_verdict` |  |
| `overall_verdict` |  |
| `evaluation_profile` |  |
| `required_channels` |  |
| `optional_channels` |  |
| `unevaluated_channels` |  |

## Scope: What This Covers

-

## Scope: What This Does Not Cover

-

## Honest Failures / Missing Evidence

Record every failed, insufficient, or unevaluated claim. Do not collapse
missing evidence into a pass.

| Item | Type | Explanation | Next Evidence Needed |
|---|---|---|---|
|  |  |  |  |

## Tamper Checks

Describe whether the included artifacts passed integrity verification.

- Pack root:
- Manifest status:
- Signature status:
- Files checked:

## How To Verify Locally

```bash
assay verify-pack ./proof_pack --json --out verify_report.json
```

For a signed Verification Gate report:

```bash
cosign verify-blob verify_report.json \
  --bundle verify_report.sigstore.json \
  --certificate-identity "<expected workflow identity>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use the exact workflow identity for the run being trusted. Do not verify only
that some valid signer signed the report.

## Challenge Path / How To Dispute

Use this section to tell a reviewer how to challenge the packet.

- Missing-evidence challenge:
- Tamper challenge:
- Replay request:
- Counterevidence submission:
- Owner or contact:

## Contact / Owner

- Responsible owner:
- Contact:
- Review route:

## Appendix: Artifact Hashes

| Artifact | Hash |
|---|---|
|  |  |
