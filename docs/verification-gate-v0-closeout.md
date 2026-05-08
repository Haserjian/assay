# Assay Verification Gate v0 Closeout

Assay Verification Gate v0 is live.

The public contract is `verify_report.json`: a portable verification judgment
for one evidence pack. The report is carried alongside `pack_manifest.json`
and signed as `verify_report.sigstore.json`.

## Canonical State

- Public verify report contract: Assay PR `#111`
- First signed report artifact path: Assay PR `#114`
- Hardened checkout-generated signed report: Assay PR `#116`
- Buyer verification runbook: Assay PR `#115`
- Public package: `assay-ai==1.23.0`
- Release-prepped but not shipped: `assay-ai==1.24.0`
- Verification action release: `assay-verify-action v1.1.0`

Use PR `#116` as the live buyer proof. PR `#114` was the first path, but
`#116` is the hardened artifact because the signed report is generated from
checkout code before signing.

## Live Buyer Proof

- Workflow run: `25539107447`
- Artifact: `assay-verify-report`
- Files:
  - `pack_manifest.json`
  - `verify.stdout.json`
  - `verify_report.json`
  - `verify_report.sigstore.json`
- Certificate identity:
  `https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge`

The buyer runbook downloaded that artifact, confirmed the report and manifest
share the same `pack_root_sha256`, and verified the report signature with
strict Sigstore identity constraints. Local verification returned:

```text
Verified OK
```

This is a one-shot proof for PR `#116`. The issued certificate remains
verifiable with the committed bundle, but future workflow runs will sign under
their own workflow identities, usually including a different `refs/pull/...`
or branch reference.

## Durable Sample

The live artifact is preserved as a small committed sample:

```text
docs/examples/verification-gate-v0/
  proof-pack/
    pack_manifest.json
    pack_signature.sig
    receipt_pack.jsonl
    verify_report.json
    verify_transcript.md
  reviewer-packet.md
  signed-report/
    verify.stdout.json
    verify_report.json
    verify_report.sigstore.json
```

Verify the committed sample with:

```bash
bash scripts/verify_verification_gate_sample.sh
```

The `proof-pack/` directory is the complete proof pack named by
`pack_manifest.json`. The `signed-report/` directory contains the public
`verify_report.json` generated from that proof pack and signed by GitHub
Actions. Those are separate files because the proof pack's own
`verify_report.json` is hash-covered by `pack_manifest.json`, while the public
report includes the final `pack_manifest_sha256` and is the Sigstore-signed
judgment artifact.

## Report Semantics

The live report proves the integrity-required gate path:

```text
integrity_verdict=PASS
claim_verdict=NOT_EVALUATED
replay_verdict=NOT_RUN
trust_verdict=NOT_EVALUATED
overall_verdict=PASS
evaluation_profile=integrity_required
required_channels=integrity
optional_channels=claim,replay,trust
unevaluated_channels=claim,replay,trust
```

`overall_verdict=PASS` means the channels required by
`evaluation_profile=integrity_required` passed. It does not mean optional
claim, replay, or trust channels were evaluated.

## What This Proves

- A PR can emit a portable signed verification judgment.
- A buyer can download the artifact from a workflow run.
- A buyer can inspect separate verdict channels.
- A buyer can confirm the report and manifest bind to the same pack root.
- A buyer can verify the report signature against the expected GitHub Actions
  workflow identity.

## What This Does Not Prove

- It does not prove full claim evaluation.
- It does not prove replay evaluation.
- It does not prove trust-policy evaluation.
- It does not prove production authorization.
- It does not prove ledger acceptance.
- It does not prove scorecard interpretation.
- It does not prove repo estate inventory.

## Doctrine

```text
pack_manifest.json = evidence object manifest
receipt_pack.jsonl = raw evidence/events
verify_report.json = verification judgment
verify_report.sigstore.json = provenance of judgment
ledger_response.json = accepted/citable position
scorecard.json = interpretation/risk summary
```

Pack root proves the evidence object. Ledger index proves accepted/citable
position. Scorecard explains interpretation.

## Next Sequence

1. Use the buyer runbook from a second clean environment or with an external
   verifier.
2. Keep `assay-ai==1.24.0` treated as release-prepped only until it is tagged
   and published.
3. Build signed `repo_manifest.json` as estate-control evidence after the
   buyer runbook has been exercised.
4. Defer ledger, scorecards, preflight, MemoryGraph, Quintet, and multi-witness
   work until the signed verification report path is boringly repeatable.
