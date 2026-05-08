# Assay Packet Taxonomy

This taxonomy keeps inventory, evidence, judgment, citation, and
interpretation separate.

## Receipt

An atomic event-level record. A receipt may record a tool call, model
invocation, policy check, test result, or other bounded action. Receipts should
preserve enough context and parent linkage to be inspected later.

## Proof Pack

A machine-verifiable bundle of receipts, evidence files, hashes, signatures,
and metadata. A proof pack lets another party verify that included evidence
was not altered after signing.

Typical files:

```text
receipt_pack.jsonl
pack_manifest.json
pack_signature.sig
verify_report.json
```

## Verify Report

`verify_report.json` is a portable verification judgment for one evidence
object. It separates verdict channels such as integrity, claim, replay, trust,
and overall verdict.

`overall_verdict=PASS` only means the channels required by the declared
`evaluation_profile` passed. Optional channels may still be `NOT_EVALUATED` or
`NOT_RUN`.

## Reviewer Packet

A human-forwardable explanation of a proof pack. It should explain the claim
set, included evidence, verification result, scope, caveats, missing evidence,
and how to challenge or reproduce the verification.

Reviewer packets should not replace the proof pack. They explain it.

## Passport

A durable status summary generated from one or more proof packs. A passport is
useful when a reviewer needs a compact status view, but it should link back to
the underlying packets and reports.

## Repo Manifest

`repo_manifest.json` is a repo or organization inventory snapshot. It answers:

```text
What repos, workflows, branches, heads, and artifacts existed at time T?
```

`repo_manifest.sigstore.json` can prove provenance of that inventory snapshot.

A repo manifest does not prove the repos are secure, correct, compliant, or
trustworthy. It is estate-control evidence, not a verification judgment.

## Ledger Response

`ledger_response.json` records accepted or citable position in a ledger. It
answers where an evidence object was received, validated under ledger policy,
and indexed.

Ledger acceptance does not make a claim true. It makes the referenced position
citable under that ledger's rules.

## Scorecard

`scorecard.json` is interpretation or risk summary. It may explain readiness,
coverage, gaps, or maturity. A scorecard should cite evidence and verification
reports rather than becoming its own proof source.

## Doctrine

```text
repo_manifest.json = repo/org inventory snapshot
repo_manifest.sigstore.json = provenance of inventory snapshot
pack_manifest.json = evidence object manifest
receipt_pack.jsonl = raw evidence/events
verify_report.json = verification judgment
verify_report.sigstore.json = provenance of judgment
ledger_response.json = accepted/citable position
scorecard.json = interpretation/risk summary
```

Pack root proves the evidence object. Ledger index proves accepted/citable
position. Scorecard explains interpretation.

GitHub artifact inventory is operational metadata, not durable proof by
itself. Preserve important sample artifacts in a durable location or release
asset when they are part of a public or buyer-facing runbook.
