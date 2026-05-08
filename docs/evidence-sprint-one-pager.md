# Evidence Sprint: Reviewer-Ready AI Evidence in Two Weeks

Assay helps teams replace unverifiable AI claims with portable proof packets
that show what passed, what failed, what was missing, and whether the artifact
was altered.

## Offer

In a fixed-scope pilot, we turn one AI/software claim set into a
reviewer-ready evidence packet with verifiable artifacts, explicit caveats,
and a repeatable verification path.

Commercial terms are handled as a fixed-scope pilot proposal, not as a public
price list in this repository.

## Who It Is For

- Teams answering customer AI-governance or security questionnaires.
- Teams preparing for vendor, procurement, model-risk, or compliance review.
- Teams using agentic or LLM-assisted workflows that need evidence beyond
  screenshots, logs, or prose attestations.
- Teams that want an honest packet showing both supported claims and gaps.

## Buyer Pain

AI review work often turns into scattered claims, screenshots, dashboard
exports, Slack explanations, and unverified logs. Reviewers then have to infer
what was claimed, what evidence supports it, and whether any artifact was
changed after the fact.

Assay turns that review moment into a packet another party can inspect.

## Deliverables

- Claim inventory for one bounded workflow or review question set.
- Evidence map linking claims to files, logs, tests, receipts, or workflow
  artifacts.
- Assay proof pack or equivalent evidence bundle.
- `verify_report.json` verification judgment.
- Reviewer Packet Lite summary.
- Local verification instructions.
- Honest-failure, missing-evidence, and tamper notes.
- CI recommendation or optional GitHub Action setup.

## Not Included

- Legal opinion or compliance certification.
- Production authorization.
- Full platform integration.
- Full model evaluation.
- Runtime monitoring.
- Guarantee of upstream data authenticity.
- Claim/replay/trust evaluation unless explicitly scoped.

## Acceptance Criteria

A reviewer can:

- See what was claimed.
- Inspect which evidence supports each claim.
- Run or understand the verification path.
- See what passed, failed, was missing, or was not evaluated.
- Confirm whether the artifact was altered after signing.
- Forward the packet internally without needing access to Assay internals.

## Caveats

The first sprint may use T0/self-contained evidence if that matches the
workflow. T0 evidence can verify internal consistency and post-signing
integrity of included artifacts. It does not independently prove signer
honesty, upstream data authenticity, or runtime completeness beyond included
evidence.

Stronger witnessing, independent anchoring, ledger acceptance, or scorecard
interpretation are later maturity layers, not assumed in the base sprint.

## Optional CI Integration

If the review target lives in GitHub, the sprint can add an Assay verification
workflow that emits `pack_manifest.json`, `verify_report.json`, and
`verify_report.sigstore.json` as review artifacts. The CI integration is scoped
to producing a repeatable verification packet; it does not imply production
authorization or legal compliance.

## Example Artifact List

```text
pack_manifest.json
receipt_pack.jsonl
verify_report.json
verify_report.sigstore.json
reviewer_packet.md
verification_instructions.md
```

For the current Verification Gate v0 sample, see:

```text
docs/examples/verification-gate-v0/
  proof-pack/
    pack_manifest.json
    pack_signature.sig
    receipt_pack.jsonl
    verify_report.json
    verify_transcript.md
  signed-report/
    verify.stdout.json
    verify_report.json
    verify_report.sigstore.json
```

## Verification Command

```bash
bash scripts/verify_verification_gate_sample.sh
```

That sample proves the integrity-required verification gate path: the report
and manifest bind to the same pack root, and the report signature verifies
against the expected GitHub Actions workflow identity. It does not prove full
claim, replay, or trust-policy evaluation.
