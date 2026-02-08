# Proof Pack Sprint (2-5 Days)

## What It Is
A fixed-scope engagement that validates agent controls, verifies evidence integrity, and delivers a portable Proof Pack your engineering, security, and legal teams can use immediately.

## What You Get
- Proof Pack folder with:
  - signed receipts
  - verifier outputs
  - discrepancy report (optional add-on)
  - reproducibility instructions
  - attestation block with separate `receipt_integrity` and `claim_check`
- Top 3 remediation actions (when discrepancy add-on is selected)
- One re-run command your team can execute

## Why It Matters
- Identifies high-risk control gaps before production incidents
- Produces audit-ready, forwardable evidence
- Converts governance requirements into executable validation artifacts

## Scope
- 5 adversarial RunCards baseline (expand to 10 in v0.1 or by request)
- Integrity verification (canonicalization/signature/schema/lineage where present)
- Claim checks for agreed claim set
- Suite and claim-set hash binding in attestation (`suite_hash`, `claim_set_hash`)
- Shadow or enforced mode execution (agreed up front)

## Delivery Artifacts
- `receipt_pack.jsonl`
- `verify_report.json`
- `verify_transcript.md`
- `pack_manifest.json`
- `pack_signature.sig`

## Optional Add-Ons (v0.1+)
- `stress_suite.json`
- `discrepancy_report.md`
- `repro.md`
- `redaction_policy.json`
- `attestation.txt` (informational projection only)

## Pricing
- Assurance Scan: $2k-$5k
- Proof Pack Sprint: $8k-$20k
- Assurance Retainer: $5k-$25k/mo

## Done Definition
- Proof Pack verifies offline
- Pack envelope signature verifies and hashes bind to delivered suite + claim set
- If discrepancy add-on is selected, report includes top 3 fixes
- Client can rerun and reproduce results with provided command

## Pricing Validation Step
- First sprint can run at $0/heavy discount to validate timing and artifact quality.
- If delivery exceeds 5 days, scope and pricing are adjusted before scaled outreach.

## What We Will Not Claim
- We do not certify universal safety.
- We do not claim court-grade anchoring without external timestamping.
- We do not promise jailbreak-proof behavior.

## Typical Buyers
- Engineering leaders shipping agent workflows
- Security/compliance teams needing evidence portability
- Procurement teams evaluating AI vendor controls
