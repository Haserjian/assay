# Constitutional Verification Report

**Subject**: Company X SOC2 Readiness Assessment
**Verified**: 2026-03-25 00:52 UTC
**Original AI verdict**: READY FOR AUDIT (7/7 COMPLIANT)
**Verified verdict**: PARTIAL (3 Ambiguous, 4 Blocked)

## Per-Claim Results

| Claim | AI Rating | Verified Status | Finding |
|-------|-----------|-----------------|---------|
| Company X meets SOC2 Type II requirements across all evaluated areas | COMPLIANT | **BLOCKED** (was AMBIGUOUS) | The evidence shows confirmed gaps (MFA exceptions, untested IR plan) and covers only a subset of SOC2 Trust Service Criteria, making a claim of meeting all evaluated areas unsupported. |
| Multi-factor authentication is enforced across ALL systems | COMPLIANT | **BLOCKED** | The MFA policy document directly contradicts the 'ALL systems' claim by documenting active exceptions for at least two named systems. |
| AES-256 encryption is applied to all data at rest | COMPLIANT | **AMBIGUOUS** (was CONFIRMED) | The January 2026 encryption audit explicitly confirms AES-256 encryption on all data stores with zero findings. |
| TLS 1.3 is used for ALL data in transit | COMPLIANT | **AMBIGUOUS** | The audit confirms TLS 1.3 for API endpoints but does not provide evidence covering internal service-to-service traffic or third-party integrations, leaving the 'ALL data in transit' claim partially supported. |
| A documented incident response plan exists | COMPLIANT | **AMBIGUOUS** (was CONFIRMED) | A documented incident response plan exists at version 3.2 with a revision date and named owner, satisfying the existence requirement. |
| The incident response plan is tested quarterly | COMPLIANT | **BLOCKED** | The IR plan document shows only one exercise in the available record period and confirms the next exercise has been postponed indefinitely, directly contradicting a claim of quarterly testing. |
| Company X is ready for a SOC2 audit | COMPLIANT | **BLOCKED** | Multiple confirmed gaps — active MFA exceptions and lapsed IR testing — combined with the absence of evidence across several SOC2 Trust Service Criteria indicate Company X is not ready for a SOC2 audit. |

## Witness Overrides

- **CLAIM-1**: AMBIGUOUS -> BLOCKED — AMBIGUOUS is too generous here. The verifier's own findings establish concrete, documented contradictions — not merely uncertainty. The MFA policy explicitly names two systems with active exceptions until at least Q3 2026, and the IR plan shows only one exercise with the next indefinitely postponed. These are not gaps in evidence coverage; they are affirmative evidence of non-compliance with specific SOC2 requirements. A claim that Company X 'meets SOC2 Type II requirements across all evaluated areas' is directly and materially contradicted by available evidence. The AMBIGUOUS designation implies the claim might be true pending more investigation; the evidence shows it is false in at least two documented areas. BLOCKED is the correct status.
- **CLAIM-3**: CONFIRMED -> AMBIGUOUS — The verifier granted CONFIRMED based on a single encryption audit artifact stating 'All data stores: AES-256 encryption confirmed.' The verification requirement specifies evidence covering 'every data store, endpoint, and backup medium in scope.' The artifact is a January 2026 point-in-time audit of unspecified scope — there is no evidence the auditor had a complete system inventory, covered endpoints and backup media, or that the scope matches the full SOC2 in-scope environment. A self-declared or internally produced audit report with no information about the auditor's qualifications, methodology, or inventory completeness does not satisfy the verification requirement for a claim using 'all data at rest.' This is not confirmed — it is partially supported, and AMBIGUOUS is the honest grade.
- **CLAIM-5**: CONFIRMED -> AMBIGUOUS — The verifier confirmed this based on the existence of IR Plan v3.2 with a revision date and named owner. However, the verification requirement specifies review of 'version control history, approval signatures, and distribution records confirming it is current and accessible to relevant staff.' The evidence shows only a document exists with a named owner and a September 2024 revision date. There is no evidence of approval signatures, distribution records, or confirmation that relevant staff can access and locate the plan. The plan is also nearly 16 months old as of early 2026 with no evidence of interim review following the January 2025 tabletop exercise. Existence is confirmed; currency and accessibility per the verification requirement are not. AMBIGUOUS is more accurate than CONFIRMED.

## Honest-Fail Declaration

> The overall AI conclusion that Company X meets SOC2 Type II requirements and is audit-ready is not supported by evidence and is contradicted by it. Specific failures: (1) MFA is demonstrably not enforced on all systems — the company's own policy document lists active exceptions with no remediation until Q3 2026 at earliest. (2) Incident response testing is not quarterly — only one exercise is documented and the next is indefinitely postponed. (3) The encryption and TLS evidence covers only a subset of systems and connection types, with no confirmed complete inventory. (4) Three of the five SOC2 Trust Service Criteria — Availability, Processing Integrity, and Privacy — have zero evidentiary coverage in any submitted artifact. (5) No independent, qualified assessor evidence exists. The AI assessment must not be used to support a SOC2 audit submission or customer trust representations. Remediation of MFA exceptions, restoration of quarterly IR testing cadence, full-scope encryption and TLS verification, and a qualified gap assessment across all five Trust Service Criteria are required before any readiness claim can be made.

## What Was NOT Checked

- The witness review is limited to artifacts referenced by the verifier: mfa_policy, ir_plan, and encryption_audit. No independent access to underlying systems, configurations, or raw logs was available.
- The completeness of the artifact set is unknown — there may be additional controls documentation not submitted for review that could alter findings for CLAIM-3, CLAIM-4, or CLAIM-5.
- The identity, qualifications, and methodology of the party who produced the encryption_audit artifact are not established, limiting confidence in its conclusions.
- The audit observation period is undefined — SOC2 Type II requires sustained evidence over a minimum 6-month period, and all artifacts appear to be point-in-time documents.
- No evidence was reviewed for Availability, Processing Integrity, Privacy Trust Service Criteria, or for vendor management, change management, logical access reviews, or business continuity controls.
- The witness cannot assess whether compensating controls exist for the documented MFA exceptions that might partially mitigate risk in a SOC2 context.

## Evidence Bundle

All receipts available in this directory. Every claim links to its evidence source.
Verify independently.
