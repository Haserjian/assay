# Claim Preflight Matrix v0

Public AI claims are becoming evidentiary objects.

Assay's job in this lane is not to decide whether an AI system is safe,
compliant, or approved. Its job is to make a public claim reviewable before
that claim appears in a PR, sales deck, security questionnaire, model card,
policy blog, release note, or compliance response.

```text
claim -> evidence -> scope -> boundary -> signed review
```

## Product Frame

Assay prevents unsupported AI claims from becoming operational liabilities.

The preflight question is:

```text
Before we publish this claim, what evidence would survive review?
```

The output is a reviewer-facing decision record. A PR comment or dashboard can
summarize the decision, but the signed packet remains authoritative.

## Claim Object

Each claim row must carry these fields:

| Field | Meaning |
|---|---|
| `claim_id` | Stable identifier for this preflight claim. |
| `claim_text` | The exact claim being reviewed. |
| `claim_type` | Category such as `frontier_risk_report`, `capability_classification`, `moderation_process`, `regulatory_classification`, or `marketing_substantiation`. |
| `source_string` | Exact source locator and short source text that triggered review. |
| `evidence_required` | Evidence items required before the claim can pass. |
| `evidence_present` | Evidence items already present in the packet. |
| `verdict_channel` | Channel that owns the decision, for example `claim`, `trust_policy`, or `classification`. |
| `verdict` | `PASS`, `NEEDS_REVIEW`, or `BLOCK`. |
| `non_claims` | Explicit statements that must not be inferred from this verdict. |
| `reviewer_action` | Stable next action for the reviewer. |
| `proof_floor` | Minimum proof tier reached by the current packet. |

`PASS` means only that the packet contains enough evidence for the exact
reviewed claim. It never means safe, compliant, production-approved, complete,
or generally trustworthy.

## Seed Matrix

| Public claim class | Example signal | Required packet |
|---|---|---|
| Frontier risk report | Anthropic's Opus 4.6 sabotage risk report | Risk-report provenance, scope, threat model, evaluation summary, redaction boundary, non-claims. |
| Capability classification | OpenAI's GPT-5.5 Instant High capability treatment | Model/version, eval basis, reasoning-effort boundary, deployment mode, safeguard boundary. |
| NCII moderation | Microsoft NCII and Take It Down process claims | Reporting flow, hash matching, removal SLA, appeal path, human review policy, real/synthetic parity. |
| EU high-risk classification | EU AI Act Article 6 / Annex III draft guidance | Intended use, provider/deployer role, Annex mapping, exception reasoning, reviewer signoff. |
| AI marketing substantiation | FTC Cox Active Listening settlement | Exact marketing line, evidence basis, opt-in proof, prohibited inference checks. |

## Verdict Semantics

| Verdict | Meaning | Reviewer action |
|---|---|---|
| `PASS` | Evidence satisfies this exact claim under this profile. | `proceed_to_normal_review` |
| `NEEDS_REVIEW` | Evidence is incomplete, stale, weak, or needs human interpretation. | `require_human_review` |
| `BLOCK` | Claim exceeds the packet, contradicts evidence, or lacks required substantiation. | `block_publication` |

Weak evidence should produce `NEEDS_REVIEW`, not fake certainty.

## Proof Floors

| Proof floor | Meaning |
|---|---|
| `T0_OBSERVATION` | One observation was captured, hashed, and optionally signed. |
| `T1_PACKET` | Evidence is assembled into a packet with explicit claim bindings and non-claims. |
| `T2_SIGNED_REVIEW` | A signed review decision binds the claim, evidence, and verdict. |
| `T3_EXTERNAL_WITNESS` | An external witness, reviewer, or transparency mechanism independently anchors the decision. |

## Non-Claims

Every preflight output must include a `non_claims` block. At minimum, preflight
does not prove:

- overall model safety
- legal compliance
- production approval
- external truth beyond included evidence
- replay equivalence unless the replay channel ran
- signer identity beyond the declared trust anchor

## Marketing Overclaim Test

A marketing claim fails preflight when it says more than the packet proves.

Example:

| Packet proves | Proposed public claim | Preflight result |
|---|---|---|
| One configured endpoint returned output matching one refusal predicate for one named probe at one time. | Our frontier model is safe against hazardous requests. | `BLOCK` |
| A reported NCII removal workflow has documented intake, duplicate matching, timestamped removals, and appeal handling. | We remove valid NCII reports and known identical copies within 48 hours under this workflow. | `NEEDS_REVIEW` until SLA evidence is present; `PASS` only if present. |

## Example Files

The first concrete fixture set lives in:

```text
examples/claim-preflight/
  claims.json
  evidence_requirements.json
  sample_verdict.json
```

These examples are teaching fixtures. They are not legal advice, compliance
certifications, or live assertions about the named organizations.
