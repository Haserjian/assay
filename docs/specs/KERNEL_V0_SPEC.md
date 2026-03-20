# Kernel v0 Spec

Kernel v0 is the minimum law-bearing vocabulary that consequential cognition must compile into before it may act, refuse, promote durable memory, or mutate policy.

This document is protocol authority for the noun boundaries. Runtime implementations remain local and alias-first.

## Constitutional Rules

1. No consequential action or refusal boundary is complete without a `Claim` bundle and a `ProofBudgetSnapshot`.
2. No negative consequential boundary is complete without a `Denial`.
3. No durable memory promotion is complete without a `BeliefUpdate`.
4. Contradictions are law-bearing only when emitted as durable artifacts with lifecycle state.
5. State-of-world or shipped-status claims in repo docs must cite a code path, schema, or test.

## Canonical Nouns

### `Claim`

Authoritative for:
- proposition under scope
- current support posture via append-only support changes
- freshness/proof posture at assertion
- lineage and contradiction references

Not authoritative for:
- final action decision
- durable memory by itself
- policy truth outside its declared scope

Required fields:
- `claim_id`
- `statement`
- `scope`
- `status`
- `proof_tier`
- `freshness`
- `support_refs`
- `contradiction_ids`
- `lineage_refs`

Assay v0 alias:
- `ClaimAssertionArtifact` is the append-only assertion event.
- `ClaimSupportChangeArtifact` mutates posture over time.

### `Denial`

Authoritative for:
- proposed action path
- blocking law or policy basis
- missing evidence
- safer lawful alternative
- cheapest next evidence move
- upgrade conditions

Not authoritative for:
- permanent impossibility
- contradiction truth
- future policy outcome

Required fields:
- `denial_id`
- `proposed_action_ref`
- `blocking_law_refs`
- `missing_evidence_refs`
- `safer_alternative`
- `cheapest_next_evidence_move`
- `upgrade_conditions`
- `related_claim_ids`
- `proof_budget_snapshot_id`

Assay v0 alias:
- `DenialRecordArtifact`

### `Contradiction`

Authoritative for:
- conflict type
- scope
- participating claims/evidence
- severity
- resolution lifecycle
- replay references

Not authoritative for:
- which side is finally true
- policy mutation outcome

Required fields:
- `contradiction_id`
- `type`
- `scope`
- `claim_refs`
- `evidence_refs`
- `severity`
- `status`
- `replay_refs`

Assay v0 alias:
- `contradiction_registration`
- `contradiction_resolution`

Allowed lifecycle states:
- `open`
- `contained`
- `settled`
- `superseded`

### `BeliefUpdate`

Authoritative for:
- belief-state mutation
- prior/new posture
- settlement status
- durability class
- lineage

Not authoritative for:
- domain execution outcome
- packaging or UI

Required fields:
- `update_id`
- `claim_id`
- `prior_state`
- `new_state`
- `settlement_status`
- `durability_class`
- `trigger_refs`
- `rationale`
- `lineage_refs`

Assay v0 alias:
- `BeliefUpdateArtifact`

### `ProofBudgetSnapshot`

Authoritative for:
- boundary kind
- required proof tier
- current proof tier
- deficit posture
- next evidence move
- escalation posture
- related claim ids

Not authoritative for:
- truth itself
- memory promotion by itself

Required fields:
- `snapshot_id`
- `boundary_kind`
- `required_tier`
- `current_tier`
- `deficit`
- `next_evidence_move`
- `escalation_posture`
- `claim_ids`

Assay v0 alias:
- `ProofBudgetSnapshotArtifact`

## Append-Only Rules

- Kernel artifacts are immutable after emission.
- Relationship changes occur through new artifacts, not mutation-in-place.
- Backward references must resolve to earlier or same-boundary artifacts.
- Derived views may summarize kernel state but are never the source of law.

## Assay Boundary Insertion Points

First enforced Assay boundary:
- `outbound_action.send_email`

Required emission at decision boundary:
- `ClaimAssertionArtifact`
- `ContradictionRegistrationArtifact` when checkpoint evaluation carries contradiction evidence
- `ProofBudgetSnapshotArtifact`

Required emission at blocked/refused boundary:
- `DenialRecordArtifact` with `related_claim_ids`, `proof_budget_snapshot_id`, and contradiction ids when present

Required emission at checkpoint resolution boundary:
- `ContradictionResolutionArtifact` for each registered contradiction
  - Negative resolutions (blocked/refused/escalated): `claim_a_prevails`
  - Positive resolutions (released): `out_of_scope`
  - Other outcomes: `deferred`

Deferred in Assay v0:
- durable memory promotion enforcement
- repo-wide noun migration
