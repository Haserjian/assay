# Checkpoint to Decision Receipt Mapping

Status: v0.1 normative mapping note

**Time semantics are `request -> evaluation -> decision -> resolution`.**
**Packaging semantics are `receipt -> proof pack -> reviewer packet`.**

Current checkpoint state is a materialized view over the append-only attempt
chain, not a mutable artifact.

## Purpose

This note defines how checkpoint lifecycle artifacts relate to Decision
Receipts without collapsing into each other.

Checkpoint artifacts and Decision Receipts answer different questions:

- checkpoint artifacts govern one attempted boundary crossing over time
- Decision Receipts record constitutional authority acts
- proof packs bundle the resulting chain into a verifiable unit
- reviewer packets disclose a bounded view of that chain to a relying party

They can reference each other. They are not interchangeable.

## Attempt Identity

A checkpoint is not a single mutable object. It is an append-only chain around
one concrete attempted boundary crossing.

- `checkpoint_type`
  - boundary class, such as `outbound_action.send_email`
- `checkpoint_attempt_id`
  - one concrete attempted crossing of that boundary
- artifact ids
  - records emitted inside that attempt, such as `request_id`,
    `evaluation_id`, `receipt_id`, and `resolution_id`

This split prevents one "checkpoint object" from trying to hold:

- attempted intent
- changing evidence posture
- multiple authority acts
- terminal operational truth

## Lifecycle Table

| Lifecycle stage | Artifact | Primary question answered | Authoritative for | Not authoritative for |
|-----------------|----------|---------------------------|-------------------|-----------------------|
| 1 | `checkpoint_request` | What crossing is being attempted? | attempted boundary crossing identity, initiator, requested consequence, target boundary | policy verdict, release eligibility, terminal outcome |
| 2 | `checkpoint_evaluation` | What does the current evidence and policy posture permit? | eligibility posture at time `t`, evidence bundle, typed gaps, route class, release conditions, relying party, disclosure profile, freshness window | binding authority act, terminal operational outcome |
| 3 | `Decision Receipt` | What did an authority decide? | constitutional verdict, disposition, authority scope, policy pinning, evidence sufficiency, provenance completeness | full preflight detail, final operational outcome |
| 4 | `checkpoint_resolution` | What actually happened to the attempt? | terminal operational state of the attempt | why authority allowed or denied the crossing |

## Packaging Table

| Packaging layer | Artifact | Purpose |
|-----------------|----------|---------|
| Atomic | receipt | one verifiable event or decision record |
| Bundle | proof pack | verifiable bundle of the relevant chain |
| Disclosure | reviewer packet | selective-disclosure surface for the relying counterparty |

Proof pack and reviewer packet are not lifecycle events. They are packaging
layers over lifecycle artifacts.

## Ownership by Artifact

### `checkpoint_request`

Authoritative for:

- attempted crossing identity
- requested consequence
- initiating actor
- target system or boundary
- stable attempt identity

Not authoritative for:

- whether the crossing is currently eligible
- whether an authority approved or refused it
- what ultimately happened in the world

### `checkpoint_evaluation`

Authoritative for:

- current evidence posture
- typed gaps and contradictions
- route or eligibility class
- release conditions
- evidence freshness window
- relying party and disclosure profile

Not authoritative for:

- binding constitutional meaning
- final operational outcome
- post hoc proof completeness after release

### `Decision Receipt`

Authoritative for:

- authority act under pinned policy
- constitutional verdict
- disposition
- evidence sufficiency and provenance completeness at decision time

Not authoritative for:

- full boundary-specific preflight state
- final dispatch or effect outcome

### `checkpoint_resolution`

Authoritative for:

- terminal operational state of the attempt
- whether release occurred
- whether dispatch occurred
- whether effect was observed or remained uncertain

Not authoritative for:

- the full preflight evidence posture
- the constitutional rationale for the authority act

## Cardinality Rules

Per `checkpoint_attempt_id`:

- exactly `1` request
- `0..n` evaluations
- `0..n` Decision Receipts
- `0..1` terminal resolution
- `0..n` execution or effect receipts

Interpretation:

- a single attempt may be re-evaluated as evidence refreshes or expires
- a single attempt may receive multiple authority acts, such as
  `DEFER -> APPROVE` or escalation followed by override
- a single attempt has at most one terminal operational outcome

Retries should not create multiple terminal resolutions for one attempt.

- if the retry is a materially new crossing, create a new `checkpoint_attempt_id`
- if the retry is part of execution under an already released attempt, record it
  in execution or effect receipts

## Reference Edges

Later artifacts point backward only. Earlier artifacts do not point forward into
unknown future state.

This preserves:

- append-only history
- no future-id prophecy
- no mutation pressure on early artifacts
- replay from what was actually known at each moment

Recommended identifier edges:

- request
  - `checkpoint_attempt_id`
  - `request_id`

- evaluation
  - `checkpoint_attempt_id`
  - `request_id`
  - `evaluation_id`
  - optional `supersedes_evaluation_id`

- Decision Receipt
  - `checkpoint_attempt_id`
  - `based_on_evaluation_id`
  - `receipt_id`
  - optional `parent_receipt_id`
  - optional `supersedes`

- resolution
  - `checkpoint_attempt_id`
  - `resolution_id`
  - `final_evaluation_id`
  - `decision_receipt_ids`

The append-only rule is:

- later artifacts may cite prior artifacts
- prior artifacts must never be patched to cite later ones

## Route vs Verdict

The checkpoint route and the Decision Receipt verdict are not the same thing.

- evaluation route classifies what the current evidence posture permits
- Decision Receipt verdict records what an authority actually did with that
  posture

Working route-to-verdict mapping:

| Evaluation route | Typical Decision Receipt meaning |
|------------------|----------------------------------|
| `allow_immediately` | `APPROVE` with disposition `execute` |
| `allow_if_approved` | `DEFER` with disposition `defer_with_obligation` |
| `block` | `REFUSE` with disposition `block` |
| `escalate` | `ABSTAIN` or `CONFLICT` with disposition `escalate` |

This is a mapping, not an identity rule. Authorities may still refuse an
otherwise technically eligible crossing under higher-order policy.

## Resolution Semantics

Resolution is terminal per attempt and records what became true after the
authority path completed or failed.

Recommended terminal resolution classes:

- `blocked`
- `expired`
- `review_rejected`
- `released`
- `dispatch_failed`
- `effect_unconfirmed`
- `effect_observed`
- `proof_incomplete`

Resolution is not a boolean approval marker. In particular:

- approval is not dispatch
- dispatch is not observed effect
- observed effect is not proof completeness

## Materialized View Rule

`Current checkpoint state` must be computed from the append-only chain, not
stored as a mutable artifact.

Derived states may include:

- latest route
- latest Decision Receipt verdict
- approval pending
- expired
- blocked
- released
- dispatch failed
- effect observed

These are read-model outputs over the attempt chain.

## Four `outbound_action.send_email` Scenarios

These scenarios are the normative v0 mapping set.

### 1. Blocked outright

1. emit `checkpoint_request`
2. emit `checkpoint_evaluation` with route `block`
3. emit Decision Receipt with verdict `REFUSE` and disposition `block`
4. emit `checkpoint_resolution` with terminal state `blocked`

What this proves:

- evaluation and refusal can terminate an attempt without release

### 2. Allow-if-approved -> approved -> released

1. emit `checkpoint_request`
2. emit `checkpoint_evaluation` with route `allow_if_approved`
3. emit Decision Receipt with verdict `DEFER` and disposition
   `defer_with_obligation`
4. append human approval evidence
5. if freshness requires it, emit a new evaluation referencing the same
   `checkpoint_attempt_id`
6. emit Decision Receipt with verdict `APPROVE` and disposition `execute`
7. emit `checkpoint_resolution` with terminal state `released`

What this proves:

- defer, approval evidence, re-evaluation, constitutional approval, and
  release are distinct moments

### 3. Allow-if-approved -> no approval -> expired

1. emit `checkpoint_request`
2. emit `checkpoint_evaluation` with route `allow_if_approved`
3. emit Decision Receipt with verdict `DEFER` and disposition
   `defer_with_obligation`
4. no qualifying approval arrives before the validity window closes
5. emit `checkpoint_resolution` with terminal state `expired`

What this proves:

- time can terminate an attempt without a later approval decision

### 4. Released -> dispatch failed

1. emit `checkpoint_request`
2. emit `checkpoint_evaluation` with route `allow_immediately` or complete the
   approval-gated path above
3. emit Decision Receipt with verdict `APPROVE` and disposition `execute`
4. attempt the outbound send
5. append execution or effect receipt showing dispatch failure
6. emit `checkpoint_resolution` with terminal state `dispatch_failed`

What this proves:

- constitutional approval is not operational success

## Anti-Confusion Rules

- `checkpoint_evaluation` is not automatically a Decision Receipt
- `checkpoint_resolution` must never overwrite evaluation truth
- Decision Receipt must not absorb full preflight detail or final outcome
- human approval evidence belongs in the chain as appended evidence, not as a
  mutation of prior artifacts
- proof pack is the verifiable bundle, not the lifecycle
- reviewer packet is the reliance surface, not the trust root

## Bottom Line

Checkpoint is about governed boundary crossing.
Decision Receipt is about authority.
Proof pack is about verifiability.
Reviewer packet is about reliance.

Keeping those roles separate is what prevents the model from collapsing back
into receipt soup.
