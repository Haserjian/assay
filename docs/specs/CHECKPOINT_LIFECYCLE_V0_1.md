# Checkpoint Lifecycle v0.1

Status: draft normative lifecycle for governed checkpoint artifacts

This document defines the lifecycle split for Assay checkpoints. The goal is to prevent one object from trying to be request, evaluation, approval, and final release at the same time.

This document governs time semantics for checkpoint artifacts.
Packaging semantics live elsewhere.

- time semantics: `request -> evaluation -> decision -> resolution`
- packaging semantics: `receipt -> proof pack -> reviewer packet`

Lifecycle artifacts are append-only records over one attempted boundary crossing.
They are not packaging containers.

## Why the split exists

A single checkpoint crossing has at least three distinct moments:

1. the action is requested
2. evidence and policy are evaluated
3. the action is resolved or released

Collapsing these into one mutable object creates semantic drift:

- an item looks both approved and pending
- human approval mutates historical truth
- freshness and release timing get blurred
- replay cannot tell what was known when

v0 therefore separates the lifecycle into three artifacts.

## Attempt identity

A checkpoint is not one mutable object. It is an append-only chain around one
concrete attempted boundary crossing.

The identity split is:

- `checkpoint_type`
  - the boundary class, such as `outbound_action.send_email`
- `checkpoint_attempt_id`
  - one concrete attempted crossing of that boundary
- artifact ids
  - records emitted inside that attempt, such as `request_id`,
    `evaluation_id`, `receipt_id`, and `resolution_id`

This split prevents one "checkpoint object" from trying to carry:

- attempted intent
- evolving evidence posture
- one or more authority acts
- terminal operational truth

## Relationship to packaging

Lifecycle artifacts and packaging layers are separate concerns.

| Layer | Artifact | Purpose |
|-------|----------|---------|
| Lifecycle | `checkpoint_request` / `checkpoint_evaluation` / `checkpoint_resolution` | govern one attempted crossing over time |
| Packaging | receipt | atomic verifiable event |
| Packaging | proof pack | verifiable bundle of relevant chain |
| Packaging | reviewer packet | selective disclosure surface for a relying party |

Proof packs and reviewer packets may package checkpoint lifecycle artifacts.
They are not lifecycle stages themselves.

## Artifact model

### 1. `checkpoint_request`

Purpose:
Capture the attempted boundary crossing and its relying-party context.

Questions answered:

- what crossing was attempted
- by whom
- for what target system
- who will rely on the result

Properties:

- created once per attempted crossing
- immutable after creation
- exactly one per `checkpoint_attempt_id`
- if intent changes materially, create a new `checkpoint_attempt_id`, not a second request

### 2. `checkpoint_evaluation`

Purpose:
Capture the pre-execution evidence bundle, shadow forecast, verifier outputs, policy thresholds, and policy outcome.

Questions answered:

- what evidence existed at evaluation time
- what evidence was missing or degraded
- what policy said about the crossing
- whether the crossing is eligible now, eligible only with review, or ineligible

Properties:

- references exactly one request
- immutable after creation
- may be superseded by a new evaluation if evidence changes or the prior evaluation expires
- is the normative v0 artifact defined by schema
- there may be `0..n` evaluations per `checkpoint_attempt_id`

### 3. `checkpoint_resolution`

Purpose:
Capture how the evaluated crossing was ultimately resolved.

Questions answered:

- was the action released, rejected, blocked, escalated, or cancelled
- who approved or rejected it
- whether a freshness re-check was performed at release time
- what evidence was appended during resolution

Properties:

- references exactly one evaluation
- immutable after creation
- should append evidence, never rewrite the evaluation
- is emitted only when the crossing reaches a terminal state
- there is at most one terminal resolution per `checkpoint_attempt_id`

## Cardinality rules

Per `checkpoint_attempt_id`:

- exactly `1` request
- `0..n` evaluations
- `0..1` terminal resolution
- `0..n` execution or effect receipts

Decision Receipts are a separate layer and may appear `0..n` times per attempt
depending on authority structure. See
`CHECKPOINT_DECISION_RECEIPT_MAPPING.md` for the authoritative boundary.

Retries do not create multiple terminal resolutions for one attempt.

- if a retry is a materially new crossing, create a new `checkpoint_attempt_id`
- if a retry is execution within an already released attempt, record it in execution or effect receipts

## Canonical states

The recommended state machine is:

```text
requested
  -> evaluated
    -> allow_immediately
      -> decision (optional constitutional layer)
        -> released
        -> dispatch_failed
    -> allow_if_approved
      -> decision (optional constitutional layer)
        -> released
        -> dispatch_failed
      -> review_rejected
      -> expired
    -> block
      -> blocked
    -> refuse
      -> refused
    -> escalate
      -> decision (optional constitutional layer)
      -> escalated
      -> re-evaluated
```

`allow_immediately`, `allow_if_approved`, `block`, `refuse`, and `escalate` are evaluation outcomes.

`released`, `dispatch_failed`, `review_rejected`, `expired`, `blocked`, `refused`, and `escalated` are resolution outcomes.

## Lifecycle invariants

1. Request, evaluation, and resolution are separate immutable records.
2. A resolution never mutates the evaluation it references.
3. If the intended action changes materially, emit a new request and a new evaluation.
4. If evidence changes materially, emit a new evaluation rather than patching the old one.
5. If release occurs after `evidence_valid_until`, re-evaluate or block.
6. Human approval is appended evidence on the resolution record.
7. Evaluation outcomes are about policy eligibility, not final release.
8. Resolution outcomes are about what actually happened, not what policy would have allowed.
9. Explanation-only witnesses may be recorded, but they must never satisfy a requirement that demands authoritative evidence.
10. Every evaluation must name the relying party and disclosure profile.
11. Later artifacts point backward only; earlier artifacts must never be patched to cite future state.
12. Current checkpoint state is a materialized view over the append-only chain, not a mutable artifact.

## Two clocks

Every checkpoint has two clocks that must remain explicit.

### Evidence clock

Tracks whether the evidence bundle is still fresh enough for the checkpoint type.

Relevant fields:

- `observed_at`
- `valid_until`
- `evidence_valid_until`
- freshness verifier outputs

### Release clock

Tracks when the crossing is actually released or resolved.

Relevant fields:

- `resolved_at`
- reviewer approval time
- final action execution time

If the release clock outruns the evidence clock, the evaluation must no longer authorize release on its own.

## Reference edges

Later artifacts point backward only. Earlier artifacts do not point forward
into unknown future state.

Recommended identifiers:

- request
  - `checkpoint_attempt_id`
  - `request_id`

- evaluation
  - `checkpoint_attempt_id`
  - `request_id`
  - `evaluation_id`
  - optional `supersedes_evaluation_id`

- resolution
  - `checkpoint_attempt_id`
  - `resolution_id`
  - `final_evaluation_id`
  - optional appended evidence refs

This preserves:

- append-only history
- no future-id prophecy
- no mutation pressure on early artifacts
- replay from what was actually known at each moment

## Relying party and disclosure

Each lifecycle artifact should preserve:

- `party_id`
- `role`
- `consequence`
- `disclosure_profile`

The same evaluation may be rendered differently for different relying parties, but the underlying evaluation record must not change.

## Missingness model

Evidence gaps must be typed.
The minimum v0 taxonomy is:

- `absent`
- `stale`
- `contradictory`
- `redacted`
- `unverifiable`

These are not render-time labels. They are part of the evidence semantics.

## Relationship to proof and attestation

In v0:

- evaluation emits an evidence bundle with policy verdict
- resolution appends the final release or refusal path

Later:

- the bundle can be signed as an attestation
- the full checkpoint lifecycle can be embedded into a proof pack
- reviewer packets can present a selective-disclosure view for counterparties

## Current state as a materialized view

`Current checkpoint state` must be derived from the append-only lifecycle chain.
It is not itself a mutable lifecycle artifact.

Examples of derived state:

- latest route
- approval pending
- expired
- blocked
- released
- dispatch failed
- effect observed

These are read-model outputs over one `checkpoint_attempt_id`.

## Example flow: blocked send

1. `checkpoint_request` asks to send an external email.
2. `checkpoint_evaluation` finds recipient verification absent and context stale.
3. Policy outcome is `block`.
4. `checkpoint_resolution` records `blocked`.

That is a successful governed outcome.

## Example flow: review-gated send

1. `checkpoint_request` asks to send an external email.
2. `checkpoint_evaluation` finds evidence sufficient but policy margin thin.
3. Policy outcome is `allow_if_approved`.
4. A human approver adds signoff evidence.
5. `checkpoint_resolution` records `released` only if the evidence clock is still valid at release time.

## Example flow: released then dispatch failed

1. `checkpoint_request` asks to send an external email.
2. `checkpoint_evaluation` finds the crossing eligible only with approval.
3. Human approval is appended as evidence.
4. Release revalidation passes.
5. Dispatch is attempted.
6. `checkpoint_resolution` records `dispatch_failed`.

This preserves that policy release and operational success are different facts.
