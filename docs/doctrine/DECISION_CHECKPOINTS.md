# Decision Checkpoints Doctrine

Status: v0.1 working doctrine

This document defines the product and governance posture for Assay decision checkpoints.

## Purpose

Assay governs AI at decision checkpoints: explicit boundaries where model output would cross into the world and create cost, risk, or irreversible state change.

A checkpoint is not a model call.
A checkpoint is a typed attempt to cross a governed boundary.

Examples:

- send outbound email
- approve code merge
- deploy to production
- export customer data
- mutate policy
- issue refund
- refuse a regulated action

## Core thesis

Before AI crosses a decision checkpoint, it must produce an evidence bundle that policy can verify.

The scarce unit is the checkpoint, not the trace.
The value is burden-of-proof routing, not post hoc explanation.

## Artifact ladder

There are three artifact levels:

1. `trace`
Operational exhaust. Useful for debugging, but not approval-grade by itself.

2. `evidence_bundle`
Typed evidence, verifier outputs, policy inputs, gaps, and uncertainty needed to review or replay a checkpoint.

3. `attestation`
A stronger, transferable form of the evidence bundle that has been policy-validated and may be signed or otherwise made tamper-evident.

In v0, the normative object is the evidence bundle with policy verdict.
Attestation is the stronger form we earn later.

## Counterparty model

A checkpoint matters only when someone else must rely on it.

Every checkpoint artifact must make the relying party explicit:

- who is relying on the checkpoint
- what consequence they are accepting
- what replay or review rights they need
- what disclosure profile they are allowed to see

Without a relying party, a checkpoint bundle is just internal process.

## Governing principles

### 1. The scarce unit is the checkpoint

We do not attempt to make all model behavior approval-grade.
We make specific boundary crossings governable.

### 2. Evidence is mandatory; explanation is optional

Explanation may help a human reviewer.
It is not sufficient proof.

Evidence means artifacts that can be checked, hashed, replayed, or independently verified.
Explanation is one witness among several, and usually a low-authority one.

### 3. Policy evaluates bundles, not narratives

Policy consumes typed evidence, verifier outputs, thresholds, and explicit gaps.
It does not accept a generic confidence score or a persuasive story.

### 4. Negative outcomes are successful governed outcomes

Valid checkpoint results include:

- `allow_immediately`
- `allow_if_approved`
- `block`
- `refuse`
- `escalate`

Blocking unsupported action is correct behavior, not product failure.

### 5. Missingness is first-class output

The system must represent missing or degraded evidence explicitly:

- `absent`
- `stale`
- `contradictory`
- `redacted`
- `unverifiable`

Premium output often looks like a precise negative bundle, not a positive explanation.

### 6. Shadow only matters if it changes routing

Shadow evaluation exists to forecast:

- required evidence
- likely failure modes
- expected uncertainty
- recommended route

If shadow does not affect routing or later calibration, it is decorative and should not exist.

### 7. Separate the evidence clock from the release clock

Checkpoint evaluation and final release do not happen on the same clock.

- The evidence clock asks whether the bundle is still fresh and valid.
- The release clock asks whether the action is being released now.

If release occurs after evidence validity expires, the system must re-evaluate or block.

### 8. Human approval is evidence

Human signoff is not outside the system.
It is a first-class evidence item and part of the checkpoint history.

### 9. Replay happens at the verifier layer

Model reasoning may not be reproducible.
Verifier-layer replay must be.

Checkpoint artifacts must preserve enough information to re-run verifier logic against the same evidence references, policy version, and thresholds.

### 10. Selective disclosure is part of the artifact

Counterparties often need the verdict and proof shape without raw prompts or sensitive content.
Disclosure rules must be part of the object model, not a later rendering trick.

## Relationship to existing Assay artifacts

### Proof Packs

Proof packs remain the signed, offline-verifiable kernel for execution evidence.
Checkpoint bundles can be compiled into or referenced by proof packs when a workflow needs counterparty-grade proof.

### Decision Receipts

Decision Receipts remain the constitutional record of a determination by an authority.
Checkpoint bundles do not replace them.

A checkpoint bundle answers:
"Was this boundary crossing sufficiently evidenced and policy-eligible?"

A Decision Receipt answers:
"What authority decided what, under what policy, and with what disposition?"

The two artifacts are complementary.

### Reviewer Packets

Reviewer packets remain the cross-boundary rendering surface for another team.
They can wrap checkpoint evidence bundles or later attestations when the relying party is external.

## Product posture

Assay is not a generic observability layer for all model activity.

Assay is a control plane for governed AI checkpoint crossings.

