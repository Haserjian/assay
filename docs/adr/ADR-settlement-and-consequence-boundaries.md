# ADR: Settlement and Consequence Boundaries

## Status

Proposed.

## Context

Assay now has a public product sentence:

```text
Assay makes reliance reviewable.
```

PR Gate and Packet Viewer make that concrete. PR Gate produces signed review
packets for pull requests, and Packet Viewer renders the packet as a
human-readable reliance surface: what the reviewer may rely on, what must not
be inferred, how to verify, and how to challenge.

The broader Loom/Guardian/AgentMesh organism uses a deeper vocabulary:
settlement, consequence, authority, provenance, execution, and memory. That
language is useful internally, but it must not leak into public Assay positioning
in a way that makes Assay sound like it settles truth, authorizes production
actions, or governs the world by itself.

The boundary sentence is:

```text
Assay makes reliance reviewable.
Loom makes consequence governable.
```

## Decision

Assay will remain the admissible evidence compiler and reliance-review layer.
Settlement and consequence are higher-order authority acts owned by the Loom
organism and its policy/runtime components.

A packet can support a settlement. A packet is not itself a settlement unless a
named authority accepts it under a named policy and records that acceptance.

The internal architecture will use these boundary concepts.

### DecisionEnvelope

A `DecisionEnvelope` records a bounded judgment made by a verifier, policy
engine, Guardian check, reviewer, or other decision authority.

It should identify:

- subject
- decision
- reasons
- policy or verifier profile
- evidence references
- signer or authority
- caveats and non-claims
- challenge path

Assay PR Gate's `decision.json` and `verify_report.json` are concrete examples
of decision-bearing artifacts, but this ADR does not declare a single universal
wire schema for all decision envelopes.

### SettlementEnvelope

A `SettlementEnvelope` records that an authorized party accepted one or more
decisions or evidence packets as operationally settled under a named policy.

It should identify:

- claim or action being settled
- accepting authority
- accepted evidence and decision references
- resulting consequence class
- caveats or residual obligations
- challenge or appeal window, when applicable
- supersession and revocation path

Assay packets may be inputs to a settlement. Assay does not create a settlement
merely by verifying a packet.

### ConsequenceReceipt

A `ConsequenceReceipt` records that authority changed world or system state.

Examples:

- a pull request was merged
- a payout was executed
- a credential was widened
- a policy was promoted
- a MemoryGraph fact was committed
- a model output was sent to an external party

It should identify:

- triggering settlement or authority decision
- actor or system that executed the consequence
- before/after state, where available
- evidence references
- rollback or mitigation path, where applicable

Consequence receipts are different from raw event receipts. Raw events record
what happened. Consequence receipts record what became true because authority
acted.

### AuthorityEnvelope

An `AuthorityEnvelope` records who or what had authority to decide, settle, or
enforce.

It should identify:

- authority identity
- scope
- capabilities
- policy basis
- signer or delegation chain
- expiry or revocation conditions

This is the boundary that prevents a signed artifact from being mistaken for
permission to act.

### ReplayContract

A `ReplayContract` defines what it would mean to replay or re-evaluate an
episode, packet, or consequence path.

It should identify:

- replay target
- inputs and environment assumptions
- nondeterminism sources
- expected invariants
- allowed drift
- explicitly non-replayable parts

Replay may upgrade reliance, but absence of replay must remain visible as
`NOT_RUN`, `NOT_EVALUATED`, or an equivalent bounded state.

## Component Boundaries

### Assay

Assay compiles, verifies, signs, renders, and exposes challenge paths for
evidence packets. It answers:

```text
What may a reviewer rely on, and what must not be inferred?
```

Assay should stay cold, portable, inspectable, and verifier-oriented. Public
Assay docs should not claim that Assay settles truth, grants production
approval, or governs consequences.

### PR Gate

PR Gate is Assay's first live packet feed. It turns pull request evidence into a
signed review decision bound to a commit.

`PASS` means Assay found no policy reason to stop normal review. It does not
mean automatic merge approval.

### Packet Viewer

Packet Viewer is the human-readable reliance surface. It shows the packet,
reliance boundary, verification path, and challenge path. It is not the proof
engine and does not replace CLI verification.

### Loom

Loom owns consequence governance: deciding when evidence, policy, and authority
are sufficient for a consequential action to become settled operational reality.

### Guardian

Guardian authorizes or blocks actions under policy. Guardian verdicts can be
inputs to Assay packets, settlement envelopes, or consequence receipts.

### Execution Spine

Execution Spine enforces authorized actions and must emit receipts for actions
with consequence.

### AgentMesh

AgentMesh traces lineage and provenance for agent work. Lineage can support
Assay packets and settlement review, but lineage alone is not settlement.

### MemoryGraph

MemoryGraph should store settled meaning, not every raw event. Raw traces and
receipts remain available as evidence, but MemoryGraph promotion requires a
settlement or equivalent authority boundary.

## Non-Goals

This ADR does not:

- add a new Assay wire format
- add a ledger to Assay
- create a hosted packet registry
- define a full Loom runtime protocol
- require public Assay docs to use settlement language
- make Packet Viewer authoritative
- make PR Gate approvals equivalent to merge approvals
- make AgentMesh lineage equivalent to proof or settlement
- define MemoryGraph write APIs

## Consequences

- Public Assay language should remain centered on reliance review.
- Internal architecture may use settlement and consequence terminology, but only
  behind clear component boundaries.
- Future Review Agents may draft packet sections, but they do not settle claims
  or authorize consequences.
- Future Counter-Packets challenge packets or settlements by identifying missing
  evidence, stale policy, signer-trust objections, replay divergence,
  overbroad claims, contradictory evidence, or scope errors.
- Future MemoryGraph promotion should reference a settlement or equivalent
  authority record instead of raw activity alone.

## Wording Rules

Use in public Assay surfaces:

```text
Assay makes reliance reviewable.
review packet
reliance boundary
what may and may not be inferred
verification path
challenge path
```

Avoid in public Assay surfaces unless the document is explicitly internal or
architectural:

```text
settlement machine
consequence ledger
constitutional runtime
recognition engine
MemoryGraph authority
```

Use internally:

```text
Assay makes reliance reviewable.
Loom makes consequence governable.
```

## Open Questions

- Which Loom component owns the canonical `SettlementEnvelope` schema?
- Should `ConsequenceReceipt` be a distinct receipt family or a constrained
  specialization of existing decision/lifecycle receipts?
- When should a human approval receipt become a settlement input versus a
  settlement authority?
- What minimum authority record is required before MemoryGraph promotion?
- How should Counter-Packets target settlements as distinct from packets?
