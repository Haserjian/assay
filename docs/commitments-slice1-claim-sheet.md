# Commitments Slice 1 Claim Sheet

**Status:** current public claim sheet for the Slice 1 commitment wedge
**Date:** 2026-04-20
**Purpose:** short external statement of what the current commitments slice
does and does not prove

---

## Evidence Baseline

This claim sheet is evidence-first. It is grounded in the merged commitment
slice on `origin/main`, not in planning memory or deck language.

- Verified repo baseline: `origin/main` at `36ad7f5`
- Merged PR inventory reviewed before writing:
  - `#82` — Slice 1: commitment fulfillment receipts and store-order hardening
  - `#83` — add `assay commitments explain <id>` read-only inspection CLI
  - `#84` — lock terminal-closure invariants via Hypothesis property tests
  - `#85` — add `list` and `overdue` CLI commands
  - `#86` — decide global-vs-per-commitment ordering
  - `#87` — extract shared lifecycle projection
  - `#89` — clean projection review nits
- No merged PR `#88` exists in the slice. That is a numbering gap, not an
  implied hidden capability.
- Focused local validation run before writing:
  - `160 passed, 2 warnings`
  - test files: `test_commitment_lifecycle`, `test_store_hardening`,
    `test_explain_commitment`, `test_commitment_terminal_invariant`,
    `test_commitments_list_overdue`, `test_commitment_projection_parity`

---

## One-Line Claim

Assay records what was promised, what happened, and whether the promise was
kept as structured, order-aware evidence that refuses false closure.

---

## What This Proves Today

At the current Slice 1 boundary, Assay can prove:

- commitments are first-class receipts, separate from observations and separate
  from terminal fulfillment
- `result.observed` does not close a commitment on its own
- a terminal fulfillment only closes a commitment if the commitment was already
  registered and a prior observation explicitly referenced it
- a terminal encountered before its anchor does not become a valid closure by
  being nearby in the store
- `assay commitments list`, `assay commitments overdue`, and
  `assay commitments explain <id>` are read-only views over the same lifecycle
  projection
- corrupt or mixed store state fails closed instead of being normalized into a
  clean answer
- `_store_seq` is stamped and validated as witnessed append order for replay,
  deterministic traversal, and tamper detection inside the issuing store

---

## What This Does Not Prove Today

Slice 1 does not currently prove:

- cryptographically signed commitment receipts
- third-party verifiable commitment proof packs or reviewer packets by default
- hostile multi-tenant or multi-host enforcement
- counter-signing or independent witness attestation for a commitment
- inherited-duty semantics such as waiver, discharge, escalation, or obligation
  carry-forward
- that a human promise or reported result was semantically true before Assay
  admitted it as evidence
- legal, regulatory, or compliance sufficiency

---

## Trust Assumptions

Use this surface only with these assumptions stated out loud:

- the issuing store is still a trusted operator boundary
- `_store_seq` is storage-layer append order, not a universal semantic
  happens-before claim across unrelated commitments
- the current writer discipline is single-host `fcntl.flock`, not distributed
  consensus
- imported, operator-entered, or externally sourced evidence is still evidence
  input, not automatically ground truth
- local integrity checks and reader behavior are real; external non-repudiation
  is not yet part of the commitment surface

---

## Required Artifacts For A Credible External Claim

For the current commitments claim to be externally reviewable, keep these
artifacts available:

- a store or fixture containing the commitment lifecycle being discussed
- the read-only command outputs for the same data set:
  - `assay commitments list`
  - `assay commitments overdue`
  - `assay commitments explain <commitment-id>`
- the relevant receipt files when the claim depends on exact order or exact
  references
- the ordering memo that defines the storage-vs-semantics split:
  `docs/doctrine/COMMITMENT_ORDERING.md`
- the focused test slice or equivalent validation evidence when claiming the
  invariants are still live

If those artifacts are missing, the surface may still be useful for internal
discussion, but the external claim is weaker.

---

## What A Hostile Reviewer Would Ask

### Is this just a fancy audit log?

No. A normal audit log can record events without carrying any closure law.
This slice records three distinct nouns with different roles:

- `commitment.registered`
- `result.observed`
- `fulfillment.commitment_kept` / `fulfillment.commitment_broken`

The readers refuse to collapse them. Observation does not count as closure, and
an orphan terminal does not count as closure either.

### What stops a malicious signer or operator from generating a receipt without doing the work?

Today, nothing in this slice should be described as external non-repudiation.
That is an intentional limit of the claim. The current proof is inside the
issuing-store boundary:

- guarded write paths enforce the normal closure rules
- fail-closed readers refuse invalid closure patterns even if a terminal is
  appended directly
- integrity checks catch malformed or mixed store state

That is useful and real, but it is not the same as an independent counterparty
verifying a signed commitment packet.

### How is this different from OpenTelemetry spans or generic traces?

Spans tell you what executed and when. This slice answers a different question:
what was promised, what was observed, and whether the promise was legitimately
closed. It is promise-lifecycle adjudication, not execution telemetry.

### What if someone appends a forged terminal directly to the store?

The normal emitter is supposed to block that path. If someone bypasses it, the
readers still refuse to count the terminal as closure unless the commitment was
already registered and a prior observation explicitly anchored it.

---

## Parked Amendment

**Amendment:** inherited-duty semantics for discharge, waiver, escalation, and
carry-forward obligations

**Status:** proposed, not yet normative

**Trigger:** first external Loom-adoption or buyer conversation that exercises
inherited-duty semantics

Until that trigger fires, do not describe Slice 1 commitments as full
obligation management or inherited-duty settlement.

---

## Safe External Wording

Safe to say:

- "Assay records what was promised, what happened, and whether the promise was kept, as structured evidence that refuses false closure."
- "A terminal receipt does not close a commitment unless prior anchored evidence already exists."
- "If the store is corrupt, the readers fail closed instead of pretending the data is clean."

Not safe to say yet:

- "Cryptographically signed commitment receipts"
- "Externally verifiable commitment packet"
- "Multi-host consensus ordering"
- "Inherited obligation / waiver / escalation support"
- "Tamper-proof" when you mean "tamper-evident inside the issuing store"

---

## See Also

- [Commitments — Slice 1 Demo Packet](demo/commitments_slice1_demo.md)
- [Commitment Ordering — Global vs Per-Commitment](doctrine/COMMITMENT_ORDERING.md)
- [Reviewer Packets](reviewer-packets.md)
