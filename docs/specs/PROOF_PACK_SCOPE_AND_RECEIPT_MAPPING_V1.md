# Proof Pack Scope And Receipt Mapping v1

**Date**: 2026-04-08
**Status**: DRAFT — boundary clarification for the current shipped system

---

## Why This Exists

Assay proof packs are easy to over-interpret.

They are the signed evidence kernel for a run. They are **not** the whole
constitutional artifact language of the larger runtime, and they are **not**
the reviewer-facing claim artifact by themselves.

This document clarifies the current boundary between:

- richer upstream receipt ecosystems, including Loom
- the Assay proof-pack contract
- compiled packets and reviewer packets that sit above proof packs

The goal is simple: prevent semantic overclaim.

---

## Current Layer Model

### 1. Upstream Receipt Universe

The broader runtime may emit a heterogeneous receipt ontology with many distinct
classes, authorities, and governance semantics. Loom is the clearest current
example: it has a registry-backed family of receipts such as `DIPReceipt`,
`EpistemicSnapshotReceipt`, `ProofTierReceipt`, `ReplayBundleReceipt`,
`CalibrationEvidenceReceipt`, `ResearchReceipt`, `ContradictionStone`,
`ThreadStone`, and `ChoirReceipt`.

That ontology is broader than the proof-pack kernel.

### 2. Proof Pack

The proof pack is the transport-grade evidence kernel:

- deterministic receipt ordering
- JCS canonicalization
- signed manifest
- detached signature parity
- offline verification
- fail-closed run-boundary enforcement

Its job is to preserve and verify the **portable evidence bundle** Assay defines
today.

Its job is **not** to act as a blanket verifier for every richer upstream
receipt class or governance concept.

### 3. Compiled Packet / Reviewer Packet

These are the claim- and reviewer-shaped layers built on top of proof packs.

- **Compiled packet**: canonical, general-purpose, third-party-verifiable trust
  artifact
- **Reviewer packet**: specialized VendorQ-oriented wrapper

They bind claims, scope, and review semantics to one or more proof packs. They
do not replace the proof pack trust root.

---

## Current Receipt Admission Policy

Today the proof-pack admission policy intentionally recognizes a narrow receipt
vocabulary. The current code allows:

### A. Flat legacy types

- `ai_workflow`
- `capability_use`
- `challenge`
- `decision_v1`
- `governance_posture_snapshot`
- `grace_check`
- `guardian_check`
- `guardian_verdict`
- `mcp_tool_call`
- `model_call`
- `refusal`
- `revocation`
- `session_metadata`
- `supersession`

### B. Namespaced dotted types

Any type matching:

```text
^[a-z0-9_]+(?:\.[a-z0-9_]+)+(?:/[a-z0-9_]+)?$
```

This means the proof-pack surface can admit namespaced receipt tokens without
requiring the proof-pack verifier to understand the full schema family behind
them.

Loom-family namespaced tokens are a narrower special case: a `loom.*` token is
proof-pack-admissible only when its row is marked `current` in
[`LOOM_RECEIPT_MAPPING_REGISTRY_V1.md`](LOOM_RECEIPT_MAPPING_REGISTRY_V1.md).

That distinction matters.

---

## What Admission Means Today

Receipt admission into a proof pack means:

- the receipt shape is accepted by the pack builder
- the receipt is serialized into the deterministic pack
- the receipt participates in pack hashing and signature verification
- the receipt contributes to pack-level integrity and run-boundary checks

Receipt admission does **not** automatically mean:

- the proof-pack verifier understands the richer semantics of that receipt type
- the proof pack is a full verifier for the upstream receipt registry
- the attestation fields encode the full governance meaning of the upstream run

The proof-pack verifier proves the **pack contract**. It does not claim to prove
the entire ontology of every producer that may have emitted receipts upstream.

---

## How Richer Upstream Receipts Fit Today

The current system can be understood using five practical handling modes.

| Mode | What happens | Verifier guarantee today |
|------|--------------|--------------------------|
| `pack-native` | Receipt is emitted directly as a flat legacy proof-pack type | Full proof-pack integrity and pack-level checks |
| `namespaced passthrough` | Receipt is emitted as a namespaced dotted type and packed as-is | Full proof-pack integrity; no blanket claim of deep schema-family understanding |
| `transformed` | Rich upstream receipt may be summarized or projected into a proof-pack-friendly receipt before packing | Full proof-pack integrity for the transformed artifact only |
| `compiled-packet binding` | Rich semantics may be carried at the claim-binding / reviewer layer rather than the proof-pack layer | Proof-pack root is verified; higher-order claim semantics are verified by the packet system |
| `out of scope` | Receipt class is not admitted into the proof-pack kernel | No proof-pack claim is made about it |

Assay now ships an initial Loom-specific mapping registry in
[`LOOM_RECEIPT_MAPPING_REGISTRY_V1.md`](LOOM_RECEIPT_MAPPING_REGISTRY_V1.md).
Coverage is still incomplete, and only rows marked `current` in that registry
describe shipped behavior.
As of this v1 draft, there are no current Loom proof-pack mappings yet, so
Loom-family receipt admission remains fail-closed.

That remaining gap is still a mapping/bridge gap, not a reason to make the
proof-pack kernel swallow the whole runtime ontology.

---

## Attestation Semantics Today

The proof-pack attestation is best understood as a compact pack-scoped summary,
not a full constitutional artifact language.

### A. Cryptographic and identity anchors

These are load-bearing for pack identity and verification:

- `attestation_sha256`
- `pack_root_sha256`
- `signer_pubkey`
- `signer_pubkey_sha256`
- manifest `files`
- manifest `expected_files`

### B. Structural execution metadata

These describe what bundle was produced:

- `pack_id`
- `run_id`
- `suite_id`
- `claim_set_id`
- `claim_set_hash`
- `n_receipts`
- `ci_binding`
- `timestamp_start`
- `timestamp_end`
- `valid_until`
- `superseded_by`

### C. Pack-scoped semantic summaries

These are honest today, but low-resolution:

- `receipt_integrity`
- `claim_check`
- `assurance_level`
- `proof_tier`
- `time_authority`

Current meaning:

- `assurance_level: "L0"` means the current public pack is at the low/default
  assurance tier described by the public Assay trust posture
- `proof_tier: "signed-pack"` means this is a signed proof-pack artifact, not a
  richer governance-tier judgment
- `time_authority: "local_clock"` means the timestamps are not independently
  time-anchored in the attestation today

These fields should not be stretched into a claim that the proof pack already
encodes the full governance tier, constitutional proof tier, or provenance
ceiling of the broader runtime.

### D. Presentation artifacts

`verify_transcript.md` is a human-readable derivative. It is useful, but it is
not the root trust object.

The root trust object remains the signed manifest plus the kernel files it
protects.

---

## What Proof Packs Are Not

Proof packs are not:

- the whole Loom receipt ontology
- a blanket verifier for every upstream receipt family
- the reviewer-facing claim artifact by themselves
- the full governance or constitutional proof language
- the provenance ceiling for every environment Assay may later integrate with

They are the signed, portable evidence kernel underneath those higher layers.

---

## What Is Most Important To Formalize Next

The next missing step is not “more crypto.”

Assay now has an explicit Loom-specific mapping registry and a fail-closed
admission seam for Loom-family proof-pack tokens.

The next missing work is to move specific Loom receipt families from `planned`
to `current` with real bridge implementations, explicit provenance carriage,
and declared lossiness where compression is unavoidable.

Until those bridges ship, proof-pack integrity can be strong while Loom
interoperability remains intentionally narrow.

That should be treated as an implementation backlog on top of an explicit
semantic contract, not confused with a failure of the proof-pack kernel itself.
