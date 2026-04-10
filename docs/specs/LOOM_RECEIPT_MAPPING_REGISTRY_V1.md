# Loom Receipt Mapping Registry v1

**Date**: 2026-04-08
**Status**: DRAFT — normative mapping registry for Loom-family receipt handling in Assay

---

## Purpose

This registry defines how specific Loom receipt families relate to the current
Assay artifact stack.

It exists to prevent two failure modes:

- silently treating a rich Loom receipt as proof-pack-compatible when it is not
- silently collapsing a rich Loom receipt into an Assay artifact without
  declaring what was preserved, dropped, or shifted to a higher layer

This is a **mapping contract**, not a philosophical note.

It is the source of truth for whether a Loom receipt family is:

- admitted into the proof-pack kernel
- transformed before packing
- carried only at the compiled-packet layer
- explicitly out of scope

---

## Layer Reminder

The layer model remains:

- **Loom receipts**: rich upstream runtime/governance language
- **Proof pack**: signed transport-grade evidence kernel
- **Compiled packet**: canonical claim/reviewer artifact
- **Reviewer packet**: VendorQ-specific wrapper

Proof-pack verification proves the proof-pack contract.
Compiled-packet and reviewer-packet verification prove higher-order binding and
review semantics on top of proof packs.

---

## Status Vocabulary

| Status | Meaning |
|--------|---------|
| `current` | Shipped behavior in the current public Assay surface |
| `planned` | Preferred mapping target; not yet a shipped bridge/enforcement path |
| `forbidden` | Must not be admitted into the proof-pack kernel in v1 |

Only rows marked `current` describe shipped behavior.
Rows marked `planned` are implementation targets, not release claims.
As of this v1 draft, no Loom rows are marked `current` yet.

---

## Handling Mode Vocabulary

| Mode | Meaning |
|------|---------|
| `pack-native` | Receipt is emitted directly in a proof-pack-admissible Assay type |
| `namespaced passthrough` | Receipt is emitted directly as a canonical lowercase namespaced token accepted by the proof-pack contract |
| `transformed` | Source receipt is projected into a proof-pack-admissible Assay artifact before packing |
| `compiled-packet-only` | Rich semantics are carried at compiled-packet / reviewer-packet level, not the proof-pack kernel |
| `out_of_scope` | Receipt family is intentionally not admitted into the proof-pack kernel |

---

## Admission Rule

The proof-pack admission policy currently accepts only:

1. a fixed flat allowlist of legacy Assay receipt types
2. lowercase namespaced dotted tokens matching the proof-pack regex

That means raw Loom `receipt_type` values such as `DIPReceipt`,
`ProofTierReceipt`, `ReplayBundleReceipt`, and `ChoirReceipt` are **not**
directly proof-pack-admissible today.

Any bridge from Loom into a proof pack must therefore do one of the following:

- emit an already-admissible Assay-native receipt type
- emit a canonical lowercase namespaced token
- stay out of the proof-pack kernel and surface the semantics in compiled packets

If a Loom receipt family has no row in this registry, or its row is not marked
`current`, direct proof-pack ingestion MUST fail closed.

---

## Transformation Requirements

When a row uses `transformed`, the bridge MUST preserve mapping provenance.

The transformed artifact MUST carry:

- `source_receipt_type`
- `source_receipt_id`
- `source_receipt_sha256`
- `mapping_registry_version`
- `mapping_mode`
- `lossiness`

`lossiness` MUST be one of:

- `none`
- `declared_lossy`

If information material to reviewer or policy interpretation is dropped, the
mapping must be marked `declared_lossy` and the dropped dimensions named in the
registry row.

---

## Registry

| Loom receipt family | Primary role in Loom | Direct proof-pack admission today | Preferred handling mode | Assay target artifact / token | Status | Verifier guarantee | Declared lossiness / notes |
|---------------------|----------------------|-----------------------------------|-------------------------|-------------------------------|--------|--------------------|----------------------------|
| `DIPReceipt` | Deterministic input, model, code, and environment provenance root | Forbidden as raw `DIPReceipt` | `transformed` | canonical namespaced receipt `loom.dip/v1` | `planned` | `assay verify-pack` proves integrity of the transformed projection only | Preserve digests and environment fingerprint. Do not compress this into coarse attestation fields alone. |
| `DIPReproReceipt` | Reproducibility check against a DIP | Forbidden as raw `DIPReproReceipt` | `transformed` | canonical namespaced receipt `loom.dip_repro/v1` | `planned` | `assay verify-pack` proves integrity of the transformed projection only | Preserve `dip_id`, `matched`, fingerprint comparison summary, and anchor reference. |
| `AnchorReceipt` | External anchoring / witness metadata | Forbidden as raw `AnchorReceipt` | `out_of_scope` | none in proof-pack kernel | `forbidden` | none at proof-pack level | Anchoring belongs to signer/ledger/witness layers until a dedicated bridge exists. |
| `EpistemicSnapshotReceipt` | Snapshot of epistemic/governance posture at decision time | Forbidden as raw `EpistemicSnapshotReceipt` | `transformed` | Assay flat type `governance_posture_snapshot` | `planned` | `assay verify-pack` proves the projected posture snapshot only | `declared_lossy`: full U-I-M, coherence, and dignity context exceed current flat proof-pack vocabulary. |
| `ProofTierReceipt` | Guardian proof-tier and route decision | Forbidden as raw `ProofTierReceipt` | `transformed` | Assay flat type `decision_v1` | `planned` | `assay verify-pack` proves the transformed decision artifact only | `declared_lossy`: route/tier/gates must be explicitly mapped; do not imply full ProofTier semantics unless preserved. |
| `ContradictionStone` | Detected contradiction under Guardian policy | Forbidden as raw `ContradictionStone` | `compiled-packet-only` | compiled-packet claim binding or packet-side note | `planned` | packet verification can prove binding to a proof root; `assay verify-pack` proves nothing about contradiction semantics by itself | Keep contradiction severity and reasons out of flat proof-pack surrogates unless a specific mapping is defined later. |
| `ThreadStone` | Narrative linkage across related receipts | Forbidden as raw `ThreadStone` | `out_of_scope` | none in proof-pack kernel | `forbidden` | none at proof-pack level | Narrative thread construction is not kernel evidence. Carry only at disclosure/report layers if needed. |
| `ChoirReceipt` | Thread closure and summary | Forbidden as raw `ChoirReceipt` | `out_of_scope` | none in proof-pack kernel | `forbidden` | none at proof-pack level | Summary receipts are presentation/narrative objects, not kernel transport artifacts. |
| `ReplayBundleReceipt` | Deterministic replay bundle and reproducibility proof | Forbidden as raw `ReplayBundleReceipt` | `transformed` | canonical namespaced receipt `loom.replay_bundle/v1` | `planned` | `assay verify-pack` proves integrity of the transformed projection only | Preserve replay digests, match result, and runner identity. |
| `EvaluationReceipt` | Canonical evaluation metrics artifact | Forbidden as raw `EvaluationReceipt` | `transformed` | canonical namespaced receipt `loom.evaluation/v1` | `planned` | `assay verify-pack` proves integrity of the transformed projection only | Preserve metric payloads and artifact hashes; packet layer remains responsible for claim sufficiency. |
| `CalibrationEvidenceReceipt` | Calibration sufficiency replay evidence | Forbidden as raw `CalibrationEvidenceReceipt` | `transformed` | canonical namespaced receipt `loom.calibration_evidence/v1` | `planned` | `assay verify-pack` proves integrity of the transformed projection only | Preserve replay counts, metrics, and hashes; do not collapse to a green/red summary. |
| `ResearchReceipt` | Research-run execution and artifact provenance | Forbidden as raw `ResearchReceipt` | `transformed` | canonical namespaced receipt `loom.research/v1` | `planned` | `assay verify-pack` proves integrity of the transformed projection only | Preserve run-card, dataset, model-config, and dip linkage hashes. |
| `EvidenceReleaseApprovalReceipt` | Dual-control approval for evidence release | Forbidden as raw `EvidenceReleaseApprovalReceipt` | `compiled-packet-only` | compiled-packet or reviewer-packet governance metadata | `planned` | packet verification can prove packet integrity and nested proof roots, not quorum semantics by itself | This governs disclosure/release, not the execution kernel. |

---

## Immediate Rules For Implementers

1. **No raw CamelCase Loom receipt types go directly into proof packs.**
   They are not admitted by the current proof-pack contract.

2. **Do not invent a one-off transform in code without a registry row.**
   Add or update the row first.

3. **If the transform is lossy, declare that lossiness.**
   Silent compression is not allowed.

4. **Do not overclaim verifier coverage.**
   `assay verify-pack` proves the proof-pack contract and the bytes admitted into
   the pack. It does not become a blanket verifier for the full Loom ontology.

5. **Use compiled packets for reviewer semantics.**
   If the receipt family primarily affects claim interpretation, approval, or
   disclosure workflow, it probably belongs above the proof-pack kernel.

---

## Priority Implementation Order

The first useful bridge set is:

1. `DIPReceipt`
2. `DIPReproReceipt`
3. `EvaluationReceipt`
4. `CalibrationEvidenceReceipt`
5. `ResearchReceipt`

Reason:

- they carry high-value provenance/evaluation evidence
- they fit the proof-pack transport role better than narrative/governance summaries
- they can be projected into namespaced proof-pack tokens without pretending the
  kernel now understands the full constitutional runtime

The second bridge set is:

6. `EpistemicSnapshotReceipt`
7. `ProofTierReceipt`
8. `EvidenceReleaseApprovalReceipt`

Reason:

- these are semantically important
- but they risk semantic compression faster
- compiled-packet/reviewer layers are usually the safer first carrier

`ContradictionStone`, `ThreadStone`, and `ChoirReceipt` should stay out of the
kernel until there is a concrete need and a non-lossy contract.

---

## Non-Goals

This registry does not claim:

- that every Loom receipt family should enter the proof-pack kernel
- that namespaced admission implies deep semantic verification
- that compiled packets replace proof packs as the trust root
- that Assay already ships every planned bridge listed above

Its job is narrower:

to make Loom→Assay handling explicit, fail-closed, and implementation-ready.
