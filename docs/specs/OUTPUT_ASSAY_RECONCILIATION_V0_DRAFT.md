# Output Assay Reconciliation v0 Draft

Status: Draft
Created: 2026-04-30

This document reconciles the proposed Output Assay witness layer with the
existing Assay kernel nouns. It is a namespace and projection contract, not an
implementation spec.

## Placement Decision

This draft belongs in `docs/specs/` because it defines an
architecture-relevant boundary between proposed Output Assay artifacts and
existing kernel claim/support artifacts. There is no existing Output Assay
spec surface to update, and the boundary should be pinned before code creates
parallel semantics.

## Decision

Output Assay is an observation layer, not a belief layer.

It may observe that an artifact contains a value-bearing unit. It must not
cause Assay's kernel to believe that observed content is true, supported, or
adopted.

The primitive is:

```text
artifact.unit_observed
```

not:

```text
artifact.claim_observed
```

Claims are one possible unit type. Other valuable units include constraints,
actions, questions, decisions, risks, emotions, insights, commitments, and
instructions.

## Core Invariant

Observation is not assertion.

No `artifact.unit_observed` receipt may create, modify, strengthen, weaken, or
delete a kernel claim. Kernel belief-state mutation requires an explicit
transition receipt.

## Canonical Nouns

### `artifact.unit_observed`

Witness-layer receipt.

Means:

> This artifact appears to contain this value-bearing unit.

Does not mean:

- the unit is true
- the unit is endorsed by Assay
- the unit is supported by external reality
- the unit is adopted into the kernel
- the artifact author personally believes the unit

Draft shape:

```json
{
  "receipt_type": "artifact.unit_observed",
  "unit_id": "unit_...",
  "unit_type": "claim | constraint | action | question | decision | risk | emotion | insight | commitment | instruction",
  "source_role": "evidence | assertion | instruction | context | example | unknown",
  "artifact_hash": "sha256:...",
  "artifact_span": {
    "text": "...",
    "start_char": 0,
    "end_char": 0
  },
  "normalized_text": "...",
  "observer": {
    "kind": "llm | human | tool",
    "provider": "openai",
    "model": "..."
  },
  "observation_confidence": 0.0,
  "observation_status": "draft | guardian_passed | guardian_warned | guardian_blocked",
  "notes": ""
}
```

`source_role` is required because a claim-like sentence may appear as evidence,
an example, quoted context, an instruction, or an adversarial specimen rather
than as the artifact's own assertion.

`observation_status` records the Guardian verdict on the observation itself,
distinct from any judgment about the artifact. It is set by the application
when stamping the receipt:

- `draft` — produced by the observer (LLM, human, or tool), not yet validated.
- `guardian_passed` — Guardian validated the observation cleanly.
- `guardian_warned` — Guardian flagged concerns but did not block.
- `guardian_blocked` — Guardian rejected the observation as unusable evidence.

Guardian status determines whether an observation is usable evidence for
downstream operations such as promotion. It does not determine whether the
observed content is true. Extraction hygiene is not truth.

### `output_assay.run`

Envelope receipt for one assay execution over one artifact under one
policy/version.

Means:

> This artifact was assayed under this policy, producing these observed units,
> support assessments, failure modes, compression outputs, and Guardian result.

Authoritative for:

- assay version and policy version
- artifact hash
- declared and inferred intent class
- observed unit references
- support-gap assessments over observed units
- failure modes and evidence spans
- compression outputs
- Guardian result
- extraction failure references, when applicable

Not authoritative for:

- kernel truth
- durable belief updates
- operator adoption of observed claims
- external factual verification unless a later verifier tier explicitly ran

### `output_assay.extraction_failure`

Quarantine receipt for a failed assay extraction.

Means:

> The system failed to produce a trustworthy Output Assay run artifact.

This is distinct from a valid `output_assay.run` describing a low-quality
artifact. Bad text is not bad extraction.

### `claim.observation_promoted`

Transition receipt from witness layer to kernel layer.

Means:

> An authorized operator or process ratified an observed claim into a kernel
> claim assertion.

This receipt preserves why the kernel is allowed to consider a claim that was
first seen inside an artifact.

Draft projection path:

```text
artifact.unit_observed
  -> claim.observation_promoted
  -> claim.asserted
```

Promotion to `claim.asserted` applies only to `unit_type = claim` in v0. Other
unit types are observation-only in v0; routing to action queues, risk ledgers,
memory surfaces, or other kernel surfaces is out of scope and deferred.

Promotion does not bypass falsifier discipline. A promoted claim defaults to
`falsifier_status = absent` and `severity = warning` unless the promotion
event explicitly names otherwise.

### `claim.asserted`

Existing kernel belief-layer receipt.

Means:

> Assay now carries this as an asserted claim inside the kernel.

Output Assay cannot emit this receipt directly from LLM extraction. It can
only supply provenance for a later promotion.

### `claim.support_changed`

Existing kernel support lifecycle receipt.

Applies to kernel claims, not raw artifact observations. Output Assay may
recommend support posture for observed units, but it cannot mutate kernel
support state without promotion.

## v0 Representation Decision

`artifact.unit_observed` is the logical primitive. Whether it is materialized
as standalone receipt rows or as nested draft objects inside the
`output_assay.run` envelope is a v0 implementation choice, not a semantic
choice.

In v0:

- Observed units MAY be physically nested inside `output_assay.run`.
- They MUST carry stable `unit_id` values and the
  `receipt_type = "artifact.unit_observed"` identity regardless of physical
  layout.
- Kernel code MUST NOT depend on physical standalone storage of observed
  units until the schema graduates.
- Promotion records MUST preserve provenance to `run_id`, `unit_id`,
  `artifact_hash`, and `artifact_span`, regardless of physical layout.

Rationale: calibration will likely revise `unit_type` boundaries,
`source_role` semantics, span rules, and confidence semantics. Stamping
standalone receipts before calibration creates migration gravity. Logical
primitive now, physical receipt later. Promotion to standalone receipt rows
happens at v0.1 / v1, after calibration stabilizes the schema.

## Rules

1. LLM extraction may produce only draft observations, never kernel claims.
2. Application code stamps observation receipts and `output_assay.run`
   envelope receipts.
3. Guardian validates span presence, author-neutrality, schema shape,
   support-gap flags, low-signal flags, and extraction boundaries.
4. Promotion to `claim.asserted` requires an explicit
   `claim.observation_promoted` transition receipt.
5. Promotion to `claim.asserted` applies only to `unit_type = claim` in v0.
6. Other unit types remain observation-only until separate routing surfaces
   exist.
7. Every promoted kernel claim must retain provenance back to the observed
   unit and source artifact hash.
8. Promotion does not bypass falsifier discipline. If the promotion event does
   not name a falsifier posture, the promoted claim records
   `falsifier_status = absent`; if it does not name severity, it records
   `severity = warning`.
9. A low-quality artifact produces a valid `output_assay.run` with Guardian
   warnings or block state.
10. Failed extraction produces `output_assay.extraction_failure`.
11. No silent repair is allowed.
12. No invented spans are allowed.
13. Observed units are logical `artifact.unit_observed` receipts whether
    physically nested inside `output_assay.run` or stamped standalone. Kernel
    consumers MUST treat them as logical receipts.
14. A `claim.observation_promoted` receipt MUST reference `run_id`,
    `unit_id`, `artifact_hash`, and `artifact_span` from the source
    observation. Promotion without full provenance is forbidden.
15. Promotion from a `guardian_blocked` observation is forbidden in v0. No
    override field is defined; future overrides require an explicit spec
    amendment.

## Compatibility Strategy

This is additive if implemented under an experimental `output_assay`
namespace. It must not change the meaning of existing kernel receipts.

Breaking or migration-required changes would include:

- allowing LLM extraction to emit `claim.asserted`
- treating `artifact.unit_observed` as kernel belief state
- mutating `claim.support_changed` from raw observations
- auto-promoting high-confidence observations without a transition receipt
- using observed non-claim units as claim assertions

## Calibration Requirement

The calibration set is the executable spec for Output Assay behavior. Minimum
v0 fixture mix:

- 5 positive controls from existing strong Assay specs
- 5 padded or speculative documents, including the duplicated Output Assay
  proposal draft
- 5 mixed-quality technical or architecture answers
- 3 ordinary business artifacts
- 2 non-claim artifacts, such as a brainstorm and an apology or support note

Each fixture should label:

- expected intent class
- expected observed units
- `source_role` for each observed unit
- expected support gaps
- expected failure modes
- expected Guardian verdict
- whether any observed claim may be promoted

Analyzer code is downstream of this fixture set.

## Non-Goals For This Draft

- No provider integration
- No CLI contract
- No JSON Schema contract
- No calibration fixture files
- No kernel migration
- No compiled packet integration
- No routing of non-claim units to other runtime surfaces

## Open Questions

1. Should `claim.observation_promoted` be a kernel receipt in v0, or remain an
   Output Assay transition receipt until promotion semantics are tested?
2. Should support assessments over observed units reuse the kernel
   falsifier/proof-debt vocabulary directly, or carry a weaker observation-only
   support taxonomy that can be projected later?

(Q1 from the prior draft — standalone vs nested representation — is resolved
in the "v0 Representation Decision" section above.)
