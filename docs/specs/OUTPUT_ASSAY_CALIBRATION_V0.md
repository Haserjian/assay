# Output Assay Calibration v0

Status: Draft
Created: 2026-04-30

This document defines the calibration contract for Output Assay v0. It is an
evaluation and fixture specification, not an analyzer implementation spec.

Calibration exists to verify observation behavior before model integration or
kernel projection. It answers: given an artifact and an intended policy lane,
what observations, Guardian outcomes, and promotion-eligibility judgments are
expected?

## Placement Decision

This document belongs in `docs/specs/` because it defines a durable,
architecture-relevant contract for evaluating Output Assay behavior. It is the
companion to `OUTPUT_ASSAY_RECONCILIATION_V0_DRAFT.md`: reconciliation defines
the nouns and projection boundaries; calibration defines the executable fixture
surface that will test those boundaries.

## Core Invariant

Calibration validates observation behavior, not kernel truth.

An expected observation says what the system should identify, normalize,
classify, and gate inside the artifact. It does not say the artifact is true,
the author is correct, or the observed unit should become kernel belief.

Guardian pass is extraction hygiene, not truth.

Promotion eligibility is not promotion.

## Calibration Scope

V0 calibration covers only the witness-layer and Guardian-layer surfaces:

- fixture metadata and declared assay lane
- expected `artifact.unit_observed` semantics
- expected Guardian verdicts over observations and the run envelope
- expected promotion eligibility for observed claims
- expected failure modes and compression outcomes when relevant

V0 calibration does not cover:

- external factual verification
- kernel `claim.asserted` creation
- kernel `claim.support_changed` mutation
- live model-provider behavior
- product UX, dashboards, or editor integrations

## Fixture Directory Layout

The fixture surface should be stable, explicit, and diffable.

Recommended v0 layout:

```text
tests/fixtures/output_assay/
  manifest.json
  README.md
  positive_controls/
    oa_001_compiled_packet_spec/
      artifact.md
      fixture.json
      expected_run.json
    oa_002_kernel_spec/
      artifact.md
      fixture.json
      expected_run.json
  negative_controls/
    oa_101_output_assay_duplicate_spec/
      artifact.md
      fixture.json
      expected_run.json
    oa_102_unanchorable_extraction/
      artifact.md
      fixture.json
      expected_run.json
  mixed_quality/
    oa_201_architecture_answer/
      artifact.md
      fixture.json
      expected_run.json
  business_artifacts/
    oa_301_status_update/
      artifact.md
      fixture.json
      expected_run.json
  non_claim_artifacts/
    oa_401_brainstorm/
      artifact.md
      fixture.json
      expected_run.json
```

Required files per fixture directory:

- `artifact.md` or `artifact.txt`: the raw artifact under assay.
- `fixture.json`: metadata describing the fixture intent and expected lanes.
- `expected_run.json`: the golden expected `output_assay.run` projection for
  comparison.

Optional files per fixture directory:

- `notes.md`: human rationale, labeling disputes, or revision history.
- `source.json`: provenance for where the artifact came from when the source is
  not obvious from repo context.

`manifest.json` should enumerate every fixture id, category, and active status
so runners can fail closed on missing or stray fixtures.

## Fixture Metadata Schema

`fixture.json` defines the calibration intent for one artifact.

Draft shape:

```json
{
  "fixture_id": "oa_001_compiled_packet_spec",
  "title": "Compiled Packet spec positive control",
  "status": "active",
  "category": "positive_control | negative_control | mixed_quality | business_artifact | non_claim_artifact",
  "artifact_path": "artifact.md",
  "artifact_hash": "sha256:...",
  "artifact_kind": "spec_proposal",
  "declared_intent_class": "argument | plan | technical_answer | decision_memo | status_update | creative | emotional_support | brainstorm | sales_pitch | research_summary",
  "expected_run_disposition": "pass | warn | block",
  "expected_failure_modes": [
    "redundancy_padding",
    "unearned_confidence"
  ],
  "expected_compression_behavior": "preserve | compress | quarantine",
  "promotion_surface": "observation_only",
  "labels": [
    "positive_control",
    "assay_spec"
  ],
  "notes": "Calibration validates internal support and observation quality only."
}
```

Required fixture metadata fields:

- `fixture_id`
- `title`
- `status`
- `category`
- `artifact_path`
- `artifact_hash`
- `declared_intent_class`
- `expected_run_disposition`
- `expected_failure_modes`
- `expected_compression_behavior`
- `promotion_surface`

Optional fixture metadata fields in v0:

- `artifact_kind`
- `labels`
- `notes`

Rules:

- `artifact_hash` must match the artifact content used in the fixture.
- `artifact_kind` may be used when the artifact form matters to calibration,
  such as `spec_proposal` for a duplicated doctrine draft or `support_note`
  for non-claim interpersonal text.
- `expected_run_disposition` is the expected Guardian-level disposition of the
  run envelope, not a truth judgment about the artifact.
- `promotion_surface` records whether the fixture includes any claim units that
  are eligible for promotion review. In v0 it is metadata only and never
  authorizes promotion by itself.
- Unknown fixture metadata fields should fail the schema check.

Lifecycle note:

- `manifest.status = seed` means the calibration corpus is still a seeded,
  evolving contract surface.
- `fixture.status = active` means the individual fixture participates in the
  current validator run.
- An active fixture is not a claim that Output Assay is production-ready; it
  only means the fixture is included in the current calibration contract.
- During `manifest.status = seed`, `failure_modes` remain open-set
  calibration vocabulary.
- Before the corpus graduates out of `seed`, recurring `failure_modes` should
  be consolidated into canonical failure-mode vocabulary.

## Expected Observed Unit Schema

`expected_run.json` must include the expected observed units for the artifact.
Observed units are logical `artifact.unit_observed` receipts whether they are
represented as nested objects in v0 or later materialized as standalone
receipts.

Minimum expected unit shape:

```json
{
  "receipt_type": "artifact.unit_observed",
  "unit_id": "unit_001",
  "unit_type": "claim | constraint | action | question | decision | risk | emotion | insight | commitment | instruction",
  "source_role": "evidence | assertion | instruction | context | example | unknown",
  "artifact_span": {
    "text": "...",
    "start_char": 0,
    "end_char": 42
  },
  "normalized_text": "...",
  "observation_status": "draft | guardian_passed | guardian_warned | guardian_blocked",
  "anchoring_expectation": "anchored | unanchorable",
  "anchoring_notes": "Future validator target for span or byte anchoring when applicable.",
  "promotion_eligibility": {
    "status": "eligible | ineligible",
    "reason": "claim_unit_with_clean_provenance",
    "reasons": [
      "unanchorable_extraction",
      "invented_span"
    ]
  }
}
```

Required expected-unit fields in v0:

- `receipt_type`
- `unit_id`
- `unit_type`
- `source_role`
- `artifact_span.text`
- `artifact_span.start_char`
- `artifact_span.end_char`
- `normalized_text`
- `observation_status`
- `promotion_eligibility`

Optional expected-unit fields in v0:

- `anchoring_expectation`
- `anchoring_notes`

Rules:

- Every expected unit must include exact span text, not only character ranges.
- `normalized_text` may differ from `artifact_span.text`, but the relationship
  must be explainable by deterministic normalization rules.
- Non-claim units must be observable in v0 when present in the artifact.
- Non-claim units must not be promotable in v0.
- `guardian_passed` does not mean the unit is true.
- `guardian_blocked` means the unit is not usable for promotion in v0.
- If an observation is `guardian_blocked`, its `promotion_eligibility.status`
  must be `ineligible`.
- `anchoring_expectation` is structural in v0. It records whether the fixture
  expects normal span anchoring or expects the observation to fail anchoring.
- Exact span-to-artifact membership and byte-bound checks are future validator
  work. The v0 contract may represent those expectations without enforcing them
  semantically yet.
- If `anchoring_expectation = unanchorable`, the observation should be
  `guardian_blocked` and promotion-ineligible.

## Expected Guardian Verdict Schema

Each fixture must encode the expected Guardian judgments at two levels:

- run envelope verdict
- per-observation status and warnings

Draft run-verdict shape:

```json
{
  "guardian_verdict": {
    "run_status": "pass | warn | block",
    "observation_counts": {
      "guardian_passed": 2,
      "guardian_warned": 1,
      "guardian_blocked": 0
    },
    "failure_modes": [
      "redundancy_padding",
      "attention_waste"
    ],
    "warnings": [
      "support_gap_present"
    ],
    "block_reasons": []
  }
}
```

Required Guardian-verdict fields:

- `guardian_verdict.run_status`
- `guardian_verdict.observation_counts`
- `guardian_verdict.failure_modes`
- `guardian_verdict.warnings`
- `guardian_verdict.block_reasons`

Rules:

- `run_status = block` means the run is not acceptable as clean evidence under
  the v0 policy surface. It does not mean the artifact is false.
- `failure_modes` must use canonical names from the Output Assay policy lane.
  Synonym drift is not allowed in fixtures.
- Observation-level `observation_status` and the aggregate
  `guardian_verdict.observation_counts` must agree exactly.
- Missing evidence spans, invented spans, or author/source judgment should be
  block conditions when the policy says they are forbidden.

## Expected Promotion Eligibility Schema

Promotion eligibility is a calibration label for claims observed in an
artifact. It is not a promotion event and does not create kernel belief.

Draft shape:

```json
{
  "promotion_eligibility": {
    "status": "eligible | ineligible",
    "reason": "claim_unit_with_clean_provenance",
    "reasons": [
      "missing_provenance",
      "guardian_blocked"
    ],
    "requires": [
      "unit_type=claim",
      "observation_status!=guardian_blocked",
      "run_id_present",
      "artifact_hash_present",
      "artifact_span_present",
      "explicit_operator_authority"
    ]
  }
}
```

Eligibility rules for v0:

- Only `unit_type = claim` may be labeled `eligible`.
- Eligibility requires usable provenance and a non-blocked observation.
- Eligibility must never imply that promotion happened.
- Eligibility must never imply the claim is true.
- Non-claim units must always be labeled `ineligible` in v0.
- `guardian_blocked` observations must always be labeled `ineligible` in v0.

Recommended ineligibility reasons:

- `non_claim_unit`
- `guardian_blocked`
- `missing_provenance`
- `unanchorable_extraction`
- `invented_span`
- `receipt_gap`
- `source_role_not_assertive`
- `support_gap_requires_review`
- `observation_status_warned_requires_operator_judgment`

## Expected Run Envelope Shape

`expected_run.json` should validate the full golden projection for one fixture.
At minimum it should contain:

```json
{
  "fixture_id": "oa_001_compiled_packet_spec",
  "input_hash": "sha256:...",
  "intent_class": "technical_answer",
  "summary": "...",
  "observed_units": [],
  "guardian_verdict": {},
  "compression": {
    "status": "preserve | compress | quarantine",
    "compressed_summary": "..."
  },
  "truth_verification": {
    "performed": false,
    "tier": "internal_support_only",
    "notes": "Calibration validates internal support and observation behavior, not external truth."
  }
}
```

The envelope may carry additional fields as the Output Assay schema evolves,
but v0 comparisons must remain stable on the required fields.

## Minimum v0 Fixture Mix

The minimum v0 set mirrors the reconciliation draft and must include both
positive and negative controls.

- 5 positive controls from existing strong Assay specs.
- 5 padded or speculative artifacts, including the duplicated Output Assay
  draft as a negative control.
- 5 mixed-quality technical or architecture answers.
- 3 ordinary business artifacts.
- 2 non-claim artifacts, such as a brainstorm and an apology/support note.

Required properties of the mix:

- At least one positive control must be expected to preserve signal with no
  major failure modes.
- At least one negative control must trigger `redundancy_padding`.
- At least one negative control must trigger `unearned_confidence` or a
  canonical claim-support-gap equivalent.
- At least one mixed-quality artifact must contain both promotable claim units
  and non-promotable non-claim units.
- At least one non-claim artifact must exercise the rule that observation is
  allowed while promotion remains forbidden.

## Golden Comparison Rules

Calibration comparisons should be deterministic and auditable.

Golden-comparison rules for v0:

1. Compare required fields exactly after canonical JSON normalization.
2. Fail closed on missing required fields.
3. Fail closed on extra unexpected top-level schema fields unless the fixture
   version explicitly allows them.
4. Compare `artifact_span.text` exactly; do not compare only offsets.
5. Compare normalized text exactly after the documented normalization step.
6. Compare failure mode names exactly; synonyms do not pass.
7. Compare observation counts exactly against observation statuses.
8. Compare promotion eligibility labels exactly.
9. Ignore provider-specific trace fields, timestamps, and runtime ids in golden
   comparisons.
10. A fixture fails if the system collapses a non-claim unit into a claim only
    to make promotion easier.
11. A fixture fails if the system treats `guardian_passed` as truth.
12. A fixture fails if the system treats promotion eligibility as a promotion
    event.

## Versioning And Drift Rules

Calibration fixtures are part of the spec surface.

- Any change to required schema fields requires an explicit spec update.
- Any rename of a canonical failure mode requires a fixture migration plan.
- New fixture categories may be added, but existing category semantics should
  not drift silently.
- Temporary analyzer regressions must not be resolved by weakening fixture
  expectations unless the spec changes first.

## Failure-Mode Vocabulary Lifecycle

Failure-mode strings are governed by manifest status.

- During `manifest.status = "seed"`, `expected_failure_modes` is open-set
  calibration vocabulary. Fixtures may introduce new failure-mode strings
  (e.g. `unanchorable_extraction`, `invented_span`, `receipt_gap`) without a
  prior canonical enum.
- Before corpus promotion out of `seed` status, recurring failure modes must
  be consolidated into a canonical vocabulary and enumerated in the spec.
  Synonyms must be merged. Single-occurrence strings should be reviewed for
  retention or removal.
- After consolidation, fixture-level introduction of new failure-mode strings
  requires an explicit spec update, matching the rename rule above.

This preserves calibration agility during seed while preventing noun
collision and silent vocabulary drift before the corpus is treated as
authoritative.

## Open Questions

1. Should v0 golden comparisons require exact ordering of observed units, or
   should ordering be canonicalized by `start_char` and `unit_id` before
   comparison?
2. Should the calibration manifest track disputed fixtures explicitly, or
   should disputes live only in per-fixture `notes.md` until resolved?
3. Should `expected_compression_behavior` remain a coarse enum in v0, or should
   compression carry a stricter token-ratio contract once real compression logic
   exists?
