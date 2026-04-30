"""Tests for the local-only Output Assay analyzer scaffold."""

from __future__ import annotations

import hashlib

import pytest

from assay.output_assay import (
    ObservationStatus,
    OutputAssayAnalyzerScaffold,
    OutputAssayDraftValidationError,
    OutputAssayRunEnvelope,
    compute_output_assay_artifact_hash,
    output_assay_analysis_draft_schema,
    stamp_output_assay_run,
    validate_output_assay_analysis_draft,
)


def _valid_payload() -> dict[str, object]:
    return {
        "intent_class": "technical_answer",
        "summary": "The draft extracts one claim and one instruction without stamping any canonical receipt fields.",
        "observed_units": [
            {
                "unit_type": "claim",
                "source_role": "assertion",
                "artifact_span": {
                    "text": "Observation is not assertion.",
                    "start_char": 0,
                    "end_char": 29,
                },
                "normalized_text": "Observation is not assertion.",
                "observation_confidence": 0.94,
                "notes": "Candidate claim pending Guardian review.",
            },
            {
                "unit_type": "instruction",
                "source_role": "instruction",
                "artifact_span": {
                    "text": "Action: validate locally first.",
                    "start_char": 30,
                    "end_char": 61,
                },
                "normalized_text": "Action: validate locally first.",
                "observation_confidence": 0.81,
                "notes": "Non-claim units remain observation-only in v0.",
            },
        ],
    }


def _artifact_text() -> str:
    return "Observation is not assertion.\nAction: validate locally first.\n"


def test_validate_output_assay_analysis_draft_accepts_valid_payload() -> None:
    draft = validate_output_assay_analysis_draft(_valid_payload())

    assert draft.intent_class.value == "technical_answer"
    assert len(draft.observed_units) == 2
    assert draft.observed_units[0].unit_type.value == "claim"


def test_validate_output_assay_analysis_draft_rejects_non_object_root() -> None:
    with pytest.raises(OutputAssayDraftValidationError) as exc_info:
        validate_output_assay_analysis_draft(["not", "an", "object"])

    assert exc_info.value.errors == ["(root): payload must be an object"]


def test_validate_output_assay_analysis_draft_rejects_extra_top_level_fields() -> None:
    payload = _valid_payload()
    payload["unexpected_top_level"] = "nope"

    with pytest.raises(OutputAssayDraftValidationError) as exc_info:
        validate_output_assay_analysis_draft(payload)

    assert any("unexpected_top_level" in error for error in exc_info.value.errors)


def test_validate_output_assay_analysis_draft_rejects_invalid_span_order() -> None:
    payload = _valid_payload()
    payload["observed_units"][0]["artifact_span"]["end_char"] = -1  # type: ignore[index]

    with pytest.raises(OutputAssayDraftValidationError) as exc_info:
        validate_output_assay_analysis_draft(payload)

    assert any(
        "artifact_span.end_char must be >= artifact_span.start_char" in error
        for error in exc_info.value.errors
    )


def test_output_assay_analyzer_scaffold_schema_is_provider_safe_root_object() -> None:
    scaffold = OutputAssayAnalyzerScaffold()
    schema = output_assay_analysis_draft_schema()

    assert scaffold.draft_schema() == schema
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert "anyOf" not in schema
    assert "oneOf" not in schema
    assert set(schema["required"]) == {"intent_class", "summary", "observed_units"}


def test_compute_output_assay_artifact_hash_is_deterministic() -> None:
    artifact_text = _artifact_text()
    expected_hash = (
        f"sha256:{hashlib.sha256(artifact_text.encode('utf-8')).hexdigest()}"
    )

    assert compute_output_assay_artifact_hash(artifact_text) == expected_hash


def test_stamp_output_assay_run_computes_hash_and_stamps_receipt_fields() -> None:
    run = stamp_output_assay_run(_artifact_text(), _valid_payload())

    assert isinstance(run, OutputAssayRunEnvelope)
    assert run.receipt_type == "output_assay.run"
    assert run.artifact_hash == compute_output_assay_artifact_hash(_artifact_text())
    assert run.intent_class.value == "technical_answer"
    assert len(run.observed_units) == 2
    assert all(
        unit.receipt_type == "artifact.unit_observed" for unit in run.observed_units
    )
    assert all(unit.artifact_hash == run.artifact_hash for unit in run.observed_units)
    assert all(unit.observer.provider == "local" for unit in run.observed_units)


def test_output_assay_run_rejects_mismatched_observed_unit_hash() -> None:
    run_payload = stamp_output_assay_run(
        _artifact_text(),
        _valid_payload(),
    ).model_dump(mode="json")
    run_payload["observed_units"][0]["artifact_hash"] = "sha256:" + ("0" * 64)

    with pytest.raises(ValueError, match="artifact_hash must match"):
        OutputAssayRunEnvelope.model_validate(run_payload)


def test_stamp_output_assay_run_is_deterministic_for_same_input() -> None:
    run_one = stamp_output_assay_run(_artifact_text(), _valid_payload())
    run_two = stamp_output_assay_run(_artifact_text(), _valid_payload())

    assert run_one.run_id == run_two.run_id
    assert [unit.unit_id for unit in run_one.observed_units] == [
        f"{run_one.run_id}_u001",
        f"{run_one.run_id}_u002",
    ]
    assert [unit.unit_id for unit in run_one.observed_units] == [
        unit.unit_id for unit in run_two.observed_units
    ]


def test_stamp_output_assay_run_keeps_promotion_closed_before_guardian() -> None:
    run = stamp_output_assay_run(_artifact_text(), _valid_payload())

    assert all(
        unit.observation_status == ObservationStatus.DRAFT
        for unit in run.observed_units
    )
    assert all(
        unit.promotion_eligibility.status.value == "ineligible"
        for unit in run.observed_units
    )
    assert (
        run.observed_units[0].promotion_eligibility.reason == "guardian_review_pending"
    )
    assert run.observed_units[1].promotion_eligibility.reason == "non_claim_unit"


def test_output_assay_analyzer_scaffold_can_stamp_local_run() -> None:
    scaffold = OutputAssayAnalyzerScaffold()
    run = scaffold.stamp_local_run(_artifact_text(), _valid_payload())

    assert run.artifact_hash == compute_output_assay_artifact_hash(_artifact_text())
    assert run.summary == _valid_payload()["summary"]
