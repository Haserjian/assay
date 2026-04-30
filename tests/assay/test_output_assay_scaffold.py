"""Tests for the local-only Output Assay analyzer scaffold."""

from __future__ import annotations

import pytest

from assay.output_assay import (
    OutputAssayAnalyzerScaffold,
    OutputAssayDraftValidationError,
    output_assay_analysis_draft_schema,
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

    assert any(
        "unexpected_top_level" in error for error in exc_info.value.errors
    )


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