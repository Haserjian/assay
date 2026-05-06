"""Tests for the local-only Output Assay analyzer scaffold."""

from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from assay.output_assay import (
    CompressionStatus,
    ObservationStatus,
    OutputAssayAnalyzerScaffold,
    OutputAssayDraftValidationError,
    OutputAssayExtractionFailure,
    OutputAssayExtractionStage,
    OutputAssayRunEnvelope,
    PromotionEligibilityStatus,
    RunDisposition,
    TruthVerificationTier,
    build_output_assay_extraction_failure,
    compute_output_assay_artifact_hash,
    guardian_validate_output_assay_run,
    output_assay_analysis_draft_schema,
    run_output_assay_locally,
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


def _non_assertive_payload() -> dict[str, object]:
    return {
        "intent_class": "technical_answer",
        "summary": "The draft observes a quoted example without treating it as the artifact's own assertion.",
        "observed_units": [
            {
                "unit_type": "claim",
                "source_role": "example",
                "artifact_span": {
                    "text": '"This framework guarantees perfect safety."',
                    "start_char": 0,
                    "end_char": 43,
                },
                "normalized_text": "This framework guarantees perfect safety.",
                "observation_confidence": 0.88,
                "notes": "Quoted example stays observable but not assertive.",
            }
        ],
    }


def _non_assertive_artifact_text() -> str:
    return '"This framework guarantees perfect safety."\n'


def _support_gap_payload() -> dict[str, object]:
    return {
        "intent_class": "technical_answer",
        "summary": "The draft contains one overconfident claim that should warn instead of pass.",
        "observed_units": [
            {
                "unit_type": "claim",
                "source_role": "assertion",
                "artifact_span": {
                    "text": "That guarantee means every reviewer will trust the artifact immediately.",
                    "start_char": 0,
                    "end_char": 72,
                },
                "normalized_text": "That guarantee means every reviewer will trust the artifact immediately.",
                "observation_confidence": 0.93,
                "notes": "Overclaim should require support-gap review.",
            }
        ],
    }


def _support_gap_artifact_text() -> str:
    return "That guarantee means every reviewer will trust the artifact immediately.\n"


def _blocked_payload() -> dict[str, object]:
    payload = deepcopy(_valid_payload())
    payload["observed_units"] = [
        payload["observed_units"][0],
        {
            "unit_type": "claim",
            "source_role": "assertion",
            "artifact_span": {
                "text": "This hidden guarantee does not appear in the artifact.",
                "start_char": 999,
                "end_char": 1052,
            },
            "normalized_text": "This hidden guarantee does not appear in the artifact.",
            "observation_confidence": 0.79,
            "notes": "This should block because the span is unanchorable.",
        },
    ]
    return payload


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


def test_guardian_validate_output_assay_run_passes_clean_assertive_claims() -> None:
    stamped_run = stamp_output_assay_run(_artifact_text(), _valid_payload())

    guarded_run = guardian_validate_output_assay_run(_artifact_text(), stamped_run)

    assert guarded_run.guardian_verdict is not None
    assert guarded_run.guardian_verdict.run_status == RunDisposition.PASS
    assert guarded_run.compression is not None
    assert guarded_run.compression.status == CompressionStatus.PRESERVE
    assert guarded_run.compression.compressed_summary == stamped_run.summary
    assert guarded_run.truth_verification is not None
    assert guarded_run.truth_verification.performed is False
    assert (
        guarded_run.truth_verification.tier
        == TruthVerificationTier.INTERNAL_SUPPORT_ONLY
    )
    assert guarded_run.guardian_verdict.observation_counts == {
        "guardian_passed": 2,
        "guardian_warned": 0,
        "guardian_blocked": 0,
    }
    assert (
        guarded_run.observed_units[0].observation_status
        == ObservationStatus.GUARDIAN_PASSED
    )
    assert (
        guarded_run.observed_units[0].promotion_eligibility.status
        == PromotionEligibilityStatus.ELIGIBLE
    )
    assert (
        guarded_run.observed_units[1].promotion_eligibility.reason == "non_claim_unit"
    )


def test_guardian_validate_output_assay_run_blocks_artifact_hash_mismatch() -> None:
    stamped_run = stamp_output_assay_run(_artifact_text(), _valid_payload())

    guarded_run = guardian_validate_output_assay_run(
        "Different artifact text.\n",
        stamped_run,
    )

    assert guarded_run.guardian_verdict is not None
    assert guarded_run.guardian_verdict.run_status == RunDisposition.BLOCK
    assert guarded_run.guardian_verdict.observation_counts == {
        "guardian_passed": 0,
        "guardian_warned": 0,
        "guardian_blocked": 2,
    }
    assert guarded_run.guardian_verdict.failure_modes == ["receipt_gap"]
    assert guarded_run.guardian_verdict.block_reasons == ["artifact_hash_mismatch"]
    assert guarded_run.compression is not None
    assert guarded_run.compression.status == CompressionStatus.QUARANTINE
    assert "artifact hash mismatch" in guarded_run.compression.compressed_summary
    assert guarded_run.truth_verification is not None
    assert guarded_run.truth_verification.performed is False
    assert all(
        observed_unit.observation_status == ObservationStatus.GUARDIAN_BLOCKED
        for observed_unit in guarded_run.observed_units
    )
    assert all(
        observed_unit.promotion_eligibility.status
        == PromotionEligibilityStatus.INELIGIBLE
        for observed_unit in guarded_run.observed_units
    )
    assert all(
        observed_unit.promotion_eligibility.reason == "receipt_gap"
        for observed_unit in guarded_run.observed_units
    )
    assert all(
        observed_unit.promotion_eligibility.reasons == ["receipt_gap"]
        for observed_unit in guarded_run.observed_units
    )


def test_output_assay_run_rejects_guardian_compression_status_mismatch() -> None:
    pass_run = guardian_validate_output_assay_run(
        _artifact_text(),
        stamp_output_assay_run(_artifact_text(), _valid_payload()),
    )
    pass_payload = pass_run.model_dump(mode="json")
    pass_payload["compression"]["status"] = "quarantine"

    with pytest.raises(ValueError, match="pass runs must preserve compression"):
        OutputAssayRunEnvelope.model_validate(pass_payload)

    block_run = guardian_validate_output_assay_run(
        _artifact_text(),
        stamp_output_assay_run(_artifact_text(), _blocked_payload()),
    )
    block_payload = block_run.model_dump(mode="json")
    block_payload["compression"]["status"] = "preserve"

    with pytest.raises(ValueError, match="blocked runs must use quarantine"):
        OutputAssayRunEnvelope.model_validate(block_payload)


def test_guardian_validate_output_assay_run_keeps_non_assertive_claim_ineligible() -> (
    None
):
    stamped_run = stamp_output_assay_run(
        _non_assertive_artifact_text(),
        _non_assertive_payload(),
    )

    guarded_run = guardian_validate_output_assay_run(
        _non_assertive_artifact_text(),
        stamped_run,
    )

    assert guarded_run.guardian_verdict is not None
    assert guarded_run.guardian_verdict.run_status == RunDisposition.PASS
    assert (
        guarded_run.observed_units[0].observation_status
        == ObservationStatus.GUARDIAN_PASSED
    )
    assert (
        guarded_run.observed_units[0].promotion_eligibility.status
        == PromotionEligibilityStatus.INELIGIBLE
    )
    assert (
        guarded_run.observed_units[0].promotion_eligibility.reason
        == "source_role_not_assertive"
    )


def test_guardian_validate_output_assay_run_warns_support_gap_claims() -> None:
    stamped_run = stamp_output_assay_run(
        _support_gap_artifact_text(),
        _support_gap_payload(),
    )

    guarded_run = guardian_validate_output_assay_run(
        _support_gap_artifact_text(),
        stamped_run,
    )

    assert guarded_run.guardian_verdict is not None
    assert guarded_run.guardian_verdict.run_status == RunDisposition.WARN
    assert guarded_run.compression is not None
    assert guarded_run.compression.status == CompressionStatus.PRESERVE
    assert guarded_run.truth_verification is not None
    assert guarded_run.truth_verification.performed is False
    assert guarded_run.guardian_verdict.failure_modes == ["unearned_confidence"]
    assert guarded_run.guardian_verdict.warnings == ["support_gap_present"]
    assert (
        guarded_run.observed_units[0].observation_status
        == ObservationStatus.GUARDIAN_WARNED
    )
    assert (
        guarded_run.observed_units[0].promotion_eligibility.reason
        == "support_gap_requires_review"
    )
    assert guarded_run.observed_units[0].promotion_eligibility.reasons == [
        "unearned_confidence",
        "support_gap_requires_review",
    ]


def test_guardian_validate_output_assay_run_blocks_unanchorable_spans_and_closes_promotion() -> (
    None
):
    stamped_run = stamp_output_assay_run(_artifact_text(), _blocked_payload())

    guarded_run = guardian_validate_output_assay_run(_artifact_text(), stamped_run)

    assert guarded_run.guardian_verdict is not None
    assert guarded_run.guardian_verdict.run_status == RunDisposition.BLOCK
    assert guarded_run.compression is not None
    assert guarded_run.compression.status == CompressionStatus.QUARANTINE
    assert (
        "blocked observation not traceable to artifact"
        in guarded_run.compression.compressed_summary
    )
    assert guarded_run.truth_verification is not None
    assert guarded_run.truth_verification.performed is False
    assert guarded_run.guardian_verdict.failure_modes == [
        "unanchorable_extraction",
        "invented_span",
        "receipt_gap",
    ]
    assert guarded_run.guardian_verdict.block_reasons == [
        "blocked_observation_not_traceable_to_artifact"
    ]
    assert (
        guarded_run.observed_units[1].observation_status
        == ObservationStatus.GUARDIAN_BLOCKED
    )
    assert (
        guarded_run.observed_units[1].promotion_eligibility.reason
        == "unanchorable_extraction"
    )
    assert guarded_run.observed_units[1].promotion_eligibility.reasons == [
        "unanchorable_extraction",
        "invented_span",
        "receipt_gap",
    ]
    assert guarded_run.observed_units[0].promotion_eligibility.reason == "receipt_gap"
    assert all(
        observed_unit.promotion_eligibility.status
        == PromotionEligibilityStatus.INELIGIBLE
        for observed_unit in guarded_run.observed_units
    )


def test_output_assay_analyzer_scaffold_can_apply_guardian() -> None:
    scaffold = OutputAssayAnalyzerScaffold()
    stamped_run = scaffold.stamp_local_run(_artifact_text(), _valid_payload())

    guarded_run = scaffold.apply_guardian(_artifact_text(), stamped_run)

    assert guarded_run.guardian_verdict is not None
    assert guarded_run.guardian_verdict.run_status == RunDisposition.PASS


def test_build_output_assay_extraction_failure_is_deterministic() -> None:
    errors = ["observed_units: Field required"]

    failure_one = build_output_assay_extraction_failure(_artifact_text(), errors)
    failure_two = build_output_assay_extraction_failure(_artifact_text(), errors)

    assert isinstance(failure_one, OutputAssayExtractionFailure)
    assert failure_one.failure_id == failure_two.failure_id
    assert failure_one.receipt_type == "output_assay.extraction_failure"
    assert failure_one.artifact_hash == compute_output_assay_artifact_hash(
        _artifact_text()
    )
    assert failure_one.extraction_stage == OutputAssayExtractionStage.DRAFT_VALIDATION
    assert failure_one.failure_modes == ["schema_validation_failed"]
    assert failure_one.errors == errors
    assert failure_one.truth_verification.performed is False
    assert (
        failure_one.truth_verification.tier
        == TruthVerificationTier.INTERNAL_SUPPORT_ONLY
    )


def test_build_output_assay_extraction_failure_supports_guardian_validation_stage() -> (
    None
):
    errors = ["guardian_verdict.run_status must match observed unit statuses"]

    failure = build_output_assay_extraction_failure(
        _artifact_text(),
        errors,
        extraction_stage=OutputAssayExtractionStage.GUARDIAN_VALIDATION,
    )

    assert failure.extraction_stage == OutputAssayExtractionStage.GUARDIAN_VALIDATION
    assert failure.failure_modes == ["guardian_validation_failed"]
    assert "Guardian validation" in failure.summary
    assert failure.errors == errors


def test_build_output_assay_extraction_failure_supports_provider_unavailable_stage() -> (
    None
):
    errors = ["provider local_stub unavailable"]

    failure = build_output_assay_extraction_failure(
        _artifact_text(),
        errors,
        extraction_stage=OutputAssayExtractionStage.PROVIDER_UNAVAILABLE,
    )

    assert failure.extraction_stage == OutputAssayExtractionStage.PROVIDER_UNAVAILABLE
    assert failure.failure_modes == ["provider_unavailable"]
    assert "no provider call was attempted" in failure.summary
    assert failure.errors == errors


def test_output_assay_extraction_failure_rejects_failure_mode_stage_mismatch() -> None:
    failure_payload = build_output_assay_extraction_failure(
        _artifact_text(),
        ["provider local_stub unavailable"],
        extraction_stage=OutputAssayExtractionStage.PROVIDER_UNAVAILABLE,
    ).model_dump(mode="json")
    failure_payload["failure_modes"] = ["schema_validation_failed"]

    with pytest.raises(ValueError, match="failure_modes must match extraction_stage"):
        OutputAssayExtractionFailure.model_validate(failure_payload)


def test_run_output_assay_locally_returns_guarded_run_for_valid_payload() -> None:
    result = run_output_assay_locally(_artifact_text(), _valid_payload())

    assert isinstance(result, OutputAssayRunEnvelope)
    assert result.guardian_verdict is not None
    assert result.compression is not None
    assert result.truth_verification is not None
    assert result.guardian_verdict.run_status == RunDisposition.PASS


def test_run_output_assay_locally_returns_extraction_failure_for_invalid_payload() -> (
    None
):
    invalid_payload = {
        "intent_class": "technical_answer",
        "summary": "Missing observed units",
    }

    result = run_output_assay_locally(_artifact_text(), invalid_payload)

    assert isinstance(result, OutputAssayExtractionFailure)
    assert result.receipt_type == "output_assay.extraction_failure"
    assert result.failure_modes == ["schema_validation_failed"]
    assert result.extraction_stage == OutputAssayExtractionStage.DRAFT_VALIDATION
    assert result.artifact_hash == compute_output_assay_artifact_hash(_artifact_text())
    assert any("observed_units" in error for error in result.errors)


def test_run_output_assay_locally_returns_guardian_validation_failure_when_guardian_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_guardian_failure(
        artifact_text: str,
        run: OutputAssayRunEnvelope,
    ) -> OutputAssayRunEnvelope:
        raise ValueError("guardian pipeline failed")

    monkeypatch.setattr(
        "assay.output_assay.analyzer.guardian_validate_output_assay_run",
        _raise_guardian_failure,
    )

    result = run_output_assay_locally(_artifact_text(), _valid_payload())

    assert isinstance(result, OutputAssayExtractionFailure)
    assert result.extraction_stage == OutputAssayExtractionStage.GUARDIAN_VALIDATION
    assert result.failure_modes == ["guardian_validation_failed"]
    assert result.errors == ["guardian pipeline failed"]


def test_output_assay_analyzer_scaffold_can_run_local_pipeline() -> None:
    scaffold = OutputAssayAnalyzerScaffold()
    result = scaffold.run_local_pipeline(_artifact_text(), _valid_payload())

    assert isinstance(result, OutputAssayRunEnvelope)
    assert result.guardian_verdict is not None
    assert result.compression is not None
    assert result.truth_verification is not None
