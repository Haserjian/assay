"""Local-only Guardian validation for stamped Output Assay runs."""

from __future__ import annotations

import hashlib
from typing import Iterable

from assay.output_assay.models import (
    CompressionStatus,
    ObservationStatus,
    OutputAssayCompression,
    OutputAssayGuardianVerdict,
    OutputAssayObservedUnit,
    OutputAssayPromotionEligibility,
    OutputAssayRunEnvelope,
    OutputAssayTruthVerification,
    PromotionEligibilityStatus,
    RunDisposition,
    SourceRole,
    TruthVerificationTier,
    UnitType,
)

SUPPORT_GAP_MARKERS = (
    "guarantee",
    "guarantees",
    "perfect",
    "definitely",
    "every ",
    "always",
)
NON_ASSERTIVE_CLAIM_SOURCE_ROLES = {
    SourceRole.EVIDENCE,
    SourceRole.INSTRUCTION,
    SourceRole.CONTEXT,
    SourceRole.EXAMPLE,
    SourceRole.UNKNOWN,
}
UNANCHORABLE_REASONS = [
    "unanchorable_extraction",
    "invented_span",
    "receipt_gap",
]
TRUTH_VERIFICATION_NOTES = "Calibration validates observation behavior and internal support only, not external truth."


def _artifact_hash(artifact_text: str) -> str:
    return f"sha256:{hashlib.sha256(artifact_text.encode('utf-8')).hexdigest()}"


def _span_matches_artifact(
    artifact_text: str,
    observed_unit: OutputAssayObservedUnit,
) -> bool:
    start_char = observed_unit.artifact_span.start_char
    end_char = observed_unit.artifact_span.end_char
    span_text = observed_unit.artifact_span.text

    if start_char < 0 or end_char < 0:
        return False
    if end_char > len(artifact_text):
        return False
    return artifact_text[start_char:end_char] == span_text


def _has_support_gap_markers(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in SUPPORT_GAP_MARKERS)


def _ineligible(
    reason: str,
    *,
    reasons: Iterable[str] | None = None,
) -> OutputAssayPromotionEligibility:
    return OutputAssayPromotionEligibility(
        status=PromotionEligibilityStatus.INELIGIBLE,
        reason=reason,
        reasons=list(reasons) if reasons is not None else None,
    )


def _eligible() -> OutputAssayPromotionEligibility:
    return OutputAssayPromotionEligibility(
        status=PromotionEligibilityStatus.ELIGIBLE,
        reason="claim_unit_with_clean_provenance",
    )


def _default_truth_verification() -> OutputAssayTruthVerification:
    return OutputAssayTruthVerification(
        performed=False,
        tier=TruthVerificationTier.INTERNAL_SUPPORT_ONLY,
        notes=TRUTH_VERIFICATION_NOTES,
    )


def _derive_compression(
    run_summary: str,
    run_status: RunDisposition,
    block_reasons: list[str],
) -> OutputAssayCompression:
    if run_status == RunDisposition.BLOCK:
        reason = block_reasons[0] if block_reasons else "guardian_blocked_run"
        return OutputAssayCompression(
            status=CompressionStatus.QUARANTINE,
            compressed_summary=(
                f"The run is quarantined because {reason.replace('_', ' ')}."
            ),
        )

    return OutputAssayCompression(
        status=CompressionStatus.PRESERVE,
        compressed_summary=run_summary,
    )


def _guardian_transition_unit(
    artifact_text: str,
    observed_unit: OutputAssayObservedUnit,
) -> tuple[OutputAssayObservedUnit, list[str], list[str], list[str]]:
    if not _span_matches_artifact(artifact_text, observed_unit):
        return (
            observed_unit.model_copy(
                update={
                    "observation_status": ObservationStatus.GUARDIAN_BLOCKED,
                    "promotion_eligibility": _ineligible(
                        "unanchorable_extraction",
                        reasons=UNANCHORABLE_REASONS,
                    ),
                }
            ),
            UNANCHORABLE_REASONS,
            [],
            ["blocked_observation_not_traceable_to_artifact"],
        )

    if observed_unit.unit_type != UnitType.CLAIM:
        return (
            observed_unit.model_copy(
                update={
                    "observation_status": ObservationStatus.GUARDIAN_PASSED,
                    "promotion_eligibility": _ineligible("non_claim_unit"),
                }
            ),
            [],
            [],
            [],
        )

    if observed_unit.source_role in NON_ASSERTIVE_CLAIM_SOURCE_ROLES:
        return (
            observed_unit.model_copy(
                update={
                    "observation_status": ObservationStatus.GUARDIAN_PASSED,
                    "promotion_eligibility": _ineligible("source_role_not_assertive"),
                }
            ),
            [],
            [],
            [],
        )

    if _has_support_gap_markers(observed_unit.normalized_text):
        return (
            observed_unit.model_copy(
                update={
                    "observation_status": ObservationStatus.GUARDIAN_WARNED,
                    "promotion_eligibility": _ineligible(
                        "support_gap_requires_review",
                        reasons=[
                            "unearned_confidence",
                            "support_gap_requires_review",
                        ],
                    ),
                }
            ),
            ["unearned_confidence"],
            ["support_gap_present"],
            [],
        )

    return (
        observed_unit.model_copy(
            update={
                "observation_status": ObservationStatus.GUARDIAN_PASSED,
                "promotion_eligibility": _eligible(),
            }
        ),
        [],
        [],
        [],
    )


def guardian_validate_output_assay_run(
    artifact_text: str,
    run: OutputAssayRunEnvelope,
) -> OutputAssayRunEnvelope:
    """Apply deterministic local Guardian checks to a stamped run."""
    if _artifact_hash(artifact_text) != run.artifact_hash:
        updated_units = [
            observed_unit.model_copy(
                update={
                    "observation_status": ObservationStatus.GUARDIAN_BLOCKED,
                    "promotion_eligibility": _ineligible(
                        "receipt_gap",
                        reasons=["receipt_gap"],
                    ),
                }
            )
            for observed_unit in run.observed_units
        ]
        guardian_verdict = OutputAssayGuardianVerdict(
            run_status=RunDisposition.BLOCK,
            observation_counts={
                ObservationStatus.GUARDIAN_PASSED.value: 0,
                ObservationStatus.GUARDIAN_WARNED.value: 0,
                ObservationStatus.GUARDIAN_BLOCKED.value: len(updated_units),
            },
            failure_modes=["receipt_gap"],
            warnings=[],
            block_reasons=["artifact_hash_mismatch"],
        )
        compression = _derive_compression(
            run.summary,
            RunDisposition.BLOCK,
            ["artifact_hash_mismatch"],
        )
        return run.model_copy(
            update={
                "observed_units": updated_units,
                "guardian_verdict": guardian_verdict,
                "compression": compression,
                "truth_verification": _default_truth_verification(),
            }
        )

    updated_units: list[OutputAssayObservedUnit] = []
    failure_modes: list[str] = []
    warnings: list[str] = []
    block_reasons: list[str] = []

    for observed_unit in run.observed_units:
        updated_unit, unit_failure_modes, unit_warnings, unit_block_reasons = (
            _guardian_transition_unit(artifact_text, observed_unit)
        )
        updated_units.append(updated_unit)
        for failure_mode in unit_failure_modes:
            if failure_mode not in failure_modes:
                failure_modes.append(failure_mode)
        for warning in unit_warnings:
            if warning not in warnings:
                warnings.append(warning)
        for block_reason in unit_block_reasons:
            if block_reason not in block_reasons:
                block_reasons.append(block_reason)

    has_blocked = any(
        observed_unit.observation_status == ObservationStatus.GUARDIAN_BLOCKED
        for observed_unit in updated_units
    )
    if has_blocked:
        updated_units = [
            observed_unit
            if observed_unit.promotion_eligibility.status
            != PromotionEligibilityStatus.ELIGIBLE
            else observed_unit.model_copy(
                update={
                    "promotion_eligibility": _ineligible(
                        "receipt_gap",
                        reasons=["receipt_gap"],
                    )
                }
            )
            for observed_unit in updated_units
        ]

    observation_counts = {
        ObservationStatus.GUARDIAN_PASSED.value: 0,
        ObservationStatus.GUARDIAN_WARNED.value: 0,
        ObservationStatus.GUARDIAN_BLOCKED.value: 0,
    }
    for observed_unit in updated_units:
        if observed_unit.observation_status == ObservationStatus.DRAFT:
            continue
        observation_counts[observed_unit.observation_status.value] += 1

    run_status = RunDisposition.PASS
    if observation_counts[ObservationStatus.GUARDIAN_BLOCKED.value] > 0:
        run_status = RunDisposition.BLOCK
    elif observation_counts[ObservationStatus.GUARDIAN_WARNED.value] > 0:
        run_status = RunDisposition.WARN

    guardian_verdict = OutputAssayGuardianVerdict(
        run_status=run_status,
        observation_counts=observation_counts,
        failure_modes=failure_modes,
        warnings=warnings,
        block_reasons=block_reasons,
    )
    compression = _derive_compression(run.summary, run_status, block_reasons)

    return run.model_copy(
        update={
            "observed_units": updated_units,
            "guardian_verdict": guardian_verdict,
            "compression": compression,
            "truth_verification": _default_truth_verification(),
        }
    )


__all__ = ["guardian_validate_output_assay_run"]
