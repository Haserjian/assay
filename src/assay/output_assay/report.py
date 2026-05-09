"""Operator-facing report rendering for local Output Assay results."""

from __future__ import annotations

from enum import Enum

from assay.output_assay.models import (
    OutputAssayExtractionFailure,
    OutputAssayRunEnvelope,
    PromotionEligibilityStatus,
)


class OutputAssayReportFormat(str, Enum):
    REPORT = "report"
    JSON = "json"


class OutputAssayFailOn(str, Enum):
    BLOCK = "block"
    EXTRACTION_FAILURE = "extraction_failure"


def _format_bool(value: bool) -> str:
    return "true" if value else "false"


def _format_list(values: list[str]) -> str:
    if not values:
        return "none"
    return ", ".join(values)


def output_assay_result_status(
    result: OutputAssayRunEnvelope | OutputAssayExtractionFailure,
) -> str:
    """Return the operator-facing status for an Output Assay result."""
    if isinstance(result, OutputAssayExtractionFailure):
        return OutputAssayFailOn.EXTRACTION_FAILURE.value
    if result.guardian_verdict is None:
        return "draft"
    return result.guardian_verdict.run_status.value


def should_fail_output_assay_result(
    result: OutputAssayRunEnvelope | OutputAssayExtractionFailure,
    fail_on: OutputAssayFailOn | None,
) -> bool:
    """Return True when the result should fail the CLI gate."""
    if fail_on is None:
        return False
    return output_assay_result_status(result) == fail_on.value


def _render_run_report(result: OutputAssayRunEnvelope) -> str:
    run_status = output_assay_result_status(result)
    truth_performed = (
        _format_bool(result.truth_verification.performed)
        if result.truth_verification is not None
        else "false"
    )
    truth_tier = (
        result.truth_verification.tier.value
        if result.truth_verification is not None
        else "pending"
    )
    compression_status = (
        result.compression.status.value
        if result.compression is not None
        else "pending_guardian"
    )
    failure_modes = (
        result.guardian_verdict.failure_modes
        if result.guardian_verdict is not None
        else []
    )
    warnings = result.guardian_verdict.warnings if result.guardian_verdict else []
    block_reasons = (
        result.guardian_verdict.block_reasons if result.guardian_verdict else []
    )

    lines = [
        "# OUTPUT ASSAY REPORT",
        "",
        "Run:",
        f"  status: {run_status}",
        f"  artifact_hash: {result.artifact_hash}",
        f"  run_id: {result.run_id}",
        f"  intent_class: {result.intent_class.value}",
        f"  summary: {result.summary}",
        (f"  truth_verification: performed={truth_performed} tier={truth_tier}"),
        "",
        "Observed units:",
    ]

    for observed_unit in result.observed_units:
        promotable = (
            observed_unit.promotion_eligibility.status
            == PromotionEligibilityStatus.ELIGIBLE
        )
        lines.extend(
            [
                (
                    "  - "
                    f"{observed_unit.unit_type.value} / "
                    f"{observed_unit.source_role.value} / "
                    f"promotable={_format_bool(promotable)} / "
                    f"status={observed_unit.observation_status.value} / "
                    f"span {observed_unit.artifact_span.start_char}:"
                    f"{observed_unit.artifact_span.end_char}"
                ),
                f"    text: {observed_unit.normalized_text}",
                (f"    reason: {observed_unit.promotion_eligibility.reason}"),
            ]
        )

    lines.extend(
        [
            "",
            "Support posture:",
            f"  failure_modes: {_format_list(failure_modes)}",
            f"  warnings: {_format_list(warnings)}",
            f"  block_reasons: {_format_list(block_reasons)}",
            "",
            "Decision:",
            f"  {compression_status}",
        ]
    )
    return "\n".join(lines)


def _render_extraction_failure_report(
    result: OutputAssayExtractionFailure,
) -> str:
    lines = [
        "# OUTPUT ASSAY REPORT",
        "",
        "Run:",
        "  status: extraction_failure",
        f"  artifact_hash: {result.artifact_hash}",
        f"  failure_id: {result.failure_id}",
        (
            "  truth_verification: "
            f"performed={_format_bool(result.truth_verification.performed)} "
            f"tier={result.truth_verification.tier.value}"
        ),
        "",
        "Failure:",
        f"  stage: {result.extraction_stage.value}",
        f"  failure_modes: {_format_list(result.failure_modes)}",
        f"  summary: {result.summary}",
        "  errors:",
    ]

    for error in result.errors:
        lines.append(f"    - {error}")

    lines.extend(
        [
            "",
            "Decision:",
            "  quarantine (no trustworthy run artifact produced)",
        ]
    )
    return "\n".join(lines)


def render_output_assay_report(
    result: OutputAssayRunEnvelope | OutputAssayExtractionFailure,
) -> str:
    """Render a deterministic Markdown report for a local Output Assay result."""
    if isinstance(result, OutputAssayExtractionFailure):
        return _render_extraction_failure_report(result)
    return _render_run_report(result)


__all__ = [
    "OutputAssayFailOn",
    "OutputAssayReportFormat",
    "output_assay_result_status",
    "render_output_assay_report",
    "should_fail_output_assay_result",
]
