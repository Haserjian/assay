"""Local-only Output Assay analyzer scaffold.

This slice stops at strict draft validation and deterministic local stamping.
Provider execution, Guardian projection, and kernel promotion land later.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from jsonschema.validators import validator_for
from pydantic import ValidationError

from assay.output_assay.guardian import guardian_validate_output_assay_run
from assay.output_assay.models import (
    ObservationStatus,
    ObserverKind,
    OutputAssayAnalysisDraft,
    OutputAssayObservedUnit,
    OutputAssayObserver,
    OutputAssayPromotionEligibility,
    OutputAssayRunEnvelope,
    PromotionEligibilityStatus,
    UnitType,
)

DEFAULT_LOCAL_OBSERVER = OutputAssayObserver(
    kind=ObserverKind.TOOL,
    provider="local",
    model="output_assay_scaffold",
)


class OutputAssayDraftValidationError(ValueError):
    """Raised when a draft payload fails local schema validation."""

    def __init__(self, errors: list[str]):
        super().__init__("Output Assay analysis draft failed local schema validation")
        self.errors = errors


def output_assay_analysis_draft_schema() -> dict[str, Any]:
    """Return the local JSON Schema for Output Assay draft validation."""
    schema = OutputAssayAnalysisDraft.model_json_schema()
    if schema.get("type") != "object":
        raise ValueError("Output Assay draft schema root must be an object")
    if "anyOf" in schema or "oneOf" in schema:
        raise ValueError("Output Assay draft schema root must not be a union")
    return schema


def _build_schema_validator() -> Any:
    schema = output_assay_analysis_draft_schema()
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    return validator_cls(schema)


def output_assay_analysis_draft_schema_errors(payload: object) -> list[str]:
    """Return schema-validation errors for a draft payload."""
    if not isinstance(payload, Mapping):
        return ["(root): payload must be an object"]

    validator = _build_schema_validator()
    payload_dict = dict(payload)
    errors: list[str] = []
    for error in sorted(
        validator.iter_errors(payload_dict),
        key=lambda item: ".".join(str(part) for part in item.absolute_path),
    ):
        path = ".".join(str(part) for part in error.absolute_path) or "(root)"
        errors.append(f"{path}: {error.message}")
    return errors


def validate_output_assay_analysis_draft(
    payload: object,
) -> OutputAssayAnalysisDraft:
    """Validate a draft payload with local schema and model checks only."""
    if isinstance(payload, OutputAssayAnalysisDraft):
        return payload

    schema_errors = output_assay_analysis_draft_schema_errors(payload)
    if schema_errors:
        raise OutputAssayDraftValidationError(schema_errors)

    try:
        return OutputAssayAnalysisDraft.model_validate(dict(payload))
    except ValidationError as exc:
        formatted_errors: list[str] = []
        for error in exc.errors():
            path = ".".join(str(part) for part in error["loc"]) or "(root)"
            formatted_errors.append(f"{path}: {error['msg']}")
        raise OutputAssayDraftValidationError(formatted_errors) from exc


def compute_output_assay_artifact_hash(artifact_text: str) -> str:
    """Return the canonical artifact hash for local Output Assay stamping."""
    return f"sha256:{hashlib.sha256(artifact_text.encode('utf-8')).hexdigest()}"


def _stable_json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _deterministic_run_id(artifact_hash: str, draft: OutputAssayAnalysisDraft) -> str:
    digest = hashlib.sha256(
        _stable_json_bytes(
            {
                "artifact_hash": artifact_hash,
                "draft": draft.model_dump(mode="json"),
            }
        )
    ).hexdigest()
    return f"oa_run_{digest[:16]}"


def _draft_promotion_eligibility(
    unit_type: UnitType,
) -> OutputAssayPromotionEligibility:
    if unit_type == UnitType.CLAIM:
        return OutputAssayPromotionEligibility(
            status=PromotionEligibilityStatus.INELIGIBLE,
            reason="guardian_review_pending",
        )
    return OutputAssayPromotionEligibility(
        status=PromotionEligibilityStatus.INELIGIBLE,
        reason="non_claim_unit",
    )


def stamp_output_assay_run(
    artifact_text: str,
    payload: object,
    *,
    observer: OutputAssayObserver | None = None,
) -> OutputAssayRunEnvelope:
    """Stamp a deterministic local-only Output Assay run envelope.

    This function performs no provider calls, no Guardian projection, and no
    promotion. It only validates the draft locally, computes the artifact hash,
    and stamps deterministic envelope and observation fields.
    """
    draft = validate_output_assay_analysis_draft(payload)
    artifact_hash = compute_output_assay_artifact_hash(artifact_text)
    run_id = _deterministic_run_id(artifact_hash, draft)
    stamped_observer = observer or DEFAULT_LOCAL_OBSERVER

    observed_units = [
        OutputAssayObservedUnit(
            unit_id=f"{run_id}_u{index:03d}",
            unit_type=observed_unit.unit_type,
            source_role=observed_unit.source_role,
            artifact_hash=artifact_hash,
            artifact_span=observed_unit.artifact_span,
            normalized_text=observed_unit.normalized_text,
            observer=stamped_observer,
            observation_confidence=observed_unit.observation_confidence,
            observation_status=ObservationStatus.DRAFT,
            promotion_eligibility=_draft_promotion_eligibility(observed_unit.unit_type),
            notes=observed_unit.notes,
        )
        for index, observed_unit in enumerate(draft.observed_units, start=1)
    ]

    return OutputAssayRunEnvelope(
        run_id=run_id,
        artifact_hash=artifact_hash,
        intent_class=draft.intent_class,
        summary=draft.summary,
        observed_units=observed_units,
    )


@dataclass(frozen=True)
class OutputAssayAnalyzerScaffold:
    """Minimal analyzer entrypoint for local validation and stamping only."""

    def draft_schema(self) -> dict[str, Any]:
        return output_assay_analysis_draft_schema()

    def validate_local_draft(self, payload: object) -> OutputAssayAnalysisDraft:
        return validate_output_assay_analysis_draft(payload)

    def stamp_local_run(
        self,
        artifact_text: str,
        payload: object,
        *,
        observer: OutputAssayObserver | None = None,
    ) -> OutputAssayRunEnvelope:
        return stamp_output_assay_run(
            artifact_text,
            payload,
            observer=observer,
        )

    def apply_guardian(
        self,
        artifact_text: str,
        run: OutputAssayRunEnvelope,
    ) -> OutputAssayRunEnvelope:
        return guardian_validate_output_assay_run(artifact_text, run)


__all__ = [
    "OutputAssayAnalyzerScaffold",
    "OutputAssayDraftValidationError",
    "compute_output_assay_artifact_hash",
    "output_assay_analysis_draft_schema",
    "output_assay_analysis_draft_schema_errors",
    "stamp_output_assay_run",
    "validate_output_assay_analysis_draft",
]
