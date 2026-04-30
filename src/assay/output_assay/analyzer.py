"""Local-only Output Assay analyzer scaffold.

This slice stops at strict draft validation. Provider execution, Guardian
projection, and canonical receipt stamping land later.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from jsonschema.validators import validator_for
from pydantic import ValidationError

from assay.output_assay.models import OutputAssayAnalysisDraft


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


@dataclass(frozen=True)
class OutputAssayAnalyzerScaffold:
    """Minimal analyzer entrypoint that performs local draft validation only."""

    def draft_schema(self) -> dict[str, Any]:
        return output_assay_analysis_draft_schema()

    def validate_local_draft(self, payload: object) -> OutputAssayAnalysisDraft:
        return validate_output_assay_analysis_draft(payload)


__all__ = [
    "OutputAssayAnalyzerScaffold",
    "OutputAssayDraftValidationError",
    "output_assay_analysis_draft_schema",
    "output_assay_analysis_draft_schema_errors",
    "validate_output_assay_analysis_draft",
]