"""Strict local draft models for Output Assay analysis."""

from __future__ import annotations

from enum import Enum

from assay._receipts.compat.pyd import BaseModel, ConfigDictLike, Field, model_validator


class IntentClass(str, Enum):
    ARGUMENT = "argument"
    PLAN = "plan"
    TECHNICAL_ANSWER = "technical_answer"
    DECISION_MEMO = "decision_memo"
    STATUS_UPDATE = "status_update"
    CREATIVE = "creative"
    EMOTIONAL_SUPPORT = "emotional_support"
    BRAINSTORM = "brainstorm"
    SALES_PITCH = "sales_pitch"
    RESEARCH_SUMMARY = "research_summary"


class UnitType(str, Enum):
    CLAIM = "claim"
    CONSTRAINT = "constraint"
    ACTION = "action"
    QUESTION = "question"
    DECISION = "decision"
    RISK = "risk"
    EMOTION = "emotion"
    INSIGHT = "insight"
    COMMITMENT = "commitment"
    INSTRUCTION = "instruction"


class SourceRole(str, Enum):
    EVIDENCE = "evidence"
    ASSERTION = "assertion"
    INSTRUCTION = "instruction"
    CONTEXT = "context"
    EXAMPLE = "example"
    UNKNOWN = "unknown"


class ArtifactSpanDraft(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    text: str
    start_char: int
    end_char: int

    @model_validator(mode="after")
    def _validate_span(self) -> "ArtifactSpanDraft":
        if not self.text:
            raise ValueError("artifact_span.text must be non-empty")
        if self.start_char < 0:
            raise ValueError("artifact_span.start_char must be >= 0")
        if self.end_char < self.start_char:
            raise ValueError(
                "artifact_span.end_char must be >= artifact_span.start_char"
            )
        return self


class OutputAssayObservedUnitDraft(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    unit_type: UnitType
    source_role: SourceRole
    artifact_span: ArtifactSpanDraft
    normalized_text: str
    observation_confidence: float = Field(ge=0.0, le=1.0)
    notes: str

    @model_validator(mode="after")
    def _validate_text_fields(self) -> "OutputAssayObservedUnitDraft":
        if not self.normalized_text:
            raise ValueError("normalized_text must be non-empty")
        if not self.notes:
            raise ValueError("notes must be non-empty")
        return self


class OutputAssayAnalysisDraft(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    intent_class: IntentClass
    summary: str
    observed_units: list[OutputAssayObservedUnitDraft]

    @model_validator(mode="after")
    def _validate_observed_units(self) -> "OutputAssayAnalysisDraft":
        if not self.summary:
            raise ValueError("summary must be non-empty")
        if not self.observed_units:
            raise ValueError("observed_units must not be empty")
        return self


__all__ = [
    "ArtifactSpanDraft",
    "IntentClass",
    "OutputAssayAnalysisDraft",
    "OutputAssayObservedUnitDraft",
    "SourceRole",
    "UnitType",
]
